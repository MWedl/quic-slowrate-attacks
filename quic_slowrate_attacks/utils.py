import asyncio
from collections import deque
import contextlib
import functools
import logging
from pathlib import Path
import random
import ssl
from inspect import iscoroutinefunction
from multiprocessing.pool import ThreadPool
from unittest import mock
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio import connect
import click

from aioquic_http3_client import HttpClient
from aioquic_doq_client import DnsClientProtocol



def parse_addr(addr):
    parts = addr.split(':')
    assert len(parts) == 2
    return parts[0], int(parts[1])


def _calculate_slowrate_wait_time(quic, time=None):
    if time is None:
        time = quic._remote_max_idle_timeout
    if time is None:
        time = 20.0
    return (time / 100.0) * random.randint(50, 75)


def calculate_slowrate_wait_time(quic, time=None):
    import utils
    return utils._calculate_slowrate_wait_time(quic, time)


def run_parallel(num_threads=None, num_async=None):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def main_func(*_):
                if iscoroutinefunction(func):
                    async def aio_main():
                        if num_async and num_async > 1:
                            return await asyncio.gather(*[func(*args, **kwargs) for _ in range(num_async)])
                        else:
                            return await func(*args, **kwargs)
                    return asyncio.run(aio_main())
                else:
                    assert num_async is None, 'num_async is only supported for async functions'
                    return func(*args, **kwargs)
            
            if num_threads and num_threads > 1:
                with ThreadPool(num_threads) as p:
                    return p.map(main_func, [None] * num_threads)[0]
            else:
                return main_func()
        
        return wrapper
    return decorator


def quic_connection_loop(alpn_protocols, create_protocol=QuicConnectionProtocol):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(addr, debug=False, *args, **kwargs):
            while True:
                try:
                    async with connect(
                        host=addr[0],
                        port=addr[1],
                        configuration=QuicConfiguration(
                            alpn_protocols=alpn_protocols,
                            verify_mode=ssl.VerifyMode.CERT_NONE,
                            secrets_log_file=(Path(__file__).parent.parent / 'quic_secrets.log').open('a') if debug else None,
                        ),
                        create_protocol=create_protocol,
                    ) as con:
                        await func(addr=addr, con=con, *args, **kwargs)
                except AssertionError:
                    raise
                except Exception as ex:
                    logging.exception(ex)
                
        return wrapper
    return decorator


def h3_connection_loop():
    return quic_connection_loop(H3_ALPN, create_protocol=HttpClient)


def doq_connection_loop():
    return quic_connection_loop(['doq'], create_protocol=DnsClientProtocol)


@contextlib.asynccontextmanager
async def h3_request_stream(con: HttpClient):
    stream_id = con.http._quic.get_next_available_stream_id()
    waiter = con._loop.create_future()
    con.request_events[stream_id] = deque()
    con.request_waiter[stream_id] = waiter

    yield stream_id

    # Finish request and receive response
    con.transmit()
    res = await asyncio.shield(waiter)
    logging.debug(f'Response: {res}')


def attack_command(decorators=None):
    def wrapper(func):
        @functools.wraps(func)
        @click.command()
        @click.argument('addr', type=parse_addr)
        @click.option('--debug', is_flag=True, default=False)
        def inner(addr, alpn=H3_ALPN[0], debug=False, *args, **kwargs):
            run_parallel_args = {
                'num_threads': 16,
                'num_async': 100,           
            }
            if debug:
                logging.getLogger().setLevel(logging.DEBUG)
                import utils
                utils._calculate_slowrate_wait_time = lambda *args, **kwargs: 1
                run_parallel_args = {}

            return run_parallel(**run_parallel_args)(func)(*args, addr=addr, alpn=alpn, debug=debug, **kwargs)
        for d in (decorators or []):
            inner = d(inner)
        return inner
    return wrapper
