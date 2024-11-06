import asyncio
import itertools
import json
from pathlib import Path
import ssl
import sys

import click
import time
import logging

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from aioquic_doq_client import DnsClientProtocol
from aioquic.quic.logger import QuicLogger
from utils import parse_addr


logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


async def check_doq(i, addr):
    log_secrets = True
    time_start = time.time()
    time_connected = None
    time_response = None
    time_end = None
    time_error = None
    error = None
    stage = 'connect'
    quic_logger = None # QuicLogger()
    try:
        async with connect(
            host=addr[0],
            port=addr[1],
            configuration=QuicConfiguration(
                alpn_protocols=['doq'],
                verify_mode=ssl.VerifyMode.CERT_NONE,
                secrets_log_file=(Path(__file__).parent.parent / 'quic_secrets.log').open('a') if log_secrets else None,
                quic_logger=quic_logger,
            ),
            create_protocol=DnsClientProtocol,
            wait_connected=True,
        ) as client:
            time_connected = time.time()
            stage = 'request'
            res = await client.query('example.com', 'A')
            time_response = time.time()
            stage = 'close'
        time_end = time.time()
        stage = 'done'
    except (Exception, asyncio.CancelledError) as ex:
        error = ex
        time_error = time.time()
        if not time_connected:
            time_connected = time_error
        if not time_response:
            time_response = time_error
        if not time_end:
            time_end = time_error

    elapsed_total = (time_end - time_start) * 1000
    elapsed_connect = (time_connected - time_start) * 1000
    elapsed_response = (time_response - time_connected) * 1000
    elapsed_close = (time_end - time_response) * 1000
    result = {
        'i': i,
        'elapsed_total': elapsed_total,
        'elapsed_connect': elapsed_connect,
        'elapsed_response': elapsed_response,
        'elapsed_close': elapsed_close,
        'is_error': bool(error),
        'error': repr(error) if error else None,
        'stage': stage,
        'time_start': time_start,
        'time_connected': time_connected,
        'time_response': time_response,
        'time_end': time_end,
        'time_error': time_error,
    }
    print(json.dumps(result))
    print(f'{i:03} total={int(elapsed_total):03}ms connect={int(elapsed_connect):03}ms response={int(elapsed_response):03}ms close={int(elapsed_close):03}ms', file=sys.stderr)

    if quic_logger:
        (Path(__file__).parent.parent / 'out' / f'qlog_{i}.json').write_text(json.dumps(quic_logger.to_dict(), indent=2))


async def check_task(*args, **kwargs):
    task = check_doq(*args, **kwargs)
    try:
        await asyncio.wait_for(task, timeout=60)
    except TimeoutError:
        pass


async def check_loop(addr):
    tasks = []
    try:
        for i in itertools.count():
            # Start task
            task = asyncio.ensure_future(check_task(i, addr))
            tasks.append(task)

            # Wait
            await asyncio.sleep(1)

            # Cleanup old tasks
            for t in tasks:
                if t.done():
                    await t
                    tasks.remove(t)
    except:
        logging.exception('Error in check_loop')
        for t in tasks:
            t.cancel()


@click.command()
@click.argument('addr', type=parse_addr)
def main(addr):
    asyncio.run(check_loop(addr))


if __name__ == '__main__':
    main()
