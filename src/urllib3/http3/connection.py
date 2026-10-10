from dataclasses import dataclass, field
import socket
import threading
import time
import typing

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection as _QuicConnection
from aioquic.h3.connection import H3Connection
from aioquic.quic import events as quic_events
from aioquic.h3 import events as h3_events

from urllib3 import HTTPHeaderDict
from urllib3.connection import Stream, _TYPE_BODY
from urllib3.response import HTTPResponse
from urllib3.http2.connection import _is_legal_header_name, _is_illegal_header_value, _LockedObject
from urllib3.connection import _get_default_user_agent


@dataclass
class HTTP3StreamData:
    url: str = field(default="")
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    events: list[h3_events.H3Event] = field(default_factory=list)


class QuicConnection:
    def __init__(
        self, host: str,
        port: int | None = None,
        timeout: float | None = None,
        blocksize: int = 8192,
        max_response_headers: int = 100,
        **kwargs
    ):
        self.host = host
        self.port = port or 443
        self.timeout = timeout
        self.blocksize = blocksize
        self.max_response_headers = max_response_headers
        quic_config = QuicConfiguration(alpn_protocols=['h3'], is_client=True)
        self._quic = _LockedObject(_QuicConnection(configuration=quic_config))
        with self._quic as quic:
            self._h3 = H3Connection(quic)
        self._sock: socket.socket | None = None
        self._connected = False
        self._stream_data: dict[Stream | int, HTTP3StreamData] = {}

    def __str__(self) -> str:
        return f"{type(self).__name__}(host={self.host!r}, port={self.port!r})"

    def __repr__(self) -> str:
        return f"<{self} at {id(self):#x}>"

    def connect(self) -> None:
        self._sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        if self.timeout is not None:
            self._sock.settimeout(self.timeout)
        with self._quic as quic:
            quic.connect((self.host, self.port), time.time())
            for dgram in quic.datagrams_to_send(time.time()):
                self._sock.sendto(*dgram)

            while True:
                event = quic.next_event()
                while event and not isinstance(event, quic_events.HandshakeCompleted):
                    event = quic.next_event()
                if event:
                    self._connected = event is not None and event.alpn_protocol == "h3"
                    break
                for dgram in quic.datagrams_to_send(time.time()):
                    self._sock.sendto(*dgram)
                data, addr = self._sock.recvfrom(65536)
                quic.receive_datagram(data, addr, time.time())

    @property
    def is_closed(self) -> bool:
        return self._sock is None

    @property
    def is_connected(self) -> bool:
        return not self.is_closed and self._connected

    def putrequest(
        self,
        method: str,
        url: str,
        skip_host: bool = False,
        skip_accept_encoding: bool = False,
        stream: Stream | None = None,
    ) -> None:
        if not self.is_connected:
            raise ConnectionError("Connection failed")
        if skip_host:
            raise NotImplementedError("`skip_host` isn't supported")
        if skip_accept_encoding:
            raise NotImplementedError("`skip_accept_encoding` isn't supported")
        if stream is None:
            raise ConnectionError("`stream` cannot be None")
        if stream in self._stream_data:
            raise ConnectionError("`put_request` was already called for this stream")

        self._stream_data[stream] = HTTP3StreamData()
        self._stream_data[stream].url = url or "/"
        #self._validate_path(url)  # type: ignore[attr-defined]

        port = self.port if self.port is not None else 443
        if ":" in self.host:
            authority = f"[{self.host}]:{port}"
        else:
            authority = f"{self.host}:{port}"

        self._stream_data[stream].headers.append((b":scheme", b"https"))
        self._stream_data[stream].headers.append((b":method", method.encode()))
        self._stream_data[stream].headers.append((b":authority", authority.encode()))
        self._stream_data[stream].headers.append((b":path", url.encode()))

    def putheader(self, header: str, *values: str, stream: Stream | None = None) -> None:
        if stream is None:
            raise ConnectionError("`stream` cannot be None")

        encoded_header = header.encode() if isinstance(header, str) else header
        encoded_header = encoded_header.lower()  # A lot of upstream code uses capitalized headers.
        if not _is_legal_header_name(encoded_header):
            raise ValueError(f"Illegal header name {str(header)}")

        for value in values:
            encoded_value = value.encode() if isinstance(value, str) else value
            if _is_illegal_header_value(encoded_value):
                raise ValueError(f"Illegal header value {str(value)}")
            self._stream_data[stream].headers.append((encoded_header, encoded_value))

    def endheaders(self, message_body: typing.Any = None, stream: Stream | None = None) -> None:
        if stream is None:
            raise ConnectionError("`stream` cannot be None")

        with self._quic as quic:
            stream.stream_id = quic.get_next_available_stream_id()
            self._stream_data[stream.stream_id] = self._stream_data[stream]
            self._h3.send_headers(
                stream.stream_id,
                headers=self._stream_data[stream].headers,
                end_stream=(message_body is None),
            )
            for dgram in quic.datagrams_to_send(time.time()):
                self._sock.sendto(*dgram)

    def request(  # type: ignore[override]
        self,
        method: str,
        url: str,
        body: _TYPE_BODY | None = None,
        headers: typing.Mapping[str, str] | None = None,
        **kwargs,
    ) -> Stream:
        stream = Stream(self)
        self.putrequest(method, url, stream=stream)

        headers = headers or {}
        for k, v in headers.items():
            if k.lower() == "transfer-encoding" and v == "chunked":
                continue
            else:
                self.putheader(k, v, stream=stream)

        if b"user-agent" not in dict(self._stream_data[stream].headers):
            self.putheader(b"user-agent", _get_default_user_agent(), stream=stream)

        if body:
            self.endheaders(message_body=body, stream=stream)
            self.send(body, stream=stream)
        else:
            self.endheaders(stream=stream)
        return stream

    def send(self, data: typing.Any, stream: Stream | None = None) -> None:
        if stream is None:
            raise ConnectionError("`stream` cannot be None")
        if stream.stream_id is None:
            raise ConnectionError("Must call `request` to create a stream")

        if hasattr(data, "read"):  # file-like objects
            while True:
                chunk = data.read(self.blocksize)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode()
                with self._quic as quic:
                    quic.send_stream_data(stream.stream_id, chunk, end_stream=False)
                    for dgram in quic.datagrams_to_send(time.time()):
                        self._sock.sendto(*dgram)
            with self._quic as quic:
                quic.send_stream_data(stream.stream_id, b'', end_stream=True)
            return

        if isinstance(data, str):  # str -> bytes
            data = data.encode()

        try:
            if isinstance(data, bytes):
                with self._quic as quic:
                    quic.send_stream_data(stream.stream_id, data, end_stream=True)
                    for dgram in quic.datagrams_to_send(time.time()):
                        self._sock.sendto(*dgram)
            else:
                for chunk in data:
                    with self._quic as quic:
                        quic.send_stream_data(stream.stream_id, chunk, end_stream=False)
                        for dgram in quic.datagrams_to_send(time.time()):
                            self._sock.sendto(*dgram)
                with self._quic as quic:
                    quic.send_stream_data(stream.stream_id, b'', end_stream=True)
        except TypeError:
            raise TypeError(
                "`data` should be str, bytes, iterable, or file. got %r" % type(data)
            )
        return True

    def _receive(self, stream: Stream) -> list[h3_events.H3Event]:
        if stream.stream_id is None:
            raise ConnectionError("Must call `request` to create a stream")

        with self._quic as quic:
            if not self._stream_data[stream].events:
                while True:
                    event = quic.next_event()
                    while event:
                        if isinstance(event, quic_events.StreamDataReceived):
                            for h3_event in self._h3.handle_event(event):
                                if h3_event.stream_id in self._stream_data:
                                    self._stream_data[h3_event.stream_id].events.append(h3_event)
                        elif isinstance(event, quic_events.StreamReset):
                            pass
                        event = quic.next_event()

                    if self._stream_data[stream].events:
                        break

                    for dgram in quic.datagrams_to_send(time.time()):
                        self._sock.sendto(*dgram)
                    data, addr = self._sock.recvfrom(65536)
                    quic.receive_datagram(data, addr, time.time())

        events = self._stream_data[stream].events
        self._stream_data[stream].events = []
        return events

    def getresponse(self, stream: Stream | None = None) -> HTTPResponse:
        if stream is None:
            raise ConnectionError("`stream` cannot be None")
        if stream.stream_id is None:
            raise ConnectionError("Must call `request` to create a stream")

        status = None
        headers = HTTPHeaderDict()
        data = bytearray()
        with self._quic as quic:
            end_stream = False
            while not end_stream:
                events = self._receive(stream)
                for event in events:
                    if isinstance(event, h3_events.HeadersReceived):
                        for header, value in event.headers:
                            if header == b':status':
                                status = int(value.decode())
                            else:
                                headers.add(header.decode('ascii'), value.decode('ascii'))
                        if event.stream_ended:
                            end_stream = True
                    elif isinstance(event, h3_events.DataReceived):
                        data += event.data
                        if event.stream_ended:
                            end_stream = True
                if not end_stream:
                    for dgram in quic.datagrams_to_send(time.time()):
                        self._sock.sendto(*dgram)
                    data, addr = self._sock.recvfrom(65536)
                    quic.receive_datagram(data, addr, time.time())

        return HTTPResponse(status=status, headers=headers, body=bytes(data), version_string='HTTP/3')

    def close_stream(self, stream: Stream | None = None) -> None:
        if stream is None:
            raise ValueError("`stream` cannot be None")
        if not stream.stream_id:
            raise ValueError("Must call `request` to create a stream")

        with self._quic as quic:
            try:
                quic.stop_stream(stream.stream_id, 0)
                for dgram in quic.datagrams_to_send(time.time()):
                    self._sock.sendto(*dgram)
            except Exception:
                pass

            if stream in self._stream_data:
                del self._stream_data[stream]
            if stream.stream_id in self._stream_data:
                del self._stream_data[stream.stream_id]

    def close(self) -> None:
        with self._quic as quic:
            quic.close()
            for dgram in quic.datagrams_to_send(time.time()):
                self._sock.sendto(*dgram)
