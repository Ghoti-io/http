"""What the two WebSocket-over-HTTP/2 reference drivers share.

The HTTP/2 side is h2 (Python); the WebSocket side is websockets' sans-I/O
Protocol, which does the framing, masking, fragmentation, the close handshake
and permessage-deflate. Neither knows of the other: RFC 8441 is what joins
them, and this driver is that join - the DATA of a stream in and out of
Protocol.receive_data() and Protocol.data_to_send().

The extension negotiation is websockets' own. It only has a way to run it
through an HTTP/1.1 handshake, so the handshake is replayed canned: the
extension offer (or the server's answer) that travelled as an h2 header field
is put into the HTTP/1.1 request (or 101 response) websockets reads, and the
result of that negotiation is the Protocol that is then used. The canned
parts - the key and its accept value - are the RFC 6455 example, and play no
part in what is checked: RFC 8441 has neither.

stdin and stdout are the HTTP/2 connection, so a harness joins them to the
other end with two pipes.
"""
import os
import sys

import h2
import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings
import websockets
from websockets.client import ClientProtocol
from websockets.extensions.permessage_deflate import (ClientPerMessageDeflateFactory,
                                                      ServerPerMessageDeflateFactory)
from websockets.frames import Close, Opcode
from websockets.protocol import OPEN
from websockets.server import ServerProtocol
from websockets.uri import parse_uri

RFC_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
MAX_SIZE = 4 << 20


def version():
    return "websockets %s over h2 %s" % (websockets.__version__, h2.__version__)


def log(*a):
    sys.stderr.write(" ".join(str(x) for x in a) + "\n")
    sys.stderr.flush()


def pattern(i, n, text):
    """Message i of n octets: ASCII and, in text, multi-octet UTF-8 too."""
    if not text:
        x = (i + 1) * 2654435761 & 0xffffffff
        out = bytearray()
        for _ in range(n):
            x = (x * 1103515245 + 12345) & 0xffffffff
            out.append((x >> 16) & 0xff)
        return bytes(out)
    base = "message %d: abc é中\U0001f600 " % i
    s = (base * (n // len(base.encode()) + 2)).encode()
    # n octets, cut on a character boundary at or below n
    s = s[:n]
    while s:
        try:
            s.decode("utf-8")
            break
        except UnicodeDecodeError:
            s = s[:-1]
    return s


class Pipe:
    """The h2 connection over stdin and stdout."""

    def __init__(self, client):
        cfg = h2.config.H2Configuration(client_side=client, header_encoding="utf-8")
        self.c = h2.connection.H2Connection(config=cfg)
        self.out = sys.stdout.buffer
        self.pending = {}  # stream -> bytes not yet sent (flow control)
        self.end_after = set()

    def start_client(self):
        """Open the connection as a client, as h2 does, unmodified.

        h2 puts every setting it knows in its first SETTINGS frame, including
        ENABLE_CONNECT_PROTOCOL with the value 0. RFC 8441 makes it a server's
        setting; this library, as a server, ignores a client's 0 (and refuses a
        1), so the bytes go out as h2 wrote them. The driver checks that the
        entry is there, so that the scenario is the one it claims to be.
        """
        self.c.initiate_connection()
        data = self.c.data_to_send()
        if b"\x00\x08\x00\x00\x00\x00" not in data:
            raise SystemExit("h2 did not send ENABLE_CONNECT_PROTOCOL=0: the scenario is not what it says")
        self.out.write(data)
        self.out.flush()

    def flush(self):
        data = self.c.data_to_send()
        if data:
            self.out.write(data)
            self.out.flush()

    def send(self, stream, data, end=False):
        self.pending[stream] = self.pending.get(stream, b"") + data
        if end:
            self.end_after.add(stream)
        self.push()

    def push(self):
        for stream in list(self.pending):
            buf = self.pending[stream]
            while buf:
                room = min(self.c.local_flow_control_window(stream),
                           self.c.max_outbound_frame_size, len(buf))
                if room <= 0:
                    break
                self.c.send_data(stream, buf[:room])
                buf = buf[room:]
            self.pending[stream] = buf
            if not buf and stream in self.end_after:
                try:
                    self.c.end_stream(stream)
                except h2.exceptions.StreamClosedError:
                    pass
                self.end_after.discard(stream)
            if not buf:
                del self.pending[stream]
        self.flush()

    def read(self):
        data = os.read(0, 65536)
        return data
