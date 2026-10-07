"""What the WebSocket reference drivers share: the line protocol, the spec in
`arg`, the canned handshakes and the reading of the frames an implementation
wrote. The protocol is the one ws_probe.c documents (tools/oracle/ws_probe.c).

Nothing here decides what any implementation does: it only builds the bytes
that bring each one to the state a case starts in, and parses the frames each
one wrote, the same way for all of them.
"""
import json
import sys

RFC_KEY = b"dGhlIHNhbXBsZSBub25jZQ=="
RFC_ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
MAX_MESSAGE = 1 << 20  # ws_probe.c: the limit every implementation is given


def hx(b):
    return bytes(b).hex()


class Spec:
    """The `arg` of a case. See ws_probe.c."""

    def __init__(self, arg):
        self.client = False
        self.protos = []
        self.d = False
        self.snct = self.cnct = False
        self.smb = self.cmb = 0
        self.ocmb = False
        if arg == "-":
            return
        for tok in arg.split(";"):
            if tok == "role=client":
                self.client = True
            elif tok == "role=server":
                self.client = False
            elif tok.startswith("p="):
                self.protos = [p for p in tok[2:].split(",") if p]
            elif tok == "d":
                self.d = True
            elif tok == "snct":
                self.snct = True
            elif tok == "cnct":
                self.cnct = True
            elif tok.startswith("smb="):
                self.smb = int(tok[4:])
            elif tok.startswith("cmb="):
                self.cmb = int(tok[4:])
            elif tok == "ocmb":
                self.ocmb = True
            else:
                raise SystemExit("unknown spec token %r" % tok)

    def deflate_text(self):
        """permessage-deflate with every parameter the spec names: as a
        client's offer, and as a server's response, which both say what was
        agreed."""
        t = "permessage-deflate"
        if self.snct:
            t += "; server_no_context_takeover"
        if self.cnct:
            t += "; client_no_context_takeover"
        if self.smb:
            t += "; server_max_window_bits=%d" % self.smb
        if self.cmb:
            t += "; client_max_window_bits=%d" % self.cmb
        return t


def server_request(spec, extra=b""):
    """The client's opening request for a `ws` case: the RFC 6455 section 1.3
    example, offering permessage-deflate with the spec's parameters."""
    head = (b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY +
            b"\r\nSec-WebSocket-Version: 13\r\n")
    if spec.d:
        head += b"Sec-WebSocket-Extensions: " + spec.deflate_text().encode() + b"\r\n"
    return head + extra + b"\r\n"


def client_response(spec, accept=RFC_ACCEPT):
    """The server's 101 for a `wc` case, answering the RFC example key."""
    head = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n")
    if spec.d:
        head += b"Sec-WebSocket-Extensions: " + spec.deflate_text().encode() + b"\r\n"
    return head + b"\r\n"


def parse_frames(raw):
    """[[opcode, payload-hex]...] of the frames in what an implementation wrote
    (masked or not). A frame that is cut ends the list."""
    out = []
    i = 0
    n = len(raw)
    while i + 2 <= n:
        op = raw[i] & 15
        masked = bool(raw[i + 1] & 0x80)
        ln = raw[i + 1] & 0x7F
        at = i + 2
        if ln == 126:
            if at + 2 > n:
                break
            ln = int.from_bytes(raw[at:at + 2], "big")
            at += 2
        elif ln == 127:
            if at + 8 > n:
                break
            ln = int.from_bytes(raw[at:at + 8], "big")
            at += 8
        key = b"\0\0\0\0"
        if masked:
            if at + 4 > n:
                break
            key = raw[at:at + 4]
            at += 4
        if ln > n - at:
            break
        body = bytes(c ^ key[k % 4] for k, c in enumerate(raw[at:at + ln]))
        out.append([op, body.hex()])
        i = at + ln
    return out


def chunks(data, split):
    if split == "byte":
        return [data[i:i + 1] for i in range(len(data))] or [b""]
    return [data]


def serve(handlers):
    """The line protocol: `id kind split arg hex` in, `id split json` out."""
    for line in sys.stdin.buffer:
        line = line.rstrip(b"\n").decode("ascii")
        f = line.split("\t")
        if len(f) != 5:
            raise SystemExit("a case needs five tab-separated fields: %r" % line[:100])
        cid, kind, split, arg, data = f
        handler = handlers.get(kind)
        if handler is None:
            raise SystemExit("unknown kind %r" % kind)
        res = handler(split, arg, bytes.fromhex(data))
        sys.stdout.write("%s\t%s\t%s\n" % (cid, split, json.dumps(res, separators=(",", ":"))))
        sys.stdout.flush()
