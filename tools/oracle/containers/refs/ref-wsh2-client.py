#!/usr/bin/env python3
"""A WebSocket client over HTTP/2 (RFC 8441): h2 and websockets, as the reference.

    ref-wsh2-client.py [--deflate] SIZE...

stdin and stdout are the HTTP/2 connection to a server that echoes. After the
server's SETTINGS enable the protocol the client opens an Extended CONNECT
(:protocol websocket, no key), offers permessage-deflate when asked, and then,
for each SIZE, sends a message of that many octets (text for even positions,
binary for odd, content a function of position and size) and waits for the echo
to match before the next. It then starts the closing handshake with 1000 and
waits for the server to end the stream. Exit 0 if every echo matched and the
handshake completed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wsh2_common as C  # noqa: E402

h2 = C.h2

if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print(C.version())
    sys.exit(0)


def canned_response(extensions):
    lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
             "Sec-WebSocket-Accept: %s" % C.RFC_ACCEPT, "Sec-WebSocket-Protocol: chat"]
    if extensions:
        lines.append("Sec-WebSocket-Extensions: %s" % extensions)
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def main(argv):
    deflate = "--deflate" in argv
    sizes = [int(a) for a in argv if not a.startswith("--")]
    pipe = C.Pipe(client=True)
    pipe.start_client()
    stream = None
    proto = None
    sent = 0
    want = None
    parts = []
    kind = None
    closed = False
    ended = False
    done_messages = False

    def send_next():
        nonlocal sent, want
        if sent >= len(sizes):
            return False
        text = sent % 2 == 0
        body = C.pattern(sent, sizes[sent], text)
        want = (text, body)
        if text:
            proto.send_text(body)
        else:
            proto.send_binary(body)
        sent += 1
        return True

    def drain():
        for chunk in proto.data_to_send():
            if chunk:
                pipe.send(stream, chunk)

    while True:
        data = pipe.read()
        if not data:
            break
        events = pipe.c.receive_data(data)
        for ev in events:
            if isinstance(ev, h2.events.RemoteSettingsChanged) and stream is None:
                if pipe.c.remote_settings.enable_connect_protocol != 1:
                    continue
                stream = pipe.c.get_next_available_stream_id()
                headers = [(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"),
                           (":path", "/chat"), (":authority", "server.example.com"),
                           ("sec-websocket-version", "13"), ("sec-websocket-protocol", "chat")]
                if deflate:
                    headers.append(("sec-websocket-extensions", "permessage-deflate; client_max_window_bits"))
                pipe.c.send_headers(stream, headers)
                pipe.flush()
            elif isinstance(ev, h2.events.ResponseReceived):
                hd = dict(ev.headers)
                if hd.get(":status") != "200":
                    C.log("the server answered", hd.get(":status"))
                    return 1
                for name in ("sec-websocket-accept", "upgrade", "connection"):
                    if name in hd:
                        C.log("the response carries", name)
                        return 1
                exts = hd.get("sec-websocket-extensions")
                factories = [C.ClientPerMessageDeflateFactory()] if deflate else None
                proto = C.ClientProtocol(C.parse_uri("ws://server.example.com/chat"),
                                         max_size=C.MAX_SIZE, extensions=factories,
                                         subprotocols=["chat"])
                request = proto.connect()
                proto.key = C.RFC_KEY
                proto.send_request(request)
                proto.data_to_send()
                proto.receive_data(canned_response(exts))
                proto.events_received()
                proto.data_to_send()
                if proto.state is not C.OPEN:
                    C.log("the handshake failed:", repr(proto.handshake_exc))
                    return 1
                if deflate and not proto.extensions:
                    C.log("permessage-deflate was offered and not negotiated")
                    return 1
                C.log("open; extensions:", [type(e).__name__ for e in proto.extensions])
                send_next()
                drain()
                pipe.push()
            elif isinstance(ev, h2.events.DataReceived):
                pipe.c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                if proto is None:
                    continue
                proto.receive_data(ev.data)
                for f in proto.events_received():
                    if f.opcode in (C.Opcode.TEXT, C.Opcode.BINARY):
                        kind = f.opcode
                        parts = [f.data]
                    elif f.opcode is C.Opcode.CONT:
                        parts.append(f.data)
                    elif f.opcode is C.Opcode.CLOSE:
                        closed = True
                        continue
                    else:
                        continue
                    if f.fin:
                        body = b"".join(parts)
                        parts = []
                        text, expect = want
                        if (kind is C.Opcode.TEXT) != text or body != expect:
                            C.log("echo %d differs: %d octets, wanted %d" % (sent - 1, len(body), len(expect)))
                            return 1
                        if not send_next():
                            done_messages = True
                            proto.send_close(1000, "bye")
                drain()
                pipe.push()
            elif isinstance(ev, h2.events.StreamEnded):
                ended = True
                C.log("the server ended the stream")
                pipe.send(stream, b"", end=True)
            elif isinstance(ev, h2.events.StreamReset):
                C.log("the stream was reset", ev.error_code)
                return 1
            elif isinstance(ev, h2.events.WindowUpdated):
                pipe.push()
        pipe.push()
        if ended:
            break
    ok = done_messages and closed and ended and proto is not None and proto.close_rcvd is not None and proto.close_rcvd.code == 1000
    if not ok:
        C.log("incomplete: sent %d of %d, close seen %s, stream ended %s, code %s" % (
            sent, len(sizes), closed, ended, getattr(getattr(proto, "close_rcvd", None), "code", None)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
