#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io HTTP.
#
# Ghoti.io HTTP is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
#
# Ghoti.io HTTP is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""A WebSocket echo server over HTTP/2 (RFC 8441): h2 and websockets, as the reference.

stdin and stdout are the HTTP/2 connection. The server enables Extended
CONNECT, accepts a CONNECT with :protocol websocket, negotiates the subprotocol
`chat` and permessage-deflate as websockets would for an HTTP/1.1 request,
answers 200, and echoes every message. The closing handshake is websockets'; a
stream the client ends without it is the abnormal closure, and the server ends
its side too. Exit status 0 if the connection ended with a completed closing
handshake or the peer's EOF after one; 1 otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wsh2_common as C  # noqa: E402

h2 = C.h2

if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print(C.version())
    sys.exit(0)


def synthetic_request(path, authority, extensions):
    lines = ["GET %s HTTP/1.1" % path, "Host: %s" % authority, "Upgrade: websocket",
             "Connection: Upgrade", "Sec-WebSocket-Key: %s" % C.RFC_KEY,
             "Sec-WebSocket-Version: 13", "Sec-WebSocket-Protocol: chat"]
    if extensions:
        lines.append("Sec-WebSocket-Extensions: %s" % extensions)
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def main():
    pipe = C.Pipe(client=False)
    pipe.c.initiate_connection()
    pipe.c.update_settings({h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
    pipe.flush()
    proto = None
    stream = None
    closed_clean = False
    msg_kind = None
    parts = []
    while True:
        data = pipe.read()
        if not data:
            break
        try:
            events = pipe.c.receive_data(data)
        except Exception as exc:  # the peer broke HTTP/2
            C.log("h2 error:", repr(exc))
            return 1
        for ev in events:
            if isinstance(ev, h2.events.RequestReceived):
                hd = dict(ev.headers)
                if hd.get(":method") != "CONNECT" or hd.get(":protocol") != "websocket":
                    pipe.c.send_headers(ev.stream_id, [(":status", "400")], end_stream=True)
                    continue
                for name in ("sec-websocket-key", "sec-websocket-accept", "upgrade", "connection"):
                    if name in hd:
                        C.log("the request carries", name)
                        return 1
                if hd.get("sec-websocket-version") != "13":
                    pipe.c.send_headers(ev.stream_id, [(":status", "426")], end_stream=True)
                    continue
                exts = hd.get("sec-websocket-extensions")
                factories = [C.ServerPerMessageDeflateFactory()] if exts else None
                proto = C.ServerProtocol(max_size=C.MAX_SIZE, extensions=factories,
                                         subprotocols=["chat"])
                proto.receive_data(synthetic_request(hd[":path"], hd[":authority"], exts))
                req = proto.events_received()[0]
                resp = proto.accept(req)
                proto.send_response(resp)
                proto.data_to_send()
                if proto.state is not C.OPEN:
                    pipe.c.send_headers(ev.stream_id, [(":status", str(resp.status_code))], end_stream=True)
                    C.log("handshake refused", resp.status_code)
                    return 1
                answer = [(":status", "200")]
                for name in ("Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"):
                    if name in resp.headers:
                        answer.append((name.lower(), resp.headers[name]))
                pipe.c.send_headers(ev.stream_id, answer)
                stream = ev.stream_id
                pipe.flush()
            elif isinstance(ev, h2.events.DataReceived):
                pipe.c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                if proto is not None:
                    proto.receive_data(ev.data)
                    for f in proto.events_received():
                        if f.opcode in (C.Opcode.TEXT, C.Opcode.BINARY):
                            msg_kind = f.opcode
                            parts = [f.data]
                        elif f.opcode is C.Opcode.CONT:
                            parts.append(f.data)
                        else:
                            continue
                        if f.fin:
                            body = b"".join(parts)
                            if msg_kind is C.Opcode.TEXT:
                                proto.send_text(body)
                            else:
                                proto.send_binary(body)
                            parts = []
                    for chunk in proto.data_to_send():
                        if chunk == b"":
                            closed_clean = True
                        else:
                            pipe.send(stream, chunk)
                    if closed_clean:
                        pipe.send(stream, b"", end=True)
            elif isinstance(ev, h2.events.StreamEnded):
                if proto is not None and not closed_clean:
                    proto.receive_eof()
                    C.log("the client ended the stream before the closing handshake")
                    pipe.send(stream, b"", end=True)
            elif isinstance(ev, h2.events.StreamReset):
                C.log("the stream was reset", ev.error_code)
                return 1
            elif isinstance(ev, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)):
                pipe.push()
        pipe.push()
    return 0 if closed_clean else 1


if __name__ == "__main__":
    sys.exit(main())
