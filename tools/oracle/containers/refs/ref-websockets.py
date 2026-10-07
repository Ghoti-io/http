#!/usr/bin/env python3
"""The websockets reference: Python, the library's sans-I/O protocol layer.

The line protocol, and the shape of every answer, are ws_probe.c's. Five kinds.

websockets keeps the protocol (websockets.protocol.Protocol, with the opening
handshake in ServerProtocol and ClientProtocol) apart from the I/O layers
(asyncio, threading), and the I/O layers are where a message is assembled from
its frames and where a text message is checked to be UTF-8. The protocol layer
reports FRAMES. So the driver is the I/O layer's smallest honest stand-in: an
application that reads each frame event as it arrives, joins the frames of a
message, and decodes a text message with the same call the threading layer's
Assembler makes (bytes.decode(), which is strict UTF-8), failing the connection
with code 1007 on UnicodeDecodeError exactly as Connection.recv() does
(websockets/sync/connection.py: protocol.fail(CloseCode.INVALID_DATA, ...)). A
text message is therefore checked when it is complete and not at the octet
(websockets' own design; the library's own tests ship no fail-fast guarantee).
What the protocol layer itself decides (opcodes, reserved bits, control frame
rules, masking, continuation order, close codes, the size limit, the
permessage-deflate extension) is the library's own.

Settings: max_size is 1 MiB (the default; the same cap this library was given),
set explicitly so that it is one of the things a control shows to be in force.

ws, wc   A Protocol in OPEN state reached the way a real one reaches it: the
         canned handshake goes through ServerProtocol (or ClientProtocol), with
         the permessage-deflate factory configured from the spec, and the
         extension negotiated is whatever the library's own negotiation makes
         of the same text this library was given. Frames are then received
         whole or one octet at a time; the Pong for a Ping and the echo of a
         Close are the protocol's own (it queues them), read from
         data_to_send().
hs       ServerProtocol over the request head: process_request through accept(),
         as the I/O layer calls it, a refusal being the response reject() makes.
         The server's subprotocols are websockets' own policy (the first of the
         server's that the client offered; a refusal when none is offered).
hc       ClientProtocol with the RFC 6455 example key (the one thing set by the
         driver: protocol.key) over the response head.
"""
import sys

import websockets
from websockets.client import ClientProtocol
from websockets.exceptions import InvalidHandshake
from websockets.extensions.permessage_deflate import (ClientPerMessageDeflateFactory,
                                                      ServerPerMessageDeflateFactory)
from websockets.frames import Close, CloseCode, Opcode
from websockets.protocol import CLIENT, CONNECTING, OPEN
from websockets.server import ServerProtocol
from websockets.uri import parse_uri

import wsref_common as C

if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print("websockets %s" % websockets.__version__)
    sys.exit(0)

MAX_SIZE = C.MAX_MESSAGE


def server_factory(spec):
    return ServerPerMessageDeflateFactory(
        server_no_context_takeover=spec.snct, client_no_context_takeover=spec.cnct,
        server_max_window_bits=spec.smb or None, client_max_window_bits=spec.cmb or None)


def client_factory(spec):
    # client_max_window_bits=True offers the parameter with no value (the
    # spec's `ocmb`); None does not offer it at all.
    return ClientPerMessageDeflateFactory(
        server_no_context_takeover=spec.snct, client_no_context_takeover=spec.cnct,
        server_max_window_bits=spec.smb or None,
        client_max_window_bits=spec.cmb or (True if spec.ocmb else None))


def flush(proto):
    return b"".join(proto.data_to_send())


def open_protocol(client, spec):
    """A Protocol in OPEN state reached through the library's own handshake, or
    (None, why)."""
    if client:
        proto = ClientProtocol(
            parse_uri("ws://server.example.com/chat"), max_size=MAX_SIZE,
            extensions=[client_factory(spec)] if spec.d else None)
        request = proto.connect()
        proto.key = C.RFC_KEY.decode()  # the response carries the RFC key's accept value
        proto.send_request(request)
        flush(proto)
        proto.receive_data(C.client_response(spec))
        proto.events_received()
        if proto.state is not OPEN:
            return None, "the handshake failed: %r" % (proto.handshake_exc,)
        if spec.d and not proto.extensions:
            return None, "the extension was not negotiated"
        return proto, ""
    proto = ServerProtocol(max_size=MAX_SIZE, extensions=[server_factory(spec)] if spec.d else None)
    proto.receive_data(C.server_request(spec))
    events = proto.events_received()
    response = proto.accept(events[0])
    proto.send_response(response)
    flush(proto)
    if proto.state is not OPEN:
        return None, "the handshake was refused: %d" % response.status_code
    if spec.d and not proto.extensions:
        return None, "the extension was not negotiated"
    return proto, ""


def stream(client):
    def run(split, arg, data):
        try:
            return run_inner(split, arg, data)
        except Exception as exc:  # an exception out of websockets is the answer
            return {"evs": [], "sent": [], "end": "failed", "fail": "",
                    "err": C.hx(("EXCEPTION %r" % (exc,)).encode())}

    def run_inner(split, arg, data):
        spec = C.Spec(arg)
        out = {"evs": [], "sent": [], "end": "open", "fail": "", "err": ""}
        try:
            proto, why = open_protocol(client, spec)
        except (AssertionError, ValueError) as exc:
            # The factory refuses the parameters: websockets cannot be put in this state.
            return {"na": "websockets cannot be configured with these parameters: %r" % (exc,)}
        except Exception as exc:
            proto, why = None, "the extension cannot be set up: %r" % (exc,)
        if proto is None:
            out["end"] = "failed"
            out["err"] = C.hx(why.encode())
            return out
        evs = out["evs"]
        sent = bytearray()
        parts = []
        first = None
        done = False
        for chunk in C.chunks(data, split):
            if done:
                break
            proto.receive_data(chunk)
            for f in proto.events_received():
                if f.opcode in (Opcode.TEXT, Opcode.BINARY, Opcode.CONT):
                    if f.opcode is not Opcode.CONT:
                        first = f.opcode
                    parts.append(bytes(f.data))
                    if f.fin:
                        msg = b"".join(parts)
                        parts = []
                        if first is Opcode.TEXT:
                            try:
                                msg.decode()
                            except UnicodeDecodeError as exc:
                                # Connection.recv(), as websockets writes it.
                                proto.fail(CloseCode.INVALID_DATA,
                                           "%s at position %d" % (exc.reason, exc.start))
                                out["fail"] = C.hx(exc.reason.encode())
                                done = True
                                break
                        evs.append(["text" if first is Opcode.TEXT else "binary", C.hx(msg), None])
                elif f.opcode is Opcode.PING:
                    evs.append(["ping", C.hx(f.data), None])
                elif f.opcode is Opcode.PONG:
                    evs.append(["pong", C.hx(f.data), None])
                elif f.opcode is Opcode.CLOSE:
                    close = Close.parse(f.data)
                    evs.append(["close", C.hx(close.reason.encode()), int(close.code)])
                    out["end"] = "closed"
                    done = True
                    break
            sent.extend(flush(proto))
            if proto.parser_exc is not None and out["end"] != "closed":
                out["end"] = "failed"
                out["fail"] = C.hx(str(proto.parser_exc).encode())
                done = True
        if done and out["end"] == "open":
            out["end"] = "failed"
        out["sent"] = C.parse_frames(bytes(sent))
        return out
    return run


def opt(v):
    return None if v is None else C.hx(v.encode() if isinstance(v, str) else v)


def hs(split, arg, data):
    spec = C.Spec(arg)
    ans = {"status": 0, "accept": None, "protocol": None, "extensions": None,
           "parse_error": False, "err": ""}
    try:
        proto = ServerProtocol(max_size=MAX_SIZE, subprotocols=spec.protos or None,
                               extensions=[server_factory(spec)] if spec.d else None)
    except (AssertionError, ValueError) as exc:
        return {"na": "websockets cannot be configured with this policy: %r" % (exc,)}
    try:
        proto.receive_data(data)
        events = proto.events_received()
    except Exception as exc:  # the protocol layer is not meant to raise here
        ans["err"] = C.hx(repr(exc).encode())
        return ans
    wire = flush(proto)  # a refusal made by the parser itself (431, 414)
    if not events:
        if wire.startswith(b"HTTP/1.1 "):
            ans["status"] = int(wire[9:12])
        elif proto.handshake_exc is not None:
            ans["status"] = 400  # InvalidMessage: no valid HTTP request
            ans["parse_error"] = True
            ans["err"] = C.hx(repr(proto.handshake_exc).encode())
        return ans
    try:
        response = proto.accept(events[0])
    except Exception as exc:
        ans["status"] = 500
        ans["err"] = C.hx(repr(exc).encode())
        return ans
    ans["status"] = response.status_code
    if response.status_code == 101:
        ans["accept"] = opt(response.headers.get("Sec-WebSocket-Accept"))
        ans["protocol"] = opt(response.headers.get("Sec-WebSocket-Protocol"))
        ans["extensions"] = opt(response.headers.get("Sec-WebSocket-Extensions"))
    return ans


def hc(split, arg, data):
    spec = C.Spec(arg)
    ans = {"accepted": False, "protocol": None, "deflate": None, "parse_error": False, "err": ""}
    try:
        proto = ClientProtocol(parse_uri("ws://server.example.com/chat"), max_size=MAX_SIZE,
                               subprotocols=spec.protos or None,
                               extensions=[client_factory(spec)] if spec.d else None)
        request = proto.connect()
        proto.key = C.RFC_KEY.decode()
        proto.send_request(request)
        flush(proto)
    except (AssertionError, ValueError) as exc:
        return {"na": "websockets cannot be configured with this offer: %r" % (exc,)}
    proto.receive_data(data)
    proto.events_received()
    exc = proto.handshake_exc
    if exc is not None:
        ans["parse_error"] = type(exc).__name__ == "InvalidMessage"
        ans["err"] = C.hx(repr(exc).encode())
        return ans
    if proto.state is not OPEN:
        return ans
    ans["accepted"] = True
    ans["protocol"] = opt(proto.subprotocol)
    for e in proto.extensions:
        if e.name == "permessage-deflate":
            ans["deflate"] = {"snct": int(e.remote_no_context_takeover),
                              "cnct": int(e.local_no_context_takeover),
                              "smb": e.remote_max_window_bits, "cmb": e.local_max_window_bits}
    return ans


if __name__ == "__main__":
    C.serve({"ws": stream(False), "wc": stream(True), "hs": hs, "hc": hc})
