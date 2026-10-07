#!/usr/bin/env python3
"""The wsproto reference: Python, sans-I/O WebSocket (wsproto on h11).

The line protocol, and the shape of every answer, are ws_probe.c's. Five kinds.

ws, wc   One Connection (wsproto.connection.Connection) in the server or the
         client role over the case's bytes, whole or one octet at a time. For
         permessage-deflate the extension object is configured the way wsproto
         negotiates it (PerMessageDeflate.accept on the offer at a server,
         .finalize on the response at a client), so the parameters are the
         library's own reading of the same text this library was given.

         wsproto hands the application TextMessage and BytesMessage pieces and
         a CloseConnection event; the driver concatenates the pieces of a
         message, and answers the way an application that does the obvious thing
         does: a Pong for a Ping, the echo of a Close the peer sent, and the
         Close wsproto itself named for a protocol failure. wsproto reports a
         failure it detects as a CloseConnection event with its own code, which
         is indistinguishable from a Close frame the peer sent by the event
         alone: the connection's own state is what tells them apart (a Close
         frame moves it to REMOTE_CLOSING, a failure leaves it OPEN), and the
         driver reads that.

         wsproto has no size limit of any kind, so the 1 MiB the other
         implementations are given has no counterpart here; a control shows it.

hs       WSConnection(SERVER) over the request head. wsproto leaves the
         subprotocol and the extension to the application, so the driver chooses
         as ws_probe.c's spec says: the first of the server's subprotocols that
         the client offered, and a PerMessageDeflate built from the policy.
hc       WSConnection(CLIENT) with the RFC 6455 example nonce (the one thing
         patched: wsproto.handshake.generate_nonce) over the response head.
wr       Not a kind of its own: the bytes this library wrote are run as ws or wc.
"""
import sys

import h11
import wsproto
from wsproto import ConnectionType, WSConnection
from wsproto.connection import Connection, ConnectionState
from wsproto.events import (AcceptConnection, BytesMessage, CloseConnection, Ping, Pong,
                            RejectConnection, Request, TextMessage)
from wsproto.extensions import PerMessageDeflate
from wsproto.utilities import LocalProtocolError, RemoteProtocolError
import wsproto.handshake

import wsref_common as C

if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print("wsproto %s (h11 %s)" % (wsproto.__version__, h11.__version__))
    sys.exit(0)

# The one thing patched: a client draws a fresh random nonce for every request,
# and the response to be read carries the accept value of the RFC's key.
wsproto.handshake.generate_nonce = lambda: C.RFC_KEY


class SpecOffer(PerMessageDeflate):
    """A PerMessageDeflate that offers what the spec says. wsproto's own offer()
    always names both window sizes (as 15) and every flag it is configured with;
    the case describes an offer of its own, the same for every implementation.
    Everything wsproto does with the response (finalize) is its own."""

    def __init__(self, spec):
        super().__init__()
        self._spec = spec

    def offer(self):
        sp = self._spec
        parts = []
        if sp.snct:
            parts.append("server_no_context_takeover")
        if sp.cnct:
            parts.append("client_no_context_takeover")
        if sp.smb:
            parts.append("server_max_window_bits=%d" % sp.smb)
        if sp.cmb:
            parts.append("client_max_window_bits=%d" % sp.cmb)
        elif sp.ocmb:
            parts.append("client_max_window_bits")
        return "; ".join(parts) if parts else True


def stream(client):
    def run(split, arg, data):
        try:
            return run_inner(split, arg, data)
        except Exception as why:  # an exception out of wsproto is the answer
            return {"evs": [], "sent": [], "end": "failed", "fail": "",
                    "err": C.hx(("EXCEPTION %r" % (why,)).encode())}

    def run_inner(split, arg, data):
        spec = C.Spec(arg)
        out = {"evs": [], "sent": [], "end": "open", "fail": "", "err": ""}
        exts = []
        if spec.d:
            ext = PerMessageDeflate()
            try:
                if client:
                    ext.finalize(spec.deflate_text())
                elif ext.accept(spec.deflate_text()) is None:
                    raise ValueError("the offer is declined")
            except ValueError as why:
                # wsproto cannot be in this state: its window is 9 to 15 bits.
                return {"na": "wsproto cannot be put in this state: %s" % why}
            exts = [ext]
        conn = Connection(ConnectionType.CLIENT if client else ConnectionType.SERVER, exts)
        sent = bytearray()
        pieces = []
        evs = out["evs"]

        def send(event):
            try:
                sent.extend(conn.send(event))
            except LocalProtocolError:
                pass  # a reply the state no longer allows

        stopped = False
        for chunk in C.chunks(data, split):
            if stopped:
                break
            try:
                conn.receive_data(chunk)
            except LocalProtocolError as why:
                out["err"] = C.hx(str(why).encode())
                break
            except Exception as why:  # wsproto raising where it should have reported
                out["end"] = "failed"
                out["err"] = C.hx(("EXCEPTION %r" % (why,)).encode())
                break
            # Lazily, as an application does: wsproto moves the connection's
            # state as each event is yielded, and a Pong may only be sent while
            # it is still OPEN.
            for ev in conn.events():
                if isinstance(ev, (TextMessage, BytesMessage)):
                    pieces.append(ev.data.encode() if isinstance(ev, TextMessage) else bytes(ev.data))
                    if ev.message_finished:
                        evs.append(["text" if isinstance(ev, TextMessage) else "binary",
                                    C.hx(b"".join(pieces)), None])
                        pieces = []
                elif isinstance(ev, Ping):
                    evs.append(["ping", C.hx(ev.payload), None])
                    send(ev.response())
                elif isinstance(ev, Pong):
                    evs.append(["pong", C.hx(ev.payload), None])
                elif isinstance(ev, CloseConnection):
                    if conn.state in (ConnectionState.REMOTE_CLOSING, ConnectionState.CLOSED):
                        evs.append(["close", C.hx((ev.reason or "").encode()), int(ev.code)])
                        out["end"] = "closed"
                        send(ev.response())
                    else:
                        out["end"] = "failed"
                        out["fail"] = C.hx((ev.reason or "").encode())
                        send(CloseConnection(code=ev.code))
                    stopped = True
                    break
        out["sent"] = C.parse_frames(bytes(sent))
        return out
    return run


def head_of(raw):
    """(status, {lower-name: value joined}) of a response head."""
    lines = raw.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    hdr = {}
    for line in lines[1:]:
        if b":" in line:
            n, v = line.split(b":", 1)
            n = n.strip().lower().decode("latin1")
            hdr[n] = (hdr[n] + b", " if n in hdr else b"") + v.strip()
    return status, hdr


def opt(v):
    return None if v is None else C.hx(v)


def hs(split, arg, data):
    ans = {"status": 500, "accept": None, "protocol": None, "extensions": None,
           "parse_error": False, "err": ""}
    try:
        return hs_inner(split, arg, data)
    except Exception as why:  # an exception out of wsproto is the answer: a server would answer 500
        ans["err"] = C.hx(("EXCEPTION %r" % (why,)).encode())
        return ans


def hs_inner(split, arg, data):
    spec = C.Spec(arg)
    ws = WSConnection(ConnectionType.SERVER)
    ans = {"status": 0, "accept": None, "protocol": None, "extensions": None,
           "parse_error": False, "err": ""}
    try:
        ws.receive_data(data)
        events = list(ws.events())
    except RemoteProtocolError as why:
        hint = why.event_hint
        ans["status"] = getattr(hint, "status_code", 400) if hint is not None else 400
        ans["parse_error"] = str(why) == "Bad HTTP message"
        ans["err"] = C.hx(str(why).encode())
        return ans
    req = next((e for e in events if isinstance(e, Request)), None)
    if req is None:
        return ans
    proto = next((p for p in spec.protos if p in req.subprotocols), None)
    exts = []
    if spec.d:
        try:
            exts = [PerMessageDeflate(
                client_no_context_takeover=spec.cnct, server_no_context_takeover=spec.snct,
                client_max_window_bits=spec.cmb or None, server_max_window_bits=spec.smb or None)]
        except ValueError as why:
            return {"na": "wsproto cannot be configured with this policy: %s" % why}
    try:
        raw = ws.send(AcceptConnection(subprotocol=proto, extensions=exts))
    except LocalProtocolError as why:
        ans["status"] = 500
        ans["err"] = C.hx(str(why).encode())
        return ans
    status, hdr = head_of(raw)
    ans["status"] = status
    ans["accept"] = opt(hdr.get("sec-websocket-accept"))
    ans["protocol"] = opt(hdr.get("sec-websocket-protocol"))
    ans["extensions"] = opt(hdr.get("sec-websocket-extensions"))
    return ans


def hc(split, arg, data):
    try:
        return hc_inner(split, arg, data)
    except Exception as why:  # an exception out of wsproto: the client has no connection
        return {"accepted": False, "protocol": None, "deflate": None, "parse_error": False,
                "err": C.hx(("EXCEPTION %r" % (why,)).encode())}


def hc_inner(split, arg, data):
    spec = C.Spec(arg)
    ws = WSConnection(ConnectionType.CLIENT)
    exts = [SpecOffer(spec)] if spec.d else []
    ws.send(Request(host="server.example.com", target="/chat", subprotocols=list(spec.protos),
                    extensions=exts))
    ans = {"accepted": False, "protocol": None, "deflate": None, "parse_error": False, "err": ""}
    try:
        ws.receive_data(data)
        events = list(ws.events())
    except RemoteProtocolError as why:
        ans["parse_error"] = str(why) == "Bad HTTP message"
        ans["err"] = C.hx(str(why).encode())
        return ans
    except ValueError as why:  # a window size that is not a number, in finalize()
        ans["err"] = C.hx(str(why).encode())
        return ans
    for ev in events:
        if isinstance(ev, AcceptConnection):
            ans["accepted"] = True
            ans["protocol"] = C.hx(ev.subprotocol.encode()) if ev.subprotocol else None
            for e in ev.extensions:
                if e.name == "permessage-deflate":
                    ans["deflate"] = {"snct": int(bool(e.server_no_context_takeover)),
                                      "cnct": int(bool(e.client_no_context_takeover)),
                                      "smb": e.server_max_window_bits,
                                      "cmb": e.client_max_window_bits}
    return ans


if __name__ == "__main__":
    C.serve({"ws": stream(False), "wc": stream(True), "hs": hs, "hc": hc})
