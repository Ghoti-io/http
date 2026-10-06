#!/usr/bin/env python3
"""The h11 reference: a pure-Python, sans-I/O HTTP/1.1 implementation.

Same protocol as http_probe.c: tab-separated cases on stdin, one `id split
json` line out, every string hex.

h11 is a connection state machine, and one Connection reads one request and
one response. So each message is read by a fresh Connection, handed whatever the
previous one left, which is the same stream seen one message at a time. A
client Connection must have sent a request before it will read a response, and
the request's method is what makes a response to HEAD bodyless, so for a
response the case's method hint is the request that is sent first.

h11 has no lenient flag. Its one tunable is max_incomplete_event_size, which
is set to this library's default head cap (64 KiB) rather than h11's 16 KiB.
"""
import json
import sys

import h11

if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print("h11 " + h11.__version__)
    sys.exit(0)

MAX_HEAD = 65536


def hx(b):
    return bytes(b).hex()


def fields(items):
    return [[hx(n), hx(v)] for n, v in items]


def new_connection(is_req, method, rest):
    if is_req:
        return h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEAD)
    c = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_HEAD)
    target = b"example.test:80" if method == "CONNECT" else b"/"
    headers = [("Host", "example.test")]
    # h11 accepts a 101 only as the answer to a request that proposed an
    # upgrade, so a stream that begins with one is read as the answer to such
    # a request. That is the request any real 101 answers.
    if rest.split(b"\r\n", 1)[0].split(b" ")[1:2] == [b"101"]:
        headers += [("Connection", "upgrade"), ("Upgrade", "x")]
    c.send(h11.Request(method=method, target=target, headers=headers))
    c.send(h11.EndOfMessage())
    return c


def read_one(is_req, method, rest, byte, stopped):
    """Read events from one Connection until its message ends.

    Returns (messages, leftover bytes, end, err, tunnel).
    """
    c = new_connection(is_req, method, rest)
    msgs = []
    cur = None
    fed = 0
    eof = False

    def feed():
        nonlocal fed
        if byte:
            c.receive_data(rest[fed:fed + 1])
            fed += 1
        else:
            c.receive_data(rest)
            fed = len(rest)

    while True:
        try:
            ev = c.next_event()
        except Exception as e:  # noqa: BLE001 - every refusal is an answer
            return msgs, b"", ("incomplete" if eof else "error"), type(e).__name__, False
        if ev is h11.NEED_DATA:
            if fed < len(rest):
                feed()
            elif not eof:
                eof = True
                c.receive_data(b"")
            else:
                return msgs, b"", "incomplete", "NEED_DATA", False
            continue
        if ev is h11.PAUSED:
            # Switched protocols, or a message ended with data left over.
            left = c.trailing_data[0] + rest[fed:]
            if cur is not None:
                # A 2xx to CONNECT is a head with no end: the tunnel begins.
                cur["upgrade"] = True
                msgs.append(done(cur))
            return msgs, left, "clean", "", c.their_state in (
                h11.MIGHT_SWITCH_PROTOCOL, h11.SWITCHED_PROTOCOL)
        if isinstance(ev, h11.ConnectionClosed):
            return msgs, b"", "clean", "", False
        if isinstance(ev, h11.Request):
            cur = {"start": {"method": hx(ev.method), "target": hx(ev.target),
                             "ver": ev.http_version.decode("latin1")},
                   "headers": fields(ev.headers.raw_items()), "body": b"",
                   "trailers": [], "upgrade": False}
        elif isinstance(ev, (h11.Response, h11.InformationalResponse)):
            cur = {"start": {"reason": hx(ev.reason), "status": ev.status_code,
                             "ver": ev.http_version.decode("latin1")},
                   "headers": fields(ev.headers.raw_items()), "body": b"",
                   "trailers": [], "upgrade": False}
            if isinstance(ev, h11.InformationalResponse):
                # A 1xx is a whole message to this library; h11 goes on to
                # read the final response on the same connection.
                cur["upgrade"] = ev.status_code == 101
                msgs.append(done(cur))
                cur = None
                if ev.status_code == 101:
                    left = rest[fed:]
                    return msgs, left, "clean", "", True
        elif isinstance(ev, h11.Data):
            cur["body"] += bytes(ev.data)
        elif isinstance(ev, h11.EndOfMessage):
            cur["trailers"] = fields(ev.headers.raw_items())
            msgs.append(done(cur))
            cur = None
            if c.their_state is h11.MIGHT_SWITCH_PROTOCOL:
                msgs[-1]["upgrade"] = True
                return msgs, b"", "clean", "", True
            if (not is_req and msgs[-1]["start"]["status"] // 100 == 2
                    and method == "CONNECT"):
                msgs[-1]["upgrade"] = True
                return msgs, b"", "clean", "", True
            # The connection is not asked for another event: what it did not
            # use is the next message.
            left = c.trailing_data[0] + rest[fed:]
            return msgs, left, "clean", "", False


def done(cur):
    cur = dict(cur)
    cur["body"] = cur["body"].hex()
    return cur


def run(is_req, method, data, byte):
    msgs = []
    rest = data
    method = "GET" if method == "-" else method
    while rest:
        got, rest, end, err, tunnel = read_one(is_req, method, rest, byte, False)
        method = "GET"
        msgs.extend(got)
        if tunnel:
            return {"msgs": msgs, "end": "clean", "err": ""}
        if end != "clean":
            return {"msgs": msgs, "end": end, "err": err}
        if not got and rest:
            # Nothing came of the bytes and nothing was refused: stop rather
            # than loop on the same input.
            return {"msgs": msgs, "end": "error", "err": "NoProgress"}
    return {"msgs": msgs, "end": "clean", "err": ""}


for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    f = line.split("\t")
    result = run(f[1] == "req", f[2], bytes.fromhex(f[4]), f[3] == "byte")
    sys.stdout.write("%s\t%s\t%s\n" % (f[0], f[3], json.dumps(result)))
    sys.stdout.flush()
