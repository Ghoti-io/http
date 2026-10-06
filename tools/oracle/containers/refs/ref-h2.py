#!/usr/bin/env python3
"""The Python h2 reference: pure-Python, sans-I/O HTTP/2 (h2 + hpack + hyperframe).

Same protocol as the other refs: tab-separated cases on stdin
(`id kind split arg hex`), one `id split json` line out, every string hex.
Three kinds: h2 (a whole client byte stream, read as a server), hd (one HPACK
block through hpack.Decoder) and he (a field list through hpack.Encoder).

kind h2. One H2Connection(client_side=False) per case, bytes in and out
(header_encoding=None, so nothing is decoded). Settings are h2's own defaults,
which already are the advertised set: MAX_CONCURRENT_STREAMS=100 (h2 sets it
itself, its protocol default being unbounded), INITIAL_WINDOW_SIZE=65535,
MAX_FRAME_SIZE=16384, HEADER_TABLE_SIZE=4096, and MAX_HEADER_LIST_SIZE=65536
(H2Connection.DEFAULT_MAX_HEADER_LIST_SIZE, which also becomes the HPACK
decoder's limit). H2Configuration has no option for that last one, and
ENABLE_PUSH is a client-side setting that a server-side Settings object does
not carry, so a server built this way never advertises it and never enables
it. Validation is left at h2's default (on, inbound and outbound).

Normalisation is NOT left at the default: normalize_inbound_headers=False.
What it does when on is _combine_cookie_fields: every `cookie` field is joined
into one, "a; b", and moved to the END of the list as a never-indexed field.
That rewrites a value and an order, which the harness needs to see raw, so the
driver sees each cookie field as the client sent it. (It is the only thing the
option does; validation is a separate flag and stays on.)

Three things the driver does that h2 does not do by itself:

* receive_data() returns its events only if it returns. When a frame in the
  middle of a chunk raises, the events of the frames before it are lost with
  the exception, which in "whole" mode would drop an accepted request just
  because a later frame was bad. A subclass taps _receive_frame and keeps what
  each frame returned; the behaviour is unchanged, only the loss is.
* h2 hands the application nothing for what it sends. The RST_STREAM and GOAWAY
  codes are read from data_to_send(): "resets" and "conn_error" are the frames
  h2 wrote, not the exceptions it raised (err carries those, class name first).
* A passive application never opens a flow-control window, and a real server's
  does as it reads. Each DataReceived is acknowledged (acknowledge_received_data)
  as a server that consumes its body would, which is what the nghttp2 and Go
  drivers' libraries do on their own. The cost is that a "whole" chunk is
  checked against the window before any acknowledgement happens, and a
  byte-at-a-time feed is acknowledged frame by frame, so an over-window body
  can be an error in one mode and not in the other: that is h2's, not noise.

"Dead" is the connection state machine reaching CLOSED, which is where h2 goes
when it queues a GOAWAY: after that every call would only raise "invalid input
in state CLOSED", so feeding stops and err says so. Short of that, an
exception (a stream error h2 raises as ProtocolError and answers with an
RST_STREAM, say) is recorded and the rest of the buffer is drained.
"""
import json
import re
import struct
import sys

import h2
import hpack
import hyperframe
import h2.config
import h2.connection
import h2.events
import h2.settings
from h2.connection import ConnectionState

if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print("h2 %s (hpack %s, hyperframe %s)"
          % (h2.__version__, hpack.__version__, hyperframe.__version__))
    sys.exit(0)

BIG = 1 << 24  # no HPACK limit decides a case


def hx(b):
    return bytes(b).hex()


def fields(items):
    return [[hx(n), hx(v)] for n, v in items]


class TappedConnection(h2.connection.H2Connection):
    """H2Connection that keeps the events of frames processed before a raise."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.tapped = []

    def _receive_frame(self, frame):
        events = super()._receive_frame(frame)
        self.tapped.extend(events)
        return events


class Case:
    def __init__(self):
        cfg = h2.config.H2Configuration(
            client_side=False, header_encoding=None,
            normalize_inbound_headers=False)
        self.c = TappedConnection(config=cfg)
        self.msgs = {}
        self.order = []
        self.resets = []
        self.conn_error = None
        self.bad_preface = False
        self.peer_goaway = False
        self.errs = []
        self.out = b""
        self.c.initiate_connection()
        self.collect()

    def collect(self):
        """Parse what h2 queued: RST_STREAM and GOAWAY codes it sent."""
        self.out += self.c.data_to_send()
        while len(self.out) >= 9:
            n = int.from_bytes(self.out[0:3], "big")
            if len(self.out) < 9 + n:
                break
            t = self.out[3]
            sid = int.from_bytes(self.out[5:9], "big") & 0x7fffffff
            body = self.out[9:9 + n]
            if t == 3 and sid != 0 and n == 4:
                self.resets.append([sid, struct.unpack(">I", body)[0]])
            elif t == 7 and n >= 8 and self.conn_error is None:
                code = struct.unpack(">I", body[4:8])[0]
                if code != 0:
                    self.conn_error = code
            self.out = self.out[9 + n:]

    def events(self, evs):
        for ev in evs:
            if isinstance(ev, h2.events.RequestReceived):
                m = {"stream": ev.stream_id, "method": None, "scheme": None,
                     "authority": None, "path": None, "headers": [],
                     "body": b"", "trailers": [], "ended": False}
                for n, v in ev.headers:
                    if n.startswith(b":"):
                        key = {b":method": "method", b":scheme": "scheme",
                               b":authority": "authority",
                               b":path": "path"}.get(bytes(n))
                        if key is not None and m[key] is None:
                            m[key] = hx(v)
                        elif key is None:
                            m["headers"].append((n, v))  # unknown pseudo: keep
                    else:
                        m["headers"].append((n, v))
                self.msgs[ev.stream_id] = m
                self.order.append(ev.stream_id)
            elif isinstance(ev, h2.events.DataReceived):
                m = self.msgs.get(ev.stream_id)
                if m is not None:
                    m["body"] += bytes(ev.data)
                try:
                    self.c.acknowledge_received_data(
                        ev.flow_controlled_length, ev.stream_id)
                except Exception as e:  # noqa: BLE001
                    self.note(e)
            elif isinstance(ev, h2.events.TrailersReceived):
                m = self.msgs.get(ev.stream_id)
                if m is not None:
                    m["trailers"] = list(ev.headers)
            elif isinstance(ev, h2.events.StreamEnded):
                m = self.msgs.get(ev.stream_id)
                if m is not None:
                    m["ended"] = True
            elif isinstance(ev, h2.events.ConnectionTerminated):
                self.peer_goaway = True  # h2 goes CLOSED on it: not a refusal
            # StreamReset (a reset the peer sent), settings, ping, window updates, priority and
            # unknown frames are not part of the answer.

    def note(self, e):
        # A byte-at-a-time feed of a bad preface raises on every byte: once.
        t = "%s: %s" % (type(e).__name__, str(e)[:200])
        if "Invalid HTTP/2 preamble" in str(e):
            # h2 stays IDLE after this and raises it again for every later byte:
            # the connection is as dead as one in CLOSED.
            self.bad_preface = True
        if t not in self.errs:
            self.errs.append(t)

    def dead(self):
        return self.c.state_machine.state == ConnectionState.CLOSED

    def feed(self, chunk):
        """One receive_data call, then the drain of what it left."""
        first = True
        while True:
            before = len(self.c.incoming_buffer._data)
            self.c.tapped = []
            try:
                self.c.receive_data(chunk if first else b"")
                ok = True
            except Exception as e:  # noqa: BLE001 - every refusal is an answer
                self.note(e)
                ok = False
            first_call, first = first, False
            self.events(self.c.tapped)
            self.collect()
            if ok:
                return
            if self.dead():
                self.errs.append("connection state CLOSED: input not fed further")
                return
            # Alive: frames after the bad one are still buffered; go on, but
            # only while each call consumes something (a frame whose header
            # is refused stays in the buffer, and would loop for ever).
            after = len(self.c.incoming_buffer._data)
            if after == 0 or (not first_call and after >= before):
                return

    def result(self):
        msgs = []
        for sid in self.order:
            m = dict(self.msgs[sid])
            m["headers"] = fields(m["headers"])
            m["trailers"] = fields(m["trailers"])
            m["body"] = hx(m["body"])
            msgs.append(m)
        # "closed": the connection state machine is CLOSED, which h2 reaches
        # for a refusal that sends no GOAWAY (a bad preface) as well as after one.
        return {"msgs": msgs, "resets": self.resets,
                "conn_error": self.conn_error,
                "closed": (self.dead() and not self.peer_goaway) or self.bad_preface,
                "err": "; ".join(self.errs)}


def run_h2(split, data):
    case = Case()
    if split == "byte":
        for i in range(len(data)):
            if case.dead():
                case.errs.append("connection state CLOSED: input not fed further")
                break
            case.feed(data[i:i + 1])
    else:
        case.feed(data)
    return case.result()


def run_hd(arg, data):
    d = hpack.Decoder(max_header_list_size=BIG)
    n = int(arg)
    d.max_allowed_table_size = n
    d.header_table_size = n
    try:
        # raw=True: bytes out. hpack builds the whole list before returning, so
        # a decode error gives no partial list; "list" is [] then.
        got = d.decode(data, raw=True)
        return {"list": fields(got), "error": False, "err": ""}
    except Exception as e:  # noqa: BLE001
        return {"list": [], "error": True,
                "err": "%s: %s" % (type(e).__name__, re.sub(
                    r" at 0x[0-9a-f]+", "", str(e))[:200])}


def run_he(arg, data):
    items = []
    i = 0
    while i < len(data):
        (nl,) = struct.unpack(">I", data[i:i + 4])
        name = data[i + 4:i + 4 + nl]
        i += 4 + nl
        (vl,) = struct.unpack(">I", data[i:i + 4])
        value = data[i + 4:i + 4 + vl]
        i += 4 + vl
        items.append((name, value))
    e = hpack.Encoder()
    e.header_table_size = int(arg)
    return {"hex": hx(e.encode(items))}


def run(kind, split, arg, data):
    try:
        if kind == "h2":
            return run_h2(split, data)
        if kind == "hd":
            return run_hd(arg, data)
        if kind == "he":
            return run_he(arg, data)
        return {"err": "unknown kind " + kind}
    except Exception as e:  # noqa: BLE001 - a case must always answer
        r = {"err": "driver %s: %s" % (type(e).__name__, str(e)[:200])}
        if kind == "h2":
            r.update({"msgs": [], "resets": [], "conn_error": None})
        elif kind == "hd":
            r.update({"list": [], "error": True})
        return r


for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    f = line.split("\t")
    result = run(f[1], f[2], f[3], bytes.fromhex(f[4]))
    sys.stdout.write("%s\t%s\t%s\n" % (f[0], f[2], json.dumps(result)))
    sys.stdout.flush()
