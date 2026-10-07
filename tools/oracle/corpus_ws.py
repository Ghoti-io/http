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
"""The WebSocket differential's corpus.

A case is (id, kind, arg, tag, data). `arg` is the spec ws_probe.c documents
("-" for nothing, else `;`-separated tokens: d, snct, cnct, smb=N, cmb=N, p=a,b,
role=..., ocmb). The kinds:

  ws  `data` is a client's byte stream after the opening handshake, read by a
      SERVER; `arg` says whether permessage-deflate was agreed, and how.
  wc  `data` is a server's byte stream, read by a CLIENT. The same rules, with
      the masking rule reversed.
  hs  `data` is a client's HTTP request head; `arg` is the server's policy.
  hc  `data` is a server's HTTP response head to the request a client made with
      the RFC 6455 example key and the offer `arg` names.
  wr  `data` is a script (ws_probe.c): this library SENDS it, in the role `arg`
      names, and the bytes it wrote are then read by every implementation as the
      peer; what each delivers must be the script's messages.

Where the cases come from, and why each source is here:

  hand      Written from RFC 6455 and RFC 7692, one case per rule, valid AND
            invalid, tagged `rfc6455-<section>:<what>` or `rfc7692-<section>:`.
            Implementations agree on every stream they all accept; the value of
            a differential is in which malformed ones each turns away, how, and
            with what close code.
  autobahn  The Autobahn|Testsuite's case families 1 to 13 (the server-side
            fuzzing client's cases) re-expressed as the byte streams they send,
            tagged `autobahn-<id>:<what>`. Autobahn itself is run by another
            gate; the point here is that a case it sends is also asked of three
            independent implementations, and of this library's byte-at-a-time
            reader. Case ids are the Autobahn ones (1.1.1 ... 13.7.18); cases
            that are about timing (6.x/7.x/9.x performance, 10.1.1
            auto-fragmentation, which are properties of a peer's transport)
            appear as their byte streams where there is one.
  rfc       The examples in RFC 6455 section 5.7 and RFC 7692 section 7.2.3.
  unit      Every `\\x`-escaped byte literal in this library's unit tests
            (tests/unit/test_ws_*.cpp), each as a whole stream, as the payload of
            a text frame and of a binary frame, and as a Close body, so a
            reference is asked everything this library was ever asked.
  gen       Single mutations of valid streams from a seeded generator: flip a
            bit, set a byte, insert, delete, cut, repeat, drop or reorder a
            frame, rewrite a header field. One mutation per case, so a
            disagreement names its cause; tag `gen:<op>@<frame>.<field>`.

The generator is seeded and its output is a pure function of (seed, count).
"""

import os
import random
import re
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.dirname(os.path.dirname(HERE))

MAXMSG = 1 << 20  # ws_probe.c: the cap every implementation is given

KEY = bytes.fromhex("37fa213d")
R1, R2, R3 = 0x40, 0x20, 0x10
OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 8, 9, 10


# ---- frames, written by hand from RFC 6455 section 5.2 ---------------------------------

def frame(op, payload=b"", fin=True, masked=True, rsv=0, key=KEY, form=0, b0=None):
    """One frame. `form` 0 is the shortest length encoding; 7, 16 or 64 forces
    that one (for the non-minimal forms). `b0` overrides the first octet."""
    n = len(payload)
    if form == 0:
        form = 7 if n < 126 else (16 if n <= 0xFFFF else 64)
    first = (0x80 if fin else 0) | rsv | (op & 15) if b0 is None else b0
    m = 0x80 if masked else 0
    if form == 7:
        head = bytes([first, m | n])
    elif form == 16:
        head = bytes([first, m | 126]) + struct.pack(">H", n)
    else:
        head = bytes([first, m | 127]) + struct.pack(">Q", n)
    if masked:
        return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return head + payload


def header(op, claimed, fin=True, masked=True, rsv=0, key=KEY, form=0):
    """A frame header that claims `claimed` payload octets and carries none: for
    the limits, which act on the header."""
    n = claimed
    if form == 0:
        form = 7 if n < 126 else (16 if n <= 0xFFFF else 64)
    first = (0x80 if fin else 0) | rsv | (op & 15)
    m = 0x80 if masked else 0
    if form == 7:
        head = bytes([first, m | n])
    elif form == 16:
        head = bytes([first, m | 126]) + struct.pack(">H", n)
    else:
        head = bytes([first, m | 127]) + struct.pack(">Q", n)
    return head + (key if masked else b"")


def close_body(code=None, reason=b""):
    if code is None:
        return b""
    return struct.pack(">H", code) + reason


# ---- permessage-deflate, written with zlib (RFC 7692 section 7.2.1) ------------------------

class Deflater:
    """One direction's compressor. `takeover` False starts every message with an
    empty window. zlib cannot do a window of 8 bits, so 8 compresses with 9; the
    cases that name 8 use messages short enough that no distance exceeds 256."""

    def __init__(self, wbits=0, takeover=True):
        self.wbits = max(wbits or 15, 9)
        self.takeover = takeover
        self.co = zlib.compressobj(6, zlib.DEFLATED, -self.wbits)

    def message(self, data):
        c = self.co.compress(data) + self.co.flush(zlib.Z_SYNC_FLUSH)
        assert c.endswith(b"\x00\x00\xff\xff")
        c = c[:-4]
        if not self.takeover:
            self.co = zlib.compressobj(6, zlib.DEFLATED, -self.wbits)
        return c


def spec(d=False, snct=False, cnct=False, smb=0, cmb=0):
    """The `arg` for a connection with permessage-deflate agreed as named."""
    if not d:
        return "-"
    s = "d"
    if snct:
        s += ";snct"
    if cnct:
        s += ";cnct"
    if smb:
        s += ";smb=%d" % smb
    if cmb:
        s += ";cmb=%d" % cmb
    return s


def compressor_for(masked, d_args):
    """The Deflater for the direction this stream goes: a client compresses with
    client_max_window_bits and client_no_context_takeover, a server with the
    server's."""
    snct, cnct, smb, cmb = d_args
    return Deflater(cmb, not cnct) if masked else Deflater(smb, not snct)


def lorem(n, seed=1):
    words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
             "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore"]
    x = seed
    s = b""
    while len(s) < n:
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        s += words[(x >> 16) % 15].encode() + b" "
    return s[:n]


def rnd(n, seed=7):
    x = seed
    out = bytearray()
    for _ in range(n):
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append(x >> 24)
    return bytes(out)


# The UTF-8 text the Autobahn cases use.
KOSME = "κόσμε".encode()  # ce ba e1 bd b9 cf 83 ce bc ce b5


class Out:
    """Collects cases: (tag, kind, arg, data)."""

    def __init__(self):
        self.cases = []

    def add(self, tag, kind, arg, data):
        self.cases.append((tag, kind, arg, bytes(data)))

    def ws(self, tag, data, arg="-"):
        self.add(tag, "ws", arg, data)

    def wc(self, tag, data, arg="-"):
        self.add(tag, "wc", arg, data)

    def both(self, tag, build, arg="-"):
        """`build(masked)` gives the stream a client (masked) or a server (not)
        would send: the same rule asked of both roles."""
        self.ws(tag, build(True), arg)
        self.wc(tag, build(False), arg)


def hand_ws():
    """Every hand-written and Autobahn-derived stream case."""
    o = Out()
    C = lambda *a, **k: frame(*a, masked=True, **k)  # a client frame

    # ------------------------------------------------------------------------------
    # RFC 6455 section 5.2: the base framing protocol
    # ------------------------------------------------------------------------------
    o.both("rfc6455-5.2:text-hello", lambda m: frame(OP_TEXT, b"Hello", masked=m))
    o.both("rfc6455-5.2:binary-hello", lambda m: frame(OP_BIN, b"Hello", masked=m))
    o.both("rfc6455-5.2:empty-text", lambda m: frame(OP_TEXT, b"", masked=m))
    o.both("rfc6455-5.2:empty-binary", lambda m: frame(OP_BIN, b"", masked=m))
    o.both("rfc6455-5.2:nothing-at-all", lambda m: b"")
    for name, n in [("125", 125), ("126", 126), ("127", 127), ("128", 128), ("255", 255),
                    ("256", 256), ("65535", 65535), ("65536", 65536)]:
        o.both("rfc6455-5.2:length-%s" % name, lambda m, n=n: frame(OP_BIN, rnd(n), masked=m))
    # Non-minimal length encodings (5.2: "the minimal number of bytes MUST be used")
    for n in (0, 5, 125):
        o.both("rfc6455-5.2:length-%d-in-16-bit-form" % n, lambda m, n=n: frame(OP_BIN, rnd(n), masked=m, form=16))
        o.both("rfc6455-5.2:length-%d-in-64-bit-form" % n, lambda m, n=n: frame(OP_BIN, rnd(n), masked=m, form=64))
    o.both("rfc6455-5.2:length-126-in-64-bit-form", lambda m: frame(OP_BIN, rnd(126), masked=m, form=64))
    o.both("rfc6455-5.2:length-65535-in-64-bit-form", lambda m: frame(OP_BIN, rnd(65535), masked=m, form=64))
    o.both("rfc6455-5.2:length-64-bit-msb-set", lambda m: bytes([0x82, (0x80 if m else 0) | 127]) + b"\x80\x00\x00\x00\x00\x01\x00\x00" + (KEY if m else b"") + b"x")
    o.both("rfc6455-5.2:length-64-bit-all-ones", lambda m: bytes([0x82, (0x80 if m else 0) | 127]) + b"\xff" * 8 + (KEY if m else b""))
    o.both("rfc6455-5.2:length-64-bit-2pow63-1", lambda m: header(OP_BIN, (1 << 63) - 1, masked=m, form=64))
    o.both("rfc6455-5.2:length-64-bit-2pow32", lambda m: header(OP_BIN, 1 << 32, masked=m, form=64))
    o.both("rfc6455-5.2:length-64-bit-2pow31", lambda m: header(OP_BIN, 1 << 31, masked=m, form=64))
    o.both("rfc6455-5.2:length-16-bit-65535-header-only", lambda m: header(OP_BIN, 65535, masked=m) + rnd(10))
    # The reserved bits (5.2: "MUST be 0 unless an extension is negotiated")
    for nm, bits in [("rsv1", R1), ("rsv2", R2), ("rsv3", R3), ("rsv1-2", R1 | R2),
                     ("rsv1-3", R1 | R3), ("rsv2-3", R2 | R3), ("rsv1-2-3", R1 | R2 | R3)]:
        o.both("rfc6455-5.2:%s-on-text" % nm, lambda m, b=bits: frame(OP_TEXT, b"x", masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-on-binary" % nm, lambda m, b=bits: frame(OP_BIN, b"x", masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-on-ping" % nm, lambda m, b=bits: frame(OP_PING, b"x", masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-on-pong" % nm, lambda m, b=bits: frame(OP_PONG, b"x", masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-on-close" % nm, lambda m, b=bits: frame(OP_CLOSE, close_body(1000), masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-on-empty-text" % nm, lambda m, b=bits: frame(OP_TEXT, b"", masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-after-valid-frames" % nm, lambda m, b=bits: frame(OP_TEXT, b"ok", masked=m) + frame(OP_PING, b"", masked=m) + frame(OP_TEXT, b"bad", masked=m, rsv=b))
        o.both("rfc6455-5.2:%s-on-continuation" % nm, lambda m, b=bits: frame(OP_TEXT, b"a", False, masked=m) + frame(OP_CONT, b"b", True, masked=m, rsv=b))
    # Opcodes (5.2): 3-7 and 11-15 are reserved
    for op in range(3, 8):
        o.both("rfc6455-5.2:reserved-data-opcode-%d" % op, lambda m, op=op: frame(op, b"", masked=m))
        o.both("rfc6455-5.2:reserved-data-opcode-%d-with-payload" % op, lambda m, op=op: frame(op, b"payload", masked=m))
        o.both("rfc6455-5.2:reserved-data-opcode-%d-after-text" % op, lambda m, op=op: frame(OP_TEXT, b"hi", masked=m) + frame(op, b"x", masked=m) + frame(OP_PING, b"", masked=m))
    for op in range(11, 16):
        o.both("rfc6455-5.2:reserved-control-opcode-%d" % op, lambda m, op=op: frame(op, b"", masked=m))
        o.both("rfc6455-5.2:reserved-control-opcode-%d-with-payload" % op, lambda m, op=op: frame(op, b"payload", masked=m))
        o.both("rfc6455-5.2:reserved-control-opcode-%d-after-text" % op, lambda m, op=op: frame(OP_TEXT, b"hi", masked=m) + frame(op, b"x", masked=m) + frame(OP_PING, b"", masked=m))
    # Masking (5.1, 5.3): a client MUST mask, a server MUST NOT
    o.ws("rfc6455-5.1:client-frame-unmasked", frame(OP_TEXT, b"Hello", masked=False))
    o.ws("rfc6455-5.1:client-frame-unmasked-empty", frame(OP_TEXT, b"", masked=False))
    o.ws("rfc6455-5.1:client-ping-unmasked", frame(OP_PING, b"x", masked=False))
    o.ws("rfc6455-5.1:client-close-unmasked", frame(OP_CLOSE, close_body(1000), masked=False))
    o.ws("rfc6455-5.1:client-unmasked-after-masked", frame(OP_TEXT, b"ok") + frame(OP_TEXT, b"bad", masked=False))
    o.ws("rfc6455-5.1:client-masked-after-unmasked", frame(OP_TEXT, b"bad", masked=False) + frame(OP_TEXT, b"ok"))
    o.wc("rfc6455-5.1:server-frame-masked", frame(OP_TEXT, b"Hello", masked=True))
    o.wc("rfc6455-5.1:server-frame-masked-empty", frame(OP_TEXT, b"", masked=True))
    o.wc("rfc6455-5.1:server-ping-masked", frame(OP_PING, b"x", masked=True))
    o.wc("rfc6455-5.1:server-close-masked", frame(OP_CLOSE, close_body(1000), masked=True))
    o.wc("rfc6455-5.1:server-masked-after-unmasked", frame(OP_TEXT, b"ok", masked=False) + frame(OP_TEXT, b"bad", masked=True))
    for k in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\x01\x02\x03\x04", b"\x80\x00\x00\x01"):
        o.ws("rfc6455-5.3:mask-key-%s" % k.hex(), frame(OP_TEXT, b"masking key " + k.hex().encode(), key=k))
        o.ws("rfc6455-5.3:mask-key-%s-long" % k.hex(), frame(OP_BIN, rnd(1000), key=k))
    # Control frames (5.5)
    o.both("rfc6455-5.5:ping-empty", lambda m: frame(OP_PING, b"", masked=m))
    o.both("rfc6455-5.5:ping-payload", lambda m: frame(OP_PING, b"Hello, world!", masked=m))
    o.both("rfc6455-5.5:ping-125", lambda m: frame(OP_PING, rnd(125), masked=m))
    o.both("rfc6455-5.5:ping-126", lambda m: frame(OP_PING, rnd(126), masked=m, form=16))
    o.both("rfc6455-5.5:ping-65535", lambda m: frame(OP_PING, rnd(65535), masked=m))
    o.both("rfc6455-5.5:ping-127-in-7-bit-header", lambda m: bytes([0x89, (0x80 if m else 0) | 127]) + (KEY if m else b"") + b"x" * 127)
    o.both("rfc6455-5.5:ping-fragmented", lambda m: frame(OP_PING, b"a", False, masked=m) + frame(OP_CONT, b"b", True, masked=m))
    o.both("rfc6455-5.5:ping-fin-clear-alone", lambda m: frame(OP_PING, b"a", False, masked=m))
    o.both("rfc6455-5.5:pong-empty", lambda m: frame(OP_PONG, b"", masked=m))
    o.both("rfc6455-5.5:pong-payload", lambda m: frame(OP_PONG, b"Hello, world!", masked=m))
    o.both("rfc6455-5.5:pong-125", lambda m: frame(OP_PONG, rnd(125), masked=m))
    o.both("rfc6455-5.5:pong-126", lambda m: frame(OP_PONG, rnd(126), masked=m, form=16))
    o.both("rfc6455-5.5:pong-fragmented", lambda m: frame(OP_PONG, b"a", False, masked=m) + frame(OP_CONT, b"b", True, masked=m))
    o.both("rfc6455-5.5:close-fragmented", lambda m: frame(OP_CLOSE, close_body(1000), False, masked=m) + frame(OP_CONT, b"", True, masked=m))
    o.both("rfc6455-5.5:close-126", lambda m: frame(OP_CLOSE, close_body(1000, b"x" * 124), masked=m, form=16))
    o.both("rfc6455-5.5:close-125", lambda m: frame(OP_CLOSE, close_body(1000, b"x" * 123), masked=m))
    o.both("rfc6455-5.5:close-124", lambda m: frame(OP_CLOSE, close_body(1000, b"x" * 122), masked=m))
    # Fragmentation (5.4)
    o.both("rfc6455-5.4:text-two-fragments", lambda m: frame(OP_TEXT, b"Hel", False, masked=m) + frame(OP_CONT, b"lo", True, masked=m))
    o.both("rfc6455-5.4:text-three-fragments", lambda m: frame(OP_TEXT, b"He", False, masked=m) + frame(OP_CONT, b"l", False, masked=m) + frame(OP_CONT, b"lo", True, masked=m))
    o.both("rfc6455-5.4:binary-three-fragments", lambda m: frame(OP_BIN, b"\x00\x01", False, masked=m) + frame(OP_CONT, b"\x02", False, masked=m) + frame(OP_CONT, b"\x03\x04", True, masked=m))
    o.both("rfc6455-5.4:empty-fragments", lambda m: frame(OP_TEXT, b"", False, masked=m) + frame(OP_CONT, b"", False, masked=m) + frame(OP_CONT, b"", True, masked=m))
    o.both("rfc6455-5.4:empty-first-then-data", lambda m: frame(OP_TEXT, b"", False, masked=m) + frame(OP_CONT, b"data", True, masked=m))
    o.both("rfc6455-5.4:data-then-empty-final", lambda m: frame(OP_TEXT, b"data", False, masked=m) + frame(OP_CONT, b"", True, masked=m))
    o.both("rfc6455-5.4:ping-between-fragments", lambda m: frame(OP_TEXT, b"Hel", False, masked=m) + frame(OP_PING, b"p", masked=m) + frame(OP_CONT, b"lo", True, masked=m))
    o.both("rfc6455-5.4:pong-between-fragments", lambda m: frame(OP_TEXT, b"Hel", False, masked=m) + frame(OP_PONG, b"p", masked=m) + frame(OP_CONT, b"lo", True, masked=m))
    o.both("rfc6455-5.4:ping-and-pong-between-fragments", lambda m: frame(OP_BIN, b"a", False, masked=m) + frame(OP_PING, b"1", masked=m) + frame(OP_CONT, b"b", False, masked=m) + frame(OP_PONG, b"2", masked=m) + frame(OP_CONT, b"c", True, masked=m))
    o.both("rfc6455-5.4:close-between-fragments", lambda m: frame(OP_TEXT, b"Hel", False, masked=m) + frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_CONT, b"lo", True, masked=m))
    o.both("rfc6455-5.4:close-ends-incomplete-message", lambda m: frame(OP_TEXT, b"Hel", False, masked=m) + frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("rfc6455-5.4:continuation-with-nothing-to-continue-fin", lambda m: frame(OP_CONT, b"x", True, masked=m))
    o.both("rfc6455-5.4:continuation-with-nothing-to-continue-nofin", lambda m: frame(OP_CONT, b"x", False, masked=m))
    o.both("rfc6455-5.4:continuation-after-complete-message", lambda m: frame(OP_TEXT, b"a", True, masked=m) + frame(OP_CONT, b"b", True, masked=m))
    o.both("rfc6455-5.4:continuation-then-text-fin", lambda m: frame(OP_CONT, b"x", True, masked=m) + frame(OP_TEXT, b"ok", True, masked=m))
    o.both("rfc6455-5.4:text-nofin-then-text", lambda m: frame(OP_TEXT, b"a", False, masked=m) + frame(OP_TEXT, b"b", True, masked=m))
    o.both("rfc6455-5.4:text-nofin-then-binary", lambda m: frame(OP_TEXT, b"a", False, masked=m) + frame(OP_BIN, b"b", True, masked=m))
    o.both("rfc6455-5.4:binary-nofin-then-text", lambda m: frame(OP_BIN, b"a", False, masked=m) + frame(OP_TEXT, b"b", True, masked=m))
    o.both("rfc6455-5.4:text-nofin-continuation-then-text", lambda m: frame(OP_TEXT, b"a", False, masked=m) + frame(OP_CONT, b"b", True, masked=m) + frame(OP_TEXT, b"c", True, masked=m))
    o.both("rfc6455-5.4:text-nofin-alone", lambda m: frame(OP_TEXT, b"a", False, masked=m))
    o.both("rfc6455-5.4:two-messages-back-to-back", lambda m: frame(OP_TEXT, b"one", masked=m) + frame(OP_BIN, b"two", masked=m) + frame(OP_TEXT, b"three", masked=m))
    o.both("rfc6455-5.4:fragmented-then-whole", lambda m: frame(OP_TEXT, b"a", False, masked=m) + frame(OP_CONT, b"b", True, masked=m) + frame(OP_BIN, b"c", masked=m))
    o.both("rfc6455-5.4:many-fragments-100", lambda m: frame(OP_BIN, b"x", False, masked=m) + b"".join(frame(OP_CONT, b"x", False, masked=m) for _ in range(98)) + frame(OP_CONT, b"x", True, masked=m))
    o.both("rfc6455-5.4:many-fragments-1024", lambda m: frame(OP_BIN, b"x", False, masked=m) + b"".join(frame(OP_CONT, b"x", False, masked=m) for _ in range(1022)) + frame(OP_CONT, b"x", True, masked=m))
    o.both("rfc6455-5.4:many-fragments-1025", lambda m: frame(OP_BIN, b"x", False, masked=m) + b"".join(frame(OP_CONT, b"x", False, masked=m) for _ in range(1023)) + frame(OP_CONT, b"x", True, masked=m))
    o.both("rfc6455-5.4:many-fragments-5000", lambda m: frame(OP_BIN, b"x", False, masked=m) + b"".join(frame(OP_CONT, b"x", False, masked=m) for _ in range(4998)) + frame(OP_CONT, b"x", True, masked=m))
    # Many control frames (a flood of pings); the library caps them per interval
    for n in (10, 100, 128, 129, 1000):
        o.both("rfc6455-5.5:pings-%d" % n, lambda m, n=n: b"".join(frame(OP_PING, b"%d" % i, masked=m) for i in range(n)))
    o.both("rfc6455-5.5:pongs-1000", lambda m: b"".join(frame(OP_PONG, b"%d" % i, masked=m) for i in range(1000)))
    o.both("rfc6455-5.5:ping-pong-interleaved", lambda m: b"".join(frame(OP_PING, b"a", masked=m) + frame(OP_PONG, b"b", masked=m) for _ in range(5)))

    # ------------------------------------------------------------------------------
    # RFC 6455 section 5.7 and 7: examples, and the closing handshake
    # ------------------------------------------------------------------------------
    o.ws("rfc6455-5.7:masked-hello", bytes.fromhex("818537fa213d7f9f4d5158"))
    o.wc("rfc6455-5.7:unmasked-hello", bytes.fromhex("810548656c6c6f"))
    o.wc("rfc6455-5.7:fragmented-unmasked", bytes.fromhex("010348656c") + bytes.fromhex("80026c6f"))
    o.wc("rfc6455-5.7:unmasked-ping", bytes.fromhex("890548656c6c6f"))
    o.ws("rfc6455-5.7:masked-pong", bytes.fromhex("8a853784b3c85f9d3fa2a2"))  # bytes not the RFC's; any key works
    o.wc("rfc6455-5.7:256-bytes-binary", bytes.fromhex("827e0100") + bytes(range(256)))
    o.wc("rfc6455-5.7:64kib-binary", bytes.fromhex("827f0000000000010000") + rnd(65536))
    o.both("rfc6455-7.1:close-empty", lambda m: frame(OP_CLOSE, b"", masked=m))
    o.both("rfc6455-7.1:close-1000", lambda m: frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("rfc6455-7.1:close-1000-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"bye"), masked=m))
    o.both("rfc6455-7.1:close-reason-utf8", lambda m: frame(OP_CLOSE, close_body(1000, KOSME), masked=m))
    o.both("rfc6455-7.1:close-123-byte-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"r" * 123), masked=m))
    o.both("rfc6455-7.1:close-twice", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("rfc6455-7.1:text-then-close", lambda m: frame(OP_TEXT, b"x", masked=m) + frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("rfc6455-7.1:ping-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_PING, b"x", masked=m))
    o.both("rfc6455-7.1:pong-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_PONG, b"x", masked=m))
    o.both("rfc6455-7.1:text-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_TEXT, b"x", masked=m))
    o.both("rfc6455-7.1:binary-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_BIN, b"x", masked=m))
    o.both("rfc6455-7.1:garbage-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + b"\xff\xff\xff")
    o.both("rfc6455-7.1:one-octet-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + b"\x81")
    o.both("rfc6455-7.1:empty-close-then-text", lambda m: frame(OP_CLOSE, b"", masked=m) + frame(OP_TEXT, b"x", masked=m))
    o.both("rfc6455-7.1:close-in-the-middle-of-pings", lambda m: frame(OP_PING, b"1", masked=m) + frame(OP_CLOSE, close_body(1001), masked=m) + frame(OP_PING, b"2", masked=m))
    # Close bodies (5.5.1) and codes (7.4)
    o.both("rfc6455-5.5.1:close-one-octet", lambda m: frame(OP_CLOSE, b"\x03", masked=m))
    o.both("rfc6455-5.5.1:close-one-octet-zero", lambda m: frame(OP_CLOSE, b"\x00", masked=m))
    o.both("rfc6455-5.5.1:close-code-only", lambda m: frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("rfc6455-5.5.1:close-bad-utf8-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80\x65\x64\x69\x74\x65\x64"), masked=m))
    o.both("rfc6455-5.5.1:close-truncated-utf8-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"ab\xe2\x82"), masked=m))
    o.both("rfc6455-5.5.1:close-overlong-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"\xc0\x80"), masked=m))
    o.both("rfc6455-5.5.1:close-surrogate-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"\xed\xa0\x80"), masked=m))
    o.both("rfc6455-5.5.1:close-bad-utf8-reason-bad-code", lambda m: frame(OP_CLOSE, close_body(5000, b"\xff"), masked=m))
    for code in (1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999):
        o.both("rfc6455-7.4:close-code-%d-valid" % code, lambda m, c=code: frame(OP_CLOSE, close_body(c, b"ok"), masked=m))
    for code in (0, 1, 500, 999, 1004, 1005, 1006, 1015, 1016, 1100, 1999, 2000, 2999, 5000, 5001, 10000, 65535):
        o.both("rfc6455-7.4:close-code-%d-invalid" % code, lambda m, c=code: frame(OP_CLOSE, close_body(c, b"x"), masked=m))
        o.both("rfc6455-7.4:close-code-%d-invalid-no-reason" % code, lambda m, c=code: frame(OP_CLOSE, close_body(c), masked=m))
    o.both("rfc6455-7.4:close-code-byte-order-swapped", lambda m: frame(OP_CLOSE, b"\xe8\x03", masked=m))
    o.both("rfc6455-7.4:close-code-after-fragment", lambda m: frame(OP_BIN, b"a", False, masked=m) + frame(OP_CLOSE, close_body(1002), masked=m))

    # ------------------------------------------------------------------------------
    # RFC 6455 section 5.6 and 8.1: text is UTF-8
    # ------------------------------------------------------------------------------
    utf8_valid = [
        ("ascii", b"plain ascii"), ("nul", b"\x00"), ("del", b"\x7f"), ("kosme", KOSME),
        ("u0080", "\u0080".encode()), ("u07ff", "߿".encode()), ("u0800", "ࠀ".encode()),
        ("ud7ff", "퟿".encode()), ("ue000", "".encode()), ("ufffd", "�".encode()),
        ("ufffe", b"\xef\xbf\xbe"), ("uffff", b"\xef\xbf\xbf"), ("u10000", "\U00010000".encode()),
        ("u1ffff", "\U0001ffff".encode()), ("u10fffd", "\U0010fffd".encode()), ("u10ffff", "\U0010ffff".encode()),
        ("u40000", "\U00040000".encode()), ("mixed", "aé€\U0001f600z".encode()),
    ]
    for nm, b in utf8_valid:
        o.both("rfc6455-5.6:utf8-valid-%s" % nm, lambda m, b=b: frame(OP_TEXT, b, masked=m))
    utf8_bad = [
        ("lone-continuation-80", b"\x80"), ("lone-continuation-bf", b"\xbf"),
        ("start-c2-alone", b"\xc2"), ("start-e2-82", b"\xe2\x82"), ("start-f0-90-80", b"\xf0\x90\x80"),
        ("overlong-c0-80", b"\xc0\x80"), ("overlong-c0-af", b"\xc0\xaf"), ("overlong-c1-bf", b"\xc1\xbf"),
        ("overlong-e0-80-af", b"\xe0\x80\xaf"), ("overlong-e0-9f-bf", b"\xe0\x9f\xbf"),
        ("overlong-f0-80-80-af", b"\xf0\x80\x80\xaf"), ("overlong-f0-8f-bf-bf", b"\xf0\x8f\xbf\xbf"),
        ("surrogate-d800", b"\xed\xa0\x80"), ("surrogate-dbff", b"\xed\xaf\xbf"), ("surrogate-dc00", b"\xed\xb0\x80"),
        ("surrogate-dfff", b"\xed\xbf\xbf"), ("surrogate-pair", b"\xed\xa0\x80\xed\xb0\x80"),
        ("above-10ffff-f4-90", b"\xf4\x90\x80\x80"), ("above-10ffff-f5", b"\xf5\x80\x80\x80"),
        ("five-byte-f8", b"\xf8\x88\x80\x80\x80"), ("six-byte-fc", b"\xfc\x84\x80\x80\x80\x80"),
        ("fe", b"\xfe"), ("ff", b"\xff"), ("fe-fe-ff-ff", b"\xfe\xfe\xff\xff"),
        ("continuation-after-ascii", b"a\x80"), ("two-continuations", b"\x80\x80"),
        ("start-then-ascii", b"\xc2a"), ("start3-then-ascii", b"\xe2\x82a"), ("start4-then-ascii", b"\xf0\x90\x80a"),
        ("start-start", b"\xc2\xc2"), ("e0-start-bad-second", b"\xe0\x80\x80"), ("ed-start-bad-second", b"\xed\x80\x80a\xed\xa0"),
        ("truncated-last", b"abc\xe2\x82"), ("kosme-then-d800", KOSME + b"\xed\xa0\x80" + b"edited"),
    ]
    for nm, b in utf8_bad:
        o.both("rfc6455-8.1:utf8-invalid-%s" % nm, lambda m, b=b: frame(OP_TEXT, b, masked=m))
        o.ws("rfc6455-8.1:utf8-invalid-%s-after-valid" % nm, frame(OP_TEXT, b"fine") + frame(OP_TEXT, b))
        o.ws("rfc6455-8.1:utf8-invalid-%s-then-close" % nm, frame(OP_TEXT, b) + frame(OP_CLOSE, close_body(1000)))
        o.ws("rfc6455-8.1:utf8-invalid-%s-as-binary-ok" % nm, frame(OP_BIN, b))
    # Every byte value alone, in the middle of text: 0x80-0xff
    for v in range(0x80, 0x100):
        o.ws("rfc6455-8.1:utf8-byte-%02x-between-ascii" % v, frame(OP_TEXT, b"a" + bytes([v]) + b"b"))
    # Every two-byte pair with a lead byte c0-f4 and every continuation class
    for lead in (0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5):
        for second in (0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0):
            o.ws("rfc6455-8.1:utf8-pair-%02x-%02x" % (lead, second), frame(OP_TEXT, bytes([lead, second]) + b"\x80\x80"))
    # Sequences split across fragments (a code point may span frames)
    for nm, b in [("kosme", KOSME), ("u20ac", "€".encode()), ("u1f600", "\U0001f600".encode()),
                  ("u10ffff", "\U0010ffff".encode()), ("u07ff", "߿".encode())]:
        for cut in range(1, len(b)):
            o.both("rfc6455-5.6:utf8-split-%s-at-%d" % (nm, cut), lambda m, b=b, cut=cut: frame(OP_TEXT, b[:cut], False, masked=m) + frame(OP_CONT, b[cut:], True, masked=m))
        o.both("rfc6455-5.6:utf8-split-%s-every-octet" % nm, lambda m, b=b: frame(OP_TEXT, b[:1], False, masked=m) + b"".join(frame(OP_CONT, b[i:i + 1], i == len(b) - 1, masked=m) for i in range(1, len(b))))
    for nm, bad_first, bad_second in [
        ("overlong", b"\xc0", b"\x80"), ("surrogate", b"\xed", b"\xa0\x80"),
        ("above-max", b"\xf4", b"\x90\x80\x80"), ("overlong-3", b"\xe0", b"\x80\x80"), ("overlong-4", b"\xf0", b"\x80\x80\x80"),
        ("f5", b"\xf5", b"\x80\x80\x80"),
    ]:
        o.both("rfc6455-5.6:utf8-split-invalid-%s" % nm, lambda m, a=bad_first, b=bad_second: frame(OP_TEXT, a, False, masked=m) + frame(OP_CONT, b, True, masked=m))
    o.both("rfc6455-5.6:utf8-ends-mid-sequence-in-first-fragment-then-binary-ok", lambda m: frame(OP_TEXT, b"\xe2\x82", False, masked=m) + frame(OP_CONT, b"\xac", True, masked=m) + frame(OP_BIN, b"\xff", masked=m))
    o.both("rfc6455-5.6:utf8-incomplete-at-final-fragment", lambda m: frame(OP_TEXT, b"ab\xe2", False, masked=m) + frame(OP_CONT, b"\x82", True, masked=m))
    o.both("rfc6455-5.6:utf8-invalid-in-first-fragment-then-never-ends", lambda m: frame(OP_TEXT, b"\xff", False, masked=m))
    o.both("rfc6455-5.6:utf8-invalid-in-middle-fragment", lambda m: frame(OP_TEXT, KOSME, False, masked=m) + frame(OP_CONT, b"\xf4\x90\x80\x80", False, masked=m) + frame(OP_CONT, b"tail", True, masked=m))
    o.both("rfc6455-5.6:utf8-invalid-then-ping", lambda m: frame(OP_TEXT, b"\xff", masked=m) + frame(OP_PING, b"x", masked=m))
    o.both("rfc6455-5.6:utf8-valid-fragments-with-pings-between", lambda m: frame(OP_TEXT, "€".encode()[:1], False, masked=m) + frame(OP_PING, b"p", masked=m) + frame(OP_CONT, "€".encode()[1:2], False, masked=m) + frame(OP_PING, b"q", masked=m) + frame(OP_CONT, "€".encode()[2:], True, masked=m))
    o.both("rfc6455-5.6:utf8-in-a-long-text-65536", lambda m: frame(OP_TEXT, ("é" * 32768).encode(), masked=m))
    o.both("rfc6455-5.6:utf8-invalid-at-the-end-of-65536", lambda m: frame(OP_TEXT, b"a" * 65535 + b"\xff", masked=m))
    o.both("rfc6455-5.6:utf8-invalid-at-the-start-of-65536", lambda m: frame(OP_TEXT, b"\xff" + b"a" * 65535, masked=m))
    o.both("rfc6455-5.6:utf8-split-at-65536-boundary", lambda m: frame(OP_TEXT, b"a" * 65535 + "é".encode()[:1], False, masked=m) + frame(OP_CONT, "é".encode()[1:], True, masked=m))
    o.both("rfc6455-5.6:binary-need-not-be-utf8", lambda m: frame(OP_BIN, bytes(range(256)), masked=m))

    # ------------------------------------------------------------------------------
    # Limits (this library's and each reference's own, 1 MiB for every one)
    # ------------------------------------------------------------------------------
    for n in (MAXMSG - 1, MAXMSG, MAXMSG + 1):
        o.ws("limit:message-%d-binary" % n, frame(OP_BIN, rnd(n)))
    o.ws("limit:message-%d-text" % MAXMSG, frame(OP_TEXT, lorem(MAXMSG)))
    o.ws("limit:message-%d-text" % (MAXMSG + 1), frame(OP_TEXT, lorem(MAXMSG + 1)))
    o.wc("limit:message-%d-binary" % MAXMSG, frame(OP_BIN, rnd(MAXMSG), masked=False))
    o.wc("limit:message-%d-binary" % (MAXMSG + 1), frame(OP_BIN, rnd(MAXMSG + 1), masked=False))
    o.ws("limit:fragments-total-1MiB", frame(OP_BIN, rnd(MAXMSG // 2), False) + frame(OP_CONT, rnd(MAXMSG // 2), True))
    o.ws("limit:fragments-total-1MiB-plus-1", frame(OP_BIN, rnd(MAXMSG // 2), False) + frame(OP_CONT, rnd(MAXMSG // 2 + 1), True))
    o.ws("limit:header-claims-1MiB-plus-1", header(OP_BIN, MAXMSG + 1))
    o.ws("limit:header-claims-1MiB", header(OP_BIN, MAXMSG))
    o.ws("limit:header-claims-2GiB", header(OP_BIN, 1 << 31, form=64))
    o.ws("limit:header-claims-1MiB-plus-1-then-data", header(OP_BIN, MAXMSG + 1) + rnd(1000))
    o.ws("limit:fragment-headers-claim-1MiB-each-of-two", header(OP_BIN, MAXMSG, False) + b"")
    o.ws("limit:second-fragment-header-pushes-over", frame(OP_BIN, rnd(MAXMSG - 1), False) + header(OP_CONT, 2))
    o.ws("limit:second-fragment-header-fits", frame(OP_BIN, rnd(MAXMSG - 2), False) + header(OP_CONT, 2))

    # ------------------------------------------------------------------------------
    # Autobahn|Testsuite, the cases of families 1 to 7 re-expressed as byte streams.
    # (Families 9, 10 are about performance and transport; 12 and 13 follow below.)
    # ------------------------------------------------------------------------------
    sizes = [("1", 0), ("2", 125), ("3", 126), ("4", 127), ("5", 128), ("6", 65535), ("7", 65536)]
    for idx, n in sizes:
        o.both("autobahn-1.1.%s:text-%d" % (idx, n), lambda m, n=n: frame(OP_TEXT, (b"*" * n), masked=m))
        o.both("autobahn-1.2.%s:binary-%d" % (idx, n), lambda m, n=n: frame(OP_BIN, rnd(n), masked=m))
    o.both("autobahn-1.1.8:text-65536-same-stream-as-1.1.7", lambda m: frame(OP_TEXT, b"*" * 65536, masked=m))
    o.both("autobahn-2.1:ping-empty", lambda m: frame(OP_PING, b"", masked=m))
    o.both("autobahn-2.2:ping-hello-world", lambda m: frame(OP_PING, b"Hello, world!", masked=m))
    o.both("autobahn-2.3:ping-binary", lambda m: frame(OP_PING, bytes([0, 255, 254, 253, 252, 251, 0, 255]), masked=m))
    o.both("autobahn-2.4:ping-125", lambda m: frame(OP_PING, b"*" * 125, masked=m))
    o.both("autobahn-2.5:ping-126", lambda m: frame(OP_PING, b"*" * 126, masked=m, form=16))
    o.both("autobahn-2.6:ping-125-two-chops", lambda m: frame(OP_PING, b"*" * 125, masked=m))
    o.both("autobahn-2.7:pong-empty", lambda m: frame(OP_PONG, b"", masked=m))
    o.both("autobahn-2.8:pong-payload", lambda m: frame(OP_PONG, b"Hello, world!", masked=m))
    o.both("autobahn-2.9:pong-then-ping", lambda m: frame(OP_PONG, b"ping1", masked=m) + frame(OP_PING, b"ping2", masked=m))
    o.both("autobahn-2.10:ten-pings", lambda m: b"".join(frame(OP_PING, b"payload-%d" % i, masked=m) for i in range(10)))
    o.both("autobahn-2.11:ten-pings-then-close", lambda m: b"".join(frame(OP_PING, b"payload-%d" % i, masked=m) for i in range(10)) + frame(OP_CLOSE, close_body(1000), masked=m))
    # Family 3: reserved bits, as Autobahn sends them (a text frame with a bit set, then more frames)
    o.both("autobahn-3.1:rsv1-text-then-ping", lambda m: frame(OP_TEXT, b"small payload", masked=m, rsv=R1) + frame(OP_PING, b"ping", masked=m))
    o.both("autobahn-3.2:rsv2-text-after-valid-text-and-ping", lambda m: frame(OP_TEXT, b"small payload", masked=m) + frame(OP_TEXT, b"small payload", masked=m, rsv=R2) + frame(OP_PING, b"", masked=m))
    o.both("autobahn-3.3:rsv1-2-text-after-ping", lambda m: frame(OP_TEXT, b"small payload", masked=m) + frame(OP_PING, b"", masked=m) + frame(OP_TEXT, b"small payload", masked=m, rsv=R1 | R2) + frame(OP_PING, b"", masked=m))
    o.both("autobahn-3.4:rsv3-text-chopped", lambda m: frame(OP_TEXT, b"small payload", masked=m, rsv=R3))
    o.both("autobahn-3.5:rsv1-2-3-binary-chopped", lambda m: frame(OP_BIN, b"\x00\xff\xfe\xfd\xfc\xfb\x00\xff", masked=m, rsv=R1 | R2 | R3))
    o.both("autobahn-3.6:rsv1-2-3-ping", lambda m: frame(OP_PING, b"", masked=m, rsv=R1 | R2 | R3))
    o.both("autobahn-3.7:rsv1-2-3-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m, rsv=R1 | R2 | R3))
    # Family 4: reserved opcodes (4.1.x non-control 3-7; 4.2.x control 11-15)
    for i, op in enumerate(range(3, 8), 1):
        o.both("autobahn-4.1.%d:opcode-%d-empty" % (i, op), lambda m, op=op: frame(op, b"", masked=m))
        o.both("autobahn-4.1.%d:opcode-%d-then-ping" % (i, op), lambda m, op=op: frame(op, b"reserved opcode payload", masked=m) + frame(OP_PING, b"", masked=m))
    for i, op in enumerate(range(11, 16), 1):
        o.both("autobahn-4.2.%d:opcode-%d-empty" % (i, op), lambda m, op=op: frame(op, b"", masked=m))
        o.both("autobahn-4.2.%d:opcode-%d-then-ping" % (i, op), lambda m, op=op: frame(op, b"reserved opcode payload", masked=m) + frame(OP_PING, b"", masked=m))
    # Family 5: fragmentation
    o.both("autobahn-5.1:ping-fragmented-with-fin-clear", lambda m: frame(OP_PING, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.2:pong-fragmented", lambda m: frame(OP_PONG, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.3:text-fragmented-two", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.4:text-fragmented-then-whole", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.5:text-fragmented-chopped", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.6:text-fragmented-with-ping-between", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_PING, b"pongme", masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.7:text-fragmented-with-ping-between-chopped", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_PING, b"pongme", masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-5.8:text-three-fragments-with-ping", lambda m: frame(OP_TEXT, b"f1", False, masked=m) + frame(OP_CONT, b"f2", False, masked=m) + frame(OP_PING, b"x", masked=m) + frame(OP_CONT, b"f3", True, masked=m))
    o.both("autobahn-5.9:continuation-fin-with-nothing-to-continue-then-text", lambda m: frame(OP_CONT, b"non-continuation payload", True, masked=m) + frame(OP_TEXT, b"Hello, world!", True, masked=m))
    o.both("autobahn-5.10:continuation-fin-with-nothing-to-continue-then-text-chopped", lambda m: frame(OP_CONT, b"non-continuation payload", True, masked=m) + frame(OP_TEXT, b"Hello, world!", True, masked=m))
    o.both("autobahn-5.11:continuation-nofin-with-nothing-to-continue-then-text", lambda m: frame(OP_CONT, b"non-continuation payload", False, masked=m) + frame(OP_TEXT, b"Hello, world!", True, masked=m))
    o.both("autobahn-5.12:continuation-nofin-with-nothing-to-continue", lambda m: frame(OP_CONT, b"non-continuation payload", False, masked=m) + frame(OP_TEXT, b"Hello, world!", True, masked=m))
    o.both("autobahn-5.13:continuation-fin-after-text-fin", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m) + frame(OP_CONT, b"fragment3", True, masked=m) + frame(OP_TEXT, b"fragment4", True, masked=m))
    o.both("autobahn-5.14:continuation-nofin-after-text-fin", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m) + frame(OP_CONT, b"fragment3", False, masked=m) + frame(OP_TEXT, b"fragment4", True, masked=m))
    o.both("autobahn-5.15:text-text-in-the-middle", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m) + frame(OP_CONT, b"fragment3", False, masked=m) + frame(OP_TEXT, b"fragment4", True, masked=m))
    o.both("autobahn-5.16:continuations-then-text-fragments", lambda m: frame(OP_CONT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", False, masked=m) + frame(OP_CONT, b"fragment3", True, masked=m) + frame(OP_TEXT, b"fragment4", False, masked=m) + frame(OP_CONT, b"fragment5", True, masked=m))
    o.both("autobahn-5.17:continuations-then-text-fragments-fin", lambda m: frame(OP_CONT, b"fragment1", True, masked=m) + frame(OP_CONT, b"fragment2", True, masked=m) + frame(OP_TEXT, b"fragment3", False, masked=m) + frame(OP_CONT, b"fragment4", True, masked=m))
    o.both("autobahn-5.18:text-nofin-then-text-in-the-middle", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_TEXT, b"fragment2", True, masked=m))
    o.both("autobahn-5.19:fragments-with-pings-and-pongs", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", False, masked=m) + frame(OP_PING, b"pongme 1!", masked=m) + frame(OP_CONT, b"fragment3", False, masked=m) + frame(OP_CONT, b"fragment4", False, masked=m) + frame(OP_PING, b"pongme 2!", masked=m) + frame(OP_CONT, b"fragment5", True, masked=m))
    o.both("autobahn-5.20:fragments-with-pings-and-pongs-chopped", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CONT, b"fragment2", False, masked=m) + frame(OP_PING, b"pongme 1!", masked=m) + frame(OP_CONT, b"fragment3", False, masked=m) + frame(OP_PONG, b"unsolicited", masked=m) + frame(OP_CONT, b"fragment4", False, masked=m) + frame(OP_PING, b"pongme 2!", masked=m) + frame(OP_CONT, b"fragment5", True, masked=m))
    # Family 6: UTF-8 (6.1 valid empty and fragmented empty; 6.2 valid; 6.3 invalid; 6.4 fail fast; 6.5-6.23)
    o.both("autobahn-6.1.1:text-empty", lambda m: frame(OP_TEXT, b"", masked=m))
    o.both("autobahn-6.1.2:text-empty-fragments-3", lambda m: frame(OP_TEXT, b"", False, masked=m) + frame(OP_CONT, b"", False, masked=m) + frame(OP_CONT, b"", True, masked=m))
    o.both("autobahn-6.1.3:text-empty-and-data-fragments", lambda m: frame(OP_TEXT, b"", False, masked=m) + frame(OP_CONT, b"MESSAGE", False, masked=m) + frame(OP_CONT, b"", True, masked=m))
    for i, parts in enumerate([[b"\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5"], [b"\xce\xba", b"\xe1\xbd\xb9", b"\xcf\x83\xce\xbc\xce\xb5"], [KOSME[:1], KOSME[1:]]], 1):
        o.both("autobahn-6.2.%d:valid-utf8-%d-fragments" % (i, len(parts)), lambda m, parts=parts: b"".join(frame(OP_TEXT if j == 0 else OP_CONT, p, j == len(parts) - 1, masked=m) for j, p in enumerate(parts)))
    o.both("autobahn-6.3.1:invalid-utf8-whole", lambda m: frame(OP_TEXT, KOSME + b"\xed\xa0\x80" + b"edited", masked=m))
    o.both("autobahn-6.3.2:invalid-utf8-chopped", lambda m: frame(OP_TEXT, KOSME + b"\xed\xa0\x80" + b"edited", masked=m))
    o.both("autobahn-6.4.1:fail-fast-invalid-in-first-fragment", lambda m: frame(OP_TEXT, KOSME, False, masked=m) + frame(OP_CONT, b"\xf4\x90\x80\x80", False, masked=m) + frame(OP_CONT, b"edited", True, masked=m))
    o.both("autobahn-6.4.2:fail-fast-invalid-then-valid", lambda m: frame(OP_TEXT, KOSME + b"\xf4\x90\x80\x80" + b"edited", False, masked=m) + frame(OP_CONT, b"tail", True, masked=m))
    o.both("autobahn-6.4.3:fail-fast-invalid-in-large-frame", lambda m: frame(OP_TEXT, KOSME + b"\xf4\x90\x80\x80" + b"x" * 100000, masked=m))
    o.both("autobahn-6.4.4:fail-fast-invalid-in-large-frame-late", lambda m: frame(OP_TEXT, b"x" * 100000 + b"\xf4\x90\x80\x80", masked=m))
    for i, (nm, b) in enumerate([("c2-80", b"\xc2\x80"), ("df-bf", b"\xdf\xbf"), ("e0-a0-80", b"\xe0\xa0\x80"), ("ef-bf-bf", b"\xef\xbf\xbf"), ("f0-90-80-80", b"\xf0\x90\x80\x80"), ("f4-8f-bf-bf", b"\xf4\x8f\xbf\xbf")], 1):
        o.both("autobahn-6.7.%d:valid-boundary-%s" % (i, nm), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, (nm, b) in enumerate([("f4-90-80-80", b"\xf4\x90\x80\x80"), ("f5-80-80-80", b"\xf5\x80\x80\x80"), ("f7-bf-bf-bf", b"\xf7\xbf\xbf\xbf"), ("f8-88-80-80-80", b"\xf8\x88\x80\x80\x80"), ("fb-bf-bf-bf-bf", b"\xfb\xbf\xbf\xbf\xbf"), ("fc-84-80-80-80-80", b"\xfc\x84\x80\x80\x80\x80"), ("fd-bf-bf-bf-bf-bf", b"\xfd\xbf\xbf\xbf\xbf\xbf")], 1):
        o.both("autobahn-6.8.%d:invalid-beyond-max-%s" % (i, nm), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, (nm, b) in enumerate([("00", b"\x00"), ("7f", b"\x7f"), ("c2-80", b"\xc2\x80"), ("df-bf", b"\xdf\xbf"), ("e0-a0-80", b"\xe0\xa0\x80"), ("ed-9f-bf", b"\xed\x9f\xbf"), ("ee-80-80", b"\xee\x80\x80"), ("ef-bf-bd", b"\xef\xbf\xbd"), ("f0-90-80-80", b"\xf0\x90\x80\x80"), ("f4-8f-bf-bf", b"\xf4\x8f\xbf\xbf")], 1):
        o.both("autobahn-6.9.%d:valid-first-last-of-length-%s" % (i, nm), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\x80", b"\xbf", b"\x80\xbf", b"\x80\xbf\x80", b"\x80\xbf\x80\xbf", b"\x80\xbf\x80\xbf\x80", b"\x80\xbf\x80\xbf\x80\xbf"], 1):
        o.both("autobahn-6.12.%d:unexpected-continuation-bytes-%d" % (i, i), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([bytes(range(0x80, 0xc0))], 1):
        o.both("autobahn-6.12.8:all-continuation-bytes", lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, rng in enumerate([range(0xc0, 0xe0), range(0xe0, 0xf0), range(0xf0, 0xf8), range(0xf8, 0xfc), range(0xfc, 0xfe)], 1):
        o.both("autobahn-6.13.%d:lonely-start-bytes-with-spaces-%d" % (i, i), lambda m, rng=rng: frame(OP_TEXT, b"".join(bytes([c]) + b" " for c in rng), masked=m))
    for i, b in enumerate([b"\xc0", b"\xe0\x80", b"\xe0\xa0", b"\xf0\x80\x80", b"\xf0\x90\x80", b"\xf8\x88\x80\x80", b"\xfc\x84\x80\x80\x80", b"\xdf", b"\xef\xbf", b"\xf7\xbf\xbf", b"\xfb\xbf\xbf\xbf", b"\xfd\xbf\xbf\xbf\xbf"], 1):
        o.both("autobahn-6.14.%d:last-continuation-missing-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    o.both("autobahn-6.15.1:all-missing-last-continuation-concatenated", lambda m: frame(OP_TEXT, b"\xc0\xe0\x80\xf0\x80\x80\xf8\x80\x80\x80\xfc\x80\x80\x80\x80\xdf\xef\xbf\xf7\xbf\xbf\xfb\xbf\xbf\xbf\xfd\xbf\xbf\xbf\xbf", masked=m))
    for i, b in enumerate([b"\xfe", b"\xff", b"\xfe\xfe\xff\xff"], 1):
        o.both("autobahn-6.16.%d:impossible-bytes-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\xc0\xaf", b"\xe0\x80\xaf", b"\xf0\x80\x80\xaf", b"\xf8\x80\x80\x80\xaf", b"\xfc\x80\x80\x80\x80\xaf"], 1):
        o.both("autobahn-6.17.%d:overlong-slash-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\xc1\xbf", b"\xe0\x9f\xbf", b"\xf0\x8f\xbf\xbf", b"\xf8\x87\xbf\xbf\xbf", b"\xfc\x83\xbf\xbf\xbf\xbf"], 1):
        o.both("autobahn-6.18.%d:overlong-maximum-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\xc0\x80", b"\xe0\x80\x80", b"\xf0\x80\x80\x80", b"\xf8\x80\x80\x80\x80", b"\xfc\x80\x80\x80\x80\x80"], 1):
        o.both("autobahn-6.19.%d:overlong-nul-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\xed\xa0\x80", b"\xed\xad\xbf", b"\xed\xae\x80", b"\xed\xaf\xbf", b"\xed\xb0\x80", b"\xed\xbe\x80", b"\xed\xbf\xbf"], 1):
        o.both("autobahn-6.20.%d:lone-surrogate-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\xed\xa0\x80\xed\xb0\x80", b"\xed\xa0\x80\xed\xbf\xbf", b"\xed\xad\xbf\xed\xb0\x80", b"\xed\xad\xbf\xed\xbf\xbf", b"\xed\xae\x80\xed\xb0\x80", b"\xed\xae\x80\xed\xbf\xbf", b"\xed\xaf\xbf\xed\xb0\x80", b"\xed\xaf\xbf\xed\xbf\xbf"], 1):
        o.both("autobahn-6.21.%d:surrogate-pair-cesu8-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate([b"\xef\xbf\xbe", b"\xef\xbf\xbf", "\U0001fffe".encode(), "\U0001ffff".encode(), "\U0010fffe".encode(), "\U0010ffff".encode(), b"\xef\xb7\x90", b"\xef\xb7\xaf"], 1):
        o.both("autobahn-6.22.%d:noncharacter-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    for i, b in enumerate(["\U000e0001".encode(), "".encode(), "\U000f0000".encode()], 1):
        o.both("autobahn-6.23.%d:private-use-%s" % (i, b.hex()), lambda m, b=b: frame(OP_TEXT, b, masked=m))
    # Family 7: closing handshake
    o.both("autobahn-7.1.1:close-handshake-after-text", lambda m: frame(OP_TEXT, b"Hello World!", masked=m) + frame(OP_CLOSE, close_body(1000, b"bye"), masked=m))
    o.both("autobahn-7.1.2:two-close-frames", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("autobahn-7.1.3:ping-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_PING, b"Hello!", masked=m))
    o.both("autobahn-7.1.4:text-after-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_TEXT, b"Hello World!", masked=m))
    o.both("autobahn-7.1.5:fragmented-text-then-close-then-continuation", lambda m: frame(OP_TEXT, b"fragment1", False, masked=m) + frame(OP_CLOSE, close_body(1000), masked=m) + frame(OP_CONT, b"fragment2", True, masked=m))
    o.both("autobahn-7.1.6:large-message-then-close", lambda m: frame(OP_TEXT, b"x" * 256 * 1024, masked=m) + frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("autobahn-7.3.1:close-empty-payload", lambda m: frame(OP_CLOSE, b"", masked=m))
    o.both("autobahn-7.3.2:close-one-octet", lambda m: frame(OP_CLOSE, b"\x00", masked=m))
    o.both("autobahn-7.3.3:close-code-only", lambda m: frame(OP_CLOSE, close_body(1000), masked=m))
    o.both("autobahn-7.3.4:close-code-and-reason", lambda m: frame(OP_CLOSE, close_body(1000, "Hello World!".encode()), masked=m))
    o.both("autobahn-7.3.5:close-123-byte-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"*" * 123), masked=m))
    o.both("autobahn-7.3.6:close-124-byte-reason", lambda m: frame(OP_CLOSE, close_body(1000, b"*" * 124), masked=m))
    o.both("autobahn-7.5.1:close-invalid-utf8-reason", lambda m: frame(OP_CLOSE, close_body(1000, KOSME + b"\xed\xa0\x80" + b"edited"), masked=m))
    for i, code in enumerate([1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999], 1):
        o.both("autobahn-7.7.%d:close-code-%d" % (i, code), lambda m, c=code: frame(OP_CLOSE, close_body(c), masked=m))
    for i, code in enumerate([0, 999, 1004, 1005, 1006, 1012, 1013, 1014, 1015, 1016, 1100, 2000, 2999], 1):
        o.both("autobahn-7.9.%d:close-code-%d" % (i, code), lambda m, c=code: frame(OP_CLOSE, close_body(c), masked=m))
    for i, code in enumerate([5000, 65535], 1):
        o.both("autobahn-7.13.%d:close-code-%d" % (i, code), lambda m, c=code: frame(OP_CLOSE, close_body(c), masked=m))
    # Family 9: large messages (the sizes up to this oracle's 1 MiB; text and binary)
    for i, n in enumerate([64 * 1024, 256 * 1024, 1024 * 1024], 1):
        o.ws("autobahn-9.1.%d:text-%d" % (i, n), frame(OP_TEXT, lorem(n)))
        o.ws("autobahn-9.2.%d:binary-%d" % (i, n), frame(OP_BIN, rnd(n)))
    for i, (n, chunk) in enumerate([(64 * 1024, 64), (64 * 1024, 256), (64 * 1024, 1024), (64 * 1024, 4096), (64 * 1024, 8192), (64 * 1024, 16384), (64 * 1024, 32768), (64 * 1024, 65536)], 1):
        data = lorem(n)
        o.ws("autobahn-9.3.%d:text-fragmented-in-%d" % (i, chunk), b"".join(frame(OP_TEXT if j == 0 else OP_CONT, data[j * chunk:(j + 1) * chunk], (j + 1) * chunk >= n) for j in range((n + chunk - 1) // chunk)))
        data = rnd(n)
        o.ws("autobahn-9.4.%d:binary-fragmented-in-%d" % (i, chunk), b"".join(frame(OP_BIN if j == 0 else OP_CONT, data[j * chunk:(j + 1) * chunk], (j + 1) * chunk >= n) for j in range((n + chunk - 1) // chunk)))
    for i, n in enumerate([1000, 1000, 1000], 1):
        o.ws("autobahn-9.5.%d:text-chopped-%d" % (i, n), frame(OP_TEXT, lorem(n)))
    o.ws("autobahn-9.7.1:many-small-text-messages", b"".join(frame(OP_TEXT, lorem(i % 50, i)) for i in range(1000)))
    o.ws("autobahn-9.8.1:many-small-binary-messages", b"".join(frame(OP_BIN, rnd(i % 50, i)) for i in range(1000)))
    o.wc("autobahn-9.7.1:many-small-text-messages", b"".join(frame(OP_TEXT, lorem(i % 50, i), masked=False) for i in range(1000)))
    return o.cases


# ------------------------------------------------------------------------------------------
# permessage-deflate (RFC 7692), and Autobahn families 12 and 13
# ------------------------------------------------------------------------------------------

# (snct, cnct, smb, cmb): the parameter sets every deflate case is asked under.
PARAM_SETS = [
    (False, False, 0, 0), (True, True, 0, 0), (True, False, 0, 0), (False, True, 0, 0),
    (False, False, 10, 10), (False, False, 9, 9), (False, False, 8, 8), (False, False, 15, 15),
    (True, True, 9, 9), (False, False, 9, 15), (False, False, 15, 9), (True, True, 11, 12),
]


def pname(p):
    snct, cnct, smb, cmb = p
    n = "".join(["s" if snct else "", "c" if cnct else ""]) or "takeover"
    if smb or cmb:
        n += "-w%d.%d" % (smb, cmb)
    return n


def pspec(p):
    return spec(True, *p)


def pmd_frames(masked, p, messages, fragments=1, ping_between=False, compressed_first=True):
    """Frames for `messages` ((type, bytes)...) compressed as the sender for this
    direction does, each message cut into `fragments` frames."""
    comp = compressor_for(masked, p)
    out = b""
    for typ, data in messages:
        c = comp.message(data)
        cuts = [c[i * len(c) // fragments:(i + 1) * len(c) // fragments] for i in range(fragments)]
        for i, piece in enumerate(cuts):
            op = typ if i == 0 else OP_CONT
            out += frame(op, piece, i == fragments - 1, masked=masked, rsv=R1 if i == 0 else 0)
            if ping_between and i < fragments - 1:
                out += frame(OP_PING, b"p%d" % i, masked=masked)
    return out


def hand_deflate():
    o = Out()
    T = OP_TEXT
    B = OP_BIN
    hello = b"Hello"
    # The RFC 7692 section 7.2.3 examples, from zlib and checked against the RFC's bytes.
    assert Deflater().message(hello) == bytes.fromhex("f248cdc9c90700"), "zlib no longer says what RFC 7692 7.2.3.1 says"
    o.both("rfc7692-7.2.3.1:hello-one-block", lambda m: frame(T, bytes.fromhex("f248cdc9c90700"), masked=m, rsv=R1), spec(True))
    o.both("rfc7692-7.2.3.2:hello-bfinal-set", lambda m: frame(T, bytes.fromhex("f348cdc9c90700"), masked=m, rsv=R1), spec(True))
    o.both("rfc7692-7.2.3.2:hello-bfinal-set-plus-zero", lambda m: frame(T, bytes.fromhex("f348cdc9c9070000"), masked=m, rsv=R1), spec(True))
    o.both("rfc7692-7.2.3.3:hello-two-blocks", lambda m: frame(T, bytes.fromhex("f248050000 00ffffca c9c90700".replace(" ", "")), masked=m, rsv=R1), spec(True))
    o.both("rfc7692-7.2.3.4:hello-stored-block", lambda m: frame(T, bytes.fromhex("000500faff48656c6c6f00"), masked=m, rsv=R1), spec(True))
    o.both("rfc7692-7.2.3.4:hello-stored-block-bfinal", lambda m: frame(T, bytes.fromhex("010500faff48656c6c6f00"), masked=m, rsv=R1), spec(True))

    def two_hello(m):
        c = Deflater()
        return frame(T, c.message(hello), masked=m, rsv=R1) + frame(T, c.message(hello), masked=m, rsv=R1)
    o.both("rfc7692-7.2.3.5:hello-twice-with-lz77-window", two_hello, spec(True))
    o.both("rfc7692-7.2.3.5:hello-twice-with-lz77-window-rfc-bytes", lambda m: frame(T, bytes.fromhex("f248cdc9c90700"), masked=m, rsv=R1) + frame(T, bytes.fromhex("f200110000"), masked=m, rsv=R1), spec(True))
    o.both("rfc7692-7.2.3.5:hello-twice-no-takeover-agreed-but-window-used", lambda m: frame(T, bytes.fromhex("f248cdc9c90700"), masked=m, rsv=R1) + frame(T, bytes.fromhex("f200110000"), masked=m, rsv=R1), spec(True, True, True))
    o.both("rfc7692-7.2.3.6:hello-fragmented", lambda m: frame(T, bytes.fromhex("f248"), False, masked=m, rsv=R1) + frame(OP_CONT, bytes.fromhex("cdc9c90700"), True, masked=m), spec(True))
    o.both("rfc7692-7.2.3.6:hello-fragmented-rsv1-on-continuation", lambda m: frame(T, bytes.fromhex("f248"), False, masked=m, rsv=R1) + frame(OP_CONT, bytes.fromhex("cdc9c90700"), True, masked=m, rsv=R1), spec(True))

    for p in PARAM_SETS:
        pn = pname(p)
        sp = pspec(p)
        wide = p[2] not in (8, 9) and p[3] not in (8, 9)  # a window of 8 or 9 bits only suits short messages
        short = [(T, b"Hello"), (T, b"Hello"), (B, bytes(range(40))), (T, KOSME)]
        o.both("rfc7692-7.2:%s:messages-with-repeats" % pn, lambda m, p=p: pmd_frames(m, p, short), sp)
        o.both("rfc7692-7.2:%s:empty-text" % pn, lambda m, p=p: pmd_frames(m, p, [(T, b"")]), sp)
        o.both("rfc7692-7.2:%s:empty-binary" % pn, lambda m, p=p: pmd_frames(m, p, [(B, b"")]), sp)
        o.both("rfc7692-7.2:%s:three-empty-messages" % pn, lambda m, p=p: pmd_frames(m, p, [(T, b""), (B, b""), (T, b"")]), sp)
        o.both("rfc7692-7.2:%s:fragments-2" % pn, lambda m, p=p: pmd_frames(m, p, [(T, b"Hello Hello Hello"), (B, b"abcabcabcabc")], 2), sp)
        o.both("rfc7692-7.2:%s:fragments-3-with-pings" % pn, lambda m, p=p: pmd_frames(m, p, [(T, b"Hello Hello Hello"), (B, b"abcabcabcabc")], 3, True), sp)
        o.both("rfc7692-7.2:%s:uncompressed-message-between" % pn, lambda m, p=p: pmd_frames(m, p, [(T, b"one")]) + frame(T, b"plain", masked=m), sp)
        if wide:
            msgs = [(T, lorem(500, 1)), (T, lorem(500, 1)), (T, lorem(500, 2)), (B, rnd(1000)), (T, lorem(5000, 3)), (T, lorem(5000, 3))]
            o.both("rfc7692-7.2:%s:lorem-and-random" % pn, lambda m, p=p, msgs=msgs: pmd_frames(m, p, msgs), sp)
            o.both("rfc7692-7.2:%s:lorem-fragmented" % pn, lambda m, p=p, msgs=msgs: pmd_frames(m, p, msgs, 4, True), sp)
            for idx, n in [("1", 0), ("2", 125), ("3", 126), ("4", 127), ("5", 128), ("6", 65535), ("7", 65536)]:
                o.both("autobahn-12.1.%s:%s:text-%d-compressed" % (idx, pn, n), lambda m, p=p, n=n: pmd_frames(m, p, [(T, lorem(n))]), sp)
                o.both("autobahn-12.2.%s:%s:binary-%d-compressed" % (idx, pn, n), lambda m, p=p, n=n: pmd_frames(m, p, [(B, rnd(n))]), sp)
        # window-size-specific: a stream that is valid for a window of exactly this many bits
        if p[3] or p[2]:
            o.both("rfc7692-7.1.2:%s:long-distance-match-in-valid-window" % pn, lambda m, p=p: pmd_frames(m, p, [(B, (lambda x: x + x[:100])(rnd(max(100, (1 << (min(v for v in (p[2], p[3]) if v) or 15)) // 2 - 200))))]), sp)

    # A window the peer was told to keep to, and does not (RFC 7692 7.1.2: the compressor's choice, the decompressor must cope up to its own)
    far = (lambda x: x + x[:200])(rnd(4000))
    for bits in (9, 10, 12):
        o.both("rfc7692-7.1.2:window-%d-agreed-compressed-with-15-distance-4000" % bits, lambda m: frame(OP_BIN, Deflater(15).message(far), masked=m, rsv=R1), spec(True, False, False, bits, bits))
    # Context takeover disagreement: the peer agreed to reset and does not (the second message references the first)
    def takeover_used(m, snct_cnct):
        c = Deflater(15, True)
        return frame(T, c.message(lorem(300, 4)), masked=m, rsv=R1) + frame(T, c.message(lorem(300, 4)), masked=m, rsv=R1)
    o.both("rfc7692-7.1.1:no-context-takeover-agreed-but-takeover-used", lambda m: takeover_used(m, True), spec(True, True, True))
    o.ws("rfc7692-7.1.1:client-no-context-takeover-only-takeover-used", takeover_used(True, True), spec(True, False, True))
    o.wc("rfc7692-7.1.1:server-no-context-takeover-only-takeover-used", takeover_used(False, True), spec(True, True, False))
    # No takeover agreed but each message is compressed alone: fine
    # Compressed message structure
    sp = spec(True)
    o.both("rfc7692-6.1:rsv1-on-control-frame-ping", lambda m: frame(OP_PING, b"x", masked=m, rsv=R1), sp)
    o.both("rfc7692-6.1:rsv1-on-control-frame-pong", lambda m: frame(OP_PONG, b"x", masked=m, rsv=R1), sp)
    o.both("rfc7692-6.1:rsv1-on-control-frame-close", lambda m: frame(OP_CLOSE, close_body(1000), masked=m, rsv=R1), sp)
    o.both("rfc7692-6.1:rsv1-on-continuation", lambda m: frame(T, Deflater().message(b"abc")[:2], False, masked=m, rsv=R1) + frame(OP_CONT, Deflater().message(b"abc")[2:], True, masked=m, rsv=R1), sp)
    o.both("rfc7692-6.1:rsv1-on-continuation-of-uncompressed-message", lambda m: frame(T, b"abc", False, masked=m) + frame(OP_CONT, b"def", True, masked=m, rsv=R1), sp)
    o.both("rfc7692-6.1:rsv2-with-deflate", lambda m: frame(T, Deflater().message(b"abc"), masked=m, rsv=R1 | R2), sp)
    o.both("rfc7692-6.1:rsv3-with-deflate", lambda m: frame(T, Deflater().message(b"abc"), masked=m, rsv=R1 | R3), sp)
    o.both("rfc7692-6.1:rsv2-alone-with-deflate", lambda m: frame(T, b"abc", masked=m, rsv=R2), sp)
    o.both("rfc7692-6.1:rsv1-on-empty-first-fragment", lambda m: frame(T, b"", False, masked=m, rsv=R1) + frame(OP_CONT, Deflater().message(b"abc"), True, masked=m), sp)
    o.both("rfc7692-6.1:uncompressed-text-in-deflate-connection", lambda m: frame(T, b"plain", masked=m), sp)
    o.both("rfc7692-6.1:uncompressed-fragments-in-deflate-connection", lambda m: frame(T, b"pl", False, masked=m) + frame(OP_CONT, b"ain", True, masked=m), sp)
    o.both("rfc7692-6.1:compressed-between-uncompressed", lambda m: frame(T, b"plain", masked=m) + frame(T, Deflater().message(b"packed"), masked=m, rsv=R1) + frame(B, b"plain", masked=m), sp)
    # Invalid and unusual deflate payloads
    bad = [
        ("random-bytes", rnd(50, 3)), ("zero-bytes", b"\x00" * 20), ("single-zero", b"\x00"), ("one-byte-ff", b"\xff"),
        ("reserved-block-type-3", b"\x07\x00"), ("stored-block-bad-nlen", bytes.fromhex("000500fbff48656c6c6f")),
        ("stored-block-truncated", bytes.fromhex("000500faff4865")), ("fixed-block-truncated", bytes.fromhex("f248cdc9")),
        ("trailing-garbage-after-bfinal", bytes.fromhex("f348cdc9c90700") + b"garbage"),
        ("distance-too-far-back", bytes.fromhex("e34043")), ("dynamic-block-bad-header", bytes.fromhex("0d0000")),
        ("empty-payload", b""),
        ("only-sync-marker", b"\x00\x00\xff\xff"), ("sync-marker-twice", b"\x00\x00\xff\xff\x00\x00\xff\xff"),
        ("stored-block-then-garbage", bytes.fromhex("000300fcff616263") + b"\xff\xff"),
    ]
    for nm, payload in bad:
        o.both("rfc7692-7.2.2:invalid-deflate-%s" % nm, lambda m, pl=payload: frame(T, pl, masked=m, rsv=R1), sp)
        o.both("rfc7692-7.2.2:invalid-deflate-%s-binary" % nm, lambda m, pl=payload: frame(B, pl, masked=m, rsv=R1), sp)
        o.both("rfc7692-7.2.2:invalid-deflate-%s-then-valid" % nm, lambda m, pl=payload: frame(T, pl, masked=m, rsv=R1) + frame(T, Deflater().message(b"ok"), masked=m, rsv=R1), sp)
    # A BFINAL block (RFC 7692 7.2.3.4 allows them) with more messages after it, context takeover on
    def bfinal_then(m):
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        a = c.compress(b"one one one") + c.flush(zlib.Z_FINISH)  # ends with a BFINAL block
        return frame(T, a, masked=m, rsv=R1) + frame(T, Deflater().message(b"two"), masked=m, rsv=R1)
    o.both("rfc7692-7.2.3.4:bfinal-block-then-another-message", bfinal_then, sp)
    o.both("rfc7692-7.2.3.4:bfinal-block-then-padding-octet", lambda m: frame(T, (lambda c: c.compress(b"one one one") + c.flush(zlib.Z_FINISH) + b"\x00")(zlib.compressobj(6, zlib.DEFLATED, -15)), masked=m, rsv=R1), sp)
    o.both("rfc7692-7.2.3.4:bfinal-block-alone", lambda m: frame(T, (lambda c: c.compress(b"one one one") + c.flush(zlib.Z_FINISH))(zlib.compressobj(6, zlib.DEFLATED, -15)), masked=m, rsv=R1), sp)
    o.both("rfc7692-7.2.2:valid-after-reset-by-error", lambda m: frame(T, Deflater().message(b"ok"), masked=m, rsv=R1), sp)
    # Decompressed text must be UTF-8
    o.both("rfc7692-8.1:compressed-text-invalid-utf8", lambda m: frame(T, Deflater().message(b"ab\xff"), masked=m, rsv=R1), sp)
    o.both("rfc7692-8.1:compressed-text-invalid-utf8-late", lambda m: frame(T, Deflater().message(b"a" * 5000 + b"\xed\xa0\x80"), masked=m, rsv=R1), sp)
    o.both("rfc7692-8.1:compressed-text-truncated-utf8", lambda m: frame(T, Deflater().message(b"ab\xe2\x82"), masked=m, rsv=R1), sp)
    o.both("rfc7692-8.1:compressed-text-utf8-split-across-fragments", lambda m: pmd_frames(m, (False, False, 0, 0), [(T, ("é€😀" * 20).encode())], 7), sp)
    o.both("rfc7692-8.1:compressed-binary-need-not-be-utf8", lambda m: frame(B, Deflater().message(b"\xff\xfe"), masked=m, rsv=R1), sp)
    o.both("rfc7692-8.1:compressed-close-reason-not-compressed", lambda m: pmd_frames(m, (False, False, 0, 0), [(T, b"x")]) + frame(OP_CLOSE, close_body(1000, b"bye"), masked=m), sp)
    # Compression-specific size limits: bombs
    zeros = lambda n: b"\x00" * n
    for n in (MAXMSG - 1, MAXMSG, MAXMSG + 1, 2 * MAXMSG, 16 * MAXMSG):
        o.ws("rfc7692-bomb:zeros-%d-text" % n, frame(T, Deflater().message(zeros(n)), rsv=R1), sp)
        o.ws("rfc7692-bomb:zeros-%d-binary" % n, frame(B, Deflater().message(zeros(n)), rsv=R1), sp)
    o.wc("rfc7692-bomb:zeros-%d-binary" % (MAXMSG + 1), frame(B, Deflater().message(zeros(MAXMSG + 1)), masked=False, rsv=R1), sp)
    o.ws("rfc7692-bomb:zeros-%d-fragmented" % (2 * MAXMSG), (lambda c: frame(B, c[:len(c) // 2], False, rsv=R1) + frame(OP_CONT, c[len(c) // 2:], True))(Deflater().message(zeros(2 * MAXMSG))), sp)
    o.ws("rfc7692-bomb:repeated-pattern-%d" % (2 * MAXMSG), frame(B, Deflater().message(b"abcdefgh" * (MAXMSG // 4)), rsv=R1), sp)
    o.ws("rfc7692-bomb:many-messages-each-under-the-cap", b"".join(frame(B, Deflater().message(zeros(MAXMSG // 2)), rsv=R1) for _ in range(8)), sp)
    o.ws("rfc7692-bomb:incompressible-1MiB", frame(B, Deflater().message(rnd(MAXMSG)), rsv=R1), sp)
    o.ws("rfc7692-bomb:incompressible-1MiB-plus-1", frame(B, Deflater().message(rnd(MAXMSG + 1)), rsv=R1), sp)
    o.ws("rfc7692-bomb:lorem-1MiB", frame(T, Deflater().message(lorem(MAXMSG)), rsv=R1), sp)
    # A compressed message and its context across many messages
    big = [(T, lorem(2000, i % 3)) for i in range(60)]
    for p in [(False, False, 0, 0), (True, True, 0, 0), (False, False, 10, 10)]:
        o.both("rfc7692-7.2:%s:sixty-messages" % pname(p), lambda m, p=p: pmd_frames(m, p, big), pspec(p))
    # Autobahn 13: parameter permutations, each with the Autobahn message sizes (shortened to what covers the code)
    for pi, p in enumerate(PARAM_SETS, 1):
        for si, n in enumerate([0, 100, 5000], 1):
            o.both("autobahn-13.%d.%d:%s:text-%d" % (pi, si, pname(p), n), lambda m, p=p, n=n: pmd_frames(m, p, [(T, lorem(n if all(v not in (8, 9) for v in p[2:]) else min(n, 150)))]), pspec(p))
    return o.cases


# ------------------------------------------------------------------------------------------
# The byte literals in this library's own unit tests
# ------------------------------------------------------------------------------------------

_C_ESC = {"n": 10, "r": 13, "t": 9, "a": 7, "b": 8, "f": 12, "v": 11, "\\": 92, "'": 39, '"': 34, "?": 63}


def c_literal(body):
    """The bytes of the inside of a C string literal (hex, octal and simple escapes)."""
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        i += 1
        e = body[i]
        if e == "x":
            j = i + 1
            while j < len(body) and body[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(int(body[i + 1:j], 16) & 255)
            i = j
        elif e in "01234567":
            j = i
            while j < len(body) and j < i + 3 and body[j] in "01234567":
                j += 1
            out.append(int(body[i:j], 8) & 255)
            i = j
        else:
            out.append(_C_ESC[e])
            i += 1
    return bytes(out)


_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def unit_literals():
    """Every string literal that holds a `\\x` escape in tests/unit/test_ws_*.cpp:
    (file, line, bytes), each distinct byte string once."""
    seen = set()
    out = []
    tdir = os.path.join(LIB, "tests", "unit")
    for name in sorted(os.listdir(tdir)):
        if not (name.startswith("test_ws_") and name.endswith(".cpp")):
            continue
        with open(os.path.join(tdir, name), encoding="utf-8") as handle:
            for no, line in enumerate(handle, 1):
                if "\\x" not in line or line.lstrip().startswith("//"):
                    continue
                # Adjacent literals concatenate: "\xce\xba" "abc"
                for m in _LITERAL.finditer(line):
                    if "\\x" not in m.group(1):
                        continue
                    b = c_literal(m.group(1))
                    if b in seen:
                        continue
                    seen.add(b)
                    out.append((name[len("test_ws_"):-len(".cpp")], no, b))
    return out


def unit_cases():
    o = Out()
    for name, no, b in unit_literals():
        tag = "unit:%s:L%d:%s" % (name, no, b[:12].hex())
        # as a whole stream (a frame or a pile of octets), in both roles
        o.ws(tag + ":stream", b)
        o.wc(tag + ":stream", b)
        # as the payload of a text frame, a binary frame and a Close body
        if len(b) < 1000:
            o.ws(tag + ":as-text", frame(OP_TEXT, b))
            o.ws(tag + ":as-binary", frame(OP_BIN, b))
            if len(b) <= 125:
                o.ws(tag + ":as-close-body", frame(OP_CLOSE, b))
                o.ws(tag + ":as-ping", frame(OP_PING, b))
    return o.cases


# ------------------------------------------------------------------------------------------
# The opening handshake: servers (hs) and clients (hc)
# ------------------------------------------------------------------------------------------

RFC_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
CRLF = b"\r\n"


def request(method="GET", target="/chat", version="HTTP/1.1", host="server.example.com",
            upgrade="websocket", connection="Upgrade", key=RFC_KEY, ver="13", extra=(),
            drop=(), crlf=CRLF):
    """The RFC 6455 section 1.3 request, with fields changed, dropped or added.
    `extra` is a list of (name, value) added at the end; a field named in `drop`
    is left out."""
    fields = [("Host", host), ("Upgrade", upgrade), ("Connection", connection),
              ("Sec-WebSocket-Key", key), ("Sec-WebSocket-Version", ver)]
    lines = ["%s %s %s" % (method, target, version)]
    for n, v in fields + list(extra):
        if n.lower() in drop or v is None:
            continue
        lines.append("%s: %s" % (n, v))
    return crlf.join(l.encode("latin1") for l in lines) + crlf + crlf


def response(status="101 Switching Protocols", accept=RFC_ACCEPT, upgrade="websocket",
             connection="Upgrade", extra=(), drop=(), version="HTTP/1.1"):
    fields = [("Upgrade", upgrade), ("Connection", connection), ("Sec-WebSocket-Accept", accept)]
    lines = ["%s %s" % (version, status)]
    for n, v in fields + list(extra):
        if n.lower() in drop or v is None:
            continue
        lines.append("%s: %s" % (n, v))
    return CRLF.join(l.encode("latin1") for l in lines) + CRLF + CRLF


def hand_hs():
    o = Out()

    def add(tag, data, arg="-"):
        o.add("rfc6455-4.2.1:" + tag if ":" not in tag else tag, "hs", arg, data)

    # the plain request, and every field it needs
    add("rfc-example", request())
    add("rfc-example-with-origin", request(extra=[("Origin", "http://example.com")]))
    add("rfc-example-with-protocol-chat-superchat", request(extra=[("Sec-WebSocket-Protocol", "chat, superchat")]), "p=superchat,chat")
    # method
    for m in ("POST", "HEAD", "PUT", "DELETE", "OPTIONS", "get", "GeT", "CONNECT", "PATCH"):
        add("method-%s" % m, request(method=m))
    # version
    add("http-1.0", request(version="HTTP/1.0"))
    add("http-2.0", request(version="HTTP/2.0"))
    add("http-0.9-shape", b"GET /chat\r\n\r\n")
    add("http-1.2", request(version="HTTP/1.2"))
    # target
    for nm, t in (("star", "*"), ("absolute-uri", "ws://server.example.com/chat"), ("http-absolute-uri", "http://server.example.com/chat"),
                  ("query", "/chat?room=1"), ("fragment", "/chat#x"), ("root", "/"), ("empty-ish", "/ "), ("percent", "/%00"), ("long", "/" + "a" * 3000)):
        add("target-%s" % nm, request(target=t))
    # Host
    add("host-missing", request(drop=("host",)))
    add("host-empty", request(host=""))
    add("host-twice", request(extra=[("Host", "other.example.com")]))
    add("host-with-port", request(host="server.example.com:8080"))
    # Upgrade
    add("upgrade-missing", request(drop=("upgrade",)))
    for nm, v in (("WebSocket", "WebSocket"), ("WEBSOCKET", "WEBSOCKET"), ("websocket-list", "websocket, foo"), ("list-first-other", "foo, websocket"),
                  ("h2c", "h2c"), ("websocket2", "websocket2"), ("websockets", "websockets"), ("empty", ""), ("space-padded", "  websocket  "), ("version-suffix", "websocket/13")):
        add("upgrade-%s" % nm, request(upgrade=v))
    add("upgrade-twice", request(extra=[("Upgrade", "websocket")]))
    add("upgrade-twice-different", request(extra=[("Upgrade", "foo")]))
    # Connection
    add("connection-missing", request(drop=("connection",)))
    for nm, v in (("lower", "upgrade"), ("UPGRADE", "UPGRADE"), ("keep-alive-upgrade", "keep-alive, Upgrade"), ("upgrade-keep-alive", "Upgrade, keep-alive"),
                  ("keep-alive", "keep-alive"), ("close", "close"), ("upgradee", "Upgradee"), ("empty", ""), ("spaces", "  Upgrade  "), ("semicolon", "Upgrade;x"), ("quoted", '"Upgrade"')):
        add("connection-%s" % nm, request(connection=v))
    add("connection-twice-upgrade-second", request(connection="keep-alive", extra=[("Connection", "Upgrade")]))
    add("connection-twice-upgrade-first", request(extra=[("Connection", "keep-alive")]))
    # Sec-WebSocket-Key
    add("key-missing", request(drop=("sec-websocket-key",)))
    add("key-empty", request(key=""))
    for nm, v in (("23-chars", RFC_KEY[:-1]), ("25-chars", RFC_KEY + "A"), ("22-chars-no-padding", "dGhlIHNhbXBsZSBub25jZQ"), ("15-octets", "AAAAAAAAAAAAAAAAAAAA"),
                  ("17-octets", "AAAAAAAAAAAAAAAAAAAAAAAA"), ("32-chars", "A" * 32), ("padding-bits-set", "AAAAAAAAAAAAAAAAAAAAAB=="), ("non-base64", "!!!!!!!!!!!!!!!!!!!!!!=="),
                  ("url-safe-alphabet", "AAAAAAAAAAAAAAAAAAAA-_=="), ("space-inside", "dGhlIHNhbXBs ZSBub25jZQ=="), ("lowercase-version", RFC_KEY.lower()), ("zero-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
                  ("padding-mid", "AAAAAAAAAAAA=AAAAAAAAA=="), ("1-padding-char", "AAAAAAAAAAAAAAAAAAAAAAA=")):
        add("key-%s" % nm, request(key=v))
    add("key-twice", request(extra=[("Sec-WebSocket-Key", RFC_KEY)]))
    add("key-twice-different", request(extra=[("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")]))
    add("key-ows-around", b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key:   " + RFC_KEY.encode() + b"   \r\nSec-WebSocket-Version: 13\r\n\r\n")
    # Sec-WebSocket-Version
    add("version-missing", request(drop=("sec-websocket-version",)))
    for nm, v in (("12", "12"), ("8", "8"), ("14", "14"), ("0", "0"), ("empty", ""), ("013", "013"), ("13-list-8", "13, 8"), ("8-list-13", "8, 13"), ("13.0", "13.0"), ("x", "x"), ("space-padded", "  13  "), ("13-with-space-inside", "1 3")):
        add("version-%s" % nm, request(ver=v))
    add("version-twice-same", request(extra=[("Sec-WebSocket-Version", "13")]))
    add("version-twice-different", request(extra=[("Sec-WebSocket-Version", "8")]))
    # Origin: no policy anywhere here
    for nm, v in (("null", "null"), ("other", "http://evil.example"), ("empty", ""), ("garbage", "not an origin")):
        add("origin-%s" % nm, request(extra=[("Origin", v)]))
    # Subprotocols (section 1.9 and 4.2.2): the server's order decides in this library
    P = lambda *vals: [("Sec-WebSocket-Protocol", v) for v in vals]
    add("protocol-none-offered-none-served", request())
    add("protocol-none-offered-chat-served", request(), "p=chat")
    add("protocol-offered-none-served", request(extra=P("chat")))
    add("protocol-match", request(extra=P("chat")), "p=chat")
    add("protocol-no-match", request(extra=P("chat")), "p=mqtt")
    add("protocol-server-order-decides", request(extra=P("chat, superchat")), "p=superchat,chat")
    add("protocol-client-order-differs", request(extra=P("superchat, chat")), "p=chat,superchat")
    add("protocol-one-of-several-served", request(extra=P("a, b, c")), "p=c,b")
    add("protocol-two-fields", request(extra=P("a", "b")), "p=b")
    add("protocol-two-fields-first-served", request(extra=P("a", "b")), "p=a")
    add("protocol-case-differs", request(extra=P("Chat")), "p=chat")
    add("protocol-empty-value", request(extra=P("")), "p=chat")
    add("protocol-empty-element", request(extra=P("chat,,superchat")), "p=superchat")
    add("protocol-trailing-comma", request(extra=P("chat,")), "p=chat")
    add("protocol-leading-comma", request(extra=P(",chat")), "p=chat")
    add("protocol-space-in-token", request(extra=P("cha t")), "p=chat")
    add("protocol-non-token-char", request(extra=P("chat/1")), "p=chat/1")
    add("protocol-quoted", request(extra=P('"chat"')), "p=chat")
    add("protocol-trailing-ows", b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY.encode() + b"\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat \t\r\n\r\n", "p=chat")
    add("protocol-name-127", request(extra=P("x" * 127)), "p=" + "x" * 127)
    add("protocol-offered-name-200-not-served", request(extra=P("x" * 200)), "p=chat")
    add("protocol-many-offered", request(extra=P(",".join("p%d" % i for i in range(60)))), "p=p59")
    # Extensions (section 9.1 and RFC 7692 section 7)
    E = lambda *vals: [("Sec-WebSocket-Extensions", v) for v in vals]
    pd = "permessage-deflate"
    add("extensions-none-offered-deflate-enabled", request(), "d")
    add("extensions-deflate-offered-deflate-disabled", request(extra=E(pd)), "-")
    add("extensions-deflate-offered-deflate-enabled", request(extra=E(pd)), "d")
    for nm, v in (
        ("snct", pd + "; server_no_context_takeover"), ("cnct", pd + "; client_no_context_takeover"),
        ("both-nct", pd + "; server_no_context_takeover; client_no_context_takeover"),
        ("smb-10", pd + "; server_max_window_bits=10"), ("cmb-10", pd + "; client_max_window_bits=10"),
        ("cmb-valueless", pd + "; client_max_window_bits"), ("smb-valueless", pd + "; server_max_window_bits"),
        ("smb-8", pd + "; server_max_window_bits=8"), ("smb-15", pd + "; server_max_window_bits=15"),
        ("smb-7", pd + "; server_max_window_bits=7"), ("smb-16", pd + "; server_max_window_bits=16"),
        ("cmb-8", pd + "; client_max_window_bits=8"), ("cmb-7", pd + "; client_max_window_bits=7"), ("cmb-16", pd + "; client_max_window_bits=16"),
        ("smb-0", pd + "; server_max_window_bits=0"), ("smb-neg", pd + "; server_max_window_bits=-9"), ("smb-abc", pd + "; server_max_window_bits=abc"),
        ("smb-empty", pd + "; server_max_window_bits="), ("smb-leading-zero", pd + "; server_max_window_bits=09"), ("smb-plus", pd + "; server_max_window_bits=+9"),
        ("smb-decimal", pd + "; server_max_window_bits=9.5"), ("smb-quoted", pd + '; server_max_window_bits="10"'), ("smb-quoted-bad", pd + '; server_max_window_bits="abc"'),
        ("snct-with-value", pd + "; server_no_context_takeover=1"), ("cnct-with-value", pd + "; client_no_context_takeover=1"),
        ("snct-twice", pd + "; server_no_context_takeover; server_no_context_takeover"), ("cnct-twice", pd + "; client_no_context_takeover; client_no_context_takeover"),
        ("smb-twice", pd + "; server_max_window_bits=9; server_max_window_bits=10"), ("cmb-twice", pd + "; client_max_window_bits=9; client_max_window_bits=10"),
        ("unknown-param", pd + "; foo=bar"), ("unknown-param-valueless", pd + "; foo"), ("unknown-param-after-valid", pd + "; server_no_context_takeover; foo"),
        ("param-case", pd + "; Server_No_Context_Takeover"), ("name-case", "Permessage-Deflate"), ("name-upper", "PERMESSAGE-DEFLATE"),
        ("spaces-around-semicolon", pd + " ;server_no_context_takeover"), ("no-space-after-semicolon", pd + ";server_no_context_takeover"),
        ("trailing-semicolon", pd + ";"), ("double-semicolon", pd + ";;server_no_context_takeover"), ("param-empty-name", pd + "; =1"),
        ("unknown-extension", "x-foo"), ("unknown-extension-with-params", "x-foo; level=2"), ("deflate-frame-legacy", "x-webkit-deflate-frame"),
        ("empty", ""), ("only-comma", ","), ("deflate-then-comma", pd + ","), ("comma-then-deflate", "," + pd),
        ("name-with-space", "permessage deflate"), ("name-token-bad", "permessage/deflate"),
        ("two-offers-same", pd + ", " + pd), ("two-offers-first-bad", pd + "; foo, " + pd), ("two-offers-second-bad", pd + ", " + pd + "; foo"),
        ("two-offers-first-smb-bad", pd + "; server_max_window_bits=7, " + pd + "; server_max_window_bits=9"),
        ("two-offers-different-params", pd + "; server_no_context_takeover, " + pd + "; client_no_context_takeover"),
        ("unknown-then-deflate", "x-foo, " + pd), ("deflate-then-unknown", pd + ", x-foo"), ("unknown-with-comma-param", "x-foo; a=\"b,c\", " + pd),
        ("many-offers-9", ", ".join([pd] * 9)), ("many-params-9", pd + "; " + "; ".join("p%d" % i for i in range(9))),
        ("quoted-string-param-with-semicolon", pd + '; foo="a;b"'),
        ("all-params", pd + "; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=11"),
        ("all-params-cmb-valueless", pd + "; client_max_window_bits; server_no_context_takeover; server_max_window_bits=11"),
        ("tab-separated", pd + ";\tserver_no_context_takeover"),
    ):
        add("extensions-offer-%s" % nm, request(extra=E(v)), "d")
    add("extensions-offer-split-over-two-fields", request(extra=E(pd, "x-foo")), "d")
    add("extensions-offer-two-fields-both-deflate", request(extra=E(pd + "; server_no_context_takeover", pd)), "d")
    add("extensions-offer-continued-with-comma-across-fields", request(extra=E(pd + ",", "x-foo")), "d")
    # Server policy against offers
    for nm, pol, v in (
        ("policy-snct-offer-plain", "d;snct", pd), ("policy-cnct-offer-plain", "d;cnct", pd), ("policy-both-nct-offer-plain", "d;snct;cnct", pd),
        ("policy-smb-10-offer-plain", "d;smb=10", pd), ("policy-smb-10-offer-smb-12", "d;smb=10", pd + "; server_max_window_bits=12"),
        ("policy-smb-10-offer-smb-9", "d;smb=10", pd + "; server_max_window_bits=9"), ("policy-smb-10-offer-smb-10", "d;smb=10", pd + "; server_max_window_bits=10"),
        ("policy-cmb-10-offer-plain", "d;cmb=10", pd), ("policy-cmb-10-offer-cmb-valueless", "d;cmb=10", pd + "; client_max_window_bits"),
        ("policy-cmb-10-offer-cmb-12", "d;cmb=10", pd + "; client_max_window_bits=12"), ("policy-cmb-10-offer-cmb-9", "d;cmb=10", pd + "; client_max_window_bits=9"),
        ("policy-cmb-15-offer-cmb-valueless", "d;cmb=15", pd + "; client_max_window_bits"), ("policy-smb-15-offer-plain", "d;smb=15", pd),
        ("policy-snct-offer-snct", "d;snct", pd + "; server_no_context_takeover"), ("policy-cnct-offer-cnct", "d;cnct", pd + "; client_no_context_takeover"),
        ("policy-cnct-offer-cmb-valueless", "d;cnct", pd + "; client_max_window_bits"),
        ("policy-everything-offer-everything", "d;snct;cnct;smb=9;cmb=9", pd + "; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=9; client_max_window_bits=9"),
        ("policy-everything-offer-plain", "d;snct;cnct;smb=9;cmb=9", pd),
        ("policy-smb-8-offer-plain", "d;smb=8", pd), ("policy-cmb-8-offer-cmb-valueless", "d;cmb=8", pd + "; client_max_window_bits"),
        ("policy-snct-two-offers-first-bad", "d;snct", pd + "; foo, " + pd),
        ("policy-snct-offer-unknown-ext-then-deflate", "d;snct", "x-foo, " + pd),
    ):
        add("extensions-%s" % nm, request(extra=E(v)), pol)
    # Everything together
    add("full-chat-deflate", request(extra=P("chat, superchat") + E(pd + "; client_max_window_bits")), "p=superchat,chat;d;snct")
    # Header-line shape
    add("obs-fold-in-key", b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY[:10].encode() + b"\r\n " + RFC_KEY[10:].encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    add("bare-lf-line-ends", request(crlf=b"\n"))
    add("space-before-colon", b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade : websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY.encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    add("tab-after-colon", b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade:\twebsocket\r\nConnection:\tUpgrade\r\nSec-WebSocket-Key:\t" + RFC_KEY.encode() + b"\r\nSec-WebSocket-Version:\t13\r\n\r\n")
    add("no-space-after-colon", b"GET /chat HTTP/1.1\r\nHost:h\r\nUpgrade:websocket\r\nConnection:Upgrade\r\nSec-WebSocket-Key:" + RFC_KEY.encode() + b"\r\nSec-WebSocket-Version:13\r\n\r\n")
    add("field-names-lowercase", b"GET /chat HTTP/1.1\r\nhost: h\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: " + RFC_KEY.encode() + b"\r\nsec-websocket-version: 13\r\n\r\n")
    add("field-names-uppercase", b"GET /chat HTTP/1.1\r\nHOST: h\r\nUPGRADE: websocket\r\nCONNECTION: Upgrade\r\nSEC-WEBSOCKET-KEY: " + RFC_KEY.encode() + b"\r\nSEC-WEBSOCKET-VERSION: 13\r\n\r\n")
    add("nul-in-value", request(extra=[("X-Test", "a\x00b")]))
    add("high-byte-in-value", request(extra=[("X-Test", "caf\xe9")]))
    add("body-with-content-length", request(extra=[("Content-Length", "5")]) + b"hello")
    add("chunked-body", request(extra=[("Transfer-Encoding", "chunked")]) + b"0\r\n\r\n")
    add("content-length-and-te", request(extra=[("Content-Length", "5"), ("Transfer-Encoding", "chunked")]) + b"hello")
    add("not-http", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 40 + b"\r\n\r\n")
    add("empty-input", b"")
    add("blank-lines-first", CRLF + CRLF + request())
    add("truncated-before-final-crlf", request()[:-2])
    add("truncated-in-the-middle", request()[:60])
    add("lowercase-method-in-request-line", request(method="get"))
    add("extra-space-in-request-line", b"GET  /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY.encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    add("tab-in-request-line", b"GET\t/chat\tHTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY.encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    # Size: the library caps the head at 8192 octets of field names and values
    add("head-8000-of-extra-field", request(extra=[("X-Pad", "a" * 7500)]))
    add("head-8300-of-extra-field", request(extra=[("X-Pad", "a" * 8300)]))
    add("head-70000-of-extra-field", request(extra=[("X-Pad", "a" * 70000)]))
    add("head-300-fields", request(extra=[("X-%d" % i, "v") for i in range(300)]))
    add("head-1100-fields", request(extra=[("X-%d" % i, "v") for i in range(1100)]))
    add("extension-offer-very-long", request(extra=E(pd + "; " + "; ".join("p%d=%d" % (i, i) for i in range(500)))), "d")
    return o.cases


def hand_hc():
    o = Out()
    pd = "permessage-deflate"

    def add(tag, data, arg="-"):
        o.add("rfc6455-4.2.2:" + tag if ":" not in tag else tag, "hc", arg, data)

    E = lambda *vals: [("Sec-WebSocket-Extensions", v) for v in vals]
    P = lambda *vals: [("Sec-WebSocket-Protocol", v) for v in vals]
    add("rfc-example", response())
    # status
    for st in ("200 OK", "301 Moved Permanently", "400 Bad Request", "401 Unauthorized", "403 Forbidden", "404 Not Found", "426 Upgrade Required", "500 Internal Server Error", "100 Continue", "102 Processing", "200", "101", "101 ", "1010 Bad", "10 x", "1xx x", "0 x", "-101 x"):
        add("status-%s" % st.replace(" ", "-"), response(status=st))
    add("http-1.0-101", response(version="HTTP/1.0"))
    add("http-2.0-101", response(version="HTTP/2.0"))
    add("http-1.2-101", response(version="HTTP/1.2"))
    # Upgrade, Connection
    add("upgrade-missing", response(drop=("upgrade",)))
    for nm, v in (("WebSocket", "WebSocket"), ("WEBSOCKET", "WEBSOCKET"), ("list", "websocket, foo"), ("foo", "foo"), ("empty", ""), ("websocket2", "websocket2"), ("padded", "  websocket  ")):
        add("upgrade-%s" % nm, response(upgrade=v))
    add("upgrade-twice", response(extra=[("Upgrade", "websocket")]))
    add("connection-missing", response(drop=("connection",)))
    for nm, v in (("lower", "upgrade"), ("UPGRADE", "UPGRADE"), ("keep-alive-upgrade", "keep-alive, Upgrade"), ("close", "close"), ("keep-alive", "keep-alive"), ("empty", ""), ("upgradee", "Upgradee")):
        add("connection-%s" % nm, response(connection=v))
    add("connection-twice", response(connection="keep-alive", extra=[("Connection", "Upgrade")]))
    # accept
    add("accept-missing", response(drop=("sec-websocket-accept",)))
    for nm, v in (("wrong", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="), ("empty", ""), ("truncated", RFC_ACCEPT[:-1]), ("extra-char", RFC_ACCEPT + "A"), ("lowercase", RFC_ACCEPT.lower()), ("padded", "  " + RFC_ACCEPT + "  "), ("quoted", '"' + RFC_ACCEPT + '"'), ("key-itself", RFC_KEY), ("no-padding", RFC_ACCEPT[:-1].rstrip("="))):
        add("accept-%s" % nm, response(accept=v))
    add("accept-twice-same", response(extra=[("Sec-WebSocket-Accept", RFC_ACCEPT)]))
    add("accept-twice-different", response(extra=[("Sec-WebSocket-Accept", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")]))
    add("accept-twice-wrong-first", response(accept="AAAAAAAAAAAAAAAAAAAAAAAAAAA=", extra=[("Sec-WebSocket-Accept", RFC_ACCEPT)]))
    # subprotocol
    add("protocol-none-offered-none-chosen", response())
    add("protocol-offered-none-chosen", response(), "p=chat")
    add("protocol-offered-chosen", response(extra=P("chat")), "p=chat")
    add("protocol-offered-two-chosen-second", response(extra=P("superchat")), "p=chat,superchat")
    add("protocol-not-offered-chosen", response(extra=P("mqtt")), "p=chat")
    add("protocol-none-offered-chosen", response(extra=P("chat")), "-")
    add("protocol-case-differs", response(extra=P("Chat")), "p=chat")
    add("protocol-two-chosen-in-one-field", response(extra=P("chat, superchat")), "p=chat,superchat")
    add("protocol-two-fields", response(extra=P("chat", "chat")), "p=chat")
    add("protocol-two-fields-different", response(extra=P("chat", "superchat")), "p=chat,superchat")
    add("protocol-empty", response(extra=P("")), "p=chat")
    add("protocol-trailing-comma", response(extra=P("chat,")), "p=chat")
    add("protocol-padded", response(extra=P("  chat  ")), "p=chat")
    add("protocol-quoted", response(extra=P('"chat"')), "p=chat")
    # extensions: each offer, and what a server may answer
    offers = [("-", "-"), ("plain", "d"), ("cnct", "d;cnct"), ("snct", "d;snct"), ("smb-10", "d;smb=10"), ("cmb-12", "d;cmb=12"), ("cmb-valueless", "d;ocmb"),
              ("everything", "d;snct;cnct;smb=9;cmb=9"), ("smb-8", "d;smb=8"), ("cmb-8", "d;cmb=8")]
    answers = [
        ("none", None), ("plain", pd), ("snct", pd + "; server_no_context_takeover"), ("cnct", pd + "; client_no_context_takeover"),
        ("both-nct", pd + "; server_no_context_takeover; client_no_context_takeover"),
        ("smb-9", pd + "; server_max_window_bits=9"), ("smb-10", pd + "; server_max_window_bits=10"), ("smb-11", pd + "; server_max_window_bits=11"), ("smb-15", pd + "; server_max_window_bits=15"),
        ("cmb-9", pd + "; client_max_window_bits=9"), ("cmb-10", pd + "; client_max_window_bits=10"), ("cmb-12", pd + "; client_max_window_bits=12"), ("cmb-13", pd + "; client_max_window_bits=13"), ("cmb-15", pd + "; client_max_window_bits=15"),
        ("cmb-valueless", pd + "; client_max_window_bits"), ("smb-valueless", pd + "; server_max_window_bits"),
        ("smb-7", pd + "; server_max_window_bits=7"), ("smb-8", pd + "; server_max_window_bits=8"), ("smb-16", pd + "; server_max_window_bits=16"), ("cmb-7", pd + "; client_max_window_bits=7"), ("cmb-8", pd + "; client_max_window_bits=8"), ("cmb-16", pd + "; client_max_window_bits=16"),
        ("smb-abc", pd + "; server_max_window_bits=abc"), ("smb-quoted", pd + '; server_max_window_bits="10"'), ("smb-leading-zero", pd + "; server_max_window_bits=010"),
        ("snct-with-value", pd + "; server_no_context_takeover=1"), ("unknown-param", pd + "; foo=1"), ("param-twice", pd + "; server_no_context_takeover; server_no_context_takeover"),
        ("smb-twice", pd + "; server_max_window_bits=9; server_max_window_bits=10"),
        ("name-case", "Permessage-Deflate"), ("unknown-extension", "x-foo"), ("unknown-then-deflate", "x-foo, " + pd), ("deflate-then-unknown", pd + ", x-foo"),
        ("deflate-twice", pd + ", " + pd), ("empty", ""), ("legacy", "x-webkit-deflate-frame"),
        ("all", pd + "; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=9; client_max_window_bits=9"),
    ]
    for oi, (on, oarg) in enumerate(offers):
        for an, av in answers:
            if oarg == "-" and an not in ("none", "plain", "snct", "cnct", "cmb-10", "smb-10", "unknown-extension", "deflate-twice", "all", "empty"):
                continue
            ex = E(av) if av is not None else []
            add("rfc7692-7.1:offer-%s:answer-%s" % (on, an), response(extra=ex), oarg)
    add("rfc7692-7.1:answer-in-two-fields", response(extra=E(pd, "x-foo")), "d")
    add("rfc7692-7.1:answer-two-fields-both-deflate", response(extra=E(pd, pd)), "d")
    # shape
    add("lf-line-ends", response().replace(b"\r\n", b"\n"))
    add("obs-fold-in-accept", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + RFC_ACCEPT[:10].encode() + b"\r\n " + RFC_ACCEPT[10:].encode() + b"\r\n\r\n")
    add("space-before-colon", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade : websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + RFC_ACCEPT.encode() + b"\r\n\r\n")
    add("no-reason-phrase", b"HTTP/1.1 101\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + RFC_ACCEPT.encode() + b"\r\n\r\n")
    add("no-reason-phrase-with-space", b"HTTP/1.1 101 \r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + RFC_ACCEPT.encode() + b"\r\n\r\n")
    add("content-length-on-101", response(extra=[("Content-Length", "0")]))
    add("content-length-5-on-101", response(extra=[("Content-Length", "5")]) + b"hello")
    add("transfer-encoding-on-101", response(extra=[("Transfer-Encoding", "chunked")]))
    add("not-http", b"SSH-2.0-OpenSSH_9.2\r\n\r\n")
    add("empty-input", b"")
    add("truncated-before-final-crlf", response()[:-2])
    add("truncated-in-the-middle", response()[:50])
    add("blank-lines-first", CRLF + response())
    add("401-with-body", b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\n\r\nnope")
    add("head-70000-of-extra-field", response(extra=[("X-Pad", "a" * 70000)]))
    add("head-300-fields", response(extra=[("X-%d" % i, "v") for i in range(300)]))
    add("extension-answer-very-long", response(extra=E(pd + "; " + "; ".join("p%d=%d" % (i, i) for i in range(500)))), "d")
    return o.cases


# ------------------------------------------------------------------------------------------
# wr: this library sends, every implementation reads
# ------------------------------------------------------------------------------------------

def script(ops):
    """A wr script (ws_probe.c) from [(letter, bytes)...]."""
    return b"".join(op.encode() + struct.pack(">I", len(d)) + d for op, d in ops)


def script_events(data):
    """What a peer must be handed for a script: [[kind, hex, code|None]...]. A
    fragmented message is one event; a Ping and a Pong are events; a Close is
    one (its code is 1005 when it carried none)."""
    evs = []
    off = 0
    pending = None  # (kind, [parts])
    while off < len(data):
        op = chr(data[off])
        n = struct.unpack(">I", data[off + 1:off + 5])[0]
        d = data[off + 5:off + 5 + n]
        off += 5 + n
        if op in "TB":
            evs.append(["text" if op == "T" else "binary", d.hex(), None])
        elif op in "ab":
            if pending is None:
                pending = ("text" if op == "a" else "binary", [])
            pending[1].append(d)
        elif op in "zy":
            if pending is None:
                pending = ("text" if op == "z" else "binary", [])
            pending[1].append(d)
            evs.append([pending[0], b"".join(pending[1]).hex(), None])
            pending = None
        elif op == "p":
            evs.append(["ping", d.hex(), None])
        elif op == "o":
            evs.append(["pong", d.hex(), None])
        elif op == "c":
            if len(d) >= 2:
                evs.append(["close", d[2:].hex(), int.from_bytes(d[:2], "big")])
            else:
                evs.append(["close", "", 1005])
        # a Pong a peer answers a Ping with is not an event of the script
    return evs


def hand_wr():
    o = Out()
    scripts = {}
    scripts["messages"] = [("T", b"Hello"), ("B", rnd(300)), ("T", b""), ("B", b""), ("T", KOSME), ("B", bytes(range(256)))]
    scripts["fragments"] = [("a", b"Hel"), ("z", b"lo"), ("b", b"\x00\x01"), ("b", b"\x02"), ("y", b"\x03")]
    scripts["fragments-with-controls"] = [("a", b"He"), ("p", b"ping"), ("a", b"l"), ("o", b"pong"), ("z", b"lo")]
    scripts["utf8-split"] = [("a", "€".encode()[:2]), ("z", "€".encode()[2:]), ("a", b"x"), ("a", "😀".encode()[:1]), ("a", "😀".encode()[1:3]), ("z", "😀".encode()[3:])]
    scripts["empty-fragments"] = [("a", b""), ("a", b""), ("z", b""), ("b", b""), ("y", b"data")]
    scripts["controls"] = [("p", b""), ("p", b"x" * 125), ("o", b""), ("o", b"y" * 125)]
    scripts["close-reason"] = [("T", b"bye"), ("c", close_body(1000, b"normal"))]
    scripts["close-code-only"] = [("c", close_body(1001))]
    scripts["close-empty"] = [("c", b"")]
    scripts["sizes"] = [("T", lorem(n)) for n in (125, 126, 127, 128, 65535, 65536)] + [("B", rnd(n)) for n in (125, 126, 65535, 65536)]
    scripts["twenty-repeats"] = [("T", lorem(400, 1)) for _ in range(20)]
    scripts["twenty-different"] = [("T", lorem(400, i)) for i in range(20)]
    scripts["big-1MiB"] = [("B", rnd(MAXMSG)), ("T", lorem(MAXMSG))]
    short = {k: scripts[k] for k in ("messages", "fragments", "fragments-with-controls", "utf8-split", "empty-fragments", "controls", "close-reason", "twenty-repeats")}
    short["twenty-repeats"] = [("T", lorem(150, 1)) for _ in range(20)]
    for role in ("client", "server"):
        for name, ops in scripts.items():
            o.add("wr:%s:none:%s" % (role, name), "wr", "role=" + role, script(ops))
        for p in PARAM_SETS:
            narrow = any(v in (8, 9) for v in p[2:])
            for name, ops in (short if narrow else scripts).items():
                if name == "big-1MiB":
                    continue
                o.add("wr:%s:%s:%s" % (role, pname(p), name), "wr", "role=%s;%s" % (role, pspec(p)), script(ops))
        o.add("wr:%s:takeover:big-1MiB" % role, "wr", "role=%s;d" % role, script(scripts["big-1MiB"]))
    return o.cases


# ------------------------------------------------------------------------------------------
# gen: single mutations of valid streams
# ------------------------------------------------------------------------------------------

def _bases():
    """Valid streams to mutate: (name, kind, arg, [frames as bytes]). The same
    list is built for both roles (kind ws: masked, wc: not)."""
    out = []
    for kind, masked in (("ws", True), ("wc", False)):
        F = lambda *a, **k: frame(*a, masked=masked, **k)
        out.append(("plain", kind, "-", [F(OP_TEXT, b"Hello"), F(OP_PING, b"hi"), F(OP_BIN, rnd(300)), F(OP_CLOSE, close_body(1000, b"bye"))]))
        out.append(("fragmented", kind, "-", [F(OP_TEXT, b"Hel", False), F(OP_PING, b"p"), F(OP_CONT, b"l", False), F(OP_CONT, b"o", True), F(OP_BIN, b"\x01\x02"), F(OP_PONG, b"q")]))
        out.append(("utf8", kind, "-", [F(OP_TEXT, "é€".encode()), F(OP_TEXT, "😀".encode()[:2], False), F(OP_CONT, "😀".encode()[2:], True), F(OP_TEXT, KOSME), F(OP_CLOSE, close_body(1001, "ü".encode()))]))
        out.append(("control", kind, "-", [F(OP_PING, b""), F(OP_PONG, b"x"), F(OP_PING, b"y" * 125), F(OP_TEXT, b"t"), F(OP_CLOSE, b"")]))
        out.append(("lengths", kind, "-", [F(OP_BIN, rnd(126)), F(OP_BIN, rnd(200), False), F(OP_CONT, rnd(1000), True), F(OP_TEXT, b"x" * 125)]))
        # The 64-bit length form is only valid from 65536 octets, which makes
        # every mutation of this one 64 KiB: drawn rarely (see generated()).
        out.append(("lengths64", kind, "-", [F(OP_BIN, rnd(65536)), F(OP_TEXT, b"x")]))
        for nm, p in (("pmd", (False, False, 0, 0)), ("pmd-nct", (True, True, 0, 0)), ("pmd-w10", (False, False, 10, 10))):
            comp = compressor_for(masked, p)
            msgs = [(OP_TEXT, lorem(150, 1)), (OP_TEXT, lorem(150, 1)), (OP_BIN, rnd(60))]
            fr = []
            for typ, data in msgs[:2]:
                fr.append(F(typ, comp.message(data), True, rsv=R1))
            c3 = comp.message(msgs[2][1])
            # No control frame inside the compressed message: wsproto mishandles
            # one (rfc7692-7.2:*:fragments-3-with-pings holds that apart), and a
            # base that trips a known defect would make every mutation of it
            # one more case of that defect.
            fr.append(F(OP_BIN, c3[:len(c3) // 2], False, rsv=R1))
            fr.append(F(OP_CONT, c3[len(c3) // 2:], True))
            fr.append(F(OP_PING, b"p"))
            out.append((nm, kind, pspec(p), fr))
    return out


FIELDS = ["b0", "len", "extlen", "mask", "payload"]


def _field_at(frames, pos):
    """('<opcode>', field) of the octet at `pos` in the concatenation of frames."""
    off = 0
    for f in frames:
        if off <= pos < off + len(f):
            i = pos - off
            op = {0: "cont", 1: "text", 2: "bin", 8: "close", 9: "ping", 10: "pong"}.get(f[0] & 15, "op%d" % (f[0] & 15))
            if i == 0:
                return op, "b0"
            if i == 1:
                return op, "len"
            l7 = f[1] & 0x7F
            ext = 2 if l7 == 126 else 8 if l7 == 127 else 0
            if i < 2 + ext:
                return op, "extlen"
            if f[1] & 0x80 and i < 2 + ext + 4:
                return op, "mask"
            return op, "payload"
        off += len(f)
    return "end", "end"


def generated(seed, count):
    rng = random.Random(seed)
    bases = _bases()
    seen = set()
    out = []
    specials = [0, 1, 2, 4, 5, 0x7f, 0x80, 0xff, 0x20, 0x3f, 0x0a, 0x0d, 0x40, 0x7e]
    ops = ["flip", "set", "insert", "delete", "truncate", "dup-frame", "drop-frame", "swap-frames",
           "opcode", "fin", "rsv", "len+", "len-", "mask-bit", "split-frame", "inject-ping"]
    for _ in range(count):
        name, kind, arg, frames = rng.choice(bases)
        if name == "lengths64" and rng.random() > 0.05:
            continue
        stream = b"".join(frames)
        op = rng.choice(ops)
        data = stream
        where = "frame"
        if op in ("flip", "set", "insert", "delete", "truncate", "opcode", "fin", "rsv", "len+", "len-", "mask-bit"):
            if op in ("opcode", "fin", "rsv", "len+", "len-", "mask-bit"):
                k = rng.randrange(len(frames))
                a = sum(len(f) for f in frames[:k])
                f = frames[k]
                if op == "opcode":
                    pos = a
                    nb = (f[0] & 0xF0) | rng.choice([0, 1, 2, 3, 7, 8, 9, 10, 11, 15])
                    data = stream[:pos] + bytes([nb]) + stream[pos + 1:]
                elif op == "fin":
                    pos = a
                    data = stream[:pos] + bytes([f[0] ^ 0x80]) + stream[pos + 1:]
                elif op == "rsv":
                    pos = a
                    data = stream[:pos] + bytes([f[0] | rng.choice([R1, R2, R3, R1 | R2, R1 | R2 | R3])]) + stream[pos + 1:]
                elif op == "mask-bit":
                    pos = a + 1
                    data = stream[:pos] + bytes([f[1] ^ 0x80]) + stream[pos + 1:]
                else:
                    pos = a + 1
                    l7 = f[1] & 0x7F
                    if l7 >= 126:
                        pos = a + 2 + (0 if l7 == 126 else 6) + (1 if l7 == 126 else 1)
                        d = 1 if op == "len+" else -1
                        data = stream[:pos] + bytes([(stream[pos] + d) & 255]) + stream[pos + 1:]
                    else:
                        nl = l7 + (1 if op == "len+" else -1)
                        if nl < 0 or nl > 125:
                            continue
                        data = stream[:pos] + bytes([(f[1] & 0x80) | nl]) + stream[pos + 1:]
            else:
                pos = rng.randrange(len(stream))
                if op == "flip":
                    data = stream[:pos] + bytes([stream[pos] ^ (1 << rng.randrange(8))]) + stream[pos + 1:]
                elif op == "set":
                    data = stream[:pos] + bytes([rng.choice(specials)]) + stream[pos + 1:]
                elif op == "insert":
                    data = stream[:pos] + bytes([rng.choice(specials)]) + stream[pos:]
                elif op == "delete":
                    data = stream[:pos] + stream[pos + 1:]
                else:
                    data = stream[:pos]
            fop, fld = _field_at(frames, pos)
            where = "%s.%s" % (fop, fld)
        else:
            k = rng.randrange(len(frames))
            fop = _field_at(frames, sum(len(f) for f in frames[:k]))[0]
            masked = kind == "ws"
            if op == "dup-frame":
                fr = frames[:k + 1] + [frames[k]] + frames[k + 1:]
            elif op == "drop-frame":
                fr = frames[:k] + frames[k + 1:]
            elif op == "swap-frames":
                j = rng.randrange(len(frames))
                if j == k:
                    continue
                fr = list(frames)
                fr[k], fr[j] = fr[j], fr[k]
            elif op == "inject-ping":
                fr = frames[:k] + [frame(OP_PING, b"i", masked=masked)] + frames[k:]
            else:  # split-frame: a data frame's payload as two frames
                f = frames[k]
                if (f[0] & 15) not in (1, 2, 0) or (f[1] & 0x7F) in (126, 127) or (f[1] & 0x7F) < 2:
                    continue
                m = bool(f[1] & 0x80)
                hl = 2 + (4 if m else 0)
                key = f[2:6] if m else KEY
                raw = bytes(b ^ key[i % 4] for i, b in enumerate(f[hl:])) if m else f[hl:]
                cut = rng.randrange(1, len(raw))
                a = frame(f[0] & 15, raw[:cut], False, masked=m, rsv=f[0] & 0x70, key=key)
                b = frame(OP_CONT, raw[cut:], bool(f[0] & 0x80), masked=m, key=key)
                fr = frames[:k] + [a, b] + frames[k + 1:]
            data = b"".join(fr)
            where = "%s.frame" % fop
        if data == stream or (kind, arg, data) in seen:
            continue
        seen.add((kind, arg, data))
        out.append(("gen:%s@%s.%s" % (op, name, where), kind, arg, data))
    return out


# ------------------------------------------------------------------------------------------
# everything
# ------------------------------------------------------------------------------------------

def all_cases(seed=1, count=6000):
    """Every case, ids assigned: dicts of id, kind, arg, tag, data."""
    raw = hand_ws() + hand_deflate() + unit_cases() + hand_hs() + hand_hc() + hand_wr() + generated(seed, count)
    cases = []
    seen = set()
    for tag, kind, arg, data in raw:
        key = (kind, arg, data)
        if key in seen:
            continue
        seen.add(key)
        cases.append({"id": len(cases), "kind": kind, "arg": arg, "tag": tag, "data": data})
    return cases


def _frames_of(data):
    """[(offset, header_len, payload_len, complete)] of the frames in a stream,
    as far as it parses; the last may be cut. Stops at a header it cannot read."""
    out = []
    pos = 0
    n = len(data)
    while pos < n:
        if n - pos < 2:
            out.append((pos, None, None, False))
            break
        b1 = data[pos + 1]
        l7 = b1 & 0x7F
        ext = 2 if l7 == 126 else 8 if l7 == 127 else 0
        hl = 2 + ext + (4 if b1 & 0x80 else 0)
        if n - pos < hl:
            out.append((pos, None, None, False))
            break
        plen = l7 if ext == 0 else int.from_bytes(data[pos + 2:pos + 2 + ext], "big")
        out.append((pos, hl, plen, n - pos >= hl + plen))
        if n - pos < hl + plen:
            break
        pos += hl + plen
    return out


def complete_stream(data, kind):
    """The stream with its last, cut frame completed, and its last message ended:
    a header that has stopped short is finished, a payload that has stopped
    short is filled with zero octets, and a message whose last frame has FIN
    clear gets an empty final continuation frame. A stream that ends on the end
    of a message is returned as it is."""
    data = _complete_frame(data, kind)
    state = False
    for pos, hl, plen, done in _frames_of(data):
        if hl is None or not done:
            break
        op = data[pos] & 15
        if op in (0, 1, 2):
            state = not (data[pos] & 0x80)
        elif op == 8:
            return data
    if state:
        data += frame(OP_CONT, b"", True, masked=(kind == "ws"))
    return data


def _complete_frame(data, kind):
    fr = _frames_of(data)
    if not fr or fr[-1][3]:
        return data
    pos, hl, plen, _ = fr[-1]
    rest = data[pos:]
    masked = kind == "ws"
    if hl is None:
        # fewer than a whole header: finish it with a 126-octet frame
        if len(rest) == 0:
            rest = b""
        if len(rest) == 1:
            rest += bytes([0x80 if masked else 0]) + b""
        b1 = rest[1]
        l7 = b1 & 0x7F
        ext = 2 if l7 == 126 else 8 if l7 == 127 else 0
        need = 2 + ext + (4 if b1 & 0x80 else 0) - len(rest)
        pad = bytearray(b"\0" * need)
        if ext == 2:
            have = max(0, len(rest) - 2)
            full = bytearray(rest[2:2 + have]) + pad[:2 - have] if have < 2 else bytearray(rest[2:4])
            if int.from_bytes(bytes(full) + b"\0" * (2 - len(full)), "big") < 126:
                if have == 0:
                    pad[0:2] = b"\x00\x7e"
                elif have == 1:
                    pad[0:1] = b"\x7e" if rest[2] == 0 else b"\x00"
        rest += bytes(pad)
        data = data[:pos] + rest
        fr = _frames_of(data)
        pos, hl, plen, done = fr[-1]
        if done:
            return data
    missing = hl + plen - (len(data) - pos)
    if missing > (1 << 21):
        return data
    return data + b"\0" * missing


def strip_controls(data):
    """The stream without its Ping and Pong frames (the frames it can parse)."""
    out = b""
    for pos, hl, plen, done in _frames_of(data):
        if hl is None or not done:
            out += data[pos:]
            break
        if (data[pos] & 15) in (9, 10):
            continue
        out += data[pos:pos + hl + plen]
    return out


def splits(c):
    """The ways a case is run: ws and wc whole and one octet at a time."""
    return ("whole", "byte") if c["kind"] in ("ws", "wc") else ("whole",)


def dump(path, cases):
    """The cases as TSV lines, split whole and byte for ws and wc: for runs where
    the references cannot be reached (other architectures, Windows)."""
    with open(path, "w") as out:
        for c in cases:
            for split in splits(c):
                out.write("%d\t%s\t%s\t%s\t%s\n" % (c["id"], c["kind"], split, c["arg"], c["data"].hex()))


if __name__ == "__main__":
    import collections
    import sys
    cs = all_cases()
    k = collections.Counter(c["kind"] for c in cs)
    print(len(cs), dict(k))
    if len(sys.argv) > 1:
        dump(sys.argv[1], cs)
