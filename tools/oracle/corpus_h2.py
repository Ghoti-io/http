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
"""The HTTP/2 differential's corpus.

A case is (id, kind, arg, tag, data):

  kind "h2"  `data` is a client's whole byte stream, preface first: the
             implementations are run as servers over it.
  kind "hd"  `data` is one HPACK block and `arg` the decoder's table size.
  kind "he"  `arg` is the encoder's table size and `data` a "field blob" (a
             4-octet name length, the name, a 4-octet value length, the value,
             repeated); every implementation encodes the list and the blocks
             are then decoded by every implementation.

Where the cases come from:

  hand      Written from RFC 9113 and RFC 7541, one case per rule, valid AND
            invalid, tagged `rfc9113-<section>:<what>` or `rfc7541-<section>:`.
            The invalid ones are the point: implementations agree on every
            stream they all accept, and the value of a differential is in which
            malformed ones each turns away, and how.
  rfc       RFC 7541 Appendix C (read from tests/hpack_rfc_vectors.h, itself
            generated from the RFC text).
  gen       Single mutations of valid streams from a seeded generator: change a
            frame's length, type, flags or stream identifier, flip an octet in a
            payload, cut or repeat or reorder frames. One mutation per case, so
            a disagreement names its cause: tag `gen:<op>@<frame>.<field>`.
  genhd     Single mutations of valid HPACK blocks.
  he        Random header lists, seeded, and the RFC's own lists.

The generator is seeded and its output is a pure function of (seed, count).
"""

import os
import random
import re
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.dirname(os.path.dirname(HERE))

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, \
    WINDOW_UPDATE, CONTINUATION = range(10)
END_STREAM, END_HEADERS, PADDED, PRIORITY_FLAG = 0x1, 0x4, 0x8, 0x20
FNAMES = ["DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE",
          "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"]


# ---- bytes -------------------------------------------------------------------------

def frame(t, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([t, flags]) + struct.pack(">I", sid) + payload


def raw_frame(length, t, flags, sid, payload=b""):
    """A frame whose length field need not match its payload."""
    return struct.pack(">I", length)[1:] + bytes([t, flags]) + struct.pack(">I", sid) + payload


def settings(pairs=(), ack=False):
    return frame(SETTINGS, 1 if ack else 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in pairs))


def u32(v):
    return struct.pack(">I", v)


def hpack_int(value, prefix, flags=0):
    mx = (1 << prefix) - 1
    if value < mx:
        return bytes([flags | value])
    out = bytearray([flags | mx])
    value -= mx
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def S(b):
    """A plain string literal."""
    return hpack_int(len(b), 7) + b


_HUFF = None


def _huff_tables():
    global _HUFF
    if _HUFF is None:
        text = open(os.path.join(LIB, "src", "http", "hpack_tables.c")).read()
        codes = [int(x, 16) for x in re.search(r"ghttp_huff_code\[257\] = \{(.*?)\};", text, re.S).group(1).replace("\n", " ").replace(",", " ").split()]
        lens = [int(x) for x in re.search(r"ghttp_huff_len\[257\] = \{(.*?)\};", text, re.S).group(1).replace(",", " ").split()]
        _HUFF = (codes, lens)
    return _HUFF


def huff(b):
    codes, lens = _huff_tables()
    acc, nbits = 0, 0
    for c in b:
        acc = (acc << lens[c]) | codes[c]
        nbits += lens[c]
    pad = (-nbits) % 8
    acc = (acc << pad) | ((1 << pad) - 1)
    nbits += pad
    return acc.to_bytes(nbits // 8, "big")


def SH(b):
    """A Huffman-coded string literal."""
    h = huff(b)
    return hpack_int(len(h), 7, 0x80) + h


def lit(n, v):
    """Literal without indexing, new name, plain strings: valid for any decoder."""
    return b"\x00" + S(n) + S(v)


def lit_inc(n, v):
    return b"\x40" + S(n) + S(v)


def lit_never(n, v):
    return b"\x10" + S(n) + S(v)


def lit_idx(index, v, prefix=4, flags=0):
    return hpack_int(index, prefix, flags) + S(v)


def idx(i):
    return hpack_int(i, 7, 0x80)


def block(fields):
    return b"".join(lit(n, v) for n, v in fields)


REQ = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"), (b":path", b"/a?b=c")]


def req(*extra, method=b"GET", path=b"/a?b=c", scheme=b"https", authority=b"example.com"):
    f = [(b":method", method), (b":scheme", scheme)]
    if authority is not None:
        f.append((b":authority", authority))
    f.append((b":path", path))
    return f + list(extra)


def hdrs(sid, fields, flags=END_HEADERS | END_STREAM):
    return frame(HEADERS, flags, sid, block(fields))


OPEN = PREFACE + settings()
OPEN_ACK = PREFACE + settings() + settings(ack=True)


def GET(sid=1, *extra, **kw):
    return hdrs(sid, req(*extra, **kw))


def POST_open(sid=1, *extra):
    return hdrs(sid, req(*extra, method=b"POST"), END_HEADERS)


# ---- hand-written h2 cases --------------------------------------------------------------

def hand():
    out = []

    def add(tag, data):
        out.append((tag, "h2", "-", data))

    O = OPEN
    # 3.4 the connection preface
    add("rfc9113-3.4:good-minimal", O)
    add("rfc9113-3.4:good-with-ack", OPEN_ACK)
    add("rfc9113-3.4:empty-input", b"")
    add("rfc9113-3.4:preface-only", PREFACE)
    for i in (0, 5, 14, 15, 20, 23):
        bad = bytearray(PREFACE)
        bad[i] ^= 0x20
        add("rfc9113-3.4:preface-wrong-octet-%d" % i, bytes(bad) + settings())
    add("rfc9113-3.4:preface-truncated", PREFACE[:23] + settings())
    add("rfc9113-3.4:http1-request", b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    add("rfc9113-3.4:no-settings-after-preface-ping", PREFACE + frame(PING, 0, 0, b"12345678"))
    add("rfc9113-3.4:no-settings-after-preface-headers", PREFACE + GET())
    add("rfc9113-3.4:settings-ack-as-first-frame", PREFACE + settings(ack=True))
    add("rfc9113-3.4:settings-after-garbage-frame-type", PREFACE + frame(0xee, 0, 0, b"x") + settings())
    # 4.1 frame format, 4.2 frame size
    add("rfc9113-4.2:data-at-max-frame-size", O + POST_open() + frame(DATA, 0, 1, b"x" * 16384) + frame(DATA, END_STREAM, 1))
    add("rfc9113-4.2:data-over-max-frame-size", O + POST_open() + frame(DATA, 0, 1, b"x" * 16385))
    add("rfc9113-4.2:data-length-claims-more-than-follows", O + POST_open() + raw_frame(100, DATA, 0, 1, b"x" * 10))
    add("rfc9113-4.2:reserved-bit-in-stream-id", O + frame(HEADERS, END_HEADERS | END_STREAM, 0x80000001, block(req())))
    add("rfc9113-4.1:unknown-flags-ignored", O + frame(HEADERS, END_HEADERS | END_STREAM | 0x80 | 0x02, 1, block(req())))
    add("rfc9113-4.1:unknown-type-stream-0", O + frame(0xee, 0, 0, b"payload") + GET())
    add("rfc9113-4.1:unknown-type-on-stream", O + frame(0xee, 0xff, 1, b"payload") + GET(3))
    add("rfc9113-4.1:unknown-type-on-idle-stream-large", O + frame(0xee, 0, 7, b"") + GET(1))
    add("rfc9113-4.1:unknown-type-inside-header-block", O + frame(HEADERS, 0, 1, block(req())) + frame(0xee, 0, 0, b"x") + frame(CONTINUATION, END_HEADERS, 1, b""))
    add("rfc9113-4.1:zero-length-unknown", O + frame(0xfe, 0, 0, b"") + GET())
    # 4.3 and 6.10 header blocks
    blk = block(req())
    add("rfc9113-6.10:continuation-two-frames", O + frame(HEADERS, END_STREAM, 1, blk[:10]) + frame(CONTINUATION, END_HEADERS, 1, blk[10:]))
    add("rfc9113-6.10:continuation-many-frames", O + frame(HEADERS, END_STREAM, 1, blk[:5]) + b"".join(frame(CONTINUATION, 0, 1, blk[5 + i:6 + i]) for i in range(len(blk) - 6)) + frame(CONTINUATION, END_HEADERS, 1, blk[-1:]))
    add("rfc9113-6.10:continuation-empty-last", O + frame(HEADERS, END_STREAM, 1, blk) + frame(CONTINUATION, END_HEADERS, 1, b""))
    add("rfc9113-6.10:continuation-empty-middle", O + frame(HEADERS, END_STREAM, 1, blk[:8]) + frame(CONTINUATION, 0, 1, b"") + frame(CONTINUATION, END_HEADERS, 1, blk[8:]))
    add("rfc9113-6.10:continuation-without-headers", O + frame(CONTINUATION, END_HEADERS, 1, blk))
    add("rfc9113-6.10:continuation-on-stream-0", O + frame(HEADERS, 0, 1, blk[:5]) + frame(CONTINUATION, END_HEADERS, 0, blk[5:]))
    add("rfc9113-6.10:continuation-other-stream", O + frame(HEADERS, 0, 1, blk[:5]) + frame(CONTINUATION, END_HEADERS, 3, blk[5:]))
    add("rfc9113-6.10:interleaved-ping", O + frame(HEADERS, END_STREAM, 1, blk[:5]) + frame(PING, 0, 0, b"12345678") + frame(CONTINUATION, END_HEADERS, 1, blk[5:]))
    add("rfc9113-6.10:interleaved-data-other-stream", O + POST_open(1) + frame(HEADERS, END_STREAM, 3, blk[:5]) + frame(DATA, 0, 1, b"x") + frame(CONTINUATION, END_HEADERS, 3, blk[5:]))
    add("rfc9113-6.10:headers-after-headers-without-end-headers", O + frame(HEADERS, 0, 1, blk[:5]) + frame(HEADERS, END_HEADERS, 3, blk))
    add("rfc9113-6.10:continuation-after-end-headers", O + frame(HEADERS, END_HEADERS | END_STREAM, 1, blk) + frame(CONTINUATION, END_HEADERS, 1, b""))
    add("rfc9113-6.10:header-block-never-ends", O + frame(HEADERS, END_STREAM, 1, blk[:5]))
    add("rfc9113-6.10:continuation-flood-40", O + frame(HEADERS, END_STREAM, 1, blk[:1]) + b"".join(frame(CONTINUATION, 0, 1, b"\x84") for _ in range(40)))
    # 6.1 DATA
    add("rfc9113-6.1:post-with-body", O + POST_open() + frame(DATA, 0, 1, b"he") + frame(DATA, END_STREAM, 1, b"llo"))
    add("rfc9113-6.1:data-on-stream-0", O + frame(DATA, 0, 0, b"x"))
    add("rfc9113-6.1:data-on-idle-stream", O + frame(DATA, 0, 1, b"x"))
    add("rfc9113-6.1:data-on-idle-stream-3", O + GET(1) + frame(DATA, 0, 3, b"x"))
    add("rfc9113-6.1:data-after-end-stream", O + POST_open() + frame(DATA, END_STREAM, 1, b"x") + frame(DATA, 0, 1, b"y"))
    add("rfc9113-6.1:data-on-get-with-end-stream", O + GET(1) + frame(DATA, 0, 1, b"x"))
    add("rfc9113-6.1:data-padded", O + POST_open() + frame(DATA, PADDED | END_STREAM, 1, b"\x03abc\0\0\0"))
    add("rfc9113-6.1:data-padded-zero", O + POST_open() + frame(DATA, PADDED | END_STREAM, 1, b"\x00abc"))
    add("rfc9113-6.1:data-padding-as-long-as-payload", O + POST_open() + frame(DATA, PADDED, 1, b"\x04abc"))
    add("rfc9113-6.1:data-padding-longer-than-payload", O + POST_open() + frame(DATA, PADDED, 1, b"\xffabc"))
    add("rfc9113-6.1:data-padded-flag-no-payload", O + POST_open() + frame(DATA, PADDED, 1, b""))
    add("rfc9113-6.1:data-padding-nonzero", O + POST_open() + frame(DATA, PADDED | END_STREAM, 1, b"\x03abcXYZ"))
    add("rfc9113-6.1:data-empty", O + POST_open() + frame(DATA, 0, 1, b"") + frame(DATA, END_STREAM, 1, b""))
    add("rfc9113-6.1:data-empty-end-only", O + POST_open() + frame(DATA, END_STREAM, 1, b""))
    # 6.2 HEADERS
    add("rfc9113-6.2:get", O + GET())
    add("rfc9113-6.2:headers-on-stream-0", O + frame(HEADERS, END_HEADERS | END_STREAM, 0, blk))
    add("rfc9113-6.2:headers-padded", O + frame(HEADERS, END_HEADERS | END_STREAM | PADDED, 1, b"\x02" + blk + b"\0\0"))
    add("rfc9113-6.2:headers-padding-too-long", O + frame(HEADERS, END_HEADERS | END_STREAM | PADDED, 1, b"\xff" + blk))
    add("rfc9113-6.2:headers-padded-no-pad-length", O + frame(HEADERS, END_HEADERS | END_STREAM | PADDED, 1, b""))
    add("rfc9113-6.2:headers-with-priority", O + frame(HEADERS, END_HEADERS | END_STREAM | PRIORITY_FLAG, 1, u32(0) + b"\x10" + blk))
    add("rfc9113-6.2:headers-with-priority-self-dependency", O + frame(HEADERS, END_HEADERS | END_STREAM | PRIORITY_FLAG, 1, u32(1) + b"\x10" + blk))
    add("rfc9113-6.2:headers-with-priority-exclusive", O + frame(HEADERS, END_HEADERS | END_STREAM | PRIORITY_FLAG, 1, u32(0x80000003) + b"\xff" + blk))
    add("rfc9113-6.2:headers-priority-flag-too-short", O + frame(HEADERS, END_HEADERS | END_STREAM | PRIORITY_FLAG, 1, b"abcd"))
    add("rfc9113-6.2:headers-padded-and-priority", O + frame(HEADERS, END_HEADERS | END_STREAM | PADDED | PRIORITY_FLAG, 1, b"\x01" + u32(0) + b"\x10" + blk + b"\0"))
    add("rfc9113-6.2:headers-empty-block", O + frame(HEADERS, END_HEADERS | END_STREAM, 1, b""))
    # 6.3 PRIORITY
    add("rfc9113-6.3:priority-idle", O + frame(PRIORITY, 0, 1, u32(0) + b"\x10"))
    add("rfc9113-6.3:priority-open", O + POST_open() + frame(PRIORITY, 0, 1, u32(0) + b"\x10") + frame(DATA, END_STREAM, 1, b"x"))
    add("rfc9113-6.3:priority-self-dependency", O + frame(PRIORITY, 0, 1, u32(1) + b"\x10"))
    add("rfc9113-6.3:priority-stream-0", O + frame(PRIORITY, 0, 0, u32(1) + b"\x10"))
    add("rfc9113-6.3:priority-4-octets", O + POST_open() + frame(PRIORITY, 0, 1, b"abcd"))
    add("rfc9113-6.3:priority-6-octets", O + POST_open() + frame(PRIORITY, 0, 1, b"abcdef"))
    add("rfc9113-6.3:priority-4-octets-idle", O + frame(PRIORITY, 0, 5, b"abcd"))
    add("rfc9113-6.3:priority-closed-stream", O + GET(1) + frame(RST_STREAM, 0, 1, u32(8)) + frame(PRIORITY, 0, 1, u32(0) + b"\x10"))
    # 6.4 RST_STREAM
    add("rfc9113-6.4:rst-open-stream", O + POST_open() + frame(RST_STREAM, 0, 1, u32(8)))
    add("rfc9113-6.4:rst-idle-stream", O + frame(RST_STREAM, 0, 1, u32(8)))
    add("rfc9113-6.4:rst-stream-0", O + frame(RST_STREAM, 0, 0, u32(8)))
    add("rfc9113-6.4:rst-3-octets", O + POST_open() + frame(RST_STREAM, 0, 1, b"abc"))
    add("rfc9113-6.4:rst-5-octets", O + POST_open() + frame(RST_STREAM, 0, 1, b"abcde"))
    add("rfc9113-6.4:rst-twice", O + POST_open() + frame(RST_STREAM, 0, 1, u32(8)) + frame(RST_STREAM, 0, 1, u32(8)))
    add("rfc9113-6.4:rst-then-data", O + POST_open() + frame(RST_STREAM, 0, 1, u32(8)) + frame(DATA, 0, 1, b"x"))
    add("rfc9113-6.4:rst-then-headers", O + POST_open() + frame(RST_STREAM, 0, 1, u32(8)) + GET(1))
    add("rfc9113-6.4:rst-then-window-update", O + POST_open() + frame(RST_STREAM, 0, 1, u32(8)) + frame(WINDOW_UPDATE, 0, 1, u32(5)))
    add("rfc9113-6.4:rst-after-get-complete", O + GET() + frame(RST_STREAM, 0, 1, u32(0)))
    add("rfc9113-6.4:rst-unknown-code", O + POST_open() + frame(RST_STREAM, 0, 1, u32(0x77)))
    # 6.5 SETTINGS
    add("rfc9113-6.5:settings-empty", PREFACE + settings())
    add("rfc9113-6.5:settings-many", PREFACE + settings([(3, 10), (4, 100), (5, 20000), (1, 0), (6, 1000)]))
    add("rfc9113-6.5:settings-on-stream", PREFACE + frame(SETTINGS, 0, 1, b""))
    add("rfc9113-6.5:settings-ack-with-payload", O + frame(SETTINGS, 1, 0, struct.pack(">HI", 3, 1)))
    add("rfc9113-6.5:settings-5-octets", PREFACE + frame(SETTINGS, 0, 0, b"abcde"))
    add("rfc9113-6.5:settings-7-octets", PREFACE + frame(SETTINGS, 0, 0, b"abcdefg"))
    add("rfc9113-6.5:settings-12-octets", PREFACE + frame(SETTINGS, 0, 0, struct.pack(">HIHI", 3, 1, 4, 2)))
    add("rfc9113-6.5:settings-again", O + settings([(3, 5)]) + GET())
    add("rfc9113-6.5:settings-ack-unsolicited", O + settings(ack=True) + settings(ack=True))
    for sid, name in ((1, "header-table-size"), (3, "max-concurrent-streams"), (6, "max-header-list-size")):
        for v in (0, 1, 4096, 0xffffffff):
            add("rfc9113-6.5.2:%s-%d" % (name, v), PREFACE + settings([(sid, v)]) + GET())
    for v in (0, 1, 2):
        add("rfc9113-6.5.2:enable-push-%d" % v, PREFACE + settings([(2, v)]) + GET())
    add("rfc9113-6.5.2:enable-push-0xffffffff", PREFACE + settings([(2, 0xffffffff)]))
    for v in (0, 1, 65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff):
        add("rfc9113-6.5.2:initial-window-%d" % v, PREFACE + settings([(4, v)]) + GET())
    for v in (0, 16383, 16384, 16385, 100000, 0xffffff, 0x1000000, 0xffffffff):
        add("rfc9113-6.5.2:max-frame-size-%d" % v, PREFACE + settings([(5, v)]) + GET())
    add("rfc9113-6.5.2:unknown-setting", PREFACE + settings([(0x99, 7)]) + GET())
    add("rfc9113-6.5.2:unknown-setting-0", PREFACE + settings([(0, 7)]) + GET())
    add("rfc9113-6.5.2:enable-connect-protocol", PREFACE + settings([(8, 1)]) + GET())
    add("rfc9113-6.5.3:settings-duplicate-id", PREFACE + settings([(3, 5), (3, 7)]) + GET())
    add("rfc9113-6.5.3:settings-window-after-data", O + POST_open() + frame(DATA, 0, 1, b"x" * 100) + settings([(4, 10)]) + frame(DATA, END_STREAM, 1, b"y"))
    # 6.6 PUSH_PROMISE
    add("rfc9113-6.6:push-promise-from-client", O + frame(PUSH_PROMISE, END_HEADERS, 1, u32(2) + block(req())))
    add("rfc9113-6.6:push-promise-open-stream", O + POST_open() + frame(PUSH_PROMISE, END_HEADERS, 1, u32(2) + block(req())))
    add("rfc9113-6.6:push-promise-stream-0", O + frame(PUSH_PROMISE, END_HEADERS, 0, u32(2) + b"x"))
    add("rfc9113-6.6:push-promise-short", O + frame(PUSH_PROMISE, END_HEADERS, 1, b"abc"))
    # 6.7 PING
    add("rfc9113-6.7:ping", O + frame(PING, 0, 0, b"12345678"))
    add("rfc9113-6.7:ping-ack", O + frame(PING, 1, 0, b"12345678"))
    add("rfc9113-6.7:ping-on-stream", O + frame(PING, 0, 1, b"12345678"))
    add("rfc9113-6.7:ping-7-octets", O + frame(PING, 0, 0, b"1234567"))
    add("rfc9113-6.7:ping-9-octets", O + frame(PING, 0, 0, b"123456789"))
    add("rfc9113-6.7:ping-then-request", O + frame(PING, 0, 0, b"12345678") + GET())
    # 6.8 GOAWAY
    add("rfc9113-6.8:goaway", O + frame(GOAWAY, 0, 0, u32(0) + u32(0)))
    add("rfc9113-6.8:goaway-debug", O + frame(GOAWAY, 0, 0, u32(0) + u32(0) + b"debug data"))
    add("rfc9113-6.8:goaway-on-stream", O + frame(GOAWAY, 0, 1, u32(0) + u32(0)))
    add("rfc9113-6.8:goaway-7-octets", O + frame(GOAWAY, 0, 0, b"1234567"))
    add("rfc9113-6.8:goaway-then-request", O + frame(GOAWAY, 0, 0, u32(0) + u32(0)) + GET())
    add("rfc9113-6.8:goaway-reserved-bit", O + frame(GOAWAY, 0, 0, u32(0x80000001) + u32(1)))
    # 6.9 WINDOW_UPDATE
    add("rfc9113-6.9:window-update-connection", O + frame(WINDOW_UPDATE, 0, 0, u32(1000)))
    add("rfc9113-6.9:window-update-zero-connection", O + frame(WINDOW_UPDATE, 0, 0, u32(0)))
    add("rfc9113-6.9:window-update-zero-stream", O + POST_open() + frame(WINDOW_UPDATE, 0, 1, u32(0)))
    add("rfc9113-6.9:window-update-zero-idle-stream", O + frame(WINDOW_UPDATE, 0, 1, u32(0)))
    add("rfc9113-6.9:window-update-overflow-connection", O + frame(WINDOW_UPDATE, 0, 0, u32(0x7fffffff)))
    add("rfc9113-6.9:window-update-overflow-stream", O + POST_open() + frame(WINDOW_UPDATE, 0, 1, u32(0x7fffffff)))
    add("rfc9113-6.9:window-update-exactly-max-connection", O + frame(WINDOW_UPDATE, 0, 0, u32(0x7fffffff - 65535)))
    add("rfc9113-6.9:window-update-max-twice-connection", O + frame(WINDOW_UPDATE, 0, 0, u32(0x7fffffff - 65535)) + frame(WINDOW_UPDATE, 0, 0, u32(1)))
    add("rfc9113-6.9:window-update-3-octets", O + frame(WINDOW_UPDATE, 0, 0, b"abc"))
    add("rfc9113-6.9:window-update-5-octets", O + frame(WINDOW_UPDATE, 0, 0, b"abcde"))
    add("rfc9113-6.9:window-update-idle-stream", O + frame(WINDOW_UPDATE, 0, 1, u32(10)))
    add("rfc9113-6.9:window-update-reserved-bit", O + frame(WINDOW_UPDATE, 0, 0, u32(0x80000010)))
    add("rfc9113-6.9:window-update-on-half-closed-remote", O + GET() + frame(WINDOW_UPDATE, 0, 1, u32(10)))
    add("rfc9113-6.9:window-update-on-closed", O + GET() + frame(RST_STREAM, 0, 1, u32(8)) + frame(WINDOW_UPDATE, 0, 1, u32(10)))
    add("rfc9113-6.9:data-64k-then-more", O + POST_open() + b"".join(frame(DATA, 0, 1, b"x" * 16384) for _ in range(4)) + frame(DATA, END_STREAM, 1, b"yy"))
    add("rfc9113-6.9:data-exactly-65535", O + POST_open() + b"".join(frame(DATA, 0, 1, b"x" * 16384) for _ in range(3)) + frame(DATA, END_STREAM, 1, b"x" * 16383))
    add("rfc9113-6.9:data-two-streams-exceed-connection", O + POST_open(1) + POST_open(3) + b"".join(frame(DATA, 0, 1 + 2 * (i % 2), b"x" * 16384) for i in range(5)))
    # 5.1 stream states and identifiers
    add("rfc9113-5.1.1:even-stream-id", O + hdrs(2, req()))
    add("rfc9113-5.1.1:stream-id-decreasing", O + GET(5) + GET(3))
    add("rfc9113-5.1.1:stream-id-reuse-closed", O + GET(1) + frame(RST_STREAM, 0, 1, u32(8)) + GET(1))
    add("rfc9113-5.1.1:stream-id-reuse-open", O + POST_open(1) + GET(1))
    add("rfc9113-5.1.1:stream-id-skip", O + GET(7))
    add("rfc9113-5.1.1:stream-id-skip-then-lower", O + GET(7) + GET(5))
    add("rfc9113-5.1.1:stream-id-max", O + GET(0x7fffffff))
    add("rfc9113-5.1.1:stream-id-max-then-more", O + GET(0x7ffffffd) + GET(0x7fffffff))
    add("rfc9113-5.1.1:two-requests", O + GET(1) + GET(3, (b"x-n", b"2")))
    add("rfc9113-5.1.1:ten-requests", O + b"".join(GET(1 + 2 * i, (b"x-n", str(i).encode())) for i in range(10)))
    add("rfc9113-5.1:headers-after-end-stream", O + GET(1) + hdrs(1, [(b"x-t", b"1")]))
    add("rfc9113-5.1:headers-after-rst", O + GET(1) + frame(RST_STREAM, 0, 1, u32(8)) + hdrs(1, [(b"x-t", b"1")]))
    add("rfc9113-5.1:half-closed-remote-data", O + GET(1) + frame(DATA, 0, 1, b"x"))
    add("rfc9113-5.1.2:concurrent-streams-100", O + b"".join(hdrs(1 + 2 * i, req(), END_HEADERS) for i in range(100)))
    add("rfc9113-5.1.2:concurrent-streams-101", O + b"".join(hdrs(1 + 2 * i, req(), END_HEADERS) for i in range(101)))
    add("rfc9113-5.1.2:concurrent-streams-reuse-after-close", O + b"".join(hdrs(1 + 2 * i, req(), END_HEADERS) for i in range(100)) + frame(RST_STREAM, 0, 1, u32(8)) + hdrs(201, req(), END_HEADERS))
    # 8.1 message framing: trailers, interim
    add("rfc9113-8.1:trailers", O + POST_open() + frame(DATA, 0, 1, b"x") + hdrs(1, [(b"x-trail", b"t")]))
    add("rfc9113-8.1:trailers-no-body", O + POST_open() + hdrs(1, [(b"x-trail", b"t")]))
    add("rfc9113-8.1:trailers-without-end-stream", O + POST_open() + hdrs(1, [(b"x-trail", b"t")], END_HEADERS))
    add("rfc9113-8.1:trailers-empty", O + POST_open() + frame(HEADERS, END_HEADERS | END_STREAM, 1, b""))
    add("rfc9113-8.1:trailers-pseudo-header", O + POST_open() + hdrs(1, [(b":path", b"/x")]))
    add("rfc9113-8.1:trailers-status", O + POST_open() + hdrs(1, [(b":status", b"200")]))
    add("rfc9113-8.1:trailers-content-length", O + POST_open() + hdrs(1, [(b"content-length", b"3")]))
    add("rfc9113-8.1:trailers-connection", O + POST_open() + hdrs(1, [(b"connection", b"close")]))
    add("rfc9113-8.1:trailers-uppercase", O + POST_open() + hdrs(1, [(b"X-Trail", b"t")]))
    add("rfc9113-8.1:trailers-continued", O + POST_open() + frame(HEADERS, END_STREAM, 1, block([(b"x-trail", b"t")])[:4]) + frame(CONTINUATION, END_HEADERS, 1, block([(b"x-trail", b"t")])[4:]))
    add("rfc9113-8.1:second-headers-with-request-pseudo", O + POST_open() + hdrs(1, req()))
    add("rfc9113-8.1:headers-three-times", O + POST_open() + hdrs(1, [(b"x-a", b"1")], END_HEADERS) + hdrs(1, [(b"x-b", b"2")]))
    # 8.1.1 content-length
    for tag, cl, body, end_headers_only in (
            ("equal", b"5", b"hello", False), ("short-data", b"5", b"hell", False), ("long-data", b"3", b"hello", False),
            ("zero-with-data", b"0", b"x", False), ("none-announced-data", None, b"x", False)):
        extra = [(b"content-length", cl)] if cl is not None else []
        add("rfc9113-8.1.1:content-length-%s" % tag, O + hdrs(1, req(*extra, method=b"POST"), END_HEADERS) + frame(DATA, END_STREAM, 1, body))
    add("rfc9113-8.1.1:content-length-and-no-data", O + hdrs(1, req((b"content-length", b"5"), method=b"POST")))
    add("rfc9113-8.1.1:content-length-zero-no-data", O + hdrs(1, req((b"content-length", b"0"), method=b"POST")))
    add("rfc9113-8.1.1:content-length-two-datas", O + hdrs(1, req((b"content-length", b"4"), method=b"POST"), END_HEADERS) + frame(DATA, 0, 1, b"ab") + frame(DATA, END_STREAM, 1, b"cd"))
    add("rfc9113-8.1.1:content-length-padded-data", O + hdrs(1, req((b"content-length", b"2"), method=b"POST"), END_HEADERS) + frame(DATA, PADDED | END_STREAM, 1, b"\x05ab\0\0\0\0\0"))
    add("rfc9113-8.1.1:content-length-trailers-early", O + hdrs(1, req((b"content-length", b"4"), method=b"POST"), END_HEADERS) + frame(DATA, 0, 1, b"ab") + hdrs(1, [(b"x", b"1")]))
    for v in (b"", b"abc", b"+5", b"-1", b"5 ", b" 5", b"05", b"5,5", b"5, 5", b"0x5", b"99999999999999999999", b"1e3", b"\xff"):
        add("rfc9113-8.1.1:content-length-value-%s" % v.hex().encode().decode() , O + hdrs(1, req((b"content-length", v), method=b"POST"), END_HEADERS) + frame(DATA, END_STREAM, 1, b"hello"))
    add("rfc9113-8.1.1:content-length-twice-equal", O + hdrs(1, req((b"content-length", b"5"), (b"content-length", b"5"), method=b"POST"), END_HEADERS) + frame(DATA, END_STREAM, 1, b"hello"))
    add("rfc9113-8.1.1:content-length-twice-different", O + hdrs(1, req((b"content-length", b"5"), (b"content-length", b"6"), method=b"POST"), END_HEADERS) + frame(DATA, END_STREAM, 1, b"hello"))
    # 8.2 fields
    for name in (b"X-Upper", b"x-Upper", b"A", b"CONTENT-TYPE"):
        add("rfc9113-8.2.1:uppercase-name-%s" % name.decode().lower().encode().decode(), O + hdrs(1, req((name, b"v"))))
    for tag, name in (("space", b"a b"), ("colon", b"a:b"), ("tab", b"a\tb"), ("nul", b"a\x00b"), ("ctl", b"a\x01"), ("del", b"a\x7f"), ("high", b"\xe9"), ("empty", b""),
                      ("quote", b'a"b'), ("slash", b"a/b"), ("paren", b"a(b"), ("at", b"a@b"), ("comma", b"a,b"), ("underscore", b"a_b"), ("dot", b"a.b"), ("tilde", b"a~b"), ("starts-digit", b"1a"), ("starts-dash", b"-a"), ("pseudo-like-mid", b"a:")):
        add("rfc9113-8.2.1:name-%s" % tag, O + hdrs(1, req((name, b"v"))))
    for tag, val in (("nul", b"a\x00b"), ("lf", b"a\nb"), ("cr", b"a\rb"), ("lead-space", b" a"), ("trail-space", b"a "), ("lead-tab", b"\ta"), ("trail-tab", b"a\t"),
                     ("empty", b""), ("inner-space", b"a b"), ("inner-tab", b"a\tb"), ("high", b"\xe9\xff"), ("del", b"a\x7fb"), ("ctl", b"a\x01b"), ("only-space", b" "),
                     ("long-8k", b"v" * 8192), ("long-20k", b"v" * 20000), ("long-70k-in-pieces", b"v" * 60000)):
        add("rfc9113-8.2.1:value-%s" % tag, O + hdrs(1, req((b"x-v", val))) if len(val) < 20000 else O + frame(HEADERS, END_STREAM, 1, block(req((b"x-v", val)))[:16384]) + b"".join(frame(CONTINUATION, 0, 1, block(req((b"x-v", val)))[i:i + 16384]) for i in range(16384, len(block(req((b"x-v", val)))) - 1, 16384)) + frame(CONTINUATION, END_HEADERS, 1, block(req((b"x-v", val)))[(len(block(req((b"x-v", val)))) - 1) // 16384 * 16384:]))
    for tag, name, val in (("connection", b"connection", b"close"), ("keep-alive", b"keep-alive", b"timeout=5"), ("proxy-connection", b"proxy-connection", b"keep-alive"),
                           ("transfer-encoding", b"transfer-encoding", b"chunked"), ("upgrade", b"upgrade", b"websocket"), ("connection-upgrade", b"connection", b"upgrade"),
                           ("te-trailers", b"te", b"trailers"), ("te-gzip", b"te", b"gzip"), ("te-trailers-gzip", b"te", b"trailers, gzip"), ("te-empty", b"te", b""), ("te-upper", b"te", b"Trailers"),
                           ("host", b"host", b"example.com"), ("host-different", b"host", b"other.test"), ("trailer", b"trailer", b"x-a"), ("expect", b"expect", b"100-continue"),
                           ("cookie", b"cookie", b"a=b"), ("accept", b"accept", b"*/*"), ("user-agent", b"user-agent", b"t")):
        add("rfc9113-8.2:field-%s" % tag, O + hdrs(1, req((name, val))))
    add("rfc9113-8.2.3:cookie-split", O + hdrs(1, req((b"cookie", b"a=b"), (b"cookie", b"c=d"), (b"cookie", b"e=f"))))
    add("rfc9113-8.2:repeated-field", O + hdrs(1, req((b"x-a", b"1"), (b"x-a", b"2"), (b"x-a", b"3"))))
    add("rfc9113-8.2:many-fields-100", O + hdrs(1, req(*[(b"x-%d" % i, b"v") for i in range(97)])))
    add("rfc9113-8.2:many-fields-101", O + hdrs(1, req(*[(b"x-%d" % i, b"v") for i in range(98)])))
    add("rfc9113-8.2:many-fields-300", O + hdrs(1, req(*[(b"x-%d" % i, b"v") for i in range(300)])))
    add("rfc9113-8.2:field-empty-name-value-both", O + hdrs(1, req((b"", b""))))
    # 8.3 pseudo-header fields
    def only(fields, tag, flags=END_HEADERS | END_STREAM):
        add(tag, O + hdrs(1, fields, flags))
    only(req(), "rfc9113-8.3.1:request-full")
    only([(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")], "rfc9113-8.3.1:request-no-authority")
    only([(b":scheme", b"https"), (b":path", b"/")], "rfc9113-8.3.1:no-method")
    only([(b":method", b"GET"), (b":path", b"/")], "rfc9113-8.3.1:no-scheme")
    only([(b":method", b"GET"), (b":scheme", b"https")], "rfc9113-8.3.1:no-path")
    only([], "rfc9113-8.3.1:no-pseudo-at-all")
    only([(b"x-a", b"1")], "rfc9113-8.3.1:no-pseudo-regular-only")
    only([(b":method", b"GET"), (b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")], "rfc9113-8.3:duplicate-method")
    only([(b":method", b"GET"), (b":scheme", b"https"), (b":scheme", b"http"), (b":path", b"/")], "rfc9113-8.3:duplicate-scheme")
    only([(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":path", b"/")], "rfc9113-8.3:duplicate-path")
    only(req() + [(b":authority", b"x")], "rfc9113-8.3:duplicate-authority")
    only([(b":method", b"GET"), (b":scheme", b"https"), (b"x-a", b"1"), (b":path", b"/")], "rfc9113-8.3:pseudo-after-regular")
    only([(b"x-a", b"1")] + req(), "rfc9113-8.3:all-pseudo-after-regular")
    only(req() + [(b":protocol", b"websocket")], "rfc9113-8.3:unknown-pseudo-protocol")
    only(req() + [(b":foo", b"bar")], "rfc9113-8.3:unknown-pseudo-foo")
    only(req() + [(b":status", b"200")], "rfc9113-8.3:response-pseudo-in-request")
    only(req() + [(b":", b"x")], "rfc9113-8.3:pseudo-empty-name")
    only(req() + [(b"::method", b"x")], "rfc9113-8.3:pseudo-double-colon")
    only(req() + [(b":Path", b"/")], "rfc9113-8.3:pseudo-upper-case")
    for tag, m in (("post", b"POST"), ("head", b"HEAD"), ("put", b"PUT"), ("delete", b"DELETE"), ("options", b"OPTIONS"), ("trace", b"TRACE"), ("patch", b"PATCH"),
                   ("lower", b"get"), ("empty", b""), ("token-chars", b"M-SEARCH"), ("space", b"G ET"), ("slash", b"G/T"), ("long", b"X" * 300), ("nul", b"G\x00T"), ("connect-in-path-form", b"CONNECT")):
        only(req(method=m), "rfc9113-8.3.1:method-%s" % tag)
    for tag, p in (("root", b"/"), ("query", b"/a?b"), ("empty", b""), ("no-slash", b"a"), ("star", b"*"), ("absolute", b"http://example.com/"), ("space", b"/a b"), ("nul", b"/a\x00"),
                   ("high", b"/\xe9"), ("fragment", b"/a#b"), ("ctl", b"/\x01"), ("percent", b"/%zz"), ("double-slash", b"//a"), ("dot-dot", b"/../a"), ("long-8k", b"/" + b"a" * 8000), ("tab", b"/a\tb"), ("backslash", b"/a\\b"), ("asterisk-options", b"*")):
        only(req(path=p, method=b"OPTIONS" if tag == "asterisk-options" else b"GET"), "rfc9113-8.3.1:path-%s" % tag)
    for tag, s in (("http", b"http"), ("https", b"https"), ("empty", b""), ("ftp", b"ftp"), ("upper", b"HTTPS"), ("junk", b"h t"), ("with-slash", b"http://"), ("long", b"a" * 100)):
        only(req(scheme=s), "rfc9113-8.3.1:scheme-%s" % tag)
    for tag, a in (("plain", b"example.com"), ("port", b"example.com:8443"), ("empty", b""), ("userinfo", b"u@example.com"), ("userinfo-pw", b"u:p@example.com"), ("space", b"a b"),
                   ("ipv6", b"[::1]:80"), ("upper", b"EXAMPLE.com"), ("nul", b"a\x00b"), ("slash", b"a/b"), ("trailing-dot", b"example.com."), ("long", b"a" * 300)):
        only(req(authority=a), "rfc9113-8.3.1:authority-%s" % tag)
    only(req(authority=b"example.com") + [(b"host", b"other.test")], "rfc9113-8.3.1:authority-host-differ")
    only(req(authority=b"example.com") + [(b"host", b"example.com")], "rfc9113-8.3.1:authority-host-same")
    only(req(authority=b"Example.COM") + [(b"host", b"example.com")], "rfc9113-8.3.1:authority-host-case")
    only(req(authority=None) + [(b"host", b"example.com")], "rfc9113-8.3.1:host-only")
    only(req(authority=None) + [(b"host", b"a"), (b"host", b"b")], "rfc9113-8.3.1:host-twice-no-authority")
    only([(b":method", b"OPTIONS"), (b":scheme", b"https"), (b":path", b"*")], "rfc9113-8.3.1:options-star")
    # 8.5 CONNECT
    only([(b":method", b"CONNECT"), (b":authority", b"example.com:443")], "rfc9113-8.5:connect", END_HEADERS)
    only([(b":method", b"CONNECT"), (b":authority", b"example.com:443")], "rfc9113-8.5:connect-end-stream")
    only([(b":method", b"CONNECT"), (b":authority", b"example.com:443"), (b":path", b"/")], "rfc9113-8.5:connect-with-path")
    only([(b":method", b"CONNECT"), (b":authority", b"example.com:443"), (b":scheme", b"https")], "rfc9113-8.5:connect-with-scheme")
    only([(b":method", b"CONNECT"), (b":scheme", b"https"), (b":authority", b"example.com:443"), (b":path", b"/")], "rfc9113-8.5:connect-with-everything")
    only([(b":method", b"CONNECT")], "rfc9113-8.5:connect-no-authority")
    only([(b":method", b"CONNECT"), (b":authority", b"example.com")], "rfc9113-8.5:connect-no-port")
    only([(b":method", b"CONNECT"), (b":authority", b"")], "rfc9113-8.5:connect-empty-authority")
    add("rfc9113-8.5:connect-with-data", O + hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:1")], END_HEADERS) + frame(DATA, 0, 1, b"tunnel bytes") + frame(DATA, END_STREAM, 1, b"more"))
    add("rfc9113-8.5:connect-with-content-length-data", O + hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:1"), (b"content-length", b"2")], END_HEADERS) + frame(DATA, END_STREAM, 1, b"tunnel bytes"))
    add("rfc9113-8.5:connect-then-headers", O + hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:1")], END_HEADERS) + hdrs(1, [(b"x", b"1")]))
    add("rfc9113-8.5:connect-then-priority", O + hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:1")], END_HEADERS) + frame(PRIORITY, 0, 1, u32(0) + b"\x10"))
    # response pseudo-headers sent to a server (a client may not send them)
    only([(b":status", b"200")], "rfc9113-8.3.2:status-as-request")
    # 8.2.2 and 8.6
    add("rfc9113-8.6:upgrade-h2c-request", O + hdrs(1, req((b"connection", b"Upgrade, HTTP2-Settings"), (b"upgrade", b"h2c"), (b"http2-settings", b"AAMAAABk"))))
    add("rfc9113-8.6:http2-settings-field", O + hdrs(1, req((b"http2-settings", b"AAMAAABk"))))
    add("rfc9113-5.5:priority-update-extension-frame", O + frame(0x10, 0, 0, u32(1) + b"u=3"))
    add("rfc9113-5.5:altsvc-extension-frame", O + frame(0x0a, 0, 0, struct.pack(">H", 0) + b""))
    add("rfc9113-5.5:origin-extension-frame", O + frame(0x0c, 0, 0, b""))
    return out


# ---- HPACK hand-written (decode) ---------------------------------------------------------------

def hand_hd():
    out = []

    def add(tag, data, table=4096):
        out.append((tag, "hd", str(table), data))

    add("rfc7541-6.1:indexed-static-2", idx(2))
    add("rfc7541-6.1:indexed-static-61", idx(61))
    add("rfc7541-6.1:indexed-zero", b"\x80")
    add("rfc7541-6.1:indexed-62-empty-table", idx(62))
    add("rfc7541-6.1:indexed-far", idx(100000))
    add("rfc7541-6.1:indexed-multi-octet-62", hpack_int(62, 7, 0x80))
    add("rfc7541-6.1:indexed-overlong-zero-pad", b"\xff\x80\x80\x80\x80\x00")
    add("rfc7541-5.1:integer-overflow-2^32", b"\xff" + b"\xff\xff\xff\xff\x0f")
    add("rfc7541-5.1:integer-truncated", b"\xff\x80")
    add("rfc7541-5.1:integer-2^31", b"\xff\x81\xff\xff\xff\x07")
    add("rfc7541-6.2.1:literal-incremental-new-name", lit_inc(b"custom-key", b"custom-header"))
    add("rfc7541-6.2.1:literal-incremental-indexed-name", lit_idx(1, b"www.example.com", 6, 0x40))
    add("rfc7541-6.2.1:literal-incremental-then-indexed", lit_inc(b"a", b"b") + idx(62))
    add("rfc7541-6.2.1:literal-incremental-twice-then-both", lit_inc(b"a", b"1") + lit_inc(b"b", b"2") + idx(62) + idx(63))
    add("rfc7541-6.2.1:literal-incremental-name-index-62", lit_inc(b"a", b"b") + lit_idx(62, b"c", 6, 0x40))
    add("rfc7541-6.2.1:literal-incremental-name-index-beyond", lit_idx(70, b"c", 6, 0x40))
    add("rfc7541-6.2.2:literal-no-index-new-name", lit(b"custom-key", b"custom-header"))
    add("rfc7541-6.2.2:literal-no-index-indexed-name", lit_idx(4, b"/sample/path"))
    add("rfc7541-6.2.2:literal-no-index-then-ref", lit(b"a", b"b") + idx(62))
    add("rfc7541-6.2.3:literal-never-new-name", lit_never(b"password", b"secret"))
    add("rfc7541-6.2.3:literal-never-indexed-name", lit_idx(23, b"secret", 4, 0x10))
    add("rfc7541-6.2:literal-empty-name", lit(b"", b"v"))
    add("rfc7541-6.2:literal-empty-value", lit(b"n", b""))
    add("rfc7541-6.2:literal-empty-both", lit(b"", b""))
    add("rfc7541-6.2:literal-name-index-zero-explicit", b"\x00" + S(b"n") + S(b"v"))
    add("rfc7541-6.2:literal-nul-in-value", lit(b"n", b"a\x00b"))
    add("rfc7541-6.2:literal-high-octets", lit(b"n\xe9", b"\xff\xfe"))
    add("rfc7541-6.2:literal-uppercase-name", lit(b"N", b"v"))
    add("rfc7541-5.2:string-truncated", b"\x00" + hpack_int(10, 7) + b"abc")
    add("rfc7541-5.2:string-length-missing", b"\x00")
    add("rfc7541-5.2:value-missing", b"\x00" + S(b"n"))
    add("rfc7541-5.2:string-long-300", lit(b"n", b"v" * 300))
    add("rfc7541-5.2:string-long-70000", lit(b"n", b"v" * 70000))
    add("rfc7541-5.2:string-length-huge", b"\x00" + hpack_int(2 ** 31 - 1, 7) + b"abc")
    add("rfc7541-5.2:huffman-www-example-com", b"\x41" + SH(b"www.example.com"))
    add("rfc7541-5.2:huffman-value", b"\x00" + S(b"n") + SH(b"some value 123"))
    add("rfc7541-5.2:huffman-name-and-value", b"\x40" + SH(b"custom-key") + SH(b"custom-value"))
    add("rfc7541-5.2:huffman-empty", b"\x00" + S(b"n") + b"\x80")
    add("rfc7541-5.2:huffman-all-256-octets", b"\x00" + S(b"n") + SH(bytes(range(256))))
    add("rfc7541-5.2:huffman-eos-in-string", b"\x00" + S(b"n") + b"\x84\xff\xff\xff\xff")
    add("rfc7541-5.2:huffman-padding-8-bits", b"\x00" + S(b"n") + b"\x82\x07\xff")
    add("rfc7541-5.2:huffman-padding-not-ones", b"\x00" + S(b"n") + b"\x81\x00")
    add("rfc7541-5.2:huffman-padding-7-ones", b"\x00" + S(b"n") + b"\x81\x07")
    add("rfc7541-5.2:huffman-padding-whole-octet-of-ones", b"\x00" + S(b"n") + b"\x81\xff")
    add("rfc7541-5.2:huffman-padding-one-bit-short", b"\x00" + S(b"n") + b"\x82\x1f\xfe")
    add("rfc7541-5.2:huffman-truncated-symbol", b"\x00" + S(b"n") + b"\x81\xfe")
    add("rfc7541-5.2:huffman-30-bit-symbol", b"\x00" + S(b"n") + b"\x84\xff\xff\xfe\x3f")
    add("rfc7541-5.2:huffman-length-lies", b"\x00" + S(b"n") + b"\x85" + huff(b"abc"))
    for size in (0, 1, 31, 32, 100, 4096, 4097, 65536):
        add("rfc7541-6.3:table-size-update-%d" % size, hpack_int(size, 5, 0x20) + idx(2))
    add("rfc7541-6.3:table-size-update-alone", hpack_int(100, 5, 0x20))
    add("rfc7541-6.3:table-size-update-twice", hpack_int(0, 5, 0x20) + hpack_int(200, 5, 0x20) + idx(2))
    add("rfc7541-6.3:table-size-update-three-times", hpack_int(0, 5, 0x20) + hpack_int(10, 5, 0x20) + hpack_int(200, 5, 0x20) + idx(2))
    add("rfc7541-6.3:table-size-update-after-field", idx(2) + hpack_int(100, 5, 0x20))
    add("rfc7541-6.3:table-size-update-after-literal", lit(b"a", b"b") + hpack_int(100, 5, 0x20))
    add("rfc7541-6.3:table-size-update-zero-evicts", lit_inc(b"a", b"b") + hpack_int(0, 5, 0x20) + idx(62))
    add("rfc7541-6.3:table-size-update-above-limit", hpack_int(5000, 5, 0x20) + idx(2))
    add("rfc7541-6.3:table-size-update-above-limit-small-table", hpack_int(100, 5, 0x20) + idx(2), 50)
    add("rfc7541-6.3:table-size-update-equal-limit-small-table", hpack_int(50, 5, 0x20) + idx(2), 50)
    add("rfc7541-4.4:entry-larger-than-table", lit_inc(b"a", b"b" * 100) + idx(62), 64)
    add("rfc7541-4.4:entry-exactly-table", lit_inc(b"a", b"b" * 31) + idx(62), 64)
    add("rfc7541-4.4:entry-one-over-table", lit_inc(b"a", b"b" * 32) + idx(62), 64)
    add("rfc7541-4.4:eviction-order", lit_inc(b"a", b"1") + lit_inc(b"b", b"2") + lit_inc(b"c", b"3") + idx(62) + idx(63), 100)
    add("rfc7541-4.4:name-from-evicted-entry", lit_inc(b"a", b"1") + lit_idx(62, b"2", 6, 0x40) + idx(62), 40)
    add("rfc7541-4.4:table-size-zero-no-indexing", lit_inc(b"a", b"b") + idx(62), 0)
    add("rfc7541-2.3:static-table-all", b"".join(idx(i) for i in range(1, 62)))
    add("rfc7541-2.3:empty-block", b"")
    add("rfc7541-2.3:many-fields-1000", b"".join(idx(2) for _ in range(1000)))
    add("rfc7541-7.1:large-table-bomb", lit_inc(b"n", b"x" * 4000) + b"".join(idx(62) for _ in range(3000)))
    add("rfc7541-2.3:indexed-pseudo-headers", idx(2) + idx(6) + idx(4) + idx(1))
    return out


# ---- RFC 7541 Appendix C ---------------------------------------------------------------------------

def rfc_vectors():
    text = open(os.path.join(LIB, "tests", "hpack_rfc_vectors.h")).read()
    out = []
    for m in re.finditer(r'\{"(C\.[2-6]\.\d)", "([0-9a-f]*)",', text):
        eid, hx = m.group(1), m.group(2)
        # Only the examples that decode from an empty table: every C.2 example
        # and the first of each chained series.
        if eid.startswith("C.2") or eid.endswith(".1"):
            table = 256 if eid[2] in "56" else 4096
            out.append(("rfc7541-C:%s" % eid, "hd", str(table), bytes.fromhex(hx)))
    return out


# ---- encode ---------------------------------------------------------------------------------------------

def blob(fields):
    return b"".join(struct.pack(">I", len(n)) + n + struct.pack(">I", len(v)) + v for n, v in fields)


def hand_he():
    out = []

    def add(tag, fields, table=4096):
        out.append((tag, "he", str(table), blob(fields)))

    add("rfc7541-C.3:request", [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com")])
    add("rfc7541-C.5:response", [(b":status", b"302"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")], 256)
    add("rfc7541-C.2:custom", [(b"custom-key", b"custom-header")])
    add("rfc7541-5.2:empty-value", [(b"x-empty", b"")])
    add("rfc7541-5.2:long-value", [(b"x-long", b"abc" * 500)])
    add("rfc7541-5.2:all-octets", [(b"x-all", bytes(range(1, 256)))])
    add("rfc7541-7.1.3:sensitive", [(b"authorization", b"Bearer abc"), (b"cookie", b"a=b"), (b"set-cookie", b"c=d")])
    add("rfc7541-2.3:repeated", [(b"x-a", b"1"), (b"x-a", b"1"), (b"x-a", b"2"), (b"x-a", b"1")])
    add("rfc7541-4:table-zero", [(b"x-a", b"1"), (b"x-a", b"1")], 0)
    add("rfc7541-4:table-small", [(b"x-a", b"1" * 20), (b"x-b", b"2" * 20), (b"x-a", b"1" * 20)], 80)
    add("rfc7541-2.3:static-names", [(b":method", b"POST"), (b"accept-encoding", b"gzip, deflate"), (b"content-length", b"0"), (b"user-agent", b"x")])
    return out


def generated_he(rng, count):
    names = [b":method", b":path", b":status", b"accept-encoding", b"cache-control", b"cookie", b"content-length",
             b"date", b"host", b"location", b"set-cookie", b"user-agent", b"x-a", b"x-b", b"authorization", b"etag"]
    out = []
    for i in range(count):
        n = rng.randint(1, 12)
        fields = []
        for _ in range(n):
            name = rng.choice(names) if rng.random() < 0.7 else bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz-") for _ in range(rng.randint(1, 12)))
            r = rng.random()
            if r < 0.4:
                val = rng.choice([b"GET", b"POST", b"/", b"200", b"gzip", b"max-age=0", b"www.example.com", b"1", b"0"])
            elif r < 0.9:
                val = bytes(rng.randint(0x20, 0x7e) for _ in range(rng.randint(0, 60)))
            else:
                val = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 30)))
            fields.append((name, val))
        out.append(("genhe:%d-fields" % (min(n, 8)), "he", str(rng.choice([4096, 4096, 256, 0, 100])), blob(fields)))
    return out


# ---- generated mutations -------------------------------------------------------------------------------------

def _bases():
    """Valid client streams to mutate: (name, [frames as bytes]) after the preface."""
    b = []
    big = [(b"x-%d" % i, b"value-%d" % i) for i in range(20)]
    b.append(("get", [settings(), GET()]))
    b.append(("post", [settings(), hdrs(1, req((b"content-length", b"11"), method=b"POST"), END_HEADERS), frame(DATA, 0, 1, b"hello "), frame(DATA, END_STREAM, 1, b"world")]))
    b.append(("trailers", [settings(), POST_open(), frame(DATA, 0, 1, b"x"), hdrs(1, [(b"x-trail", b"t")])]))
    blk = block(req(*big))
    b.append(("continuation", [settings(), frame(HEADERS, END_STREAM, 1, blk[:30]), frame(CONTINUATION, 0, 1, blk[30:60]), frame(CONTINUATION, END_HEADERS, 1, blk[60:])]))
    b.append(("control", [settings([(3, 50), (4, 1000)]), settings(ack=True), frame(PING, 0, 0, b"12345678"), frame(WINDOW_UPDATE, 0, 0, u32(100)), frame(PRIORITY, 0, 3, u32(0) + b"\x10"), GET(1)]))
    b.append(("rst", [settings(), POST_open(1), frame(DATA, 0, 1, b"abc"), frame(RST_STREAM, 0, 1, u32(8)), GET(3)]))
    b.append(("padded", [settings(), POST_open(1), frame(DATA, PADDED, 1, b"\x03abc\0\0\0"), frame(HEADERS, END_HEADERS | END_STREAM | PADDED | PRIORITY_FLAG, 3, b"\x02" + u32(0) + b"\x10" + block(req()) + b"\0\0")]))
    b.append(("dynamic", [settings(), frame(HEADERS, END_HEADERS | END_STREAM, 1, lit_inc(b":method", b"GET") + lit_inc(b":scheme", b"https") + lit_inc(b":path", b"/") + lit_inc(b":authority", b"example.com") + lit_inc(b"x-a", b"1")),
                          frame(HEADERS, END_HEADERS | END_STREAM, 3, idx(62) + idx(63) + idx(64) + idx(65) + idx(66) + lit_idx(66, b"2", 6, 0x40))]))
    b.append(("huffman", [settings(), frame(HEADERS, END_HEADERS | END_STREAM, 1, b"\x82\x87\x84\x41" + SH(b"www.example.com") + b"\x40" + SH(b"x-key") + SH(b"x-value"))]))
    b.append(("connect", [settings(), hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:443")], END_HEADERS), frame(DATA, 0, 1, b"tunnel"), frame(DATA, END_STREAM, 1, b"end")]))
    b.append(("goaway", [settings(), GET(1), frame(GOAWAY, 0, 0, u32(0) + u32(0) + b"bye")]))
    b.append(("multi", [settings(), GET(1, (b"x-n", b"1")), GET(3, (b"x-n", b"2")), hdrs(5, req((b"content-length", b"2"), method=b"POST"), END_HEADERS), frame(DATA, END_STREAM, 5, b"ab"), GET(7, (b"x-n", b"4"))]))
    return b


def _frame_spans(frames):
    spans = []
    off = len(PREFACE)
    for f in frames:
        spans.append((off, off + len(f), f[3] if len(f) > 3 else 0))
        off += len(f)
    return spans


def _where(frames, pos):
    """The frame type and field of the octet at pos of PREFACE + frames."""
    if pos < len(PREFACE):
        return "preface"
    for (a, b, t), f in zip(_frame_spans(frames), frames):
        if a <= pos < b:
            i = pos - a
            tn = FNAMES[t] if t < len(FNAMES) else "unknown"
            if i < 3:
                return tn + ".length"
            if i == 3:
                return tn + ".type"
            if i == 4:
                return tn + ".flags"
            if i < 9:
                return tn + ".stream"
            return tn + ".payload"
    return "end"


def generated(seed, count, bases=None, arg="-", tag="gen"):
    rng = random.Random(seed)
    bases = _bases() if bases is None else bases
    seen = set()
    out = []
    specials = [0, 1, 2, 4, 5, 0x7f, 0x80, 0xff, 0x20, 0x3a, 0x0a, 0x0d, 0x40]
    for _ in range(count):
        name, frames = rng.choice(bases)
        stream = PREFACE + b"".join(frames)
        op = rng.choice(["flip", "set", "insert", "delete", "truncate", "dup-frame", "drop-frame", "swap-frames", "len+", "len-", "type", "flags", "sid", "split-frame"])
        data = stream
        where = "frame"
        if op in ("flip", "set", "insert", "delete", "truncate", "len+", "len-", "type", "flags", "sid"):
            if op in ("len+", "len-", "type", "flags", "sid"):
                k = rng.randrange(len(frames))
                a, b, t = _frame_spans(frames)[k]
                if op in ("len+", "len-"):
                    pos = a + 2
                    d = 1 if op == "len+" else -1
                    ln = int.from_bytes(stream[a:a + 3], "big") + d
                    if ln < 0:
                        continue
                    data = stream[:a] + ln.to_bytes(3, "big") + stream[a + 3:]
                elif op == "type":
                    pos = a + 3
                    data = stream[:pos] + bytes([rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xee])]) + stream[pos + 1:]
                elif op == "flags":
                    pos = a + 4
                    data = stream[:pos] + bytes([stream[pos] ^ (1 << rng.randrange(8))]) + stream[pos + 1:]
                else:
                    pos = a + 5 + rng.randrange(4)
                    data = stream[:pos] + bytes([rng.choice(specials)]) + stream[pos + 1:]
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
            where = _where(frames, pos)
        else:
            k = rng.randrange(len(frames))
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
            else:  # split-frame: the payload as two frames of the same type
                f = frames[k]
                if len(f) <= 10:
                    continue
                cut = rng.randrange(10, len(f))
                t, fl = f[3], f[4]
                sid = int.from_bytes(f[5:9], "big")
                fr = frames[:k] + [frame(t, fl & ~END_HEADERS, sid, f[9:cut]), frame(t if t != HEADERS else CONTINUATION, fl, sid, f[cut:])] + frames[k + 1:]
            data = PREFACE + b"".join(fr)
            where = (FNAMES[frames[k][3]] if frames[k][3] < len(FNAMES) else "unknown") + ".frame"
        if data == stream or (op, where, data) in seen:
            continue
        seen.add((op, where, data))
        out.append(("%s:%s@%s" % (tag, op, where), "h2", arg, data))
    return out


def xreq(*extra, method=b"CONNECT", protocol=b"websocket", path=b"/chat", scheme=b"https",
         authority=b"server.example.com"):
    """An Extended CONNECT request (RFC 8441 section 4), in the order of its examples."""
    f = [(b":method", method)]
    if protocol is not None:
        f.append((b":protocol", protocol))
    if scheme is not None:
        f.append((b":scheme", scheme))
    if path is not None:
        f.append((b":path", path))
    if authority is not None:
        f.append((b":authority", authority))
    return f + list(extra)


WS_FIELDS = [(b"sec-websocket-protocol", b"chat, superchat"), (b"sec-websocket-extensions", b"permessage-deflate"),
             (b"sec-websocket-version", b"13"), (b"origin", b"http://www.example.com")]


def _xc_bases():
    """Valid Extended CONNECT client streams to mutate (arg xc)."""
    b = []
    b.append(("xc-websocket", [settings(), hdrs(1, xreq(*WS_FIELDS), END_HEADERS), frame(DATA, 0, 1, b"\x81\x85abcd12345"), frame(DATA, END_STREAM, 1, b"")]))
    b.append(("xc-two-tunnels", [settings(), hdrs(1, xreq(), END_HEADERS), hdrs(3, xreq(path=b"/other"), END_HEADERS), frame(DATA, 0, 3, b"abc"), frame(RST_STREAM, 0, 1, u32(8)), frame(DATA, END_STREAM, 3, b"")]))
    b.append(("xc-plain-connect", [settings(), hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:443")], END_HEADERS), frame(DATA, END_STREAM, 1, b"tunnel")]))
    b.append(("xc-ended", [settings(), hdrs(1, xreq(), END_HEADERS | END_STREAM)]))
    return b


def generated_xc(seed, count):
    return generated(seed + 77, count, _xc_bases(), "xc", "gen")


def extconnect():
    """Hand-written Extended CONNECT cases (RFC 8441): `arg` xc is a server that sent the setting."""
    out = []

    def add(tag, data, arg="xc"):
        out.append(("rfc8441-" + tag, "h2", arg, data))

    O = OPEN
    # section 3: the setting
    for v in (0, 1, 2, 0xffffffff):
        add("3:client-sends-setting-%d" % v, PREFACE + settings([(8, v)]) + GET(), "xc")
    add("3:client-sends-setting-1-then-0", PREFACE + settings([(8, 1)]) + settings([(8, 0)]) + GET(), "xc")
    # section 4: the request
    add("4:websocket", O + hdrs(1, xreq(), END_HEADERS) + frame(DATA, 0, 1, b"hello") + frame(DATA, END_STREAM, 1, b""))
    add("4:websocket-ended-with-headers", O + hdrs(1, xreq()))
    add("4:rfc-example", O + hdrs(1, xreq(*WS_FIELDS), END_HEADERS))
    add("4:websocket-setting-off", O + hdrs(1, xreq(), END_HEADERS), "-")
    add("4:websocket-setting-off-then-get", O + hdrs(1, xreq(), END_HEADERS) + GET(3), "-")
    for pr in (b"connect-udp", b"h2c", b"x-foo/1", b"WebSocket", b"a/b/c", b"/b", b"a/", b"web socket", b"a,b",
               b"", b"w" * 64, b"w" * 65, b"w" * 200, b"w" * 5000):
        add("4:protocol-%s" % (pr.decode()[:20].replace("/", "slash").replace(" ", "sp").replace(",", "comma") or "empty").encode().decode(),
            O + hdrs(1, xreq(protocol=pr), END_HEADERS))
    for m in (b"GET", b"POST", b"OPTIONS", b"connect"):
        add("4:protocol-on-%s" % m.decode(), O + hdrs(1, xreq(method=m), END_HEADERS))
    add("4:no-path", O + hdrs(1, xreq(path=None), END_HEADERS))
    add("4:no-scheme", O + hdrs(1, xreq(scheme=None), END_HEADERS))
    add("4:no-authority", O + hdrs(1, xreq(authority=None), END_HEADERS))
    add("4:empty-path", O + hdrs(1, xreq(path=b""), END_HEADERS))
    add("4:path-without-slash", O + hdrs(1, xreq(path=b"chat"), END_HEADERS))
    add("4:path-asterisk", O + hdrs(1, xreq(path=b"*"), END_HEADERS))
    add("4:authority-userinfo", O + hdrs(1, xreq(authority=b"u@server.example.com"), END_HEADERS))
    add("4:host-differs", O + hdrs(1, xreq((b"host", b"other.example.com")), END_HEADERS))
    add("4:host-same", O + hdrs(1, xreq((b"host", b"server.example.com")), END_HEADERS))
    add("4:duplicate-protocol", O + hdrs(1, [(b":method", b"CONNECT"), (b":protocol", b"websocket"), (b":protocol", b"websocket"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"h")], END_HEADERS))
    add("4:protocol-after-regular-field", O + hdrs(1, [(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"h"), (b"x", b"1"), (b":protocol", b"websocket")], END_HEADERS))
    add("4:protocol-uppercase-name", O + hdrs(1, [(b":method", b"CONNECT"), (b":Protocol", b"websocket"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"h")], END_HEADERS))
    add("4:plain-connect", O + hdrs(1, [(b":method", b"CONNECT"), (b":authority", b"h:443")], END_HEADERS) + frame(DATA, END_STREAM, 1, b"x"))
    add("4:plain-connect-with-scheme", O + hdrs(1, [(b":method", b"CONNECT"), (b":scheme", b"https"), (b":authority", b"h:443")], END_HEADERS))
    add("4:plain-connect-with-path", O + hdrs(1, [(b":method", b"CONNECT"), (b":path", b"/"), (b":authority", b"h:443")], END_HEADERS))
    add("4:connect-scheme-path-no-protocol", O + hdrs(1, [(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"h:443")], END_HEADERS))
    # the tunnel
    add("4:tunnel-content-length", O + hdrs(1, xreq((b"content-length", b"2")), END_HEADERS) + frame(DATA, END_STREAM, 1, b"far more than two"))
    add("4:tunnel-data-then-end", O + hdrs(1, xreq(), END_HEADERS) + frame(DATA, 0, 1, b"a") + frame(DATA, 0, 1, b"b") + frame(DATA, END_STREAM, 1, b"c"))
    add("4:tunnel-trailers", O + hdrs(1, xreq(), END_HEADERS) + frame(DATA, 0, 1, b"a") + hdrs(1, [(b"x-t", b"1")]))
    add("4:tunnel-reset", O + hdrs(1, xreq(), END_HEADERS) + frame(DATA, 0, 1, b"partial") + frame(RST_STREAM, 0, 1, u32(8)))
    add("4:tunnel-data-after-end", O + hdrs(1, xreq(), END_HEADERS) + frame(DATA, END_STREAM, 1, b"a") + frame(DATA, 0, 1, b"b"))
    add("4:tunnel-data-after-reset", O + hdrs(1, xreq(), END_HEADERS) + frame(RST_STREAM, 0, 1, u32(8)) + frame(DATA, 0, 1, b"b"))
    add("4:tunnel-window-update", O + hdrs(1, xreq(), END_HEADERS) + frame(WINDOW_UPDATE, 0, 1, u32(1000)) + frame(DATA, END_STREAM, 1, b"a"))
    add("4:tunnel-padded-data", O + hdrs(1, xreq(), END_HEADERS) + frame(DATA, PADDED | END_STREAM, 1, b"\x02ab\0\0"))
    add("4:three-tunnels", O + b"".join(hdrs(i, xreq(path=b"/%d" % i), END_HEADERS) for i in (1, 3, 5)) + frame(DATA, END_STREAM, 3, b"x"))
    add("4:tunnel-then-get", O + hdrs(1, xreq(), END_HEADERS) + GET(3) + frame(DATA, END_STREAM, 1, b"x"))
    add("4:tunnel-in-continuation", O + frame(HEADERS, 0, 1, block(xreq())[:20]) + frame(CONTINUATION, END_HEADERS, 1, block(xreq())[20:]))
    return out


def generated_hd(seed, count):
    rng = random.Random(seed + 1000)
    base = [lit_inc(b"custom-key", b"custom-header"), b"\x82\x86\x84\x41" + SH(b"www.example.com"), lit(b"a", b"b") + lit_never(b"c", b"d"),
            hpack_int(100, 5, 0x20) + lit_inc(b"x", b"y") + idx(62), lit_idx(1, b"example.com", 6, 0x40) + idx(2) + b"\x00" + S(b"n") + SH(b"value")]
    seen = set()
    out = []
    for _ in range(count):
        b = rng.choice(base)
        pos = rng.randrange(len(b) + 1)
        op = rng.choice(["flip", "set", "insert", "delete", "truncate"])
        if op == "truncate":
            d = b[:pos]
        elif pos == len(b):
            continue
        elif op == "flip":
            d = b[:pos] + bytes([b[pos] ^ (1 << rng.randrange(8))]) + b[pos + 1:]
        elif op == "set":
            d = b[:pos] + bytes([rng.choice([0, 0x7f, 0x80, 0xff, 0x20, 0x40, 0x3f, 0x1f])]) + b[pos + 1:]
        elif op == "insert":
            d = b[:pos] + bytes([rng.randrange(256)]) + b[pos:]
        else:
            d = b[:pos] + b[pos + 1:]
        if d == b or d in seen:
            continue
        seen.add(d)
        cls = "head" if pos == 0 else "mid"
        out.append(("genhd:%s@%s" % (op, cls), "hd", str(rng.choice([4096, 4096, 100])), d))
    return out


def all_cases(seed=1, count=40000, hd_count=6000, he_count=400, xc_count=3000):
    """Every case with ids assigned: dicts of id, kind, arg, tag, data."""
    rng = random.Random(seed)
    raw = (hand() + extconnect() + hand_hd() + rfc_vectors() + hand_he() + generated_he(rng, he_count)
           + generated_hd(seed, hd_count) + generated(seed, count) + generated_xc(seed, xc_count))
    cases = []
    seen = set()
    for tag, kind, arg, data in raw:
        key = (kind, arg, data)
        if key in seen:
            continue
        seen.add(key)
        if kind in ("hd", "he"):
            tag += "/t" + arg  # the table size is part of what the case is
        cases.append({"id": len(cases), "kind": kind, "arg": arg, "tag": tag, "data": data})
    return cases


def dump(path, cases):
    """The cases as TSV lines, split whole and byte for h2: for runs where the
    references cannot be reached (other architectures, Windows)."""
    with open(path, "w") as out:
        for c in cases:
            for split in (("whole", "byte") if c["kind"] == "h2" else ("whole",)):
                out.write("%d\t%s\t%s\t%s\t%s\n" % (c["id"], c["kind"], split, c["arg"], c["data"].hex()))


if __name__ == "__main__":
    import sys
    cs = all_cases()
    import collections
    k = collections.Counter(c["kind"] for c in cs)
    print(len(cs), dict(k))
    if len(sys.argv) > 1:
        dump(sys.argv[1], cs)
