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
"""The differential's corpus.

A case is (id, kind, method, tag, data): `kind` is "req" or "res", `method` is
the request method a response answers ("-" for none), `tag` names the rule or
the shape the case was written to hold, and `data` is the whole stream.

Where the cases come from, and why each source is here:

  hand      Written from RFC 9112 and from the smuggling literature, one case
            per rule, valid AND invalid. The invalid ones are the point: two
            parsers agree on every message both accept, and the whole value of
            a differential is in which malformed messages each one turns away.
  rfc       The message examples in RFC 9112 itself.
  fixture   Every HTTP message literal in this library's own unit tests, so a
            reference is asked everything this library was ever asked.
  seed      The tracked libFuzzer seeds. (A local fuzz corpus can be added
            with --fuzz-corpus; it is not part of the gate, because it is a
            directory a run grows and the gate must be repeatable.)
  gen       Single mutations of valid messages, from a seeded generator: delete
            a CR, turn a CRLF into a bare LF, insert a control byte, repeat a
            field, cut the stream short. One mutation per case, so a
            disagreement names its cause.

The generator is seeded and its output is a pure function of (seed, count).
"""

import os
import random
import re

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.dirname(os.path.dirname(HERE))

CRLF = b"\r\n"


def msg(*lines, body=b"", eol=CRLF):
    """Lines joined by eol, then the empty line, then the body."""
    return eol.join(lines) + eol + eol + body


H = b"Host: h"


def hand():
    """(tag, kind, method, bytes) for every handwritten case."""
    out = []

    def add(tag, data, kind="req", method="-"):
        out.append((tag, kind, method, data))

    # ---- requests: valid ------------------------------------------------
    add("valid", msg(b"GET / HTTP/1.1", H))
    add("valid", msg(b"GET /a/b?x=1&y=2 HTTP/1.1", H))
    add("valid-absolute", msg(b"GET http://h/p?q HTTP/1.1", H))
    add("valid-asterisk", msg(b"OPTIONS * HTTP/1.1", H))
    add("valid-connect", msg(b"CONNECT h:443 HTTP/1.1", b"Host: h:443"))
    add("valid-http10", msg(b"GET / HTTP/1.0"))
    add("valid-http10", msg(b"GET / HTTP/1.0", H))
    add("valid", msg(b"POST /p HTTP/1.1", H, b"Content-Length: 5", body=b"hello"))
    add("valid", msg(b"POST /p HTTP/1.1", H, b"Content-Length: 0"))
    add("valid-chunked", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"))
    add("valid-chunked", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"0\r\n\r\n"))
    add("chunk-ext", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"5;name=value\r\nhello\r\n0\r\n\r\n"))
    add("chunk-ext", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"5;a;b=\"q;q\"\r\nhello\r\n0;done\r\n\r\n"))
    add("chunk-hex-upper", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"A\r\n0123456789\r\n0\r\n\r\n"))
    add("chunk-hex-upper", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"a\r\n0123456789\r\n0\r\n\r\n"))
    add("chunk-leading-zeros", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"0005\r\nhello\r\n0000\r\n\r\n"))
    add("trailers", msg(b"POST /p HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"3\r\nabc\r\n0\r\nX-Sum: 1\r\nX-Other: two\r\n\r\n"))
    add("header-dup", msg(b"GET / HTTP/1.1", H, b"X: 1", b"X: 2", b"x: 3"))
    add("header-ows", msg(b"GET / HTTP/1.1", H, b"X:   padded  \t "))
    add("header-ows", msg(b"GET / HTTP/1.1", H, b"X:\tv"))
    add("header-empty-value", msg(b"GET / HTTP/1.1", H, b"X:"))
    add("header-obs-text", msg(b"GET / HTTP/1.1", H, b"X: caf\xe9 \xff\x80"))
    add("header-inner-ws", msg(b"GET / HTTP/1.1", H, b"X: a  b\tc"))
    add("pipelined", msg(b"GET /1 HTTP/1.1", H) + msg(b"GET /2 HTTP/1.1", H))
    add("pipelined", msg(b"POST /1 HTTP/1.1", H, b"Content-Length: 3", body=b"abc")
        + msg(b"GET /2 HTTP/1.1", H))
    add("pipelined", msg(b"POST /1 HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"1\r\nx\r\n0\r\n\r\n") + msg(b"GET /2 HTTP/1.1", H))
    add("leading-empty-lines", CRLF + msg(b"GET / HTTP/1.1", H))
    add("leading-empty-lines", CRLF + CRLF + CRLF + msg(b"GET / HTTP/1.1", H))
    add("empty-line-after", msg(b"GET / HTTP/1.1", H) + CRLF)
    add("empty-line-after", msg(b"POST / HTTP/1.1", H, b"Content-Length: 2", body=b"ok") + CRLF + CRLF)
    add("leading-empty-lines-lf", b"\n" + msg(b"GET / HTTP/1.1", H))
    add("cl-list-same", msg(b"POST / HTTP/1.1", H, b"Content-Length: 5, 5", body=b"hello"))
    add("cl-dup-same", msg(b"POST / HTTP/1.1", H, b"Content-Length: 5",
        b"Content-Length: 5", body=b"hello"))
    add("method-lower", msg(b"get / HTTP/1.1", H))
    add("method-unknown", msg(b"FOOBAR / HTTP/1.1", H))
    add("method-token-chars", msg(b"M-SEARCH * HTTP/1.1", H))
    add("method-bad-char", msg(b"GE@T / HTTP/1.1", H))
    add("method-empty", msg(b" / HTTP/1.1", H))
    add("long-target", msg(b"GET /" + b"a" * 5000 + b" HTTP/1.1", H))
    add("many-headers", msg(b"GET / HTTP/1.1", H,
        *[b"X-%d: v" % i for i in range(90)]))
    add("target-fragment", msg(b"GET /a#frag HTTP/1.1", H))
    add("target-pct", msg(b"GET /a%20b%zz HTTP/1.1", H))
    add("expect", msg(b"POST / HTTP/1.1", H, b"Expect: 100-continue",
        b"Content-Length: 2", body=b"ok"))
    # ---- request framing ---------------------------------------------------
    add("te-gzip-chunked", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: gzip, chunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-chunked-not-last", msg(b"POST / HTTP/1.1", H,
        b"Transfer-Encoding: chunked, gzip", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-identity", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: identity"))
    add("te-case", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: Chunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-unknown", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: foo",
        body=b"x"))
    add("te-xchunked", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: xchunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-chunked-twice", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked",
        b"Transfer-Encoding: chunked", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-two-fields", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: gzip",
        b"Transfer-Encoding: chunked", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-chunked-then-field", msg(b"POST / HTTP/1.1", H,
        b"Transfer-Encoding: chunked", b"Transfer-Encoding: gzip",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-empty", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding:", body=b""))
    add("te-trailing-ows", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked\t",
        body=b"4\r\nWiki\r\n0\r\n\r\n"))
    add("te-trailing-ows", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked ",
        body=b"4\r\nWiki\r\n0\r\n\r\n"))
    add("te-empty-element", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: , chunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-param", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked;q=1",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-http10", msg(b"POST / HTTP/1.0", b"Transfer-Encoding: chunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("cl-te", msg(b"POST / HTTP/1.1", H, b"Content-Length: 4",
        b"Transfer-Encoding: chunked", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("cl-te", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked",
        b"Content-Length: 4", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("cl-te-smuggle", msg(b"POST / HTTP/1.1", H, b"Content-Length: 6",
        b"Transfer-Encoding: chunked",
        body=b"0\r\n\r\nG") + b"ET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n")
    add("te-space-colon", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding : chunked",
        b"Content-Length: 4", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-tab-value", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding:\tchunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    add("te-obs-fold", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding:",
        b" chunked", body=b"1\r\nx\r\n0\r\n\r\n"))
    add("cl-dup-diff", msg(b"POST / HTTP/1.1", H, b"Content-Length: 5",
        b"Content-Length: 6", body=b"hello!"))
    add("cl-list-diff", msg(b"POST / HTTP/1.1", H, b"Content-Length: 5, 6", body=b"hello!"))
    for tag, value in [("cl-negative", b"-1"), ("cl-plus", b"+5"),
                       ("cl-inner-space", b"5 5"), ("cl-hex", b"0x5"),
                       ("cl-empty", b""), ("cl-overflow", b"99999999999999999999"),
                       ("cl-leading-zeros", b"005"), ("cl-trailing-comma", b"5,"),
                       ("cl-leading-comma", b",5"), ("cl-alpha", b"five"),
                       ("cl-ws-comma", b"5 , 5"), ("cl-max", b"18446744073709551615"),
                       ("cl-2-64", b"18446744073709551616"),
                       ("cl-decimal", b"5.0"), ("cl-underscore", b"5_0")]:
        add(tag, msg(b"POST / HTTP/1.1", H, b"Content-Length: " + value, body=b"hello"))
    add("cl-space-colon", msg(b"POST / HTTP/1.1", H, b"Content-Length : 5", body=b"hello"))
    add("cl-name-case", msg(b"POST / HTTP/1.1", H, b"content-LENGTH: 5", body=b"hello"))
    add("cl-short-body", msg(b"POST / HTTP/1.1", H, b"Content-Length: 10", body=b"hello"))
    add("cl-long-body", msg(b"POST / HTTP/1.1", H, b"Content-Length: 2", body=b"hello"))
    add("get-with-cl", msg(b"GET / HTTP/1.1", H, b"Content-Length: 3", body=b"abc"))
    # ---- line endings and control bytes ------------------------------------
    add("bare-lf-start", b"GET / HTTP/1.1\nHost: h\r\n\r\n")
    add("bare-lf-field", b"GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n")
    add("bare-lf-all", b"GET / HTTP/1.1\nHost: h\n\n")
    add("bare-lf-end", b"GET / HTTP/1.1\r\nHost: h\r\n\n")
    add("bare-cr-value", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\rb\r\n\r\n")
    add("bare-cr-end", b"GET / HTTP/1.1\r\nHost: h\r\r\n\r\n")
    add("bare-cr-start", b"GET / HTTP/1.1\r\r\nHost: h\r\n\r\n")
    add("bare-lf-chunk-size", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"1\nx\r\n0\r\n\r\n"))
    add("bare-lf-chunk-data", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"1\r\nx\n0\r\n\r\n"))
    add("bare-lf-trailer", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"1\r\nx\r\n0\r\nT: v\n\r\n"))
    add("bare-lf-last-chunk", msg(b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked",
        body=b"1\r\nx\r\n0\n\r\n"))
    add("nul-value", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x00b\r\n\r\n")
    add("nul-name", b"GET / HTTP/1.1\r\nHost: h\r\nX\x00Y: a\r\n\r\n")
    add("nul-target", b"GET /a\x00b HTTP/1.1\r\nHost: h\r\n\r\n")
    add("ctl-value", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n")
    add("del-value", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x7fb\r\n\r\n")
    add("vt-ff-value", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x0bb\x0c\r\n\r\n")
    add("ctl-target", b"GET /a\x1fb HTTP/1.1\r\nHost: h\r\n\r\n")
    add("high-target", b"GET /caf\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n")
    # ---- fields -------------------------------------------------------------
    add("space-before-colon", msg(b"GET / HTTP/1.1", H, b"X : y"))
    add("tab-before-colon", msg(b"GET / HTTP/1.1", H, b"X\t: y"))
    add("obs-fold", msg(b"GET / HTTP/1.1", H, b"X: a", b" b"))
    add("obs-fold-tab", msg(b"GET / HTTP/1.1", H, b"X: a", b"\tb"))
    add("obs-fold-first", msg(b"GET / HTTP/1.1", b" Host: h"))
    add("name-space", msg(b"GET / HTTP/1.1", H, b"Bad Name: v"))
    add("name-paren", msg(b"GET / HTTP/1.1", H, b"Bad(Name): v"))
    add("name-empty", msg(b"GET / HTTP/1.1", H, b": v"))
    add("name-high", msg(b"GET / HTTP/1.1", H, b"X\xe9: v"))
    add("name-token-punct", msg(b"GET / HTTP/1.1", H, b"X!#$%&'*+-.^_`|~: v"))
    add("no-colon", msg(b"GET / HTTP/1.1", H, b"NoColon"))
    add("only-colon", msg(b"GET / HTTP/1.1", H, b":"))
    add("host-missing", msg(b"GET / HTTP/1.1"))
    add("host-dup", msg(b"GET / HTTP/1.1", H, b"Host: i"))
    add("host-dup-same", msg(b"GET / HTTP/1.1", H, H))
    add("host-empty", msg(b"GET / HTTP/1.1", b"Host:"))
    add("host-space", msg(b"GET / HTTP/1.1", b"Host: a b"))
    add("host-userinfo", msg(b"GET / HTTP/1.1", b"Host: u@h"))
    add("host-absolute-mismatch", msg(b"GET http://a/ HTTP/1.1", b"Host: b"))
    add("host-absolute-missing", msg(b"GET http://a/ HTTP/1.1"))
    # ---- start line ---------------------------------------------------------
    add("sp-double", b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n")
    add("sp-tab", b"GET\t/ HTTP/1.1\r\nHost: h\r\n\r\n")
    add("sp-trailing", b"GET / HTTP/1.1 \r\nHost: h\r\n\r\n")
    add("sp-leading", b" GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    add("version-missing", b"GET /\r\nHost: h\r\n\r\n")
    add("version-lower", b"GET / http/1.1\r\nHost: h\r\n\r\n")
    add("version-garbage", b"GET / HTTP/1.1x\r\nHost: h\r\n\r\n")
    add("version-short", b"GET / HTTP/1.\r\nHost: h\r\n\r\n")
    add("version-nodot", b"GET / HTTP/11\r\nHost: h\r\n\r\n")
    add("version-2", b"GET / HTTP/2.0\r\nHost: h\r\n\r\n")
    add("version-09", b"GET / HTTP/0.9\r\nHost: h\r\n\r\n")
    add("version-12", b"GET / HTTP/1.2\r\nHost: h\r\n\r\n")
    add("version-10x", b"GET / HTTP/1.10\r\nHost: h\r\n\r\n")
    add("version-pri", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    add("target-empty", b"GET  HTTP/1.1\r\nHost: h\r\n\r\n")
    add("target-space", b"GET /a b HTTP/1.1\r\nHost: h\r\n\r\n")
    add("target-asterisk-get", msg(b"GET * HTTP/1.1", H))
    add("target-authority-get", msg(b"GET h:80 HTTP/1.1", H))
    add("target-connect-origin", msg(b"CONNECT / HTTP/1.1", H))
    add("target-connect-absolute", msg(b"CONNECT http://h/ HTTP/1.1", H))
    add("target-no-slash", msg(b"GET abc HTTP/1.1", H))
    add("http09", b"GET /\r\n")
    add("empty-input", b"")
    add("only-crlf", CRLF)
    add("garbage", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
    # ---- upgrade and tunnels ------------------------------------------------
    add("upgrade", msg(b"GET / HTTP/1.1", H, b"Connection: Upgrade", b"Upgrade: websocket")
        + b"\x81\x05hello")
    add("upgrade", msg(b"GET / HTTP/1.1", H, b"Connection: Upgrade", b"Upgrade: websocket"))
    add("upgrade-no-connection", msg(b"GET / HTTP/1.1", H, b"Upgrade: websocket"))
    add("connect-tunnel", msg(b"CONNECT h:443 HTTP/1.1", b"Host: h:443") + b"\x16\x03\x01")
    # ---- chunked errors -----------------------------------------------------
    te = (b"POST / HTTP/1.1", H, b"Transfer-Encoding: chunked")
    for tag, body in [
        ("chunk-nonhex", b"g\r\nx\r\n0\r\n\r\n"),
        ("chunk-lead-space", b" 1\r\nx\r\n0\r\n\r\n"),
        ("chunk-trail-space", b"1 \r\nx\r\n0\r\n\r\n"),
        ("chunk-0x", b"0x1\r\nx\r\n0\r\n\r\n"),
        ("chunk-plus", b"+1\r\nx\r\n0\r\n\r\n"),
        ("chunk-minus", b"-1\r\nx\r\n0\r\n\r\n"),
        ("chunk-empty-size", b"\r\nx\r\n0\r\n\r\n"),
        ("chunk-huge", b"ffffffffffffffffff\r\nx\r\n0\r\n\r\n"),
        ("chunk-2-64", b"10000000000000000\r\nx\r\n0\r\n\r\n"),
        ("chunk-data-no-crlf", b"5\r\nhelloXX0\r\n\r\n"),
        ("chunk-short-data", b"5\r\nhe\r\n0\r\n\r\n"),
        ("chunk-ext-ws", b"1 ;a=b\r\nx\r\n0\r\n\r\n"),
        ("chunk-ext-badchar", b"1;a=b\x01\r\nx\r\n0\r\n\r\n"),
        ("chunk-ext-empty", b"1;\r\nx\r\n0\r\n\r\n"),
        ("chunk-ext-quoted-crlf", b"1;a=\"b\r\n\"\r\nx\r\n0\r\n\r\n"),
        ("chunk-no-last", b"1\r\nx\r\n"),
        ("chunk-no-final-crlf", b"1\r\nx\r\n0\r\n"),
        ("chunk-after-last", b"1\r\nx\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"),
        ("chunk-trailer-cl", b"1\r\nx\r\n0\r\nContent-Length: 5\r\n\r\n"),
        ("chunk-trailer-te", b"1\r\nx\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ("chunk-trailer-host", b"1\r\nx\r\n0\r\nHost: h\r\n\r\n"),
        ("chunk-trailer-badname", b"1\r\nx\r\n0\r\nB d: v\r\n\r\n"),
        ("chunk-trailer-fold", b"1\r\nx\r\n0\r\nT: a\r\n b\r\n\r\n"),
        ("chunk-trailer-nocolon", b"1\r\nx\r\n0\r\nT\r\n\r\n"),
        ("chunk-trailer-ctl", b"1\r\nx\r\n0\r\nT: a\x01\r\n\r\n"),
        ("chunk-trailer-many", b"1\r\nx\r\n0\r\n" + b"".join(b"T%d: v\r\n" % i for i in range(20)) + b"\r\n"),
    ]:
        add(tag, msg(*te, body=body))
    # ---- responses ------------------------------------------------------------
    def res(tag, data, method="-"):
        add(tag, data, "res", method)

    res("valid", msg(b"HTTP/1.1 200 OK", b"Content-Length: 5", body=b"hello"))
    res("valid", msg(b"HTTP/1.1 404 Not Found", b"Content-Length: 0"))
    res("valid-chunked", msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked",
        body=b"5\r\nhello\r\n0\r\nT: v\r\n\r\n"))
    res("close-delimited", msg(b"HTTP/1.1 200 OK", b"X: y", body=b"until the end"))
    res("close-delimited", msg(b"HTTP/1.0 200 OK", body=b"until the end"))
    res("close-delimited-empty", b"HTTP/1.1 200 OK\r\n\r\n")
    res("head-response", msg(b"HTTP/1.1 200 OK", b"Content-Length: 5"), "HEAD")
    res("head-response", msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked"), "HEAD")
    res("head-response-body", msg(b"HTTP/1.1 200 OK", b"Content-Length: 5", body=b"hello"), "HEAD")
    res("head-then-next", msg(b"HTTP/1.1 200 OK", b"Content-Length: 5")
        + msg(b"HTTP/1.1 200 OK", b"Content-Length: 2", body=b"ok"), "HEAD")
    res("status-204", msg(b"HTTP/1.1 204 No Content"))
    res("status-204-cl", msg(b"HTTP/1.1 204 No Content", b"Content-Length: 5"))
    res("status-204-cl-body", msg(b"HTTP/1.1 204 No Content", b"Content-Length: 5", body=b"hello"))
    res("status-204-te", msg(b"HTTP/1.1 204 No Content", b"Transfer-Encoding: chunked"))
    res("status-304", msg(b"HTTP/1.1 304 Not Modified", b"Content-Length: 5"))
    res("status-304", msg(b"HTTP/1.1 304 Not Modified"))
    res("status-1xx", msg(b"HTTP/1.1 100 Continue") + msg(b"HTTP/1.1 200 OK", b"Content-Length: 2", body=b"ok"))
    res("status-1xx-cl", msg(b"HTTP/1.1 102 Processing", b"Content-Length: 5", body=b"hello"))
    res("status-101", msg(b"HTTP/1.1 101 Switching Protocols", b"Connection: Upgrade", b"Upgrade: websocket"))
    res("status-101", msg(b"HTTP/1.1 101 Switching Protocols", b"Connection: Upgrade", b"Upgrade: websocket")
        + b"\x81\x05hello")
    res("status-101-no-upgrade", msg(b"HTTP/1.1 101 Switching Protocols") + b"raw")
    res("connect-200", msg(b"HTTP/1.1 200 Connection Established") + b"\x16\x03", "CONNECT")
    res("connect-200", msg(b"HTTP/1.1 200 OK"), "CONNECT")
    res("connect-407", msg(b"HTTP/1.1 407 Proxy Auth", b"Content-Length: 0"), "CONNECT")
    res("connect-200-cl", msg(b"HTTP/1.1 200 OK", b"Content-Length: 5", body=b"hello"), "CONNECT")
    res("status-no-sp", b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n")
    res("status-empty-reason", b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n")
    res("status-two-digits", b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n")
    res("status-four-digits", b"HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n")
    res("status-099", b"HTTP/1.1 099 X\r\nContent-Length: 0\r\n\r\n")
    res("status-600", b"HTTP/1.1 600 X\r\nContent-Length: 0\r\n\r\n")
    res("status-999", b"HTTP/1.1 999 X\r\nContent-Length: 0\r\n\r\n")
    res("status-000", b"HTTP/1.1 000 X\r\nContent-Length: 0\r\n\r\n")
    res("status-alpha", b"HTTP/1.1 abc OK\r\nContent-Length: 0\r\n\r\n")
    res("status-plus", b"HTTP/1.1 +200 OK\r\nContent-Length: 0\r\n\r\n")
    res("status-no-space-after-version", b"HTTP/1.1200 OK\r\nContent-Length: 0\r\n\r\n")
    res("status-double-space", b"HTTP/1.1  200 OK\r\nContent-Length: 0\r\n\r\n")
    res("reason-tab", b"HTTP/1.1 200 O\tK\r\nContent-Length: 0\r\n\r\n")
    res("reason-obs-text", b"HTTP/1.1 200 Caf\xe9\r\nContent-Length: 0\r\n\r\n")
    res("reason-ctl", b"HTTP/1.1 200 O\x01K\r\nContent-Length: 0\r\n\r\n")
    res("reason-nul", b"HTTP/1.1 200 O\x00K\r\nContent-Length: 0\r\n\r\n")
    res("reason-long", b"HTTP/1.1 200 " + b"R" * 3000 + b"\r\nContent-Length: 0\r\n\r\n")
    res("reason-spaces", b"HTTP/1.1 200   two  spaces  \r\nContent-Length: 0\r\n\r\n")
    res("version-lower", b"http/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    res("version-2", b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
    res("version-09", b"HTTP/0.9 200 OK\r\nContent-Length: 0\r\n\r\n")
    res("leading-empty-lines", CRLF + msg(b"HTTP/1.1 200 OK", b"Content-Length: 0"))
    res("not-http", b"SSH-2.0-OpenSSH_9.7\r\n")
    res("empty-input", b"")
    res("pipelined", msg(b"HTTP/1.1 200 OK", b"Content-Length: 2", body=b"ok")
        + msg(b"HTTP/1.1 404 NF", b"Content-Length: 0"))
    res("te-trailing-ows", msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked\t",
        body=b"4\r\nWiki\r\n0\r\n\r\n"))
    res("te-trailing-ows", msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked ",
        body=b"4\r\nWiki\r\n0\r\n\r\n"))
    res("te-gzip-only", msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: gzip", body=b"data"))
    res("te-chunked-cl", msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked",
        b"Content-Length: 4", body=b"1\r\nx\r\n0\r\n\r\n"))
    res("te-http10", msg(b"HTTP/1.0 200 OK", b"Transfer-Encoding: chunked",
        body=b"1\r\nx\r\n0\r\n\r\n"))
    res("cl-dup-diff", msg(b"HTTP/1.1 200 OK", b"Content-Length: 2", b"Content-Length: 3", body=b"abc"))
    res("cl-dup-same", msg(b"HTTP/1.1 200 OK", b"Content-Length: 2", b"Content-Length: 2", body=b"ab"))
    res("cl-negative", msg(b"HTTP/1.1 200 OK", b"Content-Length: -1", body=b"ab"))
    res("cl-short-body", msg(b"HTTP/1.1 200 OK", b"Content-Length: 10", body=b"ab"))
    res("bare-lf-start", b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n")
    res("bare-lf-field", b"HTTP/1.1 200 OK\r\nContent-Length: 0\nX: y\r\n\r\n")
    res("bare-lf-all", b"HTTP/1.1 200 OK\nContent-Length: 0\n\n")
    res("bare-cr-value", b"HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n")
    res("space-before-colon", msg(b"HTTP/1.1 200 OK", b"X : y", b"Content-Length: 0"))
    res("obs-fold", msg(b"HTTP/1.1 200 OK", b"X: a", b" b", b"Content-Length: 0"))
    res("nul-value", b"HTTP/1.1 200 OK\r\nX: a\x00b\r\nContent-Length: 0\r\n\r\n")
    res("header-dup", msg(b"HTTP/1.1 200 OK", b"Set-Cookie: a=1", b"Set-Cookie: b=2", b"Content-Length: 0"))
    for tag, body in [
        ("chunk-nonhex", b"g\r\nx\r\n0\r\n\r\n"),
        ("chunk-ext", b"1;a=b\r\nx\r\n0\r\n\r\n"),
        ("chunk-huge", b"ffffffffffffffffff\r\nx\r\n0\r\n\r\n"),
        ("chunk-no-last", b"1\r\nx\r\n"),
        ("chunk-trailer-cl", b"1\r\nx\r\n0\r\nContent-Length: 5\r\n\r\n"),
        ("chunk-trailers", b"1\r\nx\r\n0\r\nA: 1\r\nB: 2\r\n\r\n"),
        ("bare-lf-chunk-size", b"1\nx\r\n0\r\n\r\n"),
    ]:
        res(tag, msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked", body=body))
    return out


def rfc():
    """The message examples in RFC 9112, verbatim where it gives bytes."""
    out = []
    out.append(("rfc9112-2.1", "req", "-", msg(
        b"GET /hello.txt HTTP/1.1", b"User-Agent: curl/7.64.1",
        b"Host: www.example.com", b"Accept-Language: en, mi")))
    out.append(("rfc9112-4", "res", "-", msg(
        b"HTTP/1.1 200 OK", b"Date: Mon, 27 Jul 2009 12:28:53 GMT",
        b"Server: Apache", b"Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT",
        b"ETag: \"34aa387-d-1568eb00\"", b"Accept-Ranges: bytes",
        b"Content-Length: 51", b"Vary: Accept-Encoding",
        b"Content-Type: text/plain",
        body=b"Hello World! My content includes a trailing CRLF.\r\n")))
    out.append(("rfc9112-7.1.3", "res", "-", msg(
        b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked", b"Trailer: Expires",
        body=b"4\r\nWiki\r\n7\r\npedia i\r\nB\r\nn \r\nchunks.\r\n0\r\n"
             b"Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n")))
    out.append(("rfc9112-7.1.3", "res", "-", msg(
        b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked",
        body=b"4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n")))
    out.append(("rfc9112-3.2.1", "req", "-", msg(
        b"GET /where?q=now HTTP/1.1", b"Host: www.example.org")))
    out.append(("rfc9112-3.2.2", "req", "-", msg(
        b"GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1",
        b"Host: www.example.org")))
    out.append(("rfc9112-3.2.3", "req", "-", msg(
        b"CONNECT www.example.com:80 HTTP/1.1", b"Host: www.example.com:80")))
    out.append(("rfc9112-3.2.4", "req", "-", msg(b"OPTIONS * HTTP/1.1", b"Host: www.example.org:8001")))
    out.append(("rfc9112-6.3-1", "res", "-", msg(b"HTTP/1.1 200 OK", b"Content-Length: 3", body=b"abc")))
    out.append(("rfc9112-9.6", "req", "-", msg(b"GET /" , H)))  # invalid: no version
    out.append(("rfc9112-5.2", "req", "-", msg(
        b"GET / HTTP/1.1", b"Host: www.example.org", b"Obs-Fold: line one", b"   line two")))
    out.append(("rfc9112-2.2", "req", "-", b"\r\n\r\n" + msg(b"GET / HTTP/1.1", H)))
    out.append(("rfc9112-6.1", "req", "-", msg(
        b"POST / HTTP/1.1", H, b"Transfer-Encoding: gzip, chunked",
        body=b"0\r\n\r\n")))
    return out


_LITERAL = re.compile(r'(crlf\(\s*)?((?:"(?:[^"\\\n]|\\.)*"\s*)+)', re.S)
_STR = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def _unescape(s):
    out = bytearray()
    i = 0
    simple = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, '"': 34, "'": 39,
              "a": 7, "b": 8, "f": 12, "v": 11}
    while i < len(s):
        c = s[i]
        if c != "\\":
            out += c.encode("utf-8")
            i += 1
            continue
        i += 1
        c = s[i]
        if c == "x":
            j = i + 1
            while j < len(s) and j < i + 3 and s[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(int(s[i + 1:j], 16))
            i = j
        elif c in simple:
            out.append(simple[c])
            i += 1
        else:
            out += c.encode("utf-8")
            i += 1
    return bytes(out)


def fixtures():
    """Every adjacent-string-literal group in the unit tests that holds an
    HTTP/1 start line. `crlf("...")` groups have their LF turned into CRLF as
    the helper does."""
    out = []
    udir = os.path.join(LIB, "tests", "unit")
    for name in sorted(os.listdir(udir)):
        if not name.endswith(".cpp"):
            continue
        text = open(os.path.join(udir, name), encoding="utf-8").read()
        for m in _LITERAL.finditer(text):
            joined = "".join(_STR.findall(m.group(2)))
            data = _unescape(joined)
            if b"HTTP/1" not in data:
                continue
            if m.group(1):
                data = re.sub(rb"(?<!\r)\n", b"\r\n", data)
            kind = "res" if data.startswith(b"HTTP/") else "req"
            out.append(("fixture:" + name, kind, "-", data))
    return out


def seeds(extra_dir=None):
    out = []
    # The committed seeds are the files named *.seed; whatever else is in the
    # directory is what a fuzzing run grew.
    sdir = os.path.join(LIB, "tests", "fuzz", "corpus", "parse")
    paths = [os.path.join(sdir, n) for n in sorted(os.listdir(sdir)) if n.endswith(".seed")] \
        if os.path.isdir(sdir) else []
    tag = "seed"
    if extra_dir:
        paths += [os.path.join(extra_dir, n) for n in sorted(os.listdir(extra_dir))]
        tag = "fuzz"
    for p in sorted(set(paths)):
        raw = open(p, "rb").read()
        if len(raw) < 2:
            continue
        out.append(("%s:%s" % (tag, os.path.basename(p)[:12]),
                    "res" if raw[0] & 1 else "req", "-", raw[2:]))
    return out


# ---- the generator ---------------------------------------------------------

def _bases():
    b = []
    b.append(msg(b"GET /index.html?a=1 HTTP/1.1", b"Host: example.test",
                 b"User-Agent: probe/1", b"Accept: */*", b"X-Dup: 1", b"X-Dup: 2"))
    b.append(msg(b"POST /submit HTTP/1.1", b"Host: example.test",
                 b"Content-Length: 11", b"Content-Type: text/plain", body=b"hello world"))
    b.append(msg(b"POST /up HTTP/1.1", b"Host: example.test",
                 b"Transfer-Encoding: chunked",
                 body=b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n"))
    b.append(msg(b"GET http://example.test/abs HTTP/1.1", b"Host: example.test")
             + msg(b"GET /second HTTP/1.1", b"Host: example.test", b"Connection: close"))
    b.append(msg(b"OPTIONS * HTTP/1.1", b"Host: example.test"))
    b.append(msg(b"GET / HTTP/1.0", b"X: y"))
    r = []
    r.append(msg(b"HTTP/1.1 200 OK", b"Content-Type: text/plain", b"Content-Length: 5",
                 b"Set-Cookie: a=1", b"Set-Cookie: b=2", body=b"hello"))
    r.append(msg(b"HTTP/1.1 200 OK", b"Transfer-Encoding: chunked",
                 body=b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nExpires: soon\r\n\r\n"))
    r.append(msg(b"HTTP/1.1 404 Not Found", b"Content-Length: 0")
             + msg(b"HTTP/1.1 204 No Content"))
    r.append(msg(b"HTTP/1.0 200 OK", b"Server: old", body=b"close delimited"))
    r.append(msg(b"HTTP/1.1 301 Moved", b"Location: /elsewhere", b"Content-Length: 0"))
    return [(x, "req") for x in b] + [(y, "res") for y in r]


_INTERESTING = [b"\x00", b"\x01", b"\x0b", b"\x0c", b"\x1f", b"\x7f", b"\x80",
                b"\xe9", b"\xff", b" ", b"\t", b"\r", b"\n", b":", b";", b",",
                b"\"", b"(", b"@", b"\\", b"%", b"#", b"?"]


def _positions(data, needle):
    out = []
    i = data.find(needle)
    while i != -1:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


def _line_label(line):
    """`start` for a start line, else the field's name if it decides framing."""
    if b":" not in line:
        return "start"
    return _field_label(line.split(b":")[0])


def _lab(v):
    """A tag-safe spelling of a mutation's value: alphanumerics, comma, dot and
    hyphen as they are, every other byte as %xx. An empty value is `empty`."""
    if not v:
        return "empty"
    return "".join(chr(b) if (chr(b).isalnum() and b < 128) or chr(b) in ",.-"
                   else "%%%02x" % b for b in v)


def _mutate(rng, data, kind):
    """One mutation. Returns (op name, new bytes), or None if the op found
    nothing to act on."""
    ops = ["delete-cr", "lf-only", "cr-only", "insert-byte", "delete-byte",
           "replace-byte", "dup-line", "drop-line", "truncate", "space-before-colon",
           "obs-fold", "cl-value", "te-add", "cl-add", "append-bytes",
           "split-crlf-crlf", "lowercase-line", "swap-lines", "double-space",
           "tab-sep", "version-change", "status-change", "method-change",
           "chunk-size", "extra-crlf"]
    op = rng.choice(ops)
    crlfs = _positions(data, CRLF)
    if op == "delete-cr" and crlfs:
        i = rng.choice(crlfs)
        return op, data[:i] + data[i + 1:]
    if op == "lf-only" and crlfs:
        i = rng.choice(crlfs)
        return op, data[:i] + b"\n" + data[i + 2:]
    if op == "cr-only" and crlfs:
        i = rng.choice(crlfs)
        return op, data[:i] + b"\r" + data[i + 2:]
    if op == "insert-byte":
        i = rng.randrange(len(data) + 1)
        v = rng.choice(_INTERESTING)
        return op + ":" + _lab(v), data[:i] + v + data[i:]
    if op == "delete-byte" and data:
        i = rng.randrange(len(data))
        return op, data[:i] + data[i + 1:]
    if op == "replace-byte" and data:
        i = rng.randrange(len(data))
        v = rng.choice(_INTERESTING)
        return op + ":" + _lab(v), data[:i] + v + data[i + 1:]
    lines = data.split(CRLF)
    if op == "dup-line" and len(lines) > 3:
        i = rng.randrange(1, len(lines) - 2)
        return op + ":" + _line_label(lines[i]), CRLF.join(lines[:i + 1] + [lines[i]] + lines[i + 1:])
    if op == "drop-line" and len(lines) > 3:
        i = rng.randrange(1, len(lines) - 2)
        return op + ":" + _line_label(lines[i]), CRLF.join(lines[:i] + lines[i + 1:])
    if op == "truncate" and len(data) > 1:
        return op, data[:rng.randrange(1, len(data))]
    if op in ("space-before-colon", "obs-fold", "lowercase-line") and len(lines) > 3:
        i = rng.randrange(1, len(lines) - 2)
        line = lines[i]
        if op == "space-before-colon" and b":" in line:
            j = line.index(b":")
            return op + ":" + _line_label(line), CRLF.join(lines[:i] + [line[:j] + b" " + line[j:]] + lines[i + 1:])
        if op == "obs-fold":
            return op + ":" + _line_label(line), CRLF.join(lines[:i] + [b" " + line] + lines[i + 1:])
        if op == "lowercase-line":
            return op + ":" + _line_label(line), CRLF.join(lines[:i] + [line.lower()] + lines[i + 1:])
    if op == "cl-value":
        k = data.find(b"Content-Length: ")
        if k != -1:
            e = data.index(CRLF, k)
            v = rng.choice([b"", b"-1", b"+1", b"0x5", b"1 1", b"1,1", b"1, 2",
                            b"00", b"99999999999999999999", b"1\x00", b" 1", b"\xd9\xa3"])
            return op + ":" + _lab(v), data[:k + 16] + v + data[e:]
    if op == "te-add" and len(lines) > 2:
        v = rng.choice([b"chunked", b"gzip, chunked", b"chunked, gzip", b"identity",
                        b"CHUNKED", b"chunked ", b", chunked", b"xchunked", b""])
        i = rng.randrange(1, len(lines) - 1)
        return op + ":" + _lab(v), CRLF.join(lines[:i] + [b"Transfer-Encoding: " + v] + lines[i:])
    if op == "cl-add" and len(lines) > 2:
        i = rng.randrange(1, len(lines) - 1)
        v = rng.choice([b"0", b"3", b"11"])
        return op + ":" + _lab(v), CRLF.join(lines[:i] + [b"Content-Length: " + v] + lines[i:])
    if op == "append-bytes":
        v = rng.choice([b"x", b"\r\n", b"\r\n\r\n", b"GET / HTTP/1.1\r\n",
                        b"\x00", b"HTTP/1.1 200 OK\r\n\r\n", b" "])
        return op + ":" + _lab(v), data + v
    if op == "split-crlf-crlf" and b"\r\n\r\n" in data:
        i = data.index(b"\r\n\r\n")
        return op, data[:i + 2] + b"\r\n" + data[i + 2:]
    if op == "swap-lines" and len(lines) > 4:
        i = rng.randrange(1, len(lines) - 3)
        label = _line_label(lines[i]) + "+" + _line_label(lines[i + 1])
        lines[i], lines[i + 1] = lines[i + 1], lines[i]
        return op + ":" + label, CRLF.join(lines)
    if op == "double-space" and b" " in lines[0]:
        j = lines[0].index(b" ")
        return op, CRLF.join([lines[0][:j] + b" " + lines[0][j:]] + lines[1:])
    if op == "tab-sep" and b" " in lines[0]:
        j = lines[0].index(b" ")
        return op, CRLF.join([lines[0][:j] + b"\t" + lines[0][j + 1:]] + lines[1:])
    if op == "version-change":
        k = data.find(b"HTTP/1.")
        if k != -1:
            v = rng.choice([b"HTTP/1.0", b"HTTP/1.2", b"HTTP/2.0", b"HTTP/0.9",
                            b"http/1.1", b"HTTP/1.", b"HTTP/11", b"HTTP/1.1x"])
            return op + ":" + _lab(v), data[:k] + v + data[k + 8:]
    if op == "status-change" and kind == "res" and data.startswith(b"HTTP/1.1 "):
        v = rng.choice([b"099", b"100", b"101", b"199", b"204", b"304", b"600",
                        b"999", b"20", b"2000", b"abc", b"+20", b"1 0"])
        return op + ":" + _lab(v), data[:9] + v + data[12:]
    if op == "method-change" and kind == "req":
        j = data.index(b" ")
        v = rng.choice([b"get", b"FOO", b"CONNECT", b"OPTIONS", b"G E", b"G\x00T", b""])
        return op + ":" + _lab(v), v + data[j:]
    if op == "chunk-size" and b"\r\n\r\n" in data:
        k = data.index(b"\r\n\r\n") + 4
        if b"chunked" in data[:k]:
            e = data.index(CRLF, k)
            v = rng.choice([b"", b"g", b"-1", b"+1", b" 1", b"1 ", b"0x1", b"1;", b"1;a",
                            b"ffffffff", b"ffffffffffffffffffff", b"00000000000000000001"])
            return op + ":" + _lab(v), data[:k] + v + data[e:]
    if op == "extra-crlf":
        i = rng.randrange(len(data) + 1)
        return op, data[:i] + CRLF + data[i:]
    return None


_FIELDS_OF_NOTE = (b"content-length", b"transfer-encoding", b"host", b"connection", b"upgrade")


def _field_label(name):
    low = name.strip().lower()
    return low.decode("latin1") if low in _FIELDS_OF_NOTE else "other"


def _contexts(base, kind):
    """What syntactic part of its message each byte of a valid `base` is.

    One label per byte: start-method, start-target, start-version, start-status,
    start-reason, field-name:<which>, field-colon:<which>, field-value:<which>, crlf,
    head-end, chunk-size, chunk-ext, chunk-data, trailer-name, trailer-colon,
    trailer-value, body. `<which>` names the fields that decide framing
    (content-length, transfer-encoding, host, connection, upgrade) and is
    `other` for the rest. Bases are valid, so this reads them with no care for
    bad input.
    """
    n = len(base)
    out = ["body"] * n

    def mark(a, b, label):
        for i in range(a, min(b, n)):
            out[i] = label

    pos = 0
    first = True
    while pos < n:
        end = base.find(b"\r\n\r\n", pos)
        if end == -1:
            break
        lines = base[pos:end + 2].split(CRLF)[:-1]
        at = pos
        te = False
        cl = None
        status = 0
        for idx, line in enumerate(lines):
            if idx == 0:
                parts = line.split(b" ", 2)
                labels = (["start-method", "start-target", "start-version"] if kind == "req"
                          else ["start-version", "start-status", "start-reason"])
                a = at
                for j, part in enumerate(parts):
                    mark(a, a + len(part), labels[j])
                    if j < len(parts) - 1:
                        mark(a + len(part), a + len(part) + 1, "start-space")
                    a += len(part) + 1
                if kind == "res" and len(parts) > 1 and parts[1].isdigit():
                    status = int(parts[1])
            else:
                c = line.find(b":")
                name, value = line[:c], line[c + 1:]
                which = _field_label(name)
                mark(at, at + c, "field-name:" + which)
                mark(at + c, at + c + 1, "field-colon:" + which)
                mark(at + c + 1, at + len(line), "field-value:" + which)
                if name.lower() == b"transfer-encoding" and b"chunked" in value.lower():
                    te = True
                if name.lower() == b"content-length":
                    cl = int(value.strip())
            mark(at + len(line), at + len(line) + 2, "crlf")
            at += len(line) + 2
        mark(end + 2, end + 4, "head-end")
        pos = end + 4
        if te:
            while pos < n:
                e = base.find(CRLF, pos)
                line = base[pos:e]
                semi = line.find(b";")
                mark(pos, pos + (semi if semi != -1 else len(line)), "chunk-size")
                if semi != -1:
                    mark(pos + semi, e, "chunk-ext")
                mark(e, e + 2, "crlf")
                size = int(line.split(b";")[0], 16)
                pos = e + 2
                if size == 0:
                    while True:  # trailers, then the empty line
                        e = base.find(CRLF, pos)
                        if e == pos:
                            mark(pos, pos + 2, "head-end")
                            pos += 2
                            break
                        t = base[pos:e]
                        c = t.find(b":")
                        mark(pos, pos + c, "trailer-name")
                        mark(pos + c, pos + c + 1, "trailer-colon")
                        mark(pos + c + 1, e, "trailer-value")
                        mark(e, e + 2, "crlf")
                        pos = e + 2
                    break
                mark(pos, pos + size, "chunk-data")
                mark(pos + size, pos + size + 2, "crlf")
                pos += size + 2
        elif cl is not None:
            mark(pos, pos + cl, "body")
            pos += cl
        elif kind == "res" and not (status // 100 == 1 or status in (204, 304)):
            mark(pos, n, "body")
            pos = n
        first = False
    return out


def _where(base, new, ctx):
    """The syntactic context of the first byte a mutation changed."""
    i = 0
    while i < len(base) and i < len(new) and base[i] == new[i]:
        i += 1
    if i >= len(ctx):
        return "end"
    return ctx[i]


def generated(seed, count):
    rng = random.Random(seed)
    bases = _bases()
    ctxs = {b: _contexts(b, k) for b, k in bases}
    out = []
    tries = 0
    while len(out) < count and tries < count * 20:
        tries += 1
        data, kind = rng.choice(bases)
        m = _mutate(rng, data, kind)
        if m is None or m[1] == data:
            continue
        method = "-"
        if kind == "res" and rng.random() < 0.1:
            method = rng.choice(["HEAD", "CONNECT"])
        where = _where(data, m[1], ctxs[data])
        # A byte-level mutation inside the Host field's name either removes the
        # Host (the exactly-one-Host rule, which the hand cases hold) or makes an
        # invalid name (which other hand cases hold), and which of the two a
        # disagreement is about cannot be told from the case. Not generated.
        if m[0].split(":")[0] in ("insert-byte", "replace-byte", "delete-byte") \
                and where in ("field-name:host", "field-colon:host"):
            continue
        out.append(("gen:%s@%s" % (m[0], where), kind, method, m[1]))
    return out


def all_cases(seed=1, count=2500, fuzz_dir=None):
    """The whole corpus, with stable ids and duplicates removed."""
    seen = set()
    cases = []
    for src in (hand(), rfc(), fixtures(), seeds(fuzz_dir), generated(seed, count)):
        for tag, kind, method, data in src:
            key = (kind, method, data)
            if key in seen:
                continue
            seen.add(key)
            cases.append({"id": len(cases), "tag": tag, "kind": kind,
                          "method": method, "data": data})
    return cases


def dump(path, cases):
    """The corpus in http_probe's input format, both ways of feeding it: one
    line per (case, split). tools/xarch/http.sh and tools/xwin/http.sh run the
    probe built for each target over this file."""
    with open(path, "w") as out:
        for c in cases:
            for split in ("whole", "byte"):
                out.write("%d\t%s\t%s\t%s\t%s\n" % (
                    c["id"], c["kind"], c["method"], split, c["data"].hex()))


if __name__ == "__main__":
    import argparse
    import collections
    ap = argparse.ArgumentParser(description="Summarise the corpus, or write it for http_probe.")
    ap.add_argument("--dump", metavar="FILE", help="write http_probe input to FILE")
    ap.add_argument("--count", type=int, default=250000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    cs = all_cases(args.seed, args.count)
    if args.dump:
        dump(args.dump, cs)
    c = collections.Counter(x["tag"].split(":")[0] for x in cs)
    print(len(cs), "cases", dict(c) if not args.dump else "written to " + args.dump)
