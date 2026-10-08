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
"""The HTTP/2 differential: this library against nghttp2, h2 and Go's x/net/http2.

    diff_h2.py --probe build/.../h2_probe [--count N] [--seed S] [--report FILE]

Every case in corpus_h2.py is run through this library (the probe) and through
each reference, in its pinned container (containers/IMAGES), and the answers
are compared. There are three kinds of case (corpus_h2.py says where they come
from):

  h2  a client's whole byte stream, run as a server over, whole and one octet
      at a time. Compared: the requests accepted (stream, method, scheme,
      authority, path, fields, body, trailers, whether the client ended it), the
      RST_STREAM frames the implementation sent (stream and code), and the
      connection error it ended with (the code of its GOAWAY).
  hd  one HPACK block through each decoder: the list, or that it was refused.
  he  a header list through each ENCODER, and every block that results through
      every DECODER, this library's included: the list must come back.

Two things are never decided by a rule file:

  - this library must answer identically whole and byte by byte, or the run
    fails;
  - the references must answer the controls (always run first): a good request
    is accepted, a bad preface is refused, an upper-case field name is not
    accepted, a known HPACK block decodes to its list, and a list this library
    encodes decodes to itself. A driver that answers the same thing to
    everything cannot give a green run.

Everything else that differs needs a line in known-h2-disagreements.tsv naming
the case's tag, the reference, the kind of difference and a class, and a line
that explains nothing fails the run as stale (unless its note begins
[flaky], for a reference whose answer depends on its own scheduling). A disagreement is never filtered
out of the denominator: the table at the end counts refused cases and agreed
refusals alongside agreed acceptances.
"""

import argparse
import collections
import concurrent.futures
import fnmatch
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus_h2  # noqa: E402
import oracle_env  # noqa: E402

REFS = ["nghttp2", "h2", "gox2"]
DEFAULT_SEED = 1
DEFAULT_COUNT = 12000

CODES = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
         4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM",
         8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
         12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}

# What a reference cannot report, dropped from BOTH sides of that comparison.
# Go canonicalises and merges: it exposes no :scheme, and moves the Host it is
# given as :authority into r.Host.
DROP_FIELDS = {
    "gox2": {"host"},
}
DROP_SCHEME = {"gox2"}

CLASSES = {
    "policy": "this library is stricter than RFC 9113 requires and says so (documentation/rfc9113.md)",
    "ref-lenient": "the reference accepts what RFC 9113 says to refuse",
    "ref-strict": "the reference refuses what RFC 9113 allows",
    "ref-model": "the reference does not model the concept, or acts at another layer (credit policy, tunnels, unknown frames)",
    "ref-limit": "a size or count limit the reference sets differently",
    "ref-bug": "the reference is wrong against its own documentation or the RFC",
    "ref-split": "the reference answers differently depending on how the input is split",
    "choice": "one side refuses and the other accepts, and the RFC leaves it open (a MAY, or no rule for the case)",
    "code": "both refuse; the error code differs and the RFC allows either, or names none for this case",
    "update": "the reference requires a block to open with a dynamic table size update after the decoder's maximum was lowered (RFC 7541 4.2) and this library, handed a table already that size, does not; with the update prepended they agree (checked)",
    "scope": "a difference in what the two sides can express, not in what they accepted",
    "timing": "the same refusal is made at another frame or octet, so the messages delivered before it differ",
    "lenient": "this library accepts what RFC 9113 says to refuse, with no consequence for what is delivered (documented)",
}


def hx(b):
    return bytes.fromhex(b)


# ---- running --------------------------------------------------------------------

def lines(cases):
    out = []
    for c in cases:
        for split in (("whole", "byte") if c["kind"] == "h2" else ("whole",)):
            out.append("%d\t%s\t%s\t%s\t%s" % (c["id"], c["kind"], split, c["arg"], c["data"].hex()))
    return "\n".join(out) + "\n"


def want_count(cases):
    return sum(2 if c["kind"] == "h2" else 1 for c in cases)


def parse_answers(name, text, want):
    out = {}
    for line in text.splitlines():
        f = line.split("\t", 2)
        if len(f) != 3:
            raise SystemExit("%s: a line that is not 'id split json': %r" % (name, line[:200]))
        try:
            out[(int(f[0]), f[1])] = json.loads(f[2])
        except ValueError as why:
            raise SystemExit("%s: unparseable answer for %s: %s" % (name, f[0], why))
    if len(out) != want:
        raise SystemExit("%s answered %d of %d questions: a crashed or truncated driver is "
                         "a failed run, not a smaller corpus" % (name, len(out), want))
    return out


def run_ours(probe, cases):
    done = subprocess.run([probe], input=lines(cases), capture_output=True, text=True,
                          errors="surrogateescape", env=dict(os.environ))
    if done.returncode != 0:
        raise SystemExit("the probe exited %d: %s" % (done.returncode, done.stderr[-2000:]))
    return parse_answers("this library", done.stdout, want_count(cases))


# A case whose arg is `xc` is run against a server that has enabled Extended
# CONNECT (RFC 8441). The references are told by their environment, so their
# drivers need no arguments of their own: the C and Python drivers read
# GHTTP_REF_XCONNECT, and Go's x/net/http2 its own GODEBUG switch.
XC_ENV = {"GHTTP_REF_XCONNECT": "1", "GODEBUG": "http2xconnect=1"}


def run_ref(name, cases):
    groups = [({}, [c for c in cases if c.get("arg") != "xc"]),
              (XC_ENV, [c for c in cases if c.get("arg") == "xc"])]
    merged = {}
    for env, sub in groups:
        if not sub:
            continue
        argv = oracle_env.command(name, env=env)
        done = subprocess.run(argv, input=lines(sub), capture_output=True, text=True)
        if done.returncode != 0:
            raise SystemExit("%s exited %d: %s" % (name, done.returncode, done.stderr[-2000:]))
        merged.update(parse_answers(name, done.stdout, want_count(sub)))
    return merged


# ---- normalising and comparing -----------------------------------------------------

def fieldmap(pairs, drop=frozenset()):
    d = collections.OrderedDict()
    for n, v in pairs:
        k = hx(n).decode("latin1").lower()
        if k in drop:
            continue
        d.setdefault(k, []).append(hx(v))
    return tuple(sorted((k, tuple(v)) for k, v in d.items()))


def opt(v):
    return None if v is None else hx(v)


def norm_h2(res, ref=None):
    drop = DROP_FIELDS.get(ref, frozenset())
    msgs = []
    for m in res["msgs"]:
        scheme = None if ref in DROP_SCHEME else opt(m["scheme"])
        msgs.append((m["stream"], opt(m["method"]), scheme, opt(m["authority"]), opt(m["path"]),
                     fieldmap(m["headers"], drop), hx(m["body"]), fieldmap(m["trailers"], drop),
                     m["ended"]))
    conn = res["conn_error"]
    if conn is None and res.get("closed"):
        conn = "CLOSED"  # hung up on the connection with no GOAWAY
    if "PROCESS CRASH" in res.get("err", ""):
        conn = "CRASH"  # the reference's own process died (gox2.main supervises)
    if ref == "gox2":
        # Go's RequestURI for CONNECT is the authority: there is no :path.
        # An Extended CONNECT (:protocol) has one, like any other request.
        has_protocol = lambda m: any(k == ":protocol" for k, _ in m[5])
        msgs = [m[:4] + (None if m[1] == b"CONNECT" and not has_protocol(m) else m[4],) + m[5:] for m in msgs]
        # Go runs each handler in its own goroutine, so the order requests are
        # recorded in is the scheduler's; they are compared in stream order.
        msgs.sort(key=lambda m: (m[0], m[1] or b""))
    resets = [tuple(r) for r in res["resets"]]
    # A reference that answers a malformed request with an error response
    # instead of resetting the stream (Go does: 400): kept apart from RST_STREAM.
    resets += [(s, "HTTP%d" % st) for s, st in res.get("answers", [])]
    resets = tuple(sorted(resets, key=lambda r: (r[0], str(r[1]))))
    # The 4th member (this library only): the input ended inside a frame. It is
    # not part of the comparison - a reference that is also waiting for the rest
    # of the frame has said the same - but it names the end of ours when the two
    # differ.
    return (tuple(msgs), resets, conn, bool(res.get("incomplete")))


MSG_PARTS = ["stream", "method", "scheme", "authority", "path", "headers", "body", "trailers", "ended"]


def end_of(conn):
    return "ok" if conn is None else "conn:" + CODES.get(conn, str(conn))


def kind_h2(ours, ref):
    """None if the same, else 'ours-end/ref-end[+msgs:parts][+resets]'."""
    if ours[:3] == ref[:3]:
        return None
    (am, ar, ac, ai), (bm, br, bc, _) = ours, ref
    kind = "%s/%s" % ("incomplete" if ac is None and ai else end_of(ac), end_of(bc))
    if am != bm:
        if len(am) != len(bm):
            kind += "+msgs:count"
        else:
            parts = set()
            for x, y in zip(am, bm):
                parts.update(p for p, a, b in zip(MSG_PARTS, x, y) if a != b)
            kind += "+msgs:" + ",".join(p for p in MSG_PARTS if p in parts)
    if ar != br:
        rst = lambda t: [r for r in t if not str(r[1]).startswith("HTTP")]
        ans = lambda t: [r for r in t if str(r[1]).startswith("HTTP")]
        if rst(ar) != rst(br):
            kind += "+resets"
        if ans(ar) != ans(br):
            kind += "+answers"
    return kind


def norm_hd(res):
    return (res["error"], tuple((hx(n), hx(v)) for n, v in res["list"]))


def kind_hd(ours, ref):
    (oe, ol), (re_, rl) = ours, ref
    if oe and re_:
        return None
    if oe != re_:
        return "%s/%s" % ("err" if oe else "ok", "err" if re_ else "ok")
    if ol != rl:
        return "ok/ok+list"
    return None


def load_known(path):
    rules = []
    with open(path, encoding="utf-8") as handle:
        for no, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            f = line.split("\t")
            if len(f) != 5:
                raise SystemExit("%s:%d: a rule is five tab-separated fields "
                                 "(tag, ref, kind, class, note)" % (path, no))
            if f[3] not in CLASSES:
                raise SystemExit("%s:%d: unknown class %r" % (path, no, f[3]))
            rules.append({"tag": f[0], "ref": f[1], "kind": f[2], "class": f[3],
                          "note": f[4], "hits": 0, "line": no})
    return rules


def explain(rules, tag, ref, kind):
    for r in rules:
        if (any(fnmatch.fnmatchcase(tag, alt) for alt in r["tag"].split("|"))
                and any(fnmatch.fnmatchcase(ref, alt) for alt in r["ref"].split("|"))
                and any(fnmatch.fnmatchcase(kind, alt) for alt in r["kind"].split("|"))):
            r["hits"] += 1
            r.setdefault("examples", []).append((tag, ref, kind))
            return r
    return None


# ---- the controls ------------------------------------------------------------------

def controls(probe):
    """Fail loudly unless the instrument can see what it claims to."""
    O = corpus_h2.OPEN
    good = O + corpus_h2.GET()
    cases = [
        {"id": 0, "kind": "h2", "arg": "-", "tag": "c", "data": good},
        {"id": 1, "kind": "h2", "arg": "-", "tag": "c", "data": b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"},
        {"id": 2, "kind": "h2", "arg": "-", "tag": "c", "data": O + corpus_h2.hdrs(1, corpus_h2.req((b"X-Upper", b"v")))},
        {"id": 3, "kind": "h2", "arg": "-", "tag": "c", "data": O + corpus_h2.hdrs(
            1, corpus_h2.req(method=b"POST"), corpus_h2.END_HEADERS) + corpus_h2.frame(corpus_h2.DATA, 1, 1, b"abc")},
        {"id": 4, "kind": "hd", "arg": "4096", "tag": "c",
         "data": bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff")},
        {"id": 5, "kind": "hd", "arg": "4096", "tag": "c", "data": b"\x80"},
        {"id": 6, "kind": "he", "arg": "4096", "tag": "c",
         "data": corpus_h2.blob([(b":method", b"GET"), (b"x-a", b"1")])},
        {"id": 7, "kind": "h2", "arg": "-", "tag": "c", "data": corpus_h2.PREFACE + corpus_h2.frame(corpus_h2.PING, 0, 0, b"12345678")},
        # Extended CONNECT is understood where it is enabled (and a reference
        # that ignored its switch would fail here, not agree by accident).
        {"id": 8, "kind": "h2", "arg": "xc", "tag": "c", "data": O + corpus_h2.hdrs(1, corpus_h2.xreq(), corpus_h2.END_HEADERS)},
        {"id": 9, "kind": "h2", "arg": "-", "tag": "c", "data": O + corpus_h2.hdrs(1, corpus_h2.xreq(), corpus_h2.END_HEADERS)},
    ]
    problems = []
    runs = [("this library", lambda: run_ours(probe, cases), None)] + [
        (r, (lambda r=r: run_ref(r, cases)), r) for r in REFS]
    for name, answerer, ref in runs:
        got = answerer()
        a = norm_h2(got[(0, "whole")], ref)
        if not (len(a[0]) == 1 and a[2] is None and a[0][0][1] == b"GET"):
            problems.append("%s did not accept a good request: %r" % (name, got[(0, "whole")]))
        b = norm_h2(got[(1, "whole")], ref)
        if b[2] is None or b[0]:
            problems.append("%s did not refuse an HTTP/1 request in place of the preface: %r" % (name, got[(1, "whole")]))
        c = norm_h2(got[(2, "whole")], ref)
        if c[0]:
            problems.append("%s accepted a request with an upper-case field name: %r" % (name, got[(2, "whole")]))
        d = norm_h2(got[(3, "whole")], ref)
        if not (d[0] and d[0][0][6] == b"abc"):
            problems.append("%s did not deliver a 3-octet body: %r" % (name, got[(3, "whole")]))
        e = norm_hd(got[(4, "whole")])
        if e[0] or [n for n, v in e[1]] != [b":method", b":scheme", b":path", b":authority"]:
            problems.append("%s did not decode RFC 7541 C.4.1: %r" % (name, got[(4, "whole")]))
        if not norm_hd(got[(5, "whole")])[0]:
            problems.append("%s accepted HPACK index 0" % name)
        if not got[(6, "whole")].get("hex"):
            problems.append("%s encoded nothing" % name)
        ping_first = norm_h2(got[(7, "whole")], ref)
        if name == "this library" and ping_first[2] is None:
            problems.append("this library accepted a PING in place of the preface SETTINGS")
        xc = norm_h2(got[(8, "whole")], ref)
        if not (len(xc[0]) == 1 and xc[2] is None and xc[0][0][1] == b"CONNECT"
                and (":protocol", (b"websocket",)) in xc[0][0][5]
                and xc[0][0][4] == b"/chat"):
            problems.append("%s did not accept an Extended CONNECT where it was enabled: %r" % (name, got[(8, "whole")]))
        if name == "this library":
            off = norm_h2(got[(9, "whole")], ref)
            if off[0]:
                problems.append("this library accepted an Extended CONNECT where it was not enabled: %r" % (got[(9, "whole")],))
    return problems


# ---- main ----------------------------------------------------------------------------------

def blob_fields(data):
    out, off = [], 0
    while off < len(data):
        n = int.from_bytes(data[off:off + 4], "big")
        off += 4
        name = data[off:off + n]
        off += n
        v = int.from_bytes(data[off:off + 4], "big")
        off += 4
        out.append((name, data[off:off + v]))
        off += v
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT,
                    help="stream mutations to draw; duplicates are dropped")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--known", default=os.path.join(HERE, "known-h2-disagreements.tsv"))
    ap.add_argument("--report", default=None, help="write every disagreement here")
    ap.add_argument("--examples", type=int, default=0)
    ap.add_argument("--rules", type=int, default=0, metavar="N",
                    help="print every rule's hit count and up to N cases it explains")
    ap.add_argument("--refs", default=",".join(REFS))
    ap.add_argument("--dump", default=None, help="write the corpus as TSV lines and stop")
    args = ap.parse_args(argv)
    refs = args.refs.split(",")

    cases = corpus_h2.all_cases(args.seed, args.count)
    if args.dump:
        corpus_h2.dump(args.dump, cases)
        print("wrote %d cases to %s" % (len(cases), args.dump))
        return 0

    problems = controls(args.probe)
    if problems:
        sys.stderr.write("### the controls failed: the run would not mean anything ###\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        return 1
    print("controls: each reference accepted a good request, refused an HTTP/1 request in place "
          "of the preface, did not accept an upper-case field name, delivered a body, decoded "
          "RFC 7541 C.4.1, refused HPACK index 0 and encoded a list")

    kinds = collections.Counter(c["kind"] for c in cases)
    by_src = collections.Counter(c["tag"].split(":")[0] if c["tag"].startswith(("gen", "genhd", "genhe")) else
                                 ("rfc7541" if c["tag"].startswith("rfc7541") else "rfc9113") for c in cases)
    print("corpus: %d cases (h2 %d, hd %d, he %d; %s), seed %d"
          % (len(cases), kinds["h2"], kinds["hd"], kinds["he"],
             ", ".join("%s %d" % kv for kv in sorted(by_src.items())), args.seed))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1 + len(refs)) as pool:
        f_ours = pool.submit(run_ours, args.probe, cases)
        f_refs = {r: pool.submit(run_ref, r, cases) for r in refs}
        ours = f_ours.result()
        answers = {r: f.result() for r, f in f_refs.items()}

    failures = []
    rules = load_known(args.known)

    def N(res_by, c, split="whole", ref=None):
        res = res_by[(c["id"], split)]
        return norm_h2(res, ref) if c["kind"] == "h2" else norm_hd(res)

    h2cases = [c for c in cases if c["kind"] == "h2"]
    hdcases = [c for c in cases if c["kind"] == "hd"]
    hecases = [c for c in cases if c["kind"] == "he"]

    # This library must not depend on how the input is cut.
    split_bad = [c for c in h2cases if norm_h2(ours[(c["id"], "whole")]) != norm_h2(ours[(c["id"], "byte")])]
    for c in split_bad[:10]:
        failures.append("this library answers differently whole and byte by byte: case %d (%s) %s"
                        % (c["id"], c["tag"], c["data"][:80].hex()))

    oe = collections.Counter(end_of(norm_h2(ours[(c["id"], "whole")])[2]) for c in h2cases)
    print("this library, h2: ended ok %d, with a connection error %d (%s); accepted a request in %d; sent a reset in %d"
          % (oe["ok"], sum(v for k, v in oe.items() if k != "ok"),
             ", ".join("%s %d" % kv for kv in sorted(oe.items()) if kv[0] != "ok"),
             sum(1 for c in h2cases if norm_h2(ours[(c["id"], "whole")])[0]),
             sum(1 for c in h2cases if norm_h2(ours[(c["id"], "whole")])[1])))

    table = {}
    report = []
    unexplained = []
    by_class = collections.defaultdict(collections.Counter)

    update_cases = []

    def record(r, c, kind):
        rule = explain(rules, c["tag"], r, kind)
        if rule and rule["class"] == "update":
            update_cases.append((r, c))
        cls = rule["class"] if rule else "UNEXPLAINED"
        by_class[r][cls] += 1
        report.append((r, c, kind, cls))
        if not rule:
            unexplained.append((r, c, kind))
        return rule

    for r in refs:
        t = collections.Counter()
        for c in h2cases + hdcases:
            o = N(ours, c, "whole", r)
            x = N(answers[r], c, "whole", r)
            kind = kind_h2(o, x) if c["kind"] == "h2" else kind_hd(o, x)
            if kind is None:
                if c["kind"] == "h2":
                    t["agree-refused" if o[2] is not None else "agree-accepted" if o[0] else "agree-empty"] += 1
                else:
                    t["agree-refused" if o[0] else "agree-accepted"] += 1
            else:
                t["differ"] += 1
                record(r, c, kind)
            if c["kind"] == "h2":
                xb = N(answers[r], c, "byte", r)
                if x != xb:
                    t["ref-split"] += 1
                    record(r, c, "split")
        table[r] = t

    # `update` is a claim: the reference refuses the block only for want of the
    # dynamic table size update that opens the first block after the decoder's
    # maximum was lowered. Checked, not assumed: with that update prepended, both
    # sides must answer alike.
    if update_cases:
        probes = []
        for r, c in update_cases:
            size = int(c["arg"])
            probes.append({"id": len(probes), "kind": "hd", "arg": c["arg"], "tag": c["tag"], "ref": r,
                           "data": corpus_h2.hpack_int(size, 5, 0x20) + c["data"]})
        want = set(p["ref"] for p in probes)
        o2 = run_ours(args.probe, probes)
        r2 = {r: run_ref(r, probes) for r in want}
        bad = [p for p in probes
               if kind_hd(norm_hd(o2[(p["id"], "whole")]), norm_hd(r2[p["ref"]][(p["id"], "whole")])) is not None]
        print("update: %d cases explained as needing a table size update; prepending it made the answers agree in %d"
              % (len(probes), len(probes) - len(bad)))
        for p in bad[:10]:
            failures.append("explained as `update`, but the answers still differ with the update prepended: %s case %s %s"
                            % (p["ref"], p["tag"], p["data"].hex()))

    # he: every encoder's block through every decoder.
    encoders = ["this library"] + refs
    blocks = {}
    for c in hecases:
        for e in encoders:
            res = (ours if e == "this library" else answers[e])[(c["id"], "whole")]
            blocks[(e, c["id"])] = bytes.fromhex(res["hex"]) if res.get("hex") is not None else b""
    he_cases = []
    for (e, cid), blk in sorted(blocks.items()):
        src = next(c for c in hecases if c["id"] == cid)
        he_cases.append({"id": len(he_cases), "kind": "hd", "arg": src["arg"], "tag": src["tag"],
                         "data": blk, "enc": e, "src": src})
    with concurrent.futures.ThreadPoolExecutor(max_workers=1 + len(refs)) as pool:
        f_ours = pool.submit(run_ours, args.probe, he_cases)
        f_refs = {r: pool.submit(run_ref, r, he_cases) for r in refs}
        dec = {"this library": f_ours.result()}
        dec.update({r: f.result() for r, f in f_refs.items()})
    he_t = collections.Counter()
    for hc in he_cases:
        want = tuple((n, v) for n, v in blob_fields(hc["src"]["data"]))
        for d in encoders:
            got = norm_hd(dec[d][(hc["id"], "whole")])
            ok = (not got[0]) and got[1] == want
            he_t["decoded" if ok else "FAILED"] += 1
            if not ok:
                kind = "err" if got[0] else "list"
                rule = explain(rules, hc["tag"], "%s>%s" % (hc["enc"], d), kind)
                cls = rule["class"] if rule else "UNEXPLAINED"
                by_class["he"][cls] += 1
                report.append(("%s>%s" % (hc["enc"], d), hc["src"], kind, cls))
                if not rule:
                    unexplained.append(("%s>%s" % (hc["enc"], d), hc["src"], kind))

    print()
    print("%-8s %6s %15s %15s %8s %9s" % ("ref", "cases", "agree-accepted", "agree-refused", "differ", "ref-split"))
    for r in refs:
        t = table[r]
        print("%-8s %6d %15d %15d %8d %9d" % (r, len(h2cases) + len(hdcases),
              t["agree-accepted"] + t["agree-empty"], t["agree-refused"], t["differ"], t["ref-split"]))
        for cls, n in sorted(by_class[r].items()):
            print("           %-12s %5d" % (cls, n))
    print("he: %d encodings (%d lists x %d encoders), each decoded by %d decoders: %d decoded to the list, %d did not"
          % (len(he_cases), len(hecases), len(encoders), len(encoders), he_t["decoded"], he_t["FAILED"]))
    for cls, n in sorted(by_class["he"].items()):
        print("           %-12s %5d" % (cls, n))

    # This library against every reference at once.
    lone_accept = lone_refuse = 0
    lone = {"accepted": collections.Counter(), "refused": collections.Counter()}
    for c in h2cases:
        o = N(ours, c)
        xs = [N(answers[r], c, "whole", r) for r in refs]
        fam = c["tag"].split("@")[0] if c["tag"].startswith("gen:") else c["tag"].split(":")[0] + ":" + c["tag"].split(":", 1)[-1][:24]
        if all(x[2] is not None for x in xs) and o[2] is None:
            lone_accept += 1
            lone["accepted"][fam] += 1
        if all(x[0] and x[2] is None for x in xs) and o[2] is not None:
            lone_refuse += 1
            lone["refused"][fam] += 1
    print("\nthis library carried on where every reference ended the connection: %d; ended it where every "
          "reference accepted a request and went on: %d (each is explained by a rule or the run fails)"
          % (lone_accept, lone_refuse))

    if args.rules:
        for r in rules:
            print("%4d  line %-4d %-11s %-12s %-44s %s" % (r["hits"], r["line"], r["class"], r["ref"], r["tag"], r["kind"]))
            for tag, ref, kind in r.get("examples", [])[:args.rules]:
                print("          e.g. %-12s %-30s %s" % (ref, kind, tag))
        for which, counter in lone.items():
            print("  alone against every reference, this library %s: %s" % (
                which, ", ".join("%s %d" % kv for kv in counter.most_common(40))))

    default_run = args.seed == DEFAULT_SEED and args.count == DEFAULT_COUNT and args.refs == ",".join(REFS)
    if not default_run:
        print("(not the default corpus: stale rules are not reported)")
    stale = [r for r in rules if r["hits"] == 0 and not r["note"].startswith("[flaky]")] if default_run else []
    for r in stale:
        failures.append("known-h2-disagreements.tsv:%d explains nothing (stale): %s %s %s"
                        % (r["line"], r["tag"], r["ref"], r["kind"]))
    if unexplained:
        sig = collections.Counter((r, k, c["tag"]) for r, c, k in unexplained)
        failures.append("%d disagreements have no rule; first signatures:" % len(unexplained))
        for (r, k, tag), n in sig.most_common(25):
            ex = next(c for rr, c, kk in unexplained if (rr, kk, c["tag"]) == (r, k, tag))
            failures.append("   %4d  %-10s %-40s tag=%-40s e.g. %s" % (n, r, k, tag, ex["data"][:70].hex()))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as out:
            for r, c, kind, cls in report:
                out.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (r, cls, kind, c["tag"], c["kind"], c["data"].hex()))
    if args.examples:
        for r, c, kind, cls in report[:args.examples]:
            print("%-10s %-12s %-40s %-40s %s" % (r, cls, kind, c["tag"], c["data"][:60].hex()))

    if failures:
        sys.stderr.write("\n### the HTTP/2 differential FAILED ###\n")
        for f in failures:
            sys.stderr.write(f + "\n")
        return 1
    print("\nevery disagreement is explained by a rule, and every rule explains one.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
