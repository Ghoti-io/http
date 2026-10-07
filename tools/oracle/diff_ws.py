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
"""The WebSocket differential: this library against wsproto, websockets and
gorilla/websocket.

    diff_ws.py --probe build/.../ws_probe [--count N] [--seed S] [--report FILE]

Every case in corpus_ws.py is run through this library (the probe) and through
each reference, in its pinned container (containers/IMAGES), and the answers are
compared. There are five kinds of case (corpus_ws.py says where they come from):

  ws  a client's byte stream after the opening handshake, read as a server,
      whole and one octet at a time. Compared: the messages delivered, in order
      (text and binary with their payloads; Pings and Pongs; the Close received,
      with its code and reason), how the connection ended (open: the input
      ended; closed: a Close was received and answered; failed: ended for a
      violation), the close code this implementation sent (the echo of the
      peer's, or the code it failed the connection with), and the payloads of
      the Pongs it answered Pings with.
  wc  the same for a server's stream, read as a client.
  hs  a client's request head, answered as a server under a policy: the
      status, the accept value, the subprotocol chosen, the extensions agreed.
  hc  a server's response head, judged as a client that sent an offer: accepted
      or not, the subprotocol, the permessage-deflate parameters agreed.
  wr  this library SENDS scripts of messages (fragmented, compressed, in both
      roles and under every context-takeover and window-bits variant), and the
      bytes it wrote are read by every implementation, this library's own reader
      included: the messages must come back intact. Nothing excuses this
      library here: a script it wrote that its own reader or a reference reads
      differently is a finding.

Two things are never decided by a rule file:

  - this library must answer identically whole and byte by byte, or the run
    fails;
  - the references must answer the controls (always run first): a good stream
    is read, a masking violation refused, a truncated stream left open, a known
    permessage-deflate message decoded, a message of exactly the size limit
    accepted by every implementation and one octet more refused by every one
    that has a limit (wsproto has none, which the control shows too), a good
    handshake accepted and a bad accept value refused. A driver that answers the
    same thing to everything cannot give a green run.

Everything else that differs needs a line in known-ws-disagreements.tsv naming
the case's tag, the reference, the kind of difference and a class, and a line
that explains nothing fails the run as stale. A disagreement is never filtered
out of the denominator: the table at the end counts refused cases and agreed
refusals alongside agreed acceptances. A case a reference cannot be put in the
state for (gorilla/websocket does permessage-deflate only without context
takeover) is counted apart as `n/a`, only where that is true, and the run fails
if a reference answers n/a for anything else.
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
import corpus_ws  # noqa: E402
import oracle_env  # noqa: E402

REFS = ["wsproto", "websockets", "gows"]
DEFAULT_SEED = 1
DEFAULT_COUNT = 14000

# A reference is also run one octet at a time over the cases up to this size
# (this library is, over all of them: that is a hard check). One octet at a time
# through Python is a call per octet.
REF_BYTE_MAX = 4096

CLASSES = {
    "policy": "this library is stricter than RFC 6455 or RFC 7692 requires and says so",
    "ref-lenient": "the reference accepts what the RFC says to refuse",
    "ref-strict": "the reference refuses what the RFC allows",
    "ref-model": "the reference does not model the concept, or acts at another layer (the application, the HTTP layer, extensions)",
    "ref-limit": "a size or count limit the reference sets differently, or has none",
    "ref-bug": "the reference is wrong against its own documentation or the RFC",
    "ref-split": "the reference answers differently depending on how the input is split",
    "choice": "one side refuses and the other accepts, and the RFC leaves it open (a MAY, or no rule for the case)",
    "code": "both refuse; the close code or the status differs and the RFC allows either, or names none for this case",
    "scope": "a difference in what the two sides can express or report, not in what they accepted",
    "timing": "the same refusal is made at another octet, frame or message, so what was delivered before it differs",
    "ref-order": "both sides act on the same violations and the reference reports another first, when a stream has several",
    "finding": "a defect in THIS library that this differential found and that is open: not an excuse but a bookmark, listed on every run and counted apart (the note says what and why)",
}

# What a reference leaves to the application, so that its driver chooses and
# the answer is the driver's and not the reference's: wsproto chooses no
# subprotocol of its own.
DROP_PROTOCOL = {"wsproto"}


def hx(b):
    return bytes.fromhex(b)


# ---- running --------------------------------------------------------------------

def splits_for(c, who):
    if c["kind"] not in ("ws", "wc"):
        return ("whole",)
    if who == "ours" or len(c["data"]) <= REF_BYTE_MAX:
        return ("whole", "byte")
    return ("whole",)


def lines(cases, who):
    out = []
    for c in cases:
        for split in splits_for(c, who):
            out.append("%d\t%s\t%s\t%s\t%s" % (c["id"], c["kind"], split, c["arg"], c["data"].hex()))
    return "\n".join(out) + "\n"


def want_count(cases, who):
    return sum(len(splits_for(c, who)) for c in cases)


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
    done = subprocess.run([probe], input=lines(cases, "ours"), capture_output=True, text=True,
                          errors="surrogateescape", env=dict(os.environ))
    if done.returncode != 0:
        raise SystemExit("the probe exited %d: %s" % (done.returncode, done.stderr[-2000:]))
    return parse_answers("this library", done.stdout, want_count(cases, "ours"))


def run_ref(name, cases, env=None):
    argv = oracle_env.command(name, env=env)
    done = subprocess.run(argv, input=lines(cases, name), capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit("%s exited %d: %s" % (name, done.returncode, done.stderr[-2000:]))
    return parse_answers(name, done.stdout, want_count(cases, name))


# ---- normalising and comparing -----------------------------------------------------

def opt(v):
    return None if v is None else hx(v)


def norm_stream(res):
    """(evs, end, sent close, pongs) of a ws or wc answer; None if n/a."""
    if res.get("na"):
        return None
    evs = tuple((k, hx(d), c) for k, d, c in res["evs"])
    close = None
    pongs = []
    for op, payload in res["sent"]:
        if op == 8 and close is None:
            body = hx(payload)
            close = int.from_bytes(body[:2], "big") if len(body) >= 2 else "empty"
        elif op == 10 and close is None:
            pongs.append(hx(payload))
    return (evs, res["end"], close, tuple(pongs))


def label(n):
    """The end of a stream as the rules name it: end[:code]."""
    evs, end, close, pongs = n
    return end if close is None else "%s:%s" % (end, close)


EV_PARTS = ["kind", "data", "code"]


def kind_stream(ours, ref):
    """None if the same, else 'ours-end/ref-end[+evs[:parts]][+pongs]'."""
    if ours == ref:
        return None
    kind = "%s/%s" % (label(ours), label(ref))
    if ours[0] != ref[0]:
        if len(ours[0]) != len(ref[0]):
            kind += "+evs:count"
        else:
            parts = set()
            for x, y in zip(ours[0], ref[0]):
                parts.update(p for p, a, b in zip(EV_PARTS, x, y) if a != b)
            kind += "+evs:" + ",".join(p for p in EV_PARTS if p in parts)
    if ours[3] != ref[3]:
        kind += "+pongs"
    return kind


def parse_extensions(text):
    """[(name, ((param, value|None)...))...] of a Sec-WebSocket-Extensions value,
    with permessage-deflate's window sizes of 15 (the default) dropped: a
    response that says so and one that says nothing agree."""
    if text is None:
        return None
    out = []
    for offer in text.split(","):
        parts = [p.strip() for p in offer.split(";")]
        if not parts or not parts[0]:
            continue
        params = []
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                v = v.strip().strip('"')
            else:
                k, v = p, None
            k = k.strip().lower()
            if k.endswith("max_window_bits") and v == "15":
                continue
            params.append((k, v))
        out.append((parts[0].lower(), tuple(sorted(params))))
    return tuple(out)


def norm_hs(res, ref=None):
    """`ref` names the reference this is compared with, on BOTH sides: what it
    leaves to the application is dropped from this library's answer too."""
    status = res["status"]
    if status != 101:
        return (status, None, None, None)
    protocol = None if ref in DROP_PROTOCOL else opt(res["protocol"])
    return (status, opt(res["accept"]), protocol,
            parse_extensions(None if res["extensions"] is None else hx(res["extensions"]).decode("latin1")))


def kind_hs(ours, ref):
    if ours == ref:
        return None
    kind = "%s/%s" % (ours[0], ref[0])
    if ours[0] == ref[0] == 101:
        parts = [n for n, a, b in zip(("accept", "protocol", "ext"), ours[1:], ref[1:]) if a != b]
        kind += "+" + ",".join(parts)
    return kind


def norm_hc(res):
    if not res["accepted"]:
        return (False, None, None)
    d = res["deflate"]
    if d is not None:
        d = (d["snct"], d["cnct"], 0 if d["smb"] in (0, 15) else d["smb"], 0 if d["cmb"] in (0, 15) else d["cmb"])
    return (True, opt(res["protocol"]), d)


def kind_hc(ours, ref):
    if ours == ref:
        return None
    word = lambda x: "accepted" if x[0] else "refused"
    kind = "%s/%s" % (word(ours), word(ref))
    if ours[0] and ref[0]:
        kind += "+" + ",".join(n for n, a, b in zip(("protocol", "deflate"), ours[1:], ref[1:]) if a != b)
    return kind


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

CF = corpus_ws.frame
HELLO_DEFLATE = bytes.fromhex("f248cdc9c90700")


def controls(probe):
    """Fail loudly unless the instrument can see what it claims to."""
    L = corpus_ws
    big = L.MAXMSG
    good_ws = CF(1, b"Hello") + CF(9, b"hi") + CF(8, L.close_body(1000, b"bye"))
    good_wc = CF(1, b"Hello", masked=False) + CF(9, b"hi", masked=False) + CF(8, L.close_body(1000, b"bye"), masked=False)
    cut = CF(1, b"Hello world")[:-3]
    both_nct = "d;snct;cnct"
    cases = [
        {"id": 0, "kind": "ws", "arg": "-", "tag": "c", "data": good_ws},
        {"id": 1, "kind": "wc", "arg": "-", "tag": "c", "data": good_wc},
        {"id": 2, "kind": "ws", "arg": "-", "tag": "c", "data": CF(1, b"Hello", masked=False)},
        {"id": 3, "kind": "wc", "arg": "-", "tag": "c", "data": CF(1, b"Hello", masked=True)},
        {"id": 4, "kind": "ws", "arg": "-", "tag": "c", "data": cut},
        {"id": 5, "kind": "ws", "arg": both_nct, "tag": "c", "data": CF(1, HELLO_DEFLATE, rsv=L.R1)},
        {"id": 6, "kind": "wc", "arg": both_nct, "tag": "c", "data": CF(1, HELLO_DEFLATE, rsv=L.R1, masked=False)},
        {"id": 7, "kind": "ws", "arg": "-", "tag": "c", "data": CF(2, L.rnd(big))},
        {"id": 8, "kind": "ws", "arg": "-", "tag": "c", "data": CF(2, L.rnd(big + 1))},
        {"id": 9, "kind": "hs", "arg": "-", "tag": "c", "data": L.request()},
        {"id": 10, "kind": "hs", "arg": "-", "tag": "c", "data": L.request(drop=("sec-websocket-key",))},
        {"id": 11, "kind": "hc", "arg": "-", "tag": "c", "data": L.response()},
        {"id": 12, "kind": "hc", "arg": "-", "tag": "c", "data": L.response(accept="AAAAAAAAAAAAAAAAAAAAAAAAAAA=")},
        {"id": 13, "kind": "ws", "arg": "-", "tag": "c", "data": CF(1, b"\xff")},
        {"id": 14, "kind": "ws", "arg": "-", "tag": "c", "data": CF(1, b"a", False) + CF(2, b"b")},
        {"id": 15, "kind": "ws", "arg": "-", "tag": "c", "data": CF(1, b"Hello", rsv=L.R1)},
    ]
    problems = []
    runs = [("this library", lambda: run_ours(probe, cases), None)] + [
        (r, (lambda r=r: run_ref(r, cases)), r) for r in REFS]
    for name, answerer, ref in runs:
        got = answerer()
        N = lambda i, split="whole": norm_stream(got[(i, split)])
        a, b = N(0), N(1)
        want = (("text", b"Hello", None), ("ping", b"hi", None), ("close", b"bye", 1000))
        for who, n in (("server", a), ("client", b)):
            if n is None or n[0] != want or n[1] != "closed" or n[2] != 1000 or n[3] != (b"hi",):
                problems.append("%s did not read a good stream as a %s (messages, a Ping answered, a Close echoed): %r"
                                % (name, who, got[(0 if who == "server" else 1, "whole")]))
        if N(2)[1] != "failed" or N(2)[0]:
            problems.append("%s did not refuse an unmasked client frame: %r" % (name, got[(2, "whole")]))
        if N(3)[1] != "failed" or N(3)[0]:
            problems.append("%s did not refuse a masked server frame: %r" % (name, got[(3, "whole")]))
        n4 = N(4)
        if n4[0] or n4[1] != "open":
            problems.append("%s did not leave a truncated stream open: %r" % (name, got[(4, "whole")]))
        for i, who in ((5, "server"), (6, "client")):
            n = N(i)
            if n is None or n[0] != (("text", b"Hello", None),) or n[1] != "open":
                problems.append("%s did not decode a known permessage-deflate message as a %s: %r" % (name, who, got[(i, "whole")]))
        n7, n8 = N(7), N(8)
        if n7 is None or n7[1] != "open" or len(n7[0]) != 1 or len(n7[0][0][1]) != big:
            problems.append("%s did not accept a message of exactly 1 MiB" % name)
        over = n8 is not None and (n8[1] == "failed" or not n8[0])
        if ref == "wsproto":
            if over:
                problems.append("wsproto refused a message over 1 MiB: it has no limit, and the controls record that; "
                                "if it has gained one, the rules about limits are stale")
        elif not over:
            problems.append("%s accepted a message over 1 MiB, so its size limit is not the one set" % name)
        elif n8[2] != 1009:
            problems.append("%s refused a message over 1 MiB but with %r and not 1009" % (name, n8[2]))
        hs = norm_hs(got[(9, "whole")], ref)
        if hs[0] != 101 or hs[1] != RFC_ACCEPT:
            problems.append("%s did not accept the RFC 6455 example handshake with its accept value: %r" % (name, got[(9, "whole")]))
        if norm_hs(got[(10, "whole")], ref)[0] == 101:
            problems.append("%s accepted a handshake with no Sec-WebSocket-Key" % name)
        if not norm_hc(got[(11, "whole")])[0]:
            problems.append("%s did not accept the RFC 6455 example response" % name)
        if norm_hc(got[(12, "whole")])[0]:
            problems.append("%s accepted a response with a wrong Sec-WebSocket-Accept" % name)
        n13 = N(13)
        if ref != "gows" and (n13 is None or n13[1] != "failed" or n13[2] != 1007):
            problems.append("%s did not fail a text message of invalid UTF-8 with 1007: %r" % (name, got[(13, "whole")]))
        if ref == "gows" and (n13 is None or n13[1] == "failed"):
            problems.append("gows refused invalid UTF-8, which it leaves to the application; the driver adds no check")
        n14 = N(14)
        if n14 is None or n14[1] != "failed":
            problems.append("%s did not refuse a new message inside a fragmented one" % name)
        n15 = N(15)
        if n15 is None or n15[1] != "failed":
            problems.append("%s accepted RSV1 with no extension agreed" % name)
        for key in got:
            if key[0] != 99 and got[key].get("na"):
                problems.append("%s answered n/a for control %d, which it can be put in the state for" % (name, key[0]))
    # The deflate control must actually be decoded by a different parameter set too (a window-bits spec)
    return problems


RFC_ACCEPT = bytes.fromhex("733370504c4d426954786151396b59477a7a685a52624b2b784f6f3d")


# ---- main ----------------------------------------------------------------------------------

def gorilla_na_expected(c):
    """Whether gows may answer n/a: permessage-deflate asked for without the
    no-context-takeover setting of the sending side (gows/main.go says why)."""
    toks = c["arg"].split(";")
    if "d" not in toks or c["kind"] not in ("ws", "wc"):
        return False
    return ("cnct" not in toks) if c["kind"] == "ws" else ("snct" not in toks)


def na_ok(ref, c):
    """Whether a reference may answer n/a for this case, which is only where it
    cannot be put in the state the case describes: gorilla/websocket with
    permessage-deflate and context takeover; wsproto and websockets with a
    window of 8 bits (zlib cannot compress with one: the extension classes
    refuse it)."""
    if ref == "gows":
        toks = c["arg"].split(";")
        if c["kind"] == "hc":
            # a Dialer offers both no_context_takeover parameters and nothing else
            return "d" in toks and not ("snct" in toks and "cnct" in toks and not any(t.startswith(("smb=", "cmb=")) or t == "ocmb" for t in toks))
        return gorilla_na_expected(c)
    return any(t in ("smb=8", "cmb=8") for t in c["arg"].split(";"))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT,
                    help="stream mutations to draw; duplicates are dropped")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--known", default=os.path.join(HERE, "known-ws-disagreements.tsv"))
    ap.add_argument("--report", default=None, help="write every disagreement here")
    ap.add_argument("--examples", type=int, default=0)
    ap.add_argument("--rules", type=int, default=0, metavar="N",
                    help="print every rule's hit count and up to N cases it explains")
    ap.add_argument("--lone", default=None, help="write the cases this library answers alone against every reference here")
    ap.add_argument("--refs", default=",".join(REFS))
    ap.add_argument("--dump", default=None, help="write the corpus as TSV lines and stop")
    args = ap.parse_args(argv)
    refs = args.refs.split(",")

    cases = corpus_ws.all_cases(args.seed, args.count)
    if args.dump:
        corpus_ws.dump(args.dump, cases)
        print("wrote %d cases to %s" % (len(cases), args.dump))
        return 0

    problems = controls(args.probe)
    if problems:
        sys.stderr.write("### the controls failed: the run would not mean anything ###\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        return 1
    print("controls: each implementation read a good stream (as a server and as a client, a Ping answered, a Close "
          "echoed), refused an unmasked client frame and a masked server frame, left a truncated stream open, "
          "decoded a known permessage-deflate message, accepted a message of 1 MiB, refused 1 MiB + 1 with 1009 "
          "(wsproto has no limit and accepted it), accepted the RFC handshake, refused one with no key and a "
          "response with a wrong accept value, failed invalid UTF-8 with 1007 (gorilla leaves it to the "
          "application), refused a new message inside a fragmented one and RSV1 with no extension")

    kinds = collections.Counter(c["kind"] for c in cases)
    by_src = collections.Counter(c["tag"].split(":")[0].split("-")[0] for c in cases)
    print("corpus: %d cases (ws %d, wc %d, hs %d, hc %d, wr %d; %s), seed %d"
          % (len(cases), kinds["ws"], kinds["wc"], kinds["hs"], kinds["hc"], kinds["wr"],
             ", ".join("%s %d" % kv for kv in sorted(by_src.items())), args.seed))

    stream_cases = [c for c in cases if c["kind"] in ("ws", "wc")]
    hs_cases = [c for c in cases if c["kind"] == "hs"]
    hc_cases = [c for c in cases if c["kind"] == "hc"]
    wr_cases = [c for c in cases if c["kind"] == "wr"]
    first = [c for c in cases if c["kind"] != "wr"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=1 + len(refs)) as pool:
        f_ours = pool.submit(run_ours, args.probe, cases)
        f_refs = {r: pool.submit(run_ref, r, first) for r in refs}
        ours = f_ours.result()
        answers = {r: f.result() for r, f in f_refs.items()}

    failures = []
    rules = load_known(args.known)

    def S(res_by, c, split="whole"):
        return norm_stream(res_by[(c["id"], split)])

    # This library must not depend on how the input is cut.
    split_bad = [c for c in stream_cases if S(ours, c, "whole") != S(ours, c, "byte")]
    for c in split_bad[:10]:
        failures.append("this library answers differently whole and byte by byte: case %d (%s) %s"
                        % (c["id"], c["tag"], c["data"][:80].hex()))

    oe = collections.Counter(S(ours, c)[1] for c in stream_cases)
    print("this library, ws and wc: ended open %d, closed %d, failed %d (%s); delivered a message in %d"
          % (oe["open"], oe["closed"], oe["failed"],
             ", ".join("%s %d" % kv for kv in sorted(collections.Counter(
                 S(ours, c)[2] for c in stream_cases if S(ours, c)[1] == "failed").items(), key=str)),
             sum(1 for c in stream_cases if any(e[0] in ("text", "binary") for e in S(ours, c)[0]))))

    table = {}
    report = []
    unexplained = []
    by_class = collections.defaultdict(collections.Counter)

    def record(r, c, kind):
        rule = explain(rules, c["tag"], r, kind)
        if rule:
            rule.setdefault("cases", []).append((r, c, kind))
        cls = rule["class"] if rule else "UNEXPLAINED"
        by_class[r][cls] += 1
        report.append((r, c, kind, cls))
        if not rule:
            unexplained.append((r, c, kind))
        return rule

    na_seen = collections.Counter()
    timing_cands = []
    after_close = []
    for r in refs:
        t = collections.Counter()
        per_kind = collections.defaultdict(collections.Counter)
        for c in stream_cases:
            x = S(answers[r], c)
            if x is None:
                if not na_ok(r, c):
                    failures.append("%s answered n/a for a case it can be put in the state for: %s" % (r, c["tag"]))
                t["n/a"] += 1
                na_seen[c["kind"]] += 1
                continue
            o = S(ours, c)
            kind = kind_stream(o, x)
            if kind is None:
                t["agree-refused" if o[1] == "failed" else "agree-accepted"] += 1
                per_kind[c["kind"]]["agree"] += 1
            else:
                t["differ"] += 1
                per_kind[c["kind"]]["differ"] += 1
                # One side still waiting, the other already ended it, the same
                # messages delivered so far, and the stream cut inside a frame or
                # a message: a candidate for `timing`, which is CHECKED below
                # (the waiting side is given the stream completed).
                waiting = ("ours" if o[1] == "open" and x[1] == "failed" else
                           "ref" if x[1] == "open" and o[1] == "failed" else None)
                if (waiting and o[0] == x[0] and o[3] == x[3]
                        and corpus_ws.complete_stream(c["data"], c["kind"]) != c["data"]):
                    timing_cands.append((waiting, r, c, kind))
                elif o[1] == "failed" and x[1] == "failed" and o[0] == x[0] and o[3] == x[3]:
                    # Both end the connection after delivering the same messages:
                    # what differs is the close code (or that one sent none).
                    by_class[r]["code"] += 1
                    report.append((r, c, kind, "code"))
                elif (o[1] == "failed" and x[1] == "failed"
                      and (o[0][:len(x[0])] == x[0] or x[0][:len(o[0])] == o[0])):
                    # Both end it, one after delivering more: they detect the
                    # violation at different octets.
                    by_class[r]["timing"] += 1
                    report.append((r, c, kind, "timing"))
                elif (o[1] == "failed" and x[1] == "closed" and o[0] == x[0] and o[3] == x[3]
                      and any(e[0] == "close" for e in o[0])):
                    after_close.append((r, c, kind, o))
                else:
                    record(r, c, kind)
            if (c["id"], "byte") in answers[r]:
                xb = S(answers[r], c, "byte")
                if x != xb:
                    t["ref-split"] += 1
                    if S(ours, c) == xb:
                        # Checked: cut into single octets the reference answers
                        # as this library does; it is the whole stream that
                        # makes it answer otherwise.
                        by_class[r]["ref-split"] += 1
                        report.append((r, c, "split", "ref-split"))
                    else:
                        record(r, c, "split")
        for c in hs_cases:
            o = norm_hs(ours[(c["id"], "whole")], r)
            if answers[r][(c["id"], "whole")].get("na"):
                if not na_ok(r, c):
                    failures.append("%s answered n/a for a case it can be put in the state for: %s" % (r, c["tag"]))
                t["n/a"] += 1
                continue
            x = norm_hs(answers[r][(c["id"], "whole")], r)
            kind = kind_hs(o, x)
            if kind is None:
                t["agree-accepted" if o[0] == 101 else "agree-refused"] += 1
                per_kind["hs"]["agree"] += 1
            else:
                t["differ"] += 1
                per_kind["hs"]["differ"] += 1
                record(r, c, kind)
        for c in hc_cases:
            o = norm_hc(ours[(c["id"], "whole")])
            if answers[r][(c["id"], "whole")].get("na"):
                if not na_ok(r, c):
                    failures.append("%s answered n/a for a case it can be put in the state for: %s" % (r, c["tag"]))
                t["n/a"] += 1
                continue
            x = norm_hc(answers[r][(c["id"], "whole")])
            kind = kind_hc(o, x)
            if kind is None:
                t["agree-accepted" if o[0] else "agree-refused"] += 1
                per_kind["hc"]["agree"] += 1
            else:
                t["differ"] += 1
                per_kind["hc"]["differ"] += 1
                record(r, c, kind)
        table[r] = (t, per_kind)

    # wr: what this library wrote, read by every implementation as the peer.
    wr_t = {r: collections.Counter() for r in ["this library"] + refs}
    wr_rows = []
    if wr_cases:
        peers = []
        for c in wr_cases:
            toks = c["arg"].split(";")
            client = "role=client" in toks
            rest = [t for t in toks if not t.startswith("role=")]
            peers.append({"id": len(peers), "kind": "ws" if client else "wc",
                          "arg": ";".join(rest) or "-", "tag": c["tag"], "src": c,
                          "data": bytes.fromhex(ours[(c["id"], "whole")]["hex"])})
        for pc, c in zip(peers, wr_cases):
            if ours[(c["id"], "whole")]["err"]:
                failures.append("this library could not send the script of %s: %s" % (c["tag"], hx(ours[(c["id"], "whole")]["err"]).decode()))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1 + len(refs)) as pool:
            f_ours = pool.submit(run_ours, args.probe, peers)
            f_refs = {r: pool.submit(run_ref, r, peers) for r in refs}
            back = {"this library": f_ours.result()}
            back.update({r: f.result() for r, f in f_refs.items()})
        for pc in peers:
            want = [tuple((k, hx(d), code) for k, d, code in corpus_ws.script_events(pc["src"]["data"]))][0]
            expect_end = "closed" if want and want[-1][0] == "close" else "open"
            for r in ["this library"] + refs:
                n = norm_stream(back[r][(pc["id"], "whole")])
                if n is None:
                    if not na_ok(r, pc):
                        failures.append("%s answered n/a for a case it can be put in the state for: %s" % (r, pc["tag"]))
                    wr_t[r]["n/a"] += 1
                    continue
                ok = n[0] == want and n[1] == expect_end
                if ok:
                    wr_t[r]["intact"] += 1
                    continue
                parts = []
                if n[0] != want:
                    parts.append("evs:count" if len(n[0]) != len(want) else "evs:" + ",".join(
                        p for p in EV_PARTS if any(a != b for x, y in zip(n[0], want) for q, a, b in zip(EV_PARTS, x, y) if q == p)))
                kind = "wr:%s%s" % (n[1], "".join("+" + p for p in parts))
                wr_t[r]["differ"] += 1
                if r == "this library":
                    rule = explain(rules, pc["tag"], r, kind)
                    if rule and rule["class"] == "finding":
                        rule.setdefault("cases", []).append((r, pc["src"], kind))
                        continue
                    failures.append("this library read back what it wrote differently: %s: %s (got %r)" % (pc["tag"], kind, n[0][:3]))
                    continue
                record(r, pc["src"], kind)
                wr_rows.append((r, pc["tag"], kind))

    # `policy`, checked: this library ended the connection and the reference had
    # answered a Close and was done, with the same messages delivered. The claim
    # is that what this library objected to is what FOLLOWS the first Close
    # frame (RFC 6455 section 1.4 has an endpoint discard it): the stream cut
    # after that frame must end `closed` here too, with the same Close sent.
    if after_close:
        probes = []
        for i, (r, c, kind, o) in enumerate(after_close):
            frs = corpus_ws._frames_of(c["data"])
            cut = next((pos + hl + plen for pos, hl, plen, done in frs
                        if hl is not None and done and (c["data"][pos] & 15) == 8), None)
            probes.append({"id": i, "kind": c["kind"], "arg": c["arg"], "tag": c["tag"],
                           "data": c["data"] if cut is None else c["data"][:cut]})
        check = run_ours(args.probe, probes)
        ac = collections.Counter()
        for i, (r, c, kind, o) in enumerate(after_close):
            n = norm_stream(check[(i, "whole")])
            if n is not None and n[1] == "closed" and n[2] == o[2] and n[0] == o[0]:
                by_class[r]["policy"] += 1
                report.append((r, c, kind, "policy"))
                ac[r] += 1
            else:
                record(r, c, kind)
        print("policy, checked: %d cases where this library failed the connection and the reference had answered a Close "
              "and was done: cut after the first Close frame this library ends it `closed` with the same Close (%s)"
              % (sum(ac.values()), ", ".join("%s %d" % kv for kv in sorted(ac.items()))))

    # `timing`, checked: the side that was still waiting is given the stream
    # completed (a header finished, a payload filled, the message ended) and
    # must then end the connection too. A candidate that does not is an
    # ordinary disagreement and needs a rule.
    if timing_cands:
        probes = [{"id": i, "kind": c["kind"], "arg": c["arg"], "tag": c["tag"],
                   "data": corpus_ws.complete_stream(c["data"], c["kind"])}
                  for i, (w, r, c, kind) in enumerate(timing_cands)]
        check_ours = run_ours(args.probe, probes)
        by_ref = collections.defaultdict(list)
        for i, (w, r, c, kind) in enumerate(timing_cands):
            by_ref[r].append(probes[i])
        check_ref = {r: run_ref(r, v) for r, v in by_ref.items()}
        auto = collections.Counter()
        for i, (w, r, c, kind) in enumerate(timing_cands):
            p = probes[i]
            side = norm_stream((check_ours if w == "ours" else check_ref[r])[(p["id"], "whole")])
            if side is not None and side[1] != "open":
                by_class[r]["timing"] += 1
                report.append((r, c, kind, "timing"))
                auto[r] += 1
            else:
                record(r, c, kind)
        print("timing, checked: %d cases where one side was waiting and the other had ended the connection, "
              "with the same messages delivered, ended it too once given the stream completed (%s)"
              % (sum(auto.values()), ", ".join("%s %d" % kv for kv in sorted(auto.items()))))

    # Claims that a rule makes about a family of cases are CHECKED, not assumed.
    # A rule's note may begin [check:NAME]:
    #   complete        the one side that was still waiting when the input ended
    #                   (the stream was cut inside a frame) is given the stream
    #                   completed: it must then end the connection too (timing).
    #   strip-controls  with every Ping and Pong frame taken out of the stream
    #                   the two sides must agree (a reference that mishandles a
    #                   control frame inside a message).
    check_runs = collections.Counter()
    for rule in rules:
        m = rule["note"].startswith("[check:") and rule["note"][7:rule["note"].index("]")]
        if not m or "cases" not in rule:
            continue
        todo = []
        for r, c, kind in rule["cases"]:
            if c["kind"] not in ("ws", "wc"):
                failures.append("rule line %d has a check, which is for streams: %s" % (rule["line"], c["tag"]))
                continue
            if m == "complete":
                o, x = S(ours, c), S(answers[r], c)
                if o is None or x is None:
                    continue
                waiting = "ours" if o[1] == "open" and x[1] == "failed" else "ref" if x[1] == "open" and o[1] == "failed" else None
                if waiting is None:
                    failures.append("rule line %d is a timing rule but %s is not one side waiting: %s %s" % (rule["line"], c["tag"], label(o), label(x)))
                    continue
                todo.append((waiting, r, c, corpus_ws.complete_stream(c["data"], c["kind"])))
            elif m == "strip-controls":
                todo.append(("both", r, c, corpus_ws.strip_controls(c["data"])))
            else:
                failures.append("rule line %d: unknown check %r" % (rule["line"], m))
        if not todo:
            continue
        probes = [{"id": i, "kind": c["kind"], "arg": c["arg"], "tag": c["tag"], "data": d}
                  for i, (w, r, c, d) in enumerate(todo)]
        check_ours = run_ours(args.probe, probes)
        by_ref = collections.defaultdict(list)
        for i, (w, r, c, d) in enumerate(todo):
            by_ref[r].append(probes[i])
        check_ref = {r: run_ref(r, v) for r, v in by_ref.items()}
        for i, (w, r, c, d) in enumerate(todo):
            p = probes[i]
            o = norm_stream(check_ours[(p["id"], "whole")])
            x = norm_stream(check_ref[r][(p["id"], "whole")])
            check_runs[m] += 1
            if m == "complete":
                side = o if w == "ours" else x
                if side is None or side[1] == "open":
                    failures.append("[check:complete] %s: %s still waits when the stream is completed (%s): %s"
                                    % (c["tag"], "this library" if w == "ours" else r, c["data"].hex()[:60], d.hex()[:80]))
            elif kind_stream(o, x) is not None:
                failures.append("[check:strip-controls] %s: %s and %s still differ with the control frames removed: %s"
                                % (c["tag"], "this library", r, kind_stream(o, x)))
    if check_runs:
        print("checks: " + ", ".join("%s on %d cases" % kv for kv in sorted(check_runs.items())))

    print()
    cases_n = len(stream_cases) + len(hs_cases) + len(hc_cases)
    print("%-11s %6s %15s %14s %8s %9s %5s" % ("ref", "cases", "agree-accepted", "agree-refused", "differ", "ref-split", "n/a"))
    for r in refs:
        t, per_kind = table[r]
        print("%-11s %6d %15d %14d %8d %9d %5d" % (r, cases_n, t["agree-accepted"], t["agree-refused"],
                                                   t["differ"], t["ref-split"], t["n/a"]))
        print("            by kind: " + ", ".join("%s %d agree %d differ" % (k, v["agree"], v["differ"])
                                                  for k, v in sorted(per_kind.items())))
        for cls, n in sorted(by_class[r].items()):
            print("           %-12s %5d" % (cls, n))
    print("wr: %d scripts this library sent, each read by every implementation as the peer:" % len(wr_cases))
    for r in ["this library"] + refs:
        print("  %-11s intact %d, differ %d, n/a %d" % (r, wr_t[r]["intact"], wr_t[r]["differ"], wr_t[r]["n/a"]))
    split_refs = sum(1 for c in stream_cases if len(c["data"]) <= REF_BYTE_MAX)
    print("each reference was also run one octet at a time over the %d stream cases of at most %d octets "
          "(this library over all %d)" % (split_refs, REF_BYTE_MAX, len(stream_cases)))

    # This library against every reference at once.
    lone = {"accepted": collections.Counter(), "refused": collections.Counter()}
    lone_accept = lone_refuse = 0
    lone_rows = []
    for c in stream_cases:
        o = S(ours, c)
        xs = [S(answers[r], c) for r in refs]
        xs = [x for x in xs if x is not None]
        if len(xs) < 2:
            continue
        fam = c["tag"].split("@")[0] if c["tag"].startswith("gen:") else ":".join(c["tag"].split(":")[:2])[:60]
        if all(x[1] == "failed" for x in xs) and o[1] != "failed":
            lone_accept += 1
            lone["accepted"][fam] += 1
            lone_rows.append(("carried-on", c, o, xs))
        if all(x[1] != "failed" for x in xs) and o[1] == "failed":
            lone_refuse += 1
            lone["refused"][fam] += 1
            lone_rows.append(("failed", c, o, xs))
    print("\nthis library carried on where every reference failed the connection: %d; failed it where every "
          "reference carried on: %d (each is explained by a rule or the run fails)" % (lone_accept, lone_refuse))

    if args.lone:
        with open(args.lone, "w", encoding="utf-8") as out:
            for what, c, o, xs in lone_rows:
                out.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (what, c["tag"], c["kind"], c["arg"], label(o), c["data"][:3000].hex()))
    if args.rules:
        for r in rules:
            print("%4d  line %-4d %-11s %-12s %-44s %s" % (r["hits"], r["line"], r["class"], r["ref"], r["tag"], r["kind"]))
            for tag, ref, kind in r.get("examples", [])[:args.rules]:
                print("          e.g. %-12s %-30s %s" % (ref, kind, tag))
        for which, counter in lone.items():
            print("  alone against every reference, this library %s: %s" % (
                which, ", ".join("%s %d" % kv for kv in counter.most_common(60))))

    findings = [r for r in rules if r["class"] == "finding"]
    if findings:
        n = sum(r["hits"] for r in findings)
        print("\n### OPEN FINDINGS: %d rules, %d cases: defects in THIS library, not excused ###" % (len(findings), n))
        for r in findings:
            print("  line %d (%d cases, e.g. %s): %s" % (r["line"], r["hits"], r.get("examples", [("-",)])[0][0], r["note"]))

    default_run = args.seed == DEFAULT_SEED and args.count == DEFAULT_COUNT and args.refs == ",".join(REFS)
    if not default_run:
        print("(not the default corpus: stale rules are not reported)")
    stale = [r for r in rules if r["hits"] == 0 and not r["note"].startswith("[flaky]")] if default_run else []
    for r in stale:
        failures.append("known-ws-disagreements.tsv:%d explains nothing (stale): %s %s %s"
                        % (r["line"], r["tag"], r["ref"], r["kind"]))
    if unexplained:
        sig = collections.Counter((r, k, c["tag"]) for r, c, k in unexplained)
        failures.append("%d disagreements have no rule; first signatures:" % len(unexplained))
        for (r, k, tag), n in sig.most_common(40):
            ex = next(c for rr, c, kk in unexplained if (rr, kk, c["tag"]) == (r, k, tag))
            failures.append("   %4d  %-10s %-44s tag=%-50s e.g. %s" % (n, r, k, tag, ex["data"][:50].hex()))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as out:
            for r, c, kind, cls in report:
                out.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (r, cls, kind, c["tag"], c["kind"], c["arg"], c["data"][:20000].hex()))
    if args.examples:
        for r, c, kind, cls in report[:args.examples]:
            print("%-10s %-12s %-40s %-40s %s" % (r, cls, kind, c["tag"], c["data"][:60].hex()))

    if failures:
        sys.stderr.write("\n### the WebSocket differential FAILED ###\n")
        for f in failures:
            sys.stderr.write(f + "\n")
        return 1
    print("\nevery disagreement is explained by a rule, and every rule explains one.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
