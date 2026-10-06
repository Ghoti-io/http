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
"""The differential: this library against llhttp, h11 and Go's net/http.

    diff.py --probe build/.../http_probe [--count N] [--seed S] [--report FILE]

Every case in corpus.py is parsed by the probe (this library) and by each
reference, whole and one byte at a time, and the answers are compared:

  - what was accepted: the messages that ended, field for field - method,
    target, version or status and reason, headers (by name, lower-cased, order
    within a name kept), body bytes, trailers;
  - what happened after them: the stream ended clean, ended inside a message
    (`incomplete`), or was refused (`error`), or stopped at a tunnel.

Two things are never decided by a rule file:

  - this library must answer identically whole and byte by byte, or the run
    fails;
  - the references must answer the controls (--controls runs first, always):
    llhttp's lenient flags are shown to change an answer, so that the strict
    setting this driver passes is known to be the one in force; and each
    reference is shown to accept a good message, refuse a bad one and notice
    a truncated one, so that a driver that silently answers "accept" to
    everything cannot produce a green run.

Everything else that differs needs a line in known-disagreements.tsv naming the
case's tag, the reference, the kind of difference and a class, and a line that
explains nothing fails the run as stale. A disagreement is never filtered out
of the denominator: the table at the end counts refused cases and agreed
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
import corpus  # noqa: E402
import oracle_env  # noqa: E402

REFS = ["llhttp", "h11", "gohttp"]
DEFAULT_SEED = 1
DEFAULT_COUNT = 250000

# What a reference cannot report, per reference, dropped from BOTH sides of
# that comparison. Go moves Host into the request's own field and consumes
# Content-Length and Transfer-Encoding into the body reader, so none of the
# three can be read back out of its header map. (It also moves Trailer into
# the request's trailer map, keyed by the names the field announced.)
DROP = {
    "gohttp": {"host", "content-length", "transfer-encoding", "trailer"},
}

CLASSES = {
    "policy": "this library is stricter than RFC 9112 requires and says so (documentation/rfc9112.md)",
    "ref-lenient": "the reference accepts what RFC 9112 says to refuse",
    "ref-strict": "the reference refuses what RFC 9112 allows",
    "ref-model": "the reference does not model the concept (tunnels, upgrade, 1xx)",
    "ref-limit": "a size limit the reference sets differently",
    "ref-bug": "the reference is wrong against its own documentation or the RFC",
    "ref-split": "the reference answers differently depending on how the input is split",
    "ref-late": "the reference refuses only once the head is complete; a stream that stops first it reports as incomplete (checked: completing the stream makes it refuse)",
    "timing": "a refusal made when the line ends here and at the offending byte there; they differ only for a stream that ends inside that line",
    "lenient": "this library accepts what RFC 9112's grammar refuses, with no framing consequence (documented)",
    "scope": "a difference in what the two sides can express, not in what they accepted",
}


def hx(b):
    return bytes.fromhex(b)


# ---- running -----------------------------------------------------------------

def case_lines(cases):
    lines = []
    for c in cases:
        for split in ("whole", "byte"):
            lines.append("%d\t%s\t%s\t%s\t%s" % (
                c["id"], c["kind"], c["method"], split, c["data"].hex()))
    return "\n".join(lines) + "\n"


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
        raise SystemExit("%s answered %d of %d questions: a crashed or truncated "
                         "driver is a failed run, not a smaller corpus" % (name, len(out), want))
    return out


def run_ours(probe, cases):
    env = dict(os.environ)
    done = subprocess.run([probe], input=case_lines(cases), capture_output=True,
                          text=True, errors="surrogateescape", env=env)
    if done.returncode != 0:
        raise SystemExit("the probe exited %d: %s" % (done.returncode, done.stderr[-2000:]))
    return parse_answers("this library", done.stdout, 2 * len(cases))


def run_ref(name, cases, env=None):
    argv = oracle_env.command(name, env=env)
    done = subprocess.run(argv, input=case_lines(cases), capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit("%s exited %d: %s" % (name, done.returncode, done.stderr[-2000:]))
    return parse_answers(name, done.stdout, 2 * len(cases))


# ---- normalising and comparing --------------------------------------------------

def norm(res, drop=frozenset()):
    """A comparable form: messages up to the first tunnel, and how it ended."""
    msgs = []
    end = res["end"]
    for m in res["msgs"]:
        def fieldmap(pairs):
            d = collections.OrderedDict()
            for n, v in pairs:
                k = hx(n).decode('latin1').lower()
                if k in drop:
                    continue
                d.setdefault(k, []).append(hx(v))
            return tuple(sorted((k, tuple(v)) for k, v in d.items()))
        start = tuple(sorted((k, v) for k, v in m["start"].items()))
        msgs.append((start, fieldmap(m["headers"]), hx(m["body"]), fieldmap(m["trailers"])))
        if m.get("upgrade"):
            end = "upgrade"
            break
    return (tuple(msgs), end)


def diff_kind(ours, ref):
    """None if the two are the same, else 'ours-end/ref-end[+what]'."""
    if ours == ref:
        return None
    (am, ae), (bm, be) = ours, ref
    kind = "%s/%s" % (ae, be)
    if am == bm:
        return kind
    n = min(len(am), len(bm))
    for i in range(n):
        if am[i] != bm[i]:
            parts = ["start", "headers", "body", "trailers"]
            what = [p for p, x, y in zip(parts, am[i], bm[i]) if x != y]
            return kind + "+" + "+".join(what)
    return kind + "+count"


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
        if (fnmatch.fnmatchcase(tag, r["tag"]) and r["ref"] in ("*", ref)
                and fnmatch.fnmatchcase(kind, r["kind"])):
            r["hits"] += 1
            r.setdefault("examples", []).append((tag, ref, kind))
            return r
    return None


# ---- the controls -----------------------------------------------------------------

def controls(probe):
    """Fail loudly unless the instrument can see what it claims to."""
    good = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    cases = [
        {"id": 0, "kind": "req", "method": "-", "data": good},
        {"id": 1, "kind": "req", "method": "-", "data": b"\x00\x01\x02garbage\r\n\r\n"},
        {"id": 2, "kind": "req", "method": "-", "data": good[:-2]},
        {"id": 3, "kind": "req", "method": "-",
         "data": b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"},
    ]
    problems = []
    for name, answerer in [("this library", lambda: run_ours(probe, cases))] + [
            (r, (lambda r=r: run_ref(r, cases))) for r in REFS]:
        got = answerer()
        a = {i: got[(i, "whole")] for i in range(4)}
        if not (len(a[0]["msgs"]) == 1 and a[0]["end"] == "clean"):
            problems.append("%s did not accept a good request: %r" % (name, a[0]))
        if a[1]["end"] != "error":
            problems.append("%s did not refuse garbage: %r" % (name, a[1]))
        if a[2]["end"] != "incomplete" and not (name == "gohttp" and a[2]["end"] == "incomplete"):
            problems.append("%s did not report a truncated request as incomplete: %r" % (name, a[2]))
        if not (len(a[3]["msgs"]) == 1 and hx(a[3]["msgs"][0]["body"]) == b"abc"):
            problems.append("%s did not read a 3-byte body: %r" % (name, a[3]))
    # llhttp's strictness: an input its lenient flags change the answer to.
    flip = [
        ("bare LF line ends", b"GET / HTTP/1.1\nHost: h\n\n"),
        ("CL with TE", b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n"
                       b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("control byte in a value", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n"),
        ("space before chunk extension", b"POST / HTTP/1.1\r\nHost: h\r\n"
                                          b"Transfer-Encoding: chunked\r\n\r\n1 ;a\r\nx\r\n0\r\n\r\n"),
    ]
    fc = [{"id": i, "kind": "req", "method": "-", "data": d} for i, (_, d) in enumerate(flip)]
    strict = run_ref("llhttp", fc)
    lenient = run_ref("llhttp", fc, env={"GHTTP_REF_LENIENT": "1"})
    flipped = []
    for i, (what, _) in enumerate(flip):
        if strict[(i, "whole")]["end"] == "error" and lenient[(i, "whole")]["end"] != "error":
            flipped.append(what)
    if not flipped:
        problems.append("llhttp's lenient flag changed no answer: the strict setting "
                        "this driver passes is not shown to be in force")
    return problems, flipped


# ---- main ---------------------------------------------------------------------------

def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT,
                    help="generated mutations to draw; duplicates are dropped, so the "
                         "corpus holds fewer (about a third as many unique cases)")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--fuzz-corpus", default=None)
    ap.add_argument("--known", default=os.path.join(HERE, "known-disagreements.tsv"))
    ap.add_argument("--report", default=None, help="write every disagreement here")
    ap.add_argument("--examples", type=int, default=0)
    ap.add_argument("--rules", type=int, default=0, metavar="N",
                    help="print every rule's hit count and up to N cases it explains")
    ap.add_argument("--refs", default=",".join(REFS))
    args = ap.parse_args(argv)
    refs = args.refs.split(",")

    problems, flipped = controls(args.probe)
    if problems:
        sys.stderr.write("### the controls failed: the run would not mean anything ###\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        return 1
    print("controls: each reference accepted a good request, refused garbage and "
          "reported a truncated one; llhttp's lenient flag flipped: %s" % ", ".join(flipped))

    cases = corpus.all_cases(args.seed, args.count, args.fuzz_corpus)
    by_src = collections.Counter(c["tag"].split(":")[0] if c["tag"].split(":")[0] in
                                 ("gen", "fixture", "seed", "fuzz") else
                                 ("rfc" if c["tag"].startswith("rfc9112") else "hand")
                                 for c in cases)
    nreq = sum(1 for c in cases if c["kind"] == "req")
    print("corpus: %d cases (%s), %d requests and %d responses, seed %d"
          % (len(cases), ", ".join("%s %d" % kv for kv in sorted(by_src.items())),
             nreq, len(cases) - nreq, args.seed))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1 + len(refs)) as pool:
        f_ours = pool.submit(run_ours, args.probe, cases)
        f_refs = {r: pool.submit(run_ref, r, cases) for r in refs}
        ours = f_ours.result()
        answers = {r: f.result() for r, f in f_refs.items()}

    failures = []
    rules = load_known(args.known)

    # This library must not depend on how the input is cut.
    ours_split = [c for c in cases if norm(ours[(c["id"], "whole")]) != norm(ours[(c["id"], "byte")])]
    for c in ours_split[:10]:
        failures.append("this library answers differently whole and byte by byte: case %d (%s) %s"
                        % (c["id"], c["tag"], c["data"][:80]))

    ours_end = collections.Counter(norm(ours[(c["id"], "whole")])[1] for c in cases)
    print("this library: ended clean %d, upgrade %d, incomplete %d, refused %d"
          % (ours_end["clean"], ours_end["upgrade"], ours_end["incomplete"], ours_end["error"]))

    table = {}
    report = []
    unexplained = []
    timing = {}  # case id -> the cases whose `timing` explanation is to be verified
    late = collections.defaultdict(dict)  # ref -> case id -> case, for `ref-late`
    by_class = collections.defaultdict(collections.Counter)
    for r in refs:
        drop = DROP.get(r, frozenset())
        t = collections.Counter()
        for c in cases:
            o = norm(ours[(c["id"], "whole")], drop)
            x = norm(answers[r][(c["id"], "whole")], drop)
            kind = diff_kind(o, x)
            if kind is None:
                t["agree-refused" if o[1] == "error" else
                  "agree-accepted" if o[0] else "agree-empty"] += 1
            else:
                rule = explain(rules, c["tag"], r, kind)
                t["differ"] += 1
                if rule and rule["class"] == "timing":
                    timing.setdefault(c["id"], c)
                if rule and rule["class"] == "ref-late":
                    late[r].setdefault(c["id"], c)
                cls = rule["class"] if rule else "UNEXPLAINED"
                by_class[r][cls] += 1
                report.append((r, c, kind, cls))
                if not rule:
                    unexplained.append((r, c, kind))
            # Reference split dependence, which is its own finding.
            xb = norm(answers[r][(c["id"], "byte")], drop)
            if x != xb:
                t["ref-split"] += 1
                rule = explain(rules, c["tag"], r, "split")
                by_class[r]["ref-split" if rule else "UNEXPLAINED"] += 1
                if not rule:
                    unexplained.append((r, c, "split"))
                report.append((r, c, "split", rule["class"] if rule else "UNEXPLAINED"))
        table[r] = t

    # A `timing` explanation is a claim that this library only refuses LATER than
    # the reference, at the end of the line rather than at the byte. It is checked,
    # not assumed: the same stream with an empty line appended must be refused,
    # or the "timing" was this library accepting what the reference refused.
    if timing:
        probes = [{"id": cid, "kind": c["kind"], "method": c["method"],
                   "data": c["data"] + b"\r\n\r\n"} for cid, c in sorted(timing.items())]
        finished = run_ours(args.probe, probes)
        bad = [c for cid, c in sorted(timing.items())
               if finished[(cid, "whole")]["end"] != "error"]
        print("timing: %d cases explained as a later refusal; completing the stream "
              "made this library refuse %d of them" % (len(timing), len(timing) - len(bad)))
        for c in bad:
            failures.append("explained as timing, but this library does not refuse it once "
                            "the line ends: case %d (%s) %r" % (c["id"], c["tag"], c["data"][:100]))

    # `ref-late` is the same claim about a reference: it refuses what this library
    # refuses, only after the head is whole. Asked of the reference, not assumed.
    for r, found in sorted(late.items()):
        probes = [{"id": cid, "kind": c["kind"], "method": c["method"],
                   "data": c["data"] + b"\r\n\r\n"} for cid, c in sorted(found.items())]
        finished = run_ref(r, probes)
        bad = [c for cid, c in sorted(found.items()) if finished[(cid, "whole")]["end"] != "error"]
        print("ref-late: %s reported %d cases as incomplete that this library refuses; "
              "completing the stream made it refuse %d" % (r, len(found), len(found) - len(bad)))
        for c in bad:
            failures.append("explained as ref-late, but %s accepts it once the head is whole: "
                            "case %d (%s) %r" % (r, c["id"], c["tag"], c["data"][:100]))

    print()
    print("%-8s %6s %15s %15s %8s %9s" % ("ref", "cases", "agree-accepted", "agree-refused", "differ", "ref-split"))
    for r in refs:
        t = table[r]
        print("%-8s %6d %15d %15d %8d %9d" % (r, len(cases), t["agree-accepted"] + t["agree-empty"],
                                              t["agree-refused"], t["differ"], t["ref-split"]))
        for cls, n in sorted(by_class[r].items()):
            print("           %-12s %5d" % (cls, n))

    # Ours against every reference at once: the disagreements that matter most.
    lone_accept = lone_refuse = 0
    lone_tags = {"accepted": collections.Counter(), "refused": collections.Counter()}
    for c in cases:
        o = norm(ours[(c["id"], "whole")])
        xs = [norm(answers[r][(c["id"], "whole")], DROP.get(r, frozenset())) for r in refs]
        fam = c["tag"].split("@")[0] if c["tag"].startswith("gen:") else c["tag"].split(":")[0]
        if all(x[1] == "error" for x in xs) and o[1] in ("clean", "upgrade"):
            lone_accept += 1
            lone_tags["accepted"][fam] += 1
        if all(x[1] != "error" and x[0] for x in xs) and o[1] == "error":
            lone_refuse += 1
            lone_tags["refused"][fam] += 1
    print("\nthis library accepted where every reference refused: %d; refused where every "
          "reference accepted a message: %d (each is explained by a rule or the run fails)"
          % (lone_accept, lone_refuse))

    if args.rules:
        for r in rules:
            print("%4d  line %-4d %-9s %-8s %-40s %s" % (r["hits"], r["line"], r["class"], r["ref"], r["tag"], r["kind"]))
            for tag, ref, kind in r.get("examples", [])[:args.rules]:
                print("          e.g. %-8s %-22s %s" % (ref, kind, tag))
    if args.rules:
        for which, counter in lone_tags.items():
            print("  alone against every reference, this library %s: %s" % (
                which, ", ".join("%s %d" % kv for kv in counter.most_common(40))))
    # A rule that explains nothing is dead weight, but only the default corpus can
    # say so: another seed or size draws other families, and a fuzz corpus draws
    # inputs with no cause to name.
    default_run = (args.seed == DEFAULT_SEED and args.count == DEFAULT_COUNT
                   and not args.fuzz_corpus)
    if not default_run:
        print("(not the default corpus: stale rules are not reported)")
    stale = [r for r in rules if r["hits"] == 0] if default_run else []
    for r in stale:
        failures.append("known-disagreements.tsv:%d explains nothing (stale): %s %s %s"
                        % (r["line"], r["tag"], r["ref"], r["kind"]))
    if args.fuzz_corpus:
        # Fuzz inputs are arbitrary bytes with no cause to name, so a rule file
        # cannot speak for them. They are reported, not gated.
        fuzzed = [u for u in unexplained if u[1]["tag"].startswith("fuzz:")]
        unexplained = [u for u in unexplained if not u[1]["tag"].startswith("fuzz:")]
        print("fuzz corpus: %d inputs, %d disagreements with a reference that no rule names "
              "(informational); this library accepted where every reference refused: see above"
              % (sum(1 for c in cases if c["tag"].startswith("fuzz:")), len(fuzzed)))
    if unexplained:
        sig = collections.Counter((r, k, c["tag"]) for r, c, k in unexplained)
        failures.append("%d disagreements have no rule; first signatures:" % len(unexplained))
        for (r, k, tag), n in sig.most_common(25):
            ex = next(c for rr, c, kk in unexplained if (rr, kk, c["tag"]) == (r, k, tag))
            failures.append("   %4d  %-7s %-24s tag=%-24s e.g. %r" % (n, r, k, tag, ex["data"][:90]))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as out:
            for r, c, kind, cls in report:
                out.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    r, cls, kind, c["tag"], c["kind"] + ":" + c["method"], c["data"].hex()))
    if args.examples:
        for r, c, kind, cls in report[:args.examples]:
            print("%-7s %-12s %-22s %-22s %r" % (r, cls, kind, c["tag"], c["data"][:100]))

    if failures:
        sys.stderr.write("\n### the differential FAILED ###\n")
        for f in failures:
            sys.stderr.write(f + "\n")
        return 1
    print("\nevery disagreement is explained by a rule, and every rule explains one.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
