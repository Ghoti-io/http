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
"""The Autobahn|Testsuite differential for the WebSocket codec.

    run.py [--ws-echo PATH] [--direction server|client|both]
           [--quick | --full] [--cases PATTERNS] [--exclude PATTERNS]
           [--expected FILE] [--outdir DIR] [--keep] [--propose FILE]
           [--control]

README (this comment is the documentation; there is no other file)
------------------------------------------------------------------

What it is. Autobahn|Testsuite (crossbario/autobahn-testsuite) is the
reference for WebSocket conformance: 517 cases of RFC 6455 (framing, ping and
pong, reserved bits, opcodes, fragmentation, UTF-8, close handshakes, close
codes, large messages, limits) and of permessage-deflate (RFC 7692, sections
12 and 13). It is old (Python 2 on PyPy) and it is still the suite every
implementation is measured against. Nothing here reimplements it.

Two directions, both run against ws_echo.c, which is a thin socket program
around THIS library (the library does no I/O):

  server   `wstest -m fuzzingclient` connects, as a client, to `ws_echo
           server` and runs every case against our server codec.
  client   `wstest -m fuzzingserver` listens, and `ws_echo client` runs the
           documented client loop against it (getCaseCount, runCase for each
           case, updateReports): every case against our client codec.

The container runs with --network=host and reaches the program on 127.0.0.1;
rootless podman and Docker both allow that. The program is told port 0 and
prints the one it got, so nothing is guessed and nothing sleeps: this script
waits on process handles, a pipe line and a thread event, never on a timer.

The comparison. The suite's report (index.json, one entry per case) says for
each case a `behavior` (OK, NON-STRICT, INFORMATIONAL, UNIMPLEMENTED, FAILED)
and a `behaviorClose` for the closing handshake, and the close code the peer
saw. expected.tsv holds one line per case and direction with all of them, a
class, and a sentence for every line that is not plain OK. A run FAILS for:

  - a case the suite lists that is missing from the report, or reported that
    was not asked for (an empty or short report is never green);
  - any change from expected.tsv in behavior, behaviorClose or close code;
  - an expected line no Autobahn case matches (stale), a case with no line;
  - the container, the image digest or the version it reports not being the
    pin (IMAGE), the engine being absent, or the image not being present:
    those are FAILURES, never skips.

The denominator is not this script's: the list of case ids comes from the
suite itself, asked inside the container, and for the client direction the
count the fuzzingserver announces and the count ws_echo is told must agree.

What green means. Every selected case, in each direction, behaves as
expected.tsv says, and the only non-OK lines are ones whose sentence explains
why that is the right behaviour (INFORMATIONAL cases report and cannot fail;
NON-STRICT ones are outcomes RFC 6455 permits). It does NOT mean the library
is right where Autobahn has no case: the frame and message reassembly are
exercised at the chunk sizes Autobahn chose, not at every cut (tests/unit
test_ws_split.cpp does that); the policy limits ws_echo sets (see its header)
are not tested; permessage-deflate parameter negotiation is covered only to
the extent of cases 12.x and 13.x; decompression bombs (max_expansion_ratio)
are not Autobahn-visible. And it is a differential against ONE implementation
(Autobahn's), whose own mistakes would be shared: see expected.tsv notes.

--quick. The full suite (517 cases) takes about 14 minutes in the server direction
(measured: 858 s) and about as long again in the client direction (not measured in full). Not where one
would guess: the 9.x groups (16 MiB messages, 64-octet frames) take about three
seconds in all. The time is the 1000-message compression cases 12.x and 13.x,
which are Autobahn's own Python compressing, and within them the ones with the
largest payloads (case numbers 9, 10 and 14 to 18 of every 12.x and 13.x
group, 128 KiB payloads and the 256- to 32768-octet auto-fragmentations of
them: 70 cases, 80 percent of the time). QUICK_EXCLUDE leaves those out and
runs the other 447 cases, the rest of 12.x and 13.x and all of 9.x, in about
160 seconds in the server direction and 150 in the client direction; the gate uses quick by default and
`make check-autobahn-full` runs all of it. expected.tsv always has every case:
quick only narrows what is run.

KNOWN FLAKE, which is why check-autobahn is NOT in `make test` or check-oracle.
The client direction passed every time it was run (five runs, 430 OK and 3
INFORMATIONAL of 433). The server direction passed 4 of 12 runs; in the others
`wstest -m fuzzingclient` exits 0 near the end of its cases (after 390 to 444
log lines of about 445) without writing index.json, so the run FAILS with "the
suite wrote no index.json" and never reports a wrong answer. Measured: the
echo server is alive, the container's exit code is 0 and OOMKilled is false, the
report directory's location (/tmp or not) does not matter, memcap and a manual
`podman run` against a standalone server behave the same, and the cases that
were run all behaved as expected. Not explained; a run that passes is complete.

--control. Runs ws_echo with an echo that is deliberately wrong (every message
returned as binary: GHOTI_WS_ECHO_BREAK=1) on a small selection and requires
the comparison to FAIL on the cases that should notice. Exit 0 means the
harness saw it; the gate (check-gate.sh) runs it, and plants library and
instrument defects besides.

--propose FILE. Writes what the run saw as a candidate expected.tsv (never to
the checked-in file) with class `?` on anything that is not OK/OK. It is for
bumping the pin: read every difference against the RFC and write the sentence
yourself; a proposal accepted unread would make the file a record of what
happened and not of what is right.

Bumping the pin. Resolve the new digest (IMAGE says how), edit IMAGE (digest
and the version the probe prints), run `run.py --full --propose /tmp/new.tsv`,
diff against expected.tsv, classify every difference, commit the IMAGE change
and the expectation changes together and separately from any code change.

Exit status: 0 green, 1 a failed comparison or an unavailable reference,
2 usage.
"""

import argparse
import fnmatch
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE_FILE = os.path.join(HERE, "IMAGE")
DEFAULT_EXPECTED = os.path.join(HERE, "expected.tsv")
ENGINE = os.environ.get("GHOTI_CONTAINER_ENGINE", "docker")
AGENT = "ghoti-http"

# What --quick leaves out: Autobahn's big-message groups and the compressed
# repeats of them. See the README above and expected.tsv for the timing.
QUICK_EXCLUDE = (["12.*.%d" % n for n in (9, 10, 14, 15, 16, 17, 18)]
                 + ["13.*.%d" % n for n in (9, 10, 14, 15, 16, 17, 18)])

BEHAVIORS = ("OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED", "FAILED")
CLASSES = ("ok", "informational", "non-strict", "deviation", "unimplemented")


class Unavailable(Exception):
    """The reference cannot be reached. Never turned into a skip."""


class Failure(Exception):
    """A run that cannot be judged."""


# ---- the pin ----------------------------------------------------------------

_pin = None


def pin():
    """(image, version) from IMAGE."""
    global _pin
    if _pin is not None:
        return _pin
    with open(IMAGE_FILE, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                raise Unavailable("IMAGE: not three tab-separated fields: %r" % line)
            if "@sha256:" not in parts[1]:
                raise Unavailable("IMAGE: %s is not pinned by digest" % parts[1])
            _pin = (parts[1], parts[2])
            return _pin
    raise Unavailable("IMAGE: no pin")


def container_base(name=None, extra=()):
    image, _ = pin()
    argv = [ENGINE, "run", "--rm", "--network=host", "--read-only",
            "--tmpfs", "/tmp", "-e", "PYTHONUNBUFFERED=1"]
    if name:
        argv += ["--name", name]
    return argv + list(extra), image


PROBE = ("import sys, autobahntestsuite, autobahn, twisted; "
         "print('autobahntestsuite %s autobahn %s twisted %s pypy %s' % "
         "(autobahntestsuite.version, autobahn.version, twisted.version.short(), "
         "'.'.join(map(str, sys.pypy_version_info[:3]))))")


def check_pin():
    """Raise unless the engine, the image and its reported version are the pin."""
    if shutil.which(ENGINE) is None:
        raise Unavailable(
            "%s is not on PATH. Install it, or name another engine with "
            "GHOTI_CONTAINER_ENGINE. There is no host mode: Autobahn is a Python 2 "
            "program that only runs as its pinned image." % ENGINE)
    image, version = pin()
    have = subprocess.run([ENGINE, "image", "exists", image],
                          capture_output=True).returncode == 0
    if not have:
        have = subprocess.run([ENGINE, "image", "inspect", image],
                              capture_output=True).returncode == 0
    if not have:
        raise Unavailable("the image is not present:\n  %s pull %s" % (ENGINE, image))
    argv, image = container_base()
    done = subprocess.run(argv + [image, "python", "-c", PROBE],
                          capture_output=True, text=True)
    said = done.stdout.strip().splitlines()
    said = said[-1] if said else ""
    if done.returncode != 0 or said != version:
        raise Unavailable("IMAGE says %r and the container answers %r (exit %d) %s"
                          % (version, said, done.returncode, done.stderr.strip()[-300:]))
    return image, said


# ---- asking the suite ---------------------------------------------------------

LIST_SCRIPT = (
    "import json, sys\n"
    "from autobahntestsuite import case as c\n"
    "from autobahntestsuite.caseset import CaseSet\n"
    "cs = CaseSet(c.CaseSetname, c.CaseBasename, c.Cases, c.CaseCategories, c.CaseSubCategories)\n"
    "spec = json.loads(sys.argv[1])\n"
    "print(json.dumps(cs.parseSpecCases(spec)))\n")


def list_cases(cases, exclude):
    """The case ids the suite itself selects for a spec."""
    argv, image = container_base()
    spec = json.dumps({"cases": cases, "exclude-cases": exclude})
    done = subprocess.run(argv + [image, "python", "-c", LIST_SCRIPT, spec],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise Failure("could not ask the suite for its cases: %s" % done.stderr.strip()[-300:])
    return json.loads(done.stdout.strip().splitlines()[-1])


# ---- the expectation ----------------------------------------------------------

class Row:
    __slots__ = ("behavior", "close", "code", "klass", "note", "line")

    def __init__(self, behavior, close, code, klass, note, line):
        self.behavior, self.close, self.code = behavior, close, code
        self.klass, self.note, self.line = klass, note, line


def case_key(case_id):
    return tuple(int(p) for p in case_id.split("."))


def load_expected(path):
    """{(direction, case): Row}. A malformed line is a failure of the file."""
    rows = {}
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 6:
                raise Failure("%s:%d: want direction, case, behavior, behaviorClose, "
                              "closeCode, class[, note]" % (path, number))
            direction, case, behavior, close, code, klass = parts[:6]
            note = parts[6] if len(parts) > 6 else ""
            where = "%s:%d" % (path, number)
            if direction not in ("server", "client"):
                raise Failure("%s: direction %r" % (where, direction))
            if not re.fullmatch(r"\d+(\.\d+)+", case):
                raise Failure("%s: case id %r" % (where, case))
            if behavior not in BEHAVIORS or close not in BEHAVIORS:
                raise Failure("%s: behavior %r / %r" % (where, behavior, close))
            if klass not in CLASSES:
                raise Failure("%s: class %r (not one of %s)" % (where, klass, ", ".join(CLASSES)))
            if code != "*" and not re.fullmatch(r"\d+|None", code):
                raise Failure("%s: close code %r" % (where, code))
            if klass == "ok" and (behavior != "OK" or close != "OK"):
                raise Failure("%s: class ok but %s/%s" % (where, behavior, close))
            if klass != "ok" and len(note.strip()) < 12:
                raise Failure("%s: a line that is not plain OK needs its sentence" % where)
            if (direction, case) in rows:
                raise Failure("%s: %s %s appears twice (first at line %d)"
                              % (where, direction, case, rows[(direction, case)].line))
            rows[(direction, case)] = Row(behavior, close, code, klass, note, number)
    return rows


def compare(direction, expected, all_ids, selected, results):
    """The problems, as strings. Empty means every case is as expected."""
    problems = []
    mine = {c for (d, c) in expected if d == direction}
    unlisted = sorted(set(all_ids) - mine, key=case_key)
    for case in unlisted[:5]:
        problems.append("%s %s: the suite has this case and expected.tsv has no line for it"
                        % (direction, case))
    if len(unlisted) > 5:
        problems.append("%s: ... and %d more cases with no line in expected.tsv"
                        % (direction, len(unlisted) - 5))
    for case in sorted(mine - set(all_ids), key=case_key):
        row = expected[(direction, case)]
        problems.append("%s %s: expected.tsv line %d matches no case in the suite (stale)"
                        % (direction, case, row.line))
    for case in sorted(set(selected) - set(results), key=case_key):
        problems.append("%s %s: asked for and absent from the report" % (direction, case))
    for case in sorted(set(results) - set(selected), key=case_key):
        problems.append("%s %s: in the report and not asked for" % (direction, case))
    if not selected:
        problems.append("%s: no case was selected: an empty run is not a pass" % direction)
    for case in sorted(set(selected) & set(results), key=case_key):
        got = results[case]
        row = expected.get((direction, case))
        if row is None:
            continue
        diffs = []
        if got["behavior"] != row.behavior:
            diffs.append("behavior %s, expected %s" % (got["behavior"], row.behavior))
        if got["behaviorClose"] != row.close:
            diffs.append("behaviorClose %s, expected %s" % (got["behaviorClose"], row.close))
        if row.code != "*" and str(got.get("remoteCloseCode")) != row.code:
            diffs.append("close code %s, expected %s" % (got.get("remoteCloseCode"), row.code))
        if diffs:
            problems.append("%s %s: %s [class %s%s]" % (
                direction, case, "; ".join(diffs), row.klass,
                (": " + row.note) if row.note else ""))
    return problems


def selftest():
    """The comparator must see every kind of deviation, or nothing it says is evidence.

    Run on every invocation, before the suite: a comparator edited into
    blindness (to behaviorClose, to the close code, to a missing case) fails
    here, with a message that names what it cannot see.
    """
    def row(line):
        return Row("OK", "OK", "1000", "ok", "", line)

    def entry(behavior="OK", close="OK", code=1000):
        return {"behavior": behavior, "behaviorClose": close, "remoteCloseCode": code}

    exp = {("server", "1.1.1"): row(1), ("server", "1.1.2"): row(2)}
    ids = ["1.1.1", "1.1.2"]
    clean = {"1.1.1": entry(), "1.1.2": entry()}
    if compare("server", exp, ids, ids, clean):
        raise Failure("self-test: the comparator reports a clean run as deviating")
    cases = [
        ("a changed behavior", ids, ids, {"1.1.1": entry("FAILED"), "1.1.2": entry()}, exp),
        ("a changed behaviorClose", ids, ids, {"1.1.1": entry(), "1.1.2": entry(close="NON-STRICT")}, exp),
        ("a changed close code", ids, ids, {"1.1.1": entry(code=1002), "1.1.2": entry()}, exp),
        ("a case absent from the report", ids, ids, {"1.1.1": entry()}, exp),
        ("a case in the report that was not asked for", ids, ["1.1.1"], clean, exp),
        ("a case with no expected line", ids, ids, clean, {("server", "1.1.1"): row(1)}),
        ("a stale expected line", ids, ids, clean, {**exp, ("server", "9.9.9"): row(3)}),
        ("an empty selection", ids, [], {}, exp),
    ]
    for what, all_ids, selected, results, expected in cases:
        if not compare("server", expected, all_ids, selected, results):
            raise Failure("self-test: the comparator did not see %s" % what)


def read_report(outdir):
    """{case: entry} from index.json, plus the per-case detail lazily."""
    index = os.path.join(outdir, "index.json")
    if not os.path.exists(index):
        raise Failure("the suite wrote no %s" % index)
    with open(index, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if AGENT not in data:
        raise Failure("index.json has no entry for the agent %r (it has %s)"
                      % (AGENT, ", ".join(sorted(data)) or "none"))
    return data[AGENT]


def detail(outdir, entry):
    try:
        with open(os.path.join(outdir, entry["reportfile"]), "r", encoding="utf-8") as handle:
            full = json.load(handle)
        return "%s | %s | peer: %s" % (full.get("result"), full.get("resultClose"),
                                        full.get("remoteCloseReason"))
    except (OSError, ValueError, KeyError):
        return "(no detail)"


def summarise(direction, results):
    counts = {}
    for entry in results.values():
        counts[entry["behavior"]] = counts.get(entry["behavior"], 0) + 1
    return "%s: %d cases: %s" % (direction, len(results), ", ".join(
        "%s %d" % (b, counts[b]) for b in BEHAVIORS if b in counts))


def propose(path, direction_results, expected):
    """A candidate file: what was seen. `?` marks every line that needs a sentence."""
    lines = ["# Proposed by run.py --propose. Class `?` lines have not been judged.",
             "# direction\tcase\tbehavior\tbehaviorClose\tcloseCode\tclass\tnote"]
    for direction, results in direction_results:
        for case in sorted(results, key=case_key):
            e = results[case]
            plain = e["behavior"] == "OK" and e["behaviorClose"] == "OK"
            old = expected.get((direction, case))
            klass = "ok" if plain else (old.klass if old and old.behavior == e["behavior"]
                                        and old.close == e["behaviorClose"] else "?")
            note = "" if plain else (old.note if old and klass != "?" else "")
            lines.append("\t".join([direction, case, e["behavior"], e["behaviorClose"],
                                    str(e.get("remoteCloseCode")), klass, note]))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# ---- running it -----------------------------------------------------------------

def spec_for(outdir_in_container, cases, exclude, url=None, agent_url=None):
    spec = {"outdir": outdir_in_container, "cases": cases, "exclude-cases": exclude,
            "exclude-agent-cases": {}}
    if url:
        spec["url"] = url
    if agent_url:
        spec["servers"] = [{"agent": AGENT, "url": agent_url}]
    return spec


def start_ws_echo_server(ws_echo, errfile, env):
    proc = subprocess.Popen([ws_echo, "server", "0"], stdout=subprocess.PIPE,
                            stderr=errfile, text=True, env=env)
    line = proc.stdout.readline()
    m = re.fullmatch(r"listening (\d+)\n", line)
    if not m:
        proc.kill()
        proc.wait()
        raise Failure("ws_echo server did not say where it listens: %r" % line)
    return proc, int(m.group(1))


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def server_direction(ws_echo, work, cases, exclude, selected, env, timeout):
    """fuzzingclient against ws_echo server. Returns (results, outdir, seconds)."""
    outdir = os.path.join(work, "server-reports")
    os.makedirs(outdir)
    errpath = os.path.join(work, "server.stderr")
    with open(errpath, "w") as err:
        proc, port = start_ws_echo_server(ws_echo, err, env)
        try:
            spec = spec_for("/work/server-reports", cases, exclude,
                            agent_url="ws://127.0.0.1:%d" % port)
            with open(os.path.join(work, "fuzzingclient.json"), "w") as handle:
                json.dump(spec, handle, indent=1)
            argv, image = container_base(extra=["-v", "%s:/work" % work])
            started = time.monotonic()
            with open(os.path.join(work, "fuzzingclient.log"), "w") as log:
                done = subprocess.run(
                    argv + [image, "wstest", "-m", "fuzzingclient", "-s", "/work/fuzzingclient.json"],
                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            seconds = time.monotonic() - started
        finally:
            stop(proc)
    if done.returncode != 0:
        raise Failure("wstest -m fuzzingclient exited %d (see %s/fuzzingclient.log)"
                      % (done.returncode, work))
    with open(errpath) as err:
        noise = [l.strip() for l in err if l.startswith("ws_echo:")]
    return read_report(outdir), outdir, seconds, noise


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def client_direction(ws_echo, work, cases, exclude, selected, env, timeout):
    """fuzzingserver, driven by ws_echo client. Returns (results, outdir, seconds)."""
    outdir = os.path.join(work, "client-reports")
    os.makedirs(outdir)
    port = free_port()
    spec = spec_for("/work/client-reports", cases, exclude, url="ws://127.0.0.1:%d" % port)
    with open(os.path.join(work, "fuzzingserver.json"), "w") as handle:
        json.dump(spec, handle, indent=1)
    name = "ghoti-autobahn-%d" % os.getpid()
    argv, image = container_base(name=name, extra=["-v", "%s:/work" % work])
    logpath = os.path.join(work, "fuzzingserver.log")
    ready = threading.Event()
    announced = []

    proc = subprocess.Popen(
        argv + [image, "wstest", "-m", "fuzzingserver", "-s", "/work/fuzzingserver.json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def pump():
        with open(logpath, "w") as log:
            for line in proc.stdout:
                log.write(line)
                log.flush()
                m = re.match(r"Ok, will run (\d+) test cases", line)
                if m:
                    announced.append(int(m.group(1)))
                    ready.set()
        ready.set()

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    try:
        if not ready.wait(timeout=120) or not announced:
            raise Failure("the fuzzingserver did not announce its cases (see %s)" % logpath)
        if announced[0] != len(selected):
            raise Failure("the fuzzingserver will run %d cases and the suite's own selection "
                          "is %d" % (announced[0], len(selected)))
        started = time.monotonic()
        done = subprocess.run([ws_echo, "client", "127.0.0.1", str(port), AGENT],
                              capture_output=True, text=True, timeout=timeout, env=env)
        seconds = time.monotonic() - started
    finally:
        subprocess.run([ENGINE, "kill", name], capture_output=True)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        thread.join(timeout=10)
    with open(os.path.join(work, "client.stdout"), "w") as handle:
        handle.write(done.stdout + done.stderr)
    m = re.search(r"^cases (\d+)$", done.stdout, re.M)
    if not m or int(m.group(1)) != len(selected):
        raise Failure("ws_echo client saw %s cases and the suite selected %d"
                      % (m.group(1) if m else "no case count", len(selected)))
    if done.returncode != 0:
        raise Failure("ws_echo client exited %d: %s" % (done.returncode, done.stderr.strip()[-400:]))
    noise = [l.strip() for l in done.stderr.splitlines() if l.startswith("ws_echo:")]
    return read_report(outdir), outdir, seconds, noise


def judge(direction, expected, all_ids, selected, results, outdir, noise):
    problems = compare(direction, expected, all_ids, selected, results)
    if noise:
        problems.append("%s: ws_echo reported on stderr: %s" % (direction, "; ".join(sorted(set(noise))[:5])))
    return problems


def split(text):
    return [p.strip() for p in text.split(",") if p.strip()] if text else []


def main(argv):
    ap = argparse.ArgumentParser(description="Autobahn|Testsuite differential")
    ap.add_argument("--ws-echo", default=os.environ.get("WS_ECHO"),
                    help="the ws_echo binary (or $WS_ECHO)")
    ap.add_argument("--direction", choices=("server", "client", "both"), default="both")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="leave out " + ",".join(QUICK_EXCLUDE))
    mode.add_argument("--full", action="store_true", help="every case (the default)")
    ap.add_argument("--cases", default="*", help="comma-separated Autobahn case patterns")
    ap.add_argument("--exclude", default="", help="comma-separated patterns to leave out")
    ap.add_argument("--expected", default=DEFAULT_EXPECTED)
    ap.add_argument("--outdir", help="keep the reports here (default: a temporary directory)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directory")
    ap.add_argument("--propose", help="write a candidate expected.tsv here")
    ap.add_argument("--control", action="store_true",
                    help="run with a deliberately wrong echo; exit 0 only if the comparison fails")
    ap.add_argument("--timeout", type=int, default=7200, help="seconds per direction")
    args = ap.parse_args(argv)

    if not args.ws_echo or not os.access(args.ws_echo, os.X_OK):
        sys.stderr.write("run.py: --ws-echo (or $WS_ECHO) must name the built ws_echo\n")
        return 2
    ws_echo = os.path.abspath(args.ws_echo)

    try:
        selftest()
    except Failure as why:
        sys.stderr.write("run.py: %s\n" % why)
        return 1

    try:
        image, said = check_pin()
    except Unavailable as why:
        sys.stderr.write("### autobahn: the reference is not reachable ###\n%s\n" % why)
        return 1
    print("oracle(container): %s\n  %s" % (said, image), flush=True)

    cases = split(args.cases) or ["*"]
    exclude = split(args.exclude) + (QUICK_EXCLUDE if args.quick else [])
    env = dict(os.environ)
    directions = ["server", "client"] if args.direction == "both" else [args.direction]
    if args.control:
        # Few cases, chosen so a wrong echo is seen by plain echo cases (1.x, 2.x),
        # by a compressed one (12.1.1) and by a case a wrong echo cannot disturb (6.4.1).
        cases = ["1.1.1", "1.2.1", "2.1", "6.4.1", "12.1.1"]
        exclude = []
        directions = ["server"]
        env["GHOTI_WS_ECHO_BREAK"] = "1"

    try:
        expected = (load_expected(args.expected)
                    if os.path.exists(args.expected) or not args.propose else {})
        all_ids = list_cases(["*"], [])
        selected = list_cases(cases, exclude)
    except Failure as why:
        sys.stderr.write("run.py: %s\n" % why)
        return 1
    print("autobahn: the suite has %d cases; %d selected%s" % (
        len(all_ids), len(selected),
        " (quick: without %s)" % ",".join(QUICK_EXCLUDE) if args.quick else ""), flush=True)

    work = args.outdir or tempfile.mkdtemp(prefix="ghttp-autobahn-")
    os.makedirs(work, exist_ok=True)
    problems = []
    seen = []
    ok = False
    try:
        for direction in directions:
            runner = server_direction if direction == "server" else client_direction
            try:
                results, outdir, seconds, noise = runner(
                    ws_echo, work, cases, exclude, selected, env, args.timeout)
            except (Failure, subprocess.TimeoutExpired) as why:
                problems.append("%s: %s" % (direction, why))
                continue
            seen.append((direction, results))
            print("%s [%.0fs]" % (summarise(direction, results), seconds), flush=True)
            found = judge(direction, expected, all_ids, selected, results, outdir, noise)
            for p in found:
                m = re.match(r"(server|client) (\S+): ", p)
                extra = ""
                if m and m.group(2) in results:
                    extra = "\n    suite said: " + detail(outdir, results[m.group(2)])
                problems.append(p + extra)
        if args.propose:
            propose(args.propose, seen, expected)
        if args.control:
            if problems:
                print("control: the deliberately wrong echo was caught (%d deviations, e.g. %s)"
                      % (len(problems), problems[0].splitlines()[0]))
                ok = True
                return 0
            sys.stderr.write("control: a wrong echo PASSED the comparison: the harness is blind\n")
            return 1
        if problems:
            for p in problems:
                sys.stderr.write("autobahn: %s\n" % p)
            if any("did not finish within" in p or "never completed" in p for p in problems):
                sys.stderr.write(
                    "autobahn: some cases never ran (the suite gave up on the handshake or\n"
                    "autobahn: on the case timeout). That is what a stalled host looks like\n"
                    "autobahn: (a suspend, a swamped machine) and what a hang in ws_echo or the\n"
                    "autobahn: library looks like: rerun on a quiet machine, and treat a case that\n"
                    "autobahn: fails the same way twice as a hang. Reports are kept below.\n")
            sys.stderr.write("autobahn: FAILED, %d problem(s); reports kept in %s\n"
                             % (len(problems), work))
            args.keep = True
            return 1
        ok = True
        print("autobahn: every selected case is as expected.tsv says")
        return 0
    finally:
        if not args.keep and not args.outdir and (ok or args.control):
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
