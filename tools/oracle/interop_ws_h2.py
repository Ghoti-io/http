#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io HTTP.
#
# Ghoti.io HTTP is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3 as
"""WebSocket over HTTP/2 against real references: the interoperability check of RFC 8441.

    interop_ws_h2.py --probe build/.../ws_h2_probe

The differential (diff_h2.py) shows that this library reads an Extended CONNECT
the way nghttp2, h2 and Go's x/net/http2 do. This shows the other half: that a
WebSocket can actually be carried over the stream. Two programs speak HTTP/2 to
each other over a pair of pipes, one of them this library's probe
(ws_h2_probe.c) and the other a reference in the pinned container
(containers/refs/):

  h2ws        h2 (Python) for HTTP/2 and websockets 17.2's sans-I/O Protocol for
              the WebSocket, as a client (ref-wsh2-client.py) and as a server
              (ref-wsh2-server.py): messages of every size class both ways, with
              and without permessage-deflate, the closing handshake.
  gox2tunnel  Go's x/net/http2 as a server that echoes an Extended CONNECT
              tunnel, and as a client that opens one (containers/refs/gox2/
              tunnel): raw octets, a megabyte each way, through windows far
              smaller than that, and END_STREAM both ways. Go has no WebSocket
              that speaks RFC 8441.

Not here, and why: gorilla/websocket and coder/websocket (the Go WebSocket
libraries) do not support RFC 8441 and cannot be run over an HTTP/2 stream;
websockets itself has no HTTP/2 transport, which is why its Protocol is joined
to h2 by this driver, as an application would; wsproto speaks HTTP/1.1 only.
nghttp2's own tools (nghttp, nghttpd) do not carry a WebSocket.

Every scenario must end with both programs exiting 0, each having checked what
it received. A control runs first and must fail: the broker corrupts one octet in
the middle of the stream, and a run in which both programs exit 0 anyway would
mean the check cannot see.
"""

import argparse
import os
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_env  # noqa: E402

SIZES = ["0", "1", "125", "126", "1000", "65535", "65536", "300000"]
TIMEOUT = int(os.environ.get("GHTTP_INTEROP_TIMEOUT", "180"))


def shuttle(src, dst, corrupt_at, counter):
    """Copy src to dst until EOF; flip one octet after `corrupt_at` octets if asked."""
    try:
        while True:
            data = os.read(src.fileno(), 65536)
            if not data:
                break
            if corrupt_at is not None and counter[0] <= corrupt_at < counter[0] + len(data):
                i = corrupt_at - counter[0]
                data = data[:i] + bytes([data[i] ^ 0x55]) + data[i + 1:]
            counter[0] += len(data)
            dst.write(data)
            dst.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass
    finally:
        try:
            dst.close()
        except (BrokenPipeError, OSError):
            pass


def drain(pipe, sink):
    try:
        while True:
            data = os.read(pipe.fileno(), 65536)
            if not data:
                break
            sink.append(data)
    except OSError:
        pass


def run_pair(a_argv, b_argv, corrupt_at=None):
    """Join two programs' stdio. Returns (exit a, exit b, stderr a, stderr b)."""
    procs = [subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for argv in (a_argv, b_argv)]
    pa, pb = procs
    errs = [[], []]
    threads = [
        threading.Thread(target=shuttle, args=(pa.stdout, pb.stdin, corrupt_at, [0]), daemon=True),
        threading.Thread(target=shuttle, args=(pb.stdout, pa.stdin, None, [0]), daemon=True),
        threading.Thread(target=drain, args=(pa.stderr, errs[0]), daemon=True),
        threading.Thread(target=drain, args=(pb.stderr, errs[1]), daemon=True),
    ]
    for th in threads:
        th.start()
    codes = []
    for p in procs:
        try:
            codes.append(p.wait(timeout=TIMEOUT))
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            codes.append(-9)
    for th in threads:
        th.join(5)
    text = ["".join(x.decode("utf-8", "replace") for x in e) for e in errs]
    return codes[0], codes[1], text[0], text[1]


def ours(probe, *args):
    return [probe] + list(args)


def h2ws(role, *args):
    script = "/usr/local/lib/ghttp-ref/ref-wsh2-%s.py" % role
    return oracle_env.command("h2ws", ["python3", script] + list(args))


def go(role, *args):
    return oracle_env.command("gox2tunnel", ["ref-gox2tunnel", role] + list(args),
                              env={"GODEBUG": "http2xconnect=1"})


def scenarios(probe):
    s = []
    for deflate in (False, True):
        flag = ["--deflate"] if deflate else []
        d = " with permessage-deflate" if deflate else ""
        s.append(("this library serves, websockets+h2 is the client, messages of every size%s" % d,
                  ours(probe, "server"), h2ws("client", *(flag + SIZES))))
        s.append(("websockets+h2 serves, this library is the client, messages of every size%s" % d,
                  h2ws("server"), ours(probe, "client", *(flag + SIZES))))
    s.append(("this library serves, an unmodified h2 client (its SETTINGS carry ENABLE_CONNECT_PROTOCOL=0), 1 octet",
              ours(probe, "server"), h2ws("client", "1")))
    s.append(("this library serves an echo tunnel, Go's x/net/http2 is the client (1 MiB)",
              ours(probe, "server", "--raw"), go("client", str(1 << 20))))
    s.append(("Go's x/net/http2 serves an echo tunnel, this library is the client (1 MiB)",
              go("server"), ours(probe, "client", "--raw", str(1 << 20))))
    s.append(("the same, 1 octet",
              go("server"), ours(probe, "client", "--raw", "1")))
    return s


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    args = ap.parse_args(argv)
    names = ["h2ws", "gox2tunnel"]
    print(oracle_env.provenance(names))

    # The control: the same run as the first scenario, one octet flipped after
    # the handshake. It must not end with both sides satisfied.
    name, a, b = scenarios(args.probe)[0]
    ra, rb, ea, eb = run_pair(a, b, corrupt_at=4000)
    if ra == 0 and rb == 0:
        sys.stderr.write("### the interoperability check cannot see a corrupted stream: "
                         "both sides exited 0 after one octet was changed ###\n")
        return 1
    print("control: a corrupted stream ends the run (exits %d and %d)" % (ra, rb))

    failures = []
    for name, a, b in scenarios(args.probe):
        ra, rb, ea, eb = run_pair(a, b)
        status = "ok" if ra == 0 and rb == 0 else "FAILED (exits %d and %d)" % (ra, rb)
        print("%-100s %s" % (name, status))
        if ra != 0 or rb != 0:
            failures.append((name, ea, eb))
    if failures:
        sys.stderr.write("\n### the WebSocket-over-HTTP/2 interoperability check FAILED ###\n")
        for name, ea, eb in failures:
            sys.stderr.write("%s\n  first program:\n%s\n  second program:\n%s\n" % (name, ea[-1500:], eb[-1500:]))
        return 1
    print("every scenario ended with both programs satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
