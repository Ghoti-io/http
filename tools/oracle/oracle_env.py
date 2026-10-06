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
"""How a reference is reached, so that nothing else spells one.

Copied from the model library's oracle_env.py, which is the built-here shape:
the image has no upstream digest, so check_pin() is the guarantee and the
version each reference prints is what it checks.

**There is no host mode.** Every other converted library keeps one for a
machine with no container engine. Here the references are Node, a Python
package and a Go program compiled into the image, and a host that happened to
have a different llhttp would answer a different question under the same name,
which is the failure this arrangement exists to remove. No engine, or no
image, is an error and never a skip.

`command("llhttp")` returns the argv that runs that reference's driver inside
the pinned image, reading cases from stdin. `--network none`, because a
reference that could fetch anything mid-run is not the pin.
"""

import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGES = os.path.join(HERE, "containers", "IMAGES")
ENGINE = os.environ.get("GHOTI_CONTAINER_ENGINE", "docker")

# name -> (version probe argv, driver argv). The drivers are in the image;
# containers/refs/ holds their sources.
REFS = {
    "llhttp": (["llhttp-version"],
               ["node", "/usr/local/lib/ghttp-ref/ref-llhttp.js"]),
    "h11": (["h11-version"],
            ["python3", "/usr/local/lib/ghttp-ref/ref-h11.py"]),
    "gohttp": (["go-version"], ["ref-go"]),
}


class OracleUnavailable(Exception):
    """The reference cannot be reached. Never caught into a skip by a gate
    that was asked to judge."""


_pins = None
_cache = {}


def pins():
    """The IMAGES table: name -> (image, version, description)."""
    global _pins
    if _pins is not None:
        return _pins
    _pins = {}
    with open(IMAGES, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                raise OracleUnavailable(
                    "containers/IMAGES: not three tab-separated fields: %r" % line)
            _pins[parts[0]] = (parts[1], parts[2], parts[3] if len(parts) > 3 else "")
    return _pins


def _have_image(image):
    for argv in ([ENGINE, "image", "exists", image], [ENGINE, "image", "inspect", image]):
        if subprocess.run(argv, capture_output=True).returncode == 0:
            return True
    return False


def ensure(name):
    """Make the reference runnable, or raise saying what is missing."""
    if shutil.which(ENGINE) is None:
        raise OracleUnavailable(
            "%s is not on PATH. Install it, or name another engine with "
            "GHOTI_CONTAINER_ENGINE. There is no host mode: see oracle_env.py." % ENGINE)
    table = pins()
    if name not in table or name not in REFS:
        raise OracleUnavailable("no pin for %r in tools/oracle/containers/IMAGES" % name)
    image = table[name][0]
    if not _have_image(image):
        raise OracleUnavailable(
            "the image for %s is not present. It is built here, not pulled:\n"
            "  make oracle-build\n  %s" % (name, image))


def command(name, argv=None, env=None):
    """The argv prefix that runs `name`'s reference, reading stdin.

    `env` is a dict of variables set inside the container. Only the strictness
    control uses it (GHTTP_REF_LENIENT); a gate run sets none.
    """
    ensure(name)
    inner = argv if argv is not None else REFS[name][1]
    pre = [ENGINE, "run", "--rm", "-i", "--network", "none", "--read-only"]
    for key, value in sorted((env or {}).items()):
        pre += ["--env", "%s=%s" % (key, value)]
    return pre + [pins()[name][0]] + list(inner)


def version(name):
    """What the reference says it is. Runs it; the answer is cached."""
    if name in _cache:
        return _cache[name]
    finished = subprocess.run(command(name, REFS[name][0]), capture_output=True, text=True)
    text = finished.stdout.strip().splitlines()
    text = text[0] if text else ""
    if finished.returncode != 0 or not text:
        raise OracleUnavailable("%s probe exited %s: %r" % (name, finished.returncode, text))
    _cache[name] = text
    return text


def check_pin(name):
    """Raise unless the reference says what containers/IMAGES says it is."""
    said = pins()[name][1]
    got = version(name)
    if said not in got:
        raise OracleUnavailable("%s: IMAGES says %s and it answers %r" % (name, said, got))
    return got


def provenance(names):
    """One line naming every reference that answered."""
    return "oracle(container): " + ", ".join(
        "%s %s" % (n, check_pin(n)) for n in names)


if __name__ == "__main__":
    import sys
    try:
        print(provenance(list(REFS)))
    except OracleUnavailable as why:
        sys.stderr.write("oracle-version: %s\n" % why)
        sys.exit(1)
