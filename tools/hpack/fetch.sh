#!/bin/sh
#
# fetch.sh: download RFC 7541 into tools/hpack/data/, and check it.
#
# The HPACK static table and Huffman code in src/http/hpack_tables.c are
# generated from Appendices A and B of RFC 7541 by gen_tables.py, and
# `make check-hpack-tables` requires the committed file to be what the
# generator produces from this text. The text is pinned by SHA-256 so that the
# check measures the RFC and not whatever a mirror serves today.
#
# Needs the network the first time; the download is kept (and gitignored).

set -eu
here=$(cd "$(dirname "$0")" && pwd)
dest="$here/data/rfc7541.txt"
want=2239d7f8fb839b69ae2e928e685559b11376888269f131512197a0e3bacf7f7a
mkdir -p "$here/data"
# A download that was interrupted leaves a .part file; it is never the RFC.
rm -f "$dest.part"
if [ ! -f "$dest" ]; then
  # Bounded: a stalled mirror must fail the gate, not hang it.
  trap 'rm -f "$dest.part"' EXIT INT TERM
  curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 \
    https://www.rfc-editor.org/rfc/rfc7541.txt -o "$dest.part"
  mv "$dest.part" "$dest"
  trap - EXIT INT TERM
fi
have=$(sha256sum "$dest" | cut -d' ' -f1)
if [ "$have" != "$want" ]; then
  echo "fetch.sh: $dest has SHA-256 $have, expected $want" >&2
  echo "fetch.sh: delete it and run again, or raise the pin deliberately" >&2
  exit 1
fi
