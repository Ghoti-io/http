#!/bin/sh
#
# check-defects: show that the test suite turns red for each planted defect.
#
# A gate that has never been seen to fail is not known to be a gate. This one
# copies the tree, plants one defect in the copy by an exact textual edit,
# builds it and runs the unit tests, and requires that the run FAIL and that
# the failure name the test written for that defect. It first runs the
# unpatched copy, which must pass: if the control fails, every "caught"
# below would only be a build broken for another reason.
#
# The edit is checked, not assumed. A patch whose anchor text has been
# re-wrapped or renamed matches nothing and would leave a pristine copy
# that passes - reported as a surviving defect, which looks like a gap in
# the tests and is a stale patch - so a patch that did not change the file is
# its own error, named as such.
#
# Usage (from the library root, by `make check-defects`):
#   tools/check-defects.sh <make> <build-dir> [make arguments...]
# The make arguments (PREFIX=..., CUTIL_PC=...) are passed to every nested make.

set -u

MAKE_CMD="${1:?usage: check-defects.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-defects.sh <make> <build-dir> [make args]}"
shift 2
# Kept in a variable: inside a function "$@" is the function's own arguments.
MARGS="-j$(nproc 2>/dev/null || echo 4) $*"

# The parent make's flags (a jobserver whose descriptors this shell does not
# have, -j, variable overrides) would only confuse the nested makes; what they
# need is passed in MARGS.
unset MAKEFLAGS MFLAGS

ROOT=$(pwd)
SCRATCH="$ROOT/build/defects"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

# A copy of everything the build reads, and NOT of the build tree. Copying the
# object files would save one compile, but this gate runs as a prerequisite of
# `make test`, so under -j the original tree can be half written while it is
# copied: an archive caught mid-write failed the link with "member is not an
# object". The control builds from nothing instead, in its own directory,
# and each defect copies the finished control.
copy_tree() {
  dest=$1
  mkdir -p "$dest"
  for d in src include tests tools pkgconfig documentation examples; do
    [ -e "$ROOT/$d" ] && cp -a "$ROOT/$d" "$dest/"
  done
  cp -a "$ROOT/Makefile" "$ROOT/Doxyfile" "$dest/"
  # A fuzzing run grows the corpus; no unit test reads it.
  rm -rf "$dest/tests/fuzz/corpus"
}

fail=0

copy_tree "$SCRATCH/control"
if ! ( cd "$SCRATCH/control" && "$MAKE_CMD" --no-print-directory test TEST_GATES= $MARGS ) \
    > "$SCRATCH/control.log" 2>&1; then
  printf 'check-defects: the CONTROL (unpatched) copy fails its own tests, so no\n' >&2
  printf 'result below would mean anything. Its log:\n' >&2
  tail -40 "$SCRATCH/control.log" >&2
  exit 1
fi
printf 'check-defects: control passes\n'

# plant <name> <file> <test executable> <expected failing test> <old> <new>
#
# Only the executable that holds the test written for the defect is run: `make
# test` stops at the first executable that fails, so a defect that breaks an
# earlier one as well would otherwise never reach the test named for it.
plant() {
  name=$1 file=$2 exe=$3 expect=$4 old=$5 new=$6
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  python3 - "$dir/$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if text.count(old) != 1:
    sys.stderr.write("anchor matched %d times in %s\n" % (text.count(old), path))
    sys.exit(3)
open(path, "w").write(text.replace(old, new))
PY
  rc=$?
  if [ $rc -ne 0 ]; then
    printf 'check-defects: %s: THE PATCH DID NOT APPLY (stale anchor), nothing was tested\n' "$name" >&2
    fail=1
    return
  fi
  if cmp -s "$ROOT/$file" "$dir/$file"; then
    printf 'check-defects: %s: the patched file equals the original\n' "$name" >&2
    fail=1
    return
  fi
  # A fresh timestamp, so that make rebuilds the object whatever the clock.
  touch "$dir/$file"
  # The control's binaries came along in the copy. A test executable whose path
  # did not match make's rule exactly would be taken as already built and the
  # OLD binary run against nothing patched: a green run that planted nothing.
  # So they are removed, and a path that cannot be built is an error.
  rm -f "$dir/$BUILD_DIR"/apps/test* "$dir/$BUILD_DIR"/apps/*.a \
    "$dir/$BUILD_DIR"/apps/*.so*
  if ( cd "$dir" && "$MAKE_CMD" --no-print-directory test TEST_GATES= \
      TEST_EXECUTABLES="$BUILD_DIR/apps/$exe" $MARGS ) > "$dir.log" 2>&1; then
    printf '\033[0;31mcheck-defects: %s: the tests PASSED with the defect planted\033[0m\n' "$name" >&2
    fail=1
  elif grep -q "FAILED.*$expect" "$dir.log"; then
    printf 'check-defects: %s: caught by %s\n' "$name" "$expect"
  else
    printf '\033[0;31mcheck-defects: %s: the run failed, but not in %s - read %s\033[0m\n' \
      "$name" "$expect" "$dir.log" >&2
    tail -20 "$dir.log" >&2
    trap - EXIT
    fail=1
  fi
}

plant accept-cl-and-te src/http/util.c testParser_request \
  'RequestSmuggling.ContentLengthWithTransferEncodingIsCorrupt' \
  '  if (have_te && have_cl) {
    return GHTTP_ERR_CORRUPT;
  }' \
  '  if (have_te && have_cl) {
    have_cl = false;
  }'

plant ignore-header-count src/http/parser.c testLimits \
  'Limits.HeaderCountBoundsTheFieldsAndNotTheStartLine' \
  '      if (c->lines - start_lines > max_fields && c->lines > start_lines) {' \
  '      if (c->lines - start_lines > max_fields && c->lines > start_lines && 0) {'

plant ignore-chunk-size-cap src/http/parser.c testLimits \
  'Limits.ChunkSizeIsCappedByTheDeclaredSizeBeforeAnyOfItIsRead' \
  '  if (size > p->limits.max_chunk_size
      || size > p->limits.max_body_bytes - p->body_total) {' \
  '  if (size > p->limits.max_body_bytes - p->body_total) {'

plant split-dependent-crlf src/http/parser.c testSplit \
  'Split.EveryTwoWaySplitGivesTheSameResultAsTheWholeMessage' \
  '  Collector * c = &p->col;
  bool trailer = (p->state == ST_TRAILERS);' \
  '  Collector * c = &p->col;
  c->prev_cr = false; // forgets a CR that ended the previous piece
  bool trailer = (p->state == ST_TRAILERS);'

# HTTP/2 (story 3b). Each defect is the one the spec names.
plant h2-flow-control-off-by-one src/http/h2conn.c testH2conn \
  'H2FlowReceive.DataBeyondTheConnectionWindowIsAConnectionError' \
  '  if ((int64_t)len > c->recv_window) {
    return conn_fail(c, GHTTP_H2_FLOW_CONTROL_ERROR,
        "DATA exceeds the connection window", GHTTP_ERR_CORRUPT);' \
  '  if ((int64_t)len > c->recv_window + 1) {
    return conn_fail(c, GHTTP_H2_FLOW_CONTROL_ERROR,
        "DATA exceeds the connection window", GHTTP_ERR_CORRUPT);'

plant h2-send-window-off-by-one src/http/h2conn.c testH2conn \
  'H2FlowSend.DataIsHeldBackAtTheWindowAndResumesOnWindowUpdate_Section6_9' \
  '  return w > 0 ? (size_t)w : 0;
}

size_t ghttp_h2_conn_send_window' \
  '  return w > 0 ? (size_t)w + 1 : 0;
}

size_t ghttp_h2_conn_send_window'

plant h2-unbounded-continuation src/http/h2conn.c testH2conn \
  'H2HeaderBlock.AContinuationFloodStopsAtTheLimitPlusOne_Cve2024_27316Class' \
  '  if (++c->hb_frames - 1 > c->limits.max_continuation_frames) {' \
  '  if (++c->hb_frames - 1 > c->limits.max_continuation_frames && 0) {'

plant hpack-table-size-not-enforced src/http/hpack.c testHpack \
  'HpackDecoder.AnUpdateAboveTheAdvertisedMaximumIsACompressionError' \
  '      if (v > d->cap) {
        return GHTTP_ERR_CORRUPT;
      }
      table_set_max(&d->table, v);' \
  '      table_set_max(&d->table, v);'

plant h2-stream-state-skip src/http/h2conn.c testH2conn \
  'H2Streams.FramesOnAnIdleStreamAreAProtocolError_Section5_1' \
  '    case SS_IDLE:
      return proto(c, "DATA on an idle stream");' \
  '    case SS_IDLE:
      return GHTTP_OK;'

# The generated HPACK tables are checked against the RFC by a gate of their
# own, not by a unit test: plant a changed Huffman code in a copy and require
# that gate to fail (and to pass on the copy before it).
tdir="$SCRATCH/hpack-table-edit"
cp -a "$SCRATCH/control" "$tdir"
mkdir -p "$tdir/tools/hpack"
if ! ( cd "$tdir" && "$MAKE_CMD" --no-print-directory check-hpack-tables $MARGS ) > "$tdir.ctl.log" 2>&1; then
  printf 'check-defects: check-hpack-tables fails on the unplanted copy; read %s\n' "$tdir.ctl.log" >&2
  tail -5 "$tdir.ctl.log" >&2
  fail=1
else
  python3 - "$tdir/src/http/hpack_tables.c" <<'PY'
import re, sys
p = sys.argv[1]
t = open(p).read()
m = re.search(r'0x[0-9a-f]+', t)
if not m:
    sys.exit(3)
i = m.end() - 1
c = t[i]
t = t[:i] + ('1' if c != '1' else '2') + t[i+1:]
open(p, "w").write(t)
PY
  if [ $? -ne 0 ]; then
    printf 'check-defects: hpack-table-edit: THE PATCH DID NOT APPLY\n' >&2
    fail=1
  elif ( cd "$tdir" && "$MAKE_CMD" --no-print-directory check-hpack-tables $MARGS ) > "$tdir.log" 2>&1; then
    printf '\033[0;31mcheck-defects: hpack-table-edit: check-hpack-tables PASSED with a table entry changed\033[0m\n' >&2
    fail=1
  elif grep -q "is not what tools/hpack/gen_tables.py produces" "$tdir.log"; then
    printf 'check-defects: hpack-table-edit: caught by check-hpack-tables\n'
  else
    printf '\033[0;31mcheck-defects: hpack-table-edit: failed, but not as the gate fails - read %s\033[0m\n' "$tdir.log" >&2
    trap - EXIT
    fail=1
  fi
fi

if [ $fail -ne 0 ]; then
  printf '\033[0;31mcheck-defects: FAILED\033[0m\n' >&2
  exit 1
fi
printf '\033[0;32mEvery planted defect turns the unit tests red.\033[0m\n'
