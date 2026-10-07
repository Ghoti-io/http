#!/bin/sh
#
# check-autobahn-gate: show that the Autobahn gate turns red.
#
# A differential that has never been seen to fail is not known to be one. This
# plants defects in a copy of the tree, one at a time, and requires that run.py
# FAIL and that its failure name the case the defect should be seen at:
#
#   in the library: UTF-8 validation that forgets the bytes of an earlier
#   fragment (6.x); a text message allowed to end inside a UTF-8 sequence
#   (6.x); the reserved-bit check removed (3.x); the unmasked-client-frame
#   check removed (see the note at that plant: Autobahn may not see it, and
#   the gate says so rather than pretending);
#
#   in the instrument: an expected.tsv line deleted, one invented, one
#   changed; a comparator blind to behaviorClose, to the close code; a report
#   that loses a case; an empty selection; a wrong echo (run.py --control).
#
# It first runs the unpatched copy over the same selection, which must pass:
# if the control fails, every "caught" below would only be a run broken for
# another reason.
#
# Usage (from the library root, by `make check-autobahn-gate`):
#   tools/oracle/autobahn/check-gate.sh <make> <build-dir> [make arguments...]
#
# The make arguments (PREFIX=, CUTIL_PC=, ...) are passed to the copy's build
# of the library and of ws_echo, which is built by the `autobahn-echo` target.

set -u

MAKE_CMD="${1:?usage: check-gate.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-gate.sh <make> <build-dir> [make args]}"
shift 2
MARGS="-j$(nproc 2>/dev/null || echo 4) $*"
unset MAKEFLAGS MFLAGS

ROOT=$(pwd)
SCRATCH="$ROOT/build/autobahn-gate"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

AB=tools/oracle/autobahn
ECHO_REL="$BUILD_DIR/apps/oracle/ws_echo"

copy_tree() {
  dest=$1
  mkdir -p "$dest"
  for d in src include tests tools pkgconfig documentation examples; do
    [ -e "$ROOT/$d" ] && cp -a "$ROOT/$d" "$dest/"
  done
  cp -a "$ROOT/Makefile" "$ROOT/Doxyfile" "$dest/"
  rm -rf "$dest/tests/fuzz/corpus"
}

# What the control and every library plant run over: the groups that carry the
# planted defects' needles, small enough that the whole gate is minutes. The
# full groups are `make check-autobahn`'s.
SELECTION='1.1.1,2.1,3.*,5.*,6.*,7.1.1,10.1.1,12.1.1,12.1.2,13.1.1'

# run <dir> <name> [extra run.py args...]: log in <dir>.log, status returned.
run_ab() {
  dir=$1
  shift 2
  ( cd "$dir" && python3 $AB/run.py --ws-echo "$dir/$ECHO_REL" --direction "$DIRECTION" \
      "$@" ) > "$dir.log" 2>&1
}

fail=0
DIRECTION=server

copy_tree "$SCRATCH/control"
if ! ( cd "$SCRATCH/control" && "$MAKE_CMD" --no-print-directory autobahn-echo $MARGS ) \
    > "$SCRATCH/control-build.log" 2>&1; then
  printf 'check-autobahn-gate: the control copy does not build:\n' >&2
  tail -20 "$SCRATCH/control-build.log" >&2
  exit 1
fi
if ! run_ab "$SCRATCH/control" control --cases "$SELECTION"; then
  printf 'check-autobahn-gate: the CONTROL (unpatched) copy fails, so no result below\n' >&2
  printf 'would mean anything. Its log:\n' >&2
  tail -30 "$SCRATCH/control.log" >&2
  exit 1
fi
printf 'check-autobahn-gate: control passes (%s)\n' "$(grep -m1 '^autobahn: the suite' "$SCRATCH/control.log")"

# edit <dir> <file> <old> <new>: an exact one-occurrence replacement, checked.
edit() {
  python3 - "$1/$2" "$3" "$4" <<'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if text.count(old) != 1:
    sys.stderr.write("anchor matched %d times in %s\n" % (text.count(old), path))
    sys.exit(3)
open(path, "w").write(text.replace(old, new))
PY
}

red() {
  printf '\033[0;31mcheck-autobahn-gate: %s\033[0m\n' "$1" >&2
  fail=1
}

# expect_red <name> <dir> <needle> <cases>
expect_red() {
  name=$1 dir=$2 needle=$3 cases=$4
  if run_ab "$dir" "$name" --cases "$cases"; then
    red "$name: the run PASSED with the defect planted"
  elif grep -q -- "$needle" "$dir.log"; then
    printf 'check-autobahn-gate: %s: caught (%s)\n' "$name" "$(grep -m1 -- "$needle" "$dir.log" | cut -c1-120)"
    printf '    %s case(s) differ: %s\n' "$(grep -c "^autobahn: $DIRECTION [0-9.]*: " "$dir.log")" \
      "$(grep -o "^autobahn: $DIRECTION [0-9.]*" "$dir.log" | sed "s/^autobahn: $DIRECTION //" | head -12 | tr '\n' ' ')"
  else
    red "$name: it failed, but not with \"$needle\" - read $dir.log"
    tail -15 "$dir.log" >&2
    trap - EXIT
  fi
}

# plant_lib <name> <file> <old> <new> <needle> <cases>
plant_lib() {
  name=$1 file=$2 old=$3 new=$4 needle=$5 cases=$6
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  if ! edit "$dir" "$file" "$old" "$new"; then
    red "$name: THE PATCH DID NOT APPLY (stale anchor), nothing was tested"
    return
  fi
  touch "$dir/$file"
  # The control's archive and program came along; a path make did not match
  # would leave the OLD binary to run against nothing patched.
  rm -f "$dir/$BUILD_DIR"/apps/*.a "$dir/$BUILD_DIR"/apps/*.so* "$dir/$ECHO_REL"
  if ! ( cd "$dir" && "$MAKE_CMD" --no-print-directory autobahn-echo $MARGS ) > "$dir-build.log" 2>&1; then
    red "$name: the patched copy does not build"
    tail -10 "$dir-build.log" >&2
    return
  fi
  expect_red "$name" "$dir" "$needle" "$cases"
}

# plant_harness <name> <file> <old> <new> <needle> <cases>: a patch to the
# instrument, run with the control's unpatched program.
plant_harness() {
  name=$1 file=$2 old=$3 new=$4 needle=$5 cases=$6
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  if ! edit "$dir" "$file" "$old" "$new"; then
    red "$name: THE PATCH DID NOT APPLY (stale anchor), nothing was tested"
    return
  fi
  expect_red "$name" "$dir" "$needle" "$cases"
}

# blind_lib <name> <file> <old> <new> <cases>: a defect Autobahn is known not
# to see. The run must stay GREEN; it is reported, never counted as a failure,
# so the gate says what it cannot show instead of implying coverage.
blind_lib() {
  name=$1 file=$2 old=$3 new=$4 cases=$5
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  if ! edit "$dir" "$file" "$old" "$new"; then
    red "$name: THE PATCH DID NOT APPLY (stale anchor), nothing was tested"
    return
  fi
  touch "$dir/$file"
  rm -f "$dir/$BUILD_DIR"/apps/*.a "$dir/$BUILD_DIR"/apps/*.so* "$dir/$ECHO_REL"
  if ! ( cd "$dir" && "$MAKE_CMD" --no-print-directory autobahn-echo $MARGS ) > "$dir-build.log" 2>&1; then
    red "$name: the patched copy does not build"
    return
  fi
  if run_ab "$dir" "$name" --cases "$cases"; then
    printf 'check-autobahn-gate: %s: NOT seen by Autobahn (documented blind spot; the unit tests hold it)\n' "$name"
  else
    printf 'check-autobahn-gate: %s: Autobahn DID see it now - move it into the planted list\n' "$name"
    fail=1
    trap - EXIT
  fi
}

# ---- the library -----------------------------------------------------------

plant_lib utf8-state-lost-between-fragments src/http/ws_conn.c \
  '  c->msg_frames++;
  if (c->msg_compressed) {
    c->msg_wire += fh->payload_len;' \
  '  c->msg_frames++;
  ghttp_ws_utf8_init(&c->utf8);
  if (c->msg_compressed) {
    c->msg_wire += fh->payload_len;' \
  'server 6\.2\.3:' '6.*'

plant_lib text-may-end-inside-a-utf8-sequence src/http/ws_conn.c \
  '  if (c->msg_opcode == GHTTP_WS_OP_TEXT && !ghttp_ws_utf8_complete(&c->utf8)) {' \
  '  if (0) {' \
  'server 6\.6\.1:' '6.*'

plant_lib reserved-bit-check-removed src/http/ws_conn.c \
  '  if (bits & ~allowed) {' \
  '  if (0) {' \
  'server 3\.1:' '3.*'

plant_lib reserved-opcode-accepted src/http/ws_frame.c \
  '  if (!ghttp_ws_opcode_is_defined(opcode)) {
    return GHTTP_ERR_CORRUPT;
  }' \
  '  if (0) {
    return GHTTP_ERR_CORRUPT;
  }' \
  'server 4\.1\.1:' '4.*'

plant_lib fragmented-control-frame-accepted src/http/ws_frame.c \
  '  if (ghttp_ws_opcode_is_control(opcode) && !fin) {' \
  '  if (0) {' \
  'server 5\.1:' '5.*'

plant_lib invalid-close-code-accepted src/http/ws_conn.c \
  '    if (!ghttp_ws_close_code_is_valid(code)) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
          "a Close frame carries a code that may not be sent");' \
  '    if (0) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
          "a Close frame carries a code that may not be sent");' \
  'server 7\.9\.1:' '7.*'

plant_lib close-reason-utf8-not-checked src/http/ws_conn.c \
  '    if (ghttp_ws_utf8_feed(&v, reason, reason_len) != GHTTP_OK
        || !ghttp_ws_utf8_complete(&v)) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_INVALID_PAYLOAD,
          "the reason of a Close frame is not valid UTF-8");' \
  '    if (0) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_INVALID_PAYLOAD,
          "the reason of a Close frame is not valid UTF-8");' \
  'server 7\.5\.1:' '7.*'

# The client direction: the same copy, `ws_echo client` against the suite's server.
DIRECTION=client
plant_lib client-frames-sent-unmasked src/http/ws_conn.c \
  '  if (key) {
    h.masked = 1;' \
  '  if (0) {
    h.masked = 1;' \
  'client 1\.1\.1' '1.1.1,2.1,6.4.1'
DIRECTION=server

# What Autobahn cannot see, said out loud. Autobahn's client always masks, so
# a server that stops insisting on it is not noticed by any case: the unit
# tests (tests/unit/test_ws_conn.cpp) are what hold that line. If this ever
# turns red, Autobahn has learned to see it and the plant above it belongs in
# the list.
blind_lib unmasked-client-frame-accepted src/http/ws_conn.c \
  '  if (c->role == GHTTP_WS_SERVER && !fh->masked) {' \
  '  if (0) {' \
  '1.1.1,2.1,3.*,4.*,5.*,6.*'

# ---- the instrument -------------------------------------------------------------

plant_harness expected-line-deleted tools/oracle/autobahn/expected.tsv \
  'server	6.4.1	OK	OK	1007	ok' \
  '' \
  'server 6\.4\.1: the suite has this case and expected.tsv has no line for it' '6.4.1'

plant_harness expected-line-for-a-case-that-does-not-exist tools/oracle/autobahn/expected.tsv \
  'server	6.4.1	OK	OK	1007	ok' \
  'server	6.4.1	OK	OK	1007	ok
server	6.4.9	OK	OK	1007	ok' \
  'matches no case in the suite (stale)' '6.4.1'

plant_harness expected-outcome-changed tools/oracle/autobahn/expected.tsv \
  'server	6.4.1	OK	OK	1007	ok' \
  'server	6.4.1	NON-STRICT	NON-STRICT	1007	non-strict	an expectation that no longer holds, for the gate' \
  'server 6\.4\.1: behavior OK, expected NON-STRICT' '6.4.1'

plant_harness expected-close-code-changed tools/oracle/autobahn/expected.tsv \
  'server	6.4.1	OK	OK	1007	ok' \
  'server	6.4.1	OK	OK	1002	ok' \
  'server 6\.4\.1: close code 1007, expected 1002' '6.4.1'

plant_harness comparator-blind-to-behavior-close tools/oracle/autobahn/run.py \
  '        if got["behaviorClose"] != row.close:' \
  '        if False:' \
  'did not see a changed behaviorClose' '6.4.1'

plant_harness comparator-blind-to-close-code tools/oracle/autobahn/run.py \
  '        if row.code != "*" and str(got.get("remoteCloseCode")) != row.code:' \
  '        if False:' \
  'did not see a changed close code' '6.4.1'

plant_harness comparator-blind-to-absent-cases tools/oracle/autobahn/run.py \
  '    for case in sorted(set(selected) - set(results), key=case_key):' \
  '    for case in []:' \
  'did not see a case absent from the report' '6.4.1'

plant_harness report-loses-a-case tools/oracle/autobahn/run.py \
  '    return data[AGENT]' \
  '    return {k: v for k, v in data[AGENT].items() if k != "6.4.1"}' \
  'server 6\.4\.1: asked for and absent from the report' '6.4.1,6.4.2'

plant_harness empty-selection tools/oracle/autobahn/run.py \
  '    selected = list_cases(cases, exclude)' \
  '    selected = []' \
  'no case was selected' '6.4.1'

# The wrong echo: a whole run with a program that returns every message as
# binary. run.py --control exits 0 only if the comparison failed.
dir="$SCRATCH/wrong-echo"
cp -a "$SCRATCH/control" "$dir"
if ( cd "$dir" && python3 $AB/run.py --ws-echo "$dir/$ECHO_REL" --control ) > "$dir.log" 2>&1; then
  printf 'check-autobahn-gate: wrong-echo: caught (%s)\n' "$(grep -m1 '^control:' "$dir.log" | cut -c1-110)"
else
  red "wrong-echo: the harness did not see a wrong echo - read $dir.log"
  tail -10 "$dir.log" >&2
  trap - EXIT
fi

if [ $fail -ne 0 ]; then
  printf '\033[0;31mcheck-autobahn-gate: FAILED\033[0m\n' >&2
  exit 1
fi
printf '\033[0;32mEvery planted defect turns the Autobahn gate red.\033[0m\n'
