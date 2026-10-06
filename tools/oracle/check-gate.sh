#!/bin/sh
#
# check-oracle-gate: show that the oracle gate turns red.
#
# A differential that has never been seen to fail is not known to be one. This
# plants defects in a copy of the tree, one at a time, and requires that
# `diff.py` FAIL and that its failure say what the defect is:
#
#   in the library: a message shape this library should refuse that it now
#   accepts (Content-Length with Transfer-Encoding; a second Host; two different
#   Content-Lengths), which the references hold the line on;
#
#   in the instrument: a rule deleted from known-disagreements.tsv; a
#   comparator that cannot see body bytes; a reference that answers "clean, no
#   messages" to everything; llhttp's lenient flag in force during the run (caught by the strictness
#   control, which then sees the flag change nothing); the
#   strictness control looking for a variable the driver does not read.
#
# It first runs the unpatched copy, which must pass: if the control fails, every
# "caught" below would only be a run broken for another reason.
#
# Usage (from the library root, by `make check-oracle-gate`):
#   tools/oracle/check-gate.sh <make> <build-dir> [make arguments...]

set -u

MAKE_CMD="${1:?usage: check-gate.sh <make> <build-dir> [make args]}"
BUILD_DIR="${2:?usage: check-gate.sh <make> <build-dir> [make args]}"
shift 2
MARGS="-j$(nproc 2>/dev/null || echo 4) $*"
unset MAKEFLAGS MFLAGS

ROOT=$(pwd)
SCRATCH="$ROOT/build/oracle-gate"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

copy_tree() {
  dest=$1
  mkdir -p "$dest"
  for d in src include tests tools pkgconfig documentation examples; do
    [ -e "$ROOT/$d" ] && cp -a "$ROOT/$d" "$dest/"
  done
  cp -a "$ROOT/Makefile" "$ROOT/Doxyfile" "$dest/"
  # A fuzzing run grows the corpus; only the committed seeds are the differential's.
  rm -rf "$dest/tests/fuzz/corpus"
  mkdir -p "$dest/tests/fuzz/corpus/parse"
  cp -a "$ROOT"/tests/fuzz/corpus/parse/*.seed "$dest/tests/fuzz/corpus/parse/"
}

# $LD_LIBRARY_PATH names where cutil's shared object is, as the Makefile's
# TEST_LD_PATH does for the tests.
LDP="$ROOT/$BUILD_DIR/apps:${LD_LIBRARY_PATH:-}"

# Which differential is being shown to fail: the HTTP/1 one first, then HTTP/2.
DIFF_SCRIPT=diff.py
PROBE_NAME=http_probe
probe_of() { printf '%s' "$1/$BUILD_DIR/apps/oracle/$PROBE_NAME"; }

# run <dir> -> log in <dir>.log, status returned
run_diff() {
  dir=$1
  ( cd "$dir" && LD_LIBRARY_PATH="$LDP" python3 tools/oracle/$DIFF_SCRIPT \
      --probe "$(probe_of "$dir")" ) > "$dir.log" 2>&1
}

fail=0

copy_tree "$SCRATCH/control"
if ! ( cd "$SCRATCH/control" && "$MAKE_CMD" --no-print-directory oracle-probe $MARGS ) \
    > "$SCRATCH/control-build.log" 2>&1; then
  printf 'check-oracle-gate: the control copy does not build:\n' >&2
  tail -20 "$SCRATCH/control-build.log" >&2
  exit 1
fi
if ! run_diff "$SCRATCH/control"; then
  printf 'check-oracle-gate: the CONTROL (unpatched) copy fails the differential, so no\n' >&2
  printf 'result below would mean anything. Its log:\n' >&2
  tail -30 "$SCRATCH/control.log" >&2
  exit 1
fi
printf 'check-oracle-gate: control passes\n'

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

expect_red() {  # name dir needle
  name=$1 dir=$2 needle=$3
  if run_diff "$dir"; then
    printf '\033[0;31mcheck-oracle-gate: %s: the differential PASSED with the defect planted\033[0m\n' "$name" >&2
    fail=1
  elif grep -q -- "$needle" "$dir.log"; then
    printf 'check-oracle-gate: %s: caught (%s)\n' "$name" "$needle"
  else
    printf '\033[0;31mcheck-oracle-gate: %s: it failed, but not with "%s" - read %s\033[0m\n' \
      "$name" "$needle" "$dir.log" >&2
    tail -15 "$dir.log" >&2
    trap - EXIT
    fail=1
  fi
}

# plant_lib <name> <file> <old> <new> <needle>
plant_lib() {
  name=$1 file=$2 old=$3 new=$4 needle=$5
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  if ! edit "$dir" "$file" "$old" "$new"; then
    printf 'check-oracle-gate: %s: THE PATCH DID NOT APPLY (stale anchor), nothing was tested\n' "$name" >&2
    fail=1
    return
  fi
  touch "$dir/$file"
  # The control's probe and archive came along: a path make did not match would
  # leave the OLD binary to run against nothing patched.
  rm -f "$dir/$BUILD_DIR"/apps/*.a "$dir/$BUILD_DIR"/apps/*.so* "$dir/$BUILD_DIR"/apps/oracle/http_probe \
    "$dir/$BUILD_DIR"/apps/oracle/h2_probe
  if ! ( cd "$dir" && "$MAKE_CMD" --no-print-directory oracle-probe $MARGS ) > "$dir-build.log" 2>&1; then
    printf 'check-oracle-gate: %s: the patched copy does not build\n' "$name" >&2
    tail -10 "$dir-build.log" >&2
    fail=1
    return
  fi
  expect_red "$name" "$dir" "$needle"
}

# plant_harness <name> <file> <old> <new> <needle>: a patch to the instrument,
# run with the control's unpatched probe.
plant_harness() {
  name=$1 file=$2 old=$3 new=$4 needle=$5
  dir="$SCRATCH/$name"
  cp -a "$SCRATCH/control" "$dir"
  if ! edit "$dir" "$file" "$old" "$new"; then
    printf 'check-oracle-gate: %s: THE PATCH DID NOT APPLY (stale anchor), nothing was tested\n' "$name" >&2
    fail=1
    return
  fi
  expect_red "$name" "$dir" "$needle"
}

plant_lib accept-cl-and-te src/http/util.c \
  '  if (have_te && have_cl) {
    return GHTTP_ERR_CORRUPT;
  }' \
  '  if (have_te && have_cl) {
    have_cl = false;
  }' \
  'cl-te'

plant_lib allow-two-hosts src/http/util.c \
  '        || ghttp_headers_find(h, "host", first + 1) != GHTTP_HEADERS_NPOS) {' \
  '        || (ghttp_headers_find(h, "host", first + 1) != GHTTP_HEADERS_NPOS && 0)) {' \
  'host-dup'

plant_lib allow-differing-content-lengths src/http/util.c \
  '          if (have_cl && v != cl) {' \
  '          if (have_cl && v != cl && 0) {' \
  'cl-dup-diff'

plant_harness rule-deleted tools/oracle/known-disagreements.tsv \
  'te-http10	*	error/*	policy	Transfer-Encoding in an HTTP/1.0 message is refused (section 6.1)' \
  '' \
  'have no rule'

plant_harness comparator-blind-to-bodies tools/oracle/diff.py \
  'msgs.append((start, fieldmap(m["headers"]), hx(m["body"]), fieldmap(m["trailers"])))' \
  'msgs.append((start, fieldmap(m["headers"]), b"", fieldmap(m["trailers"])))' \
  'explains nothing'

plant_harness reference-answers-nothing tools/oracle/diff.py \
  '    return parse_answers(name, done.stdout, 2 * len(cases))' \
  '    got = parse_answers(name, done.stdout, 2 * len(cases))
    if name == "h11":
        got = {k: {"msgs": [], "end": "clean", "err": ""} for k in got}
    return got' \
  'did not accept a good request'

plant_harness llhttp-lenient-during-the-run tools/oracle/diff.py \
  '    argv = oracle_env.command(name, env=env)' \
  '    argv = oracle_env.command(name, env=({"GHTTP_REF_LENIENT": "1"} if name == "llhttp" and env is None else env))' \
  'lenient flag changed no answer'

plant_harness strictness-control-misses-the-flag tools/oracle/diff.py \
  'env={"GHTTP_REF_LENIENT": "1"})
    flipped = []' \
  'env={"GHTTP_REF_LENIENTX": "1"})
    flipped = []' \
  'lenient flag changed no answer'

# ---- HTTP/2 (story 3b): the same, against diff_h2.py -----------------------------

DIFF_SCRIPT=diff_h2.py
PROBE_NAME=h2_probe
rm -rf "$SCRATCH/control.log"
if ! run_diff "$SCRATCH/control"; then
  printf 'check-oracle-gate: the CONTROL copy fails the HTTP/2 differential, so no\n' >&2
  printf 'HTTP/2 result below would mean anything. Its log:\n' >&2
  tail -30 "$SCRATCH/control.log" >&2
  exit 1
fi
printf 'check-oracle-gate: HTTP/2 control passes\n'

plant_lib h2-accept-uppercase-field-name src/http/h2msg.c \
  '  return ghttp_is_tchar(c) && !(c >= '"'A'"' && c <= '"'Z'"');' \
  '  return ghttp_is_tchar(c);' \
  'upper-case field name'

plant_lib h2-accept-hpack-index-zero src/http/hpack.c \
  '  if (idx == 0) {
    return GHTTP_ERR_CORRUPT;
  }
  if (idx <= GHTTP_HPACK_STATIC_COUNT) {' \
  '  if (idx <= GHTTP_HPACK_STATIC_COUNT) {' \
  'accepted HPACK index 0'

plant_lib h2-accept-data-on-idle-stream src/http/h2conn.c \
  '    case SS_IDLE:
      return proto(c, "DATA on an idle stream");' \
  '    case SS_IDLE:
      return GHTTP_OK;' \
  'have no rule'

plant_harness h2-rule-deleted tools/oracle/known-h2-disagreements.tsv \
  'rfc9113-6.2:headers-padding-too-long	gox2	conn:PROTOCOL_ERROR/ok+resets	code	' \
  '# rfc9113-6.2:headers-padding-too-long	gox2	conn:PROTOCOL_ERROR/ok+resets	code	' \
  'have no rule'

plant_harness h2-comparator-blind-to-bodies tools/oracle/diff_h2.py \
  '                     fieldmap(m["headers"], drop), hx(m["body"]), fieldmap(m["trailers"], drop),' \
  '                     fieldmap(m["headers"], drop), b"", fieldmap(m["trailers"], drop),' \
  'did not deliver a 3-octet body'

plant_harness h2-reference-answers-nothing tools/oracle/diff_h2.py \
  '    return parse_answers(name, done.stdout, want_count(cases))


# ---- normalising' \
  '    got = parse_answers(name, done.stdout, want_count(cases))
    if name == "h2":
        for v in got.values():
            v.update(msgs=[], resets=[], conn_error=None, closed=False)
    return got


# ---- normalising' \
  'did not accept a good request'

if [ $fail -ne 0 ]; then
  printf '\033[0;31mcheck-oracle-gate: FAILED\033[0m\n' >&2
  exit 1
fi
printf '\033[0;32mEvery planted defect turns the oracle gate red.\033[0m\n'
