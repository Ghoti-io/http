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

plant h2-rapid-reset-not-counted src/http/h2conn.c testH2conn \
  'H2Abuse.RapidResetStopsAtTheLimitPlusOne_Cve2023_44487' \
  '      if (++c->n_rst > c->limits.max_rst_per_interval) {
        return calm(c, "too many RST_STREAM frames");
      }
      return on_rst(c, &f);' \
  '      if (++c->n_rst > c->limits.max_rst_per_interval && 0) {
        return calm(c, "too many RST_STREAM frames");
      }
      return on_rst(c, &f);'

plant h2-own-resets-not-counted src/http/h2conn.c testH2conn \
  'H2Abuse.ResetsThisEndpointSendsBecauseOfThePeerCountTowardRapidReset' \
  '  if (++c->n_rst > c->limits.max_rst_per_interval) {
    return calm(c, "too many RST_STREAM frames");
  }
  return check_output(c);' \
  '  return check_output(c);'

plant h2-goaway-names-an-unaccepted-block src/http/h2conn.c testH2conn \
  'H2Goaway.ABlockThatWasNeverAcceptedIsNotNamedByTheGoaway_Section6_8' \
  '      c->highest_peer_id = id;  // opening it closes every lower idle stream' \
  '      c->highest_peer_id = id;
      c->last_peer_id = id;  // PLANTED: the GOAWAY id follows the block, not its acceptance'

plant h2-closed-ring-forgets-as-error src/http/h2conn.c testH2conn \
  'H2Streams.ALateFrameOnAStreamTheRingHasForgottenIsDiscardedNotAProtocolError' \
  '  return id <= c->closed_evicted_max;' \
  '  return c && 0 && id <= c->closed_evicted_max;'

plant h2-reset-in-block-not-discarded src/http/h2conn.c testH2conn \
  'H2Streams.ResettingAStreamBetweenItsHeadersAndItsContinuationKeepsHpackInStep' \
  '    c->hb_kind = KIND_DISCARD;  // its block is still arriving: decode it, drop it' \
  '    (void)0;  // its block is still arriving: decode it, drop it'

# WebSocket (story 3c). The four the spec names, and the rest of the checks that
# a frame codec is judged by: each is one condition removed or one constant
# changed, and each is caught by the test written for the rule it breaks.
plant ws-unmasked-client-frame-accepted src/http/ws_conn.c testWs_conn \
  'WsConn.AServerRefusesAnUnmaskedClientFrameWith1002' \
  '  if (c->role == GHTTP_WS_SERVER && !fh->masked) {' \
  '  if (c->role == GHTTP_WS_SERVER && !fh->masked && 0) {'

plant ws-utf8-not-carried-across-fragments src/http/ws_conn.c testWs_conn \
  'WsAutobahn.Case6_2_ValidUtf8SplitAtEveryOctetOfTheMessageIsDeliveredWhole' \
  '  c->msg_frames++;
  if (c->msg_compressed) {' \
  '  ghttp_ws_utf8_init(&c->utf8);  // PLANTED: the validator starts afresh at every frame
  c->msg_frames++;
  if (c->msg_compressed) {'

plant ws-utf8-not-carried-across-feeds src/http/ws_frame.c testWs_frame \
  'WsUtf8.ACodePointMayBeCutAnywhereAndTheAnswerIsTheSame' \
  '  v->need = need;' \
  '  v->need = 0;  // PLANTED: a code point cut by the end of a piece is forgotten'

plant ws-control-frame-fragmentation-allowed src/http/ws_frame.c testWs_conn \
  'WsAutobahn.Case5_1And5_2_AFragmentedControlFrameClosesWith1002' \
  '  if (ghttp_ws_opcode_is_control(opcode) && !fin) {
    return GHTTP_ERR_CORRUPT;  // section 5.5: control frames must not be fragmented
  }' \
  '  if (ghttp_ws_opcode_is_control(opcode) && !fin && 0) {
    return GHTTP_ERR_CORRUPT;
  }'

plant ws-nonminimal-length-allowed src/http/ws_frame.c testWs_frame \
  'WsFrameHeader.ALengthNotInItsShortestEncodingIsRefused' \
  '    if (plen < 126) {
      return GHTTP_ERR_CORRUPT;  // section 5.2: the minimal encoding
    }' \
  '    if (plen < 126 && 0) {
      return GHTTP_ERR_CORRUPT;
    }'

plant ws-reserved-bit-without-extension-allowed src/http/ws_conn.c testWs_conn \
  'WsAutobahn.Case3_1To3_7_AReservedBitOnAnyFrameClosesWith1002' \
  '  if (bits & ~allowed) {' \
  '  if ((bits & ~allowed) && 0) {'

plant ws-close-code-1005-allowed src/http/ws_frame.c testWs_frame \
  'WsCloseCode.TheCodesThatMayBeOnTheWireAreExactlyThoseTheRfcAndTheRegistryAllow' \
  '  if (code >= 1007 && code <= 1014) {' \
  '  if (code >= 1005 && code <= 1014) {'

plant ws-fragment-flood-unbounded src/http/ws_conn.c testWs_conn \
  'WsLimitsConn.AFragmentFloodIsStoppedAtTheLimitNotOneFragmentLater' \
  '  if (frames >= c->limits.max_fragments) {' \
  '  if (frames >= c->limits.max_fragments && 0) {'

plant ws-message-limit-off-by-one src/http/ws_conn.c testWs_conn \
  'WsLimitsConn.AMessageOverTheMessageLimitIsRefusedBeforeItsLastFrameArrives' \
  '    if (fh->payload_len > cap - (have < cap ? have : cap)) {' \
  '    if (fh->payload_len > cap + 1 - (have < cap ? have : cap)) {'

plant ws-control-flood-unbounded src/http/ws_conn.c testWs_conn \
  'WsLimitsConn.ControlFramesPerIntervalAreCountedAndTheIntervalRenews' \
  '    if (++c->ctl_count > c->limits.max_control_per_interval) {' \
  '    if (++c->ctl_count > c->limits.max_control_per_interval && 0) {'

plant ws-mask-offset-forgotten src/http/ws_conn.c testWs_split \
  'WsSplit.AValidStreamGivesTheSameAnswerCutAnywhereAtEitherRole' \
  '          ghttp_ws_mask(piece, k, c->fh.mask_key, c->payload_done);' \
  '          ghttp_ws_mask(piece, k, c->fh.mask_key, 0);  // PLANTED: each piece masked from key 0'

plant ws-accept-guid-wrong include/ghoti.io/http/ws_handshake.h testWs_handshake \
  'WsAccept.TheRfcExampleKeyGivesTheRfcExampleAccept' \
  '#define GHTTP_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"' \
  '#define GHTTP_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B12"'

plant ws-inflate-unbounded src/http/ws_deflate.c testWs_deflate \
  'WsDeflate.ABombIsStoppedAtTheMessageLimitBeforeItsOutputIsHeld' \
  '  return by_ratio < cap ? by_ratio : cap;' \
  '  return (by_ratio < cap ? by_ratio : cap) | UINT64_MAX;  // PLANTED: neither the message limit nor the ratio'

plant ws-expansion-ratio-off src/http/ws_deflate.c testWs_deflate \
  'WsDeflate.TheExpansionRatioStopsAMessageThatGrowsMoreThanItMayPerOctetOfInput' \
  '    by_ratio = d->max_ratio * d->in_total + RATIO_SLACK;' \
  '    by_ratio = UINT64_MAX;  // PLANTED: the ratio is never applied'

plant ws-deflate-trailer-not-stripped src/http/ws_deflate.c testWs_deflate \
  'WsDeflate.The_Hello_ExampleIsCompressedToTheRfcsOctetsAndTheirTrailerIsNotSent' \
  '  ghttp_buffer_truncate(out, total - sizeof(TRAILER));' \
  '  (void)total;  // PLANTED: the 0x00 0x00 0xff 0xff stays on the message'

plant ws-context-takeover-ignored src/http/ws_conn.c testWs_deflate \
  'WsDeflate.WithoutContextTakeoverEveryMessageIsTheSameOctets' \
  '      server ? p->server_no_context_takeover : p->client_no_context_takeover,
      server ? p->client_no_context_takeover : p->server_no_context_takeover,' \
  '      false,
      false,'

# The review round: the handshake's refusals, the negotiation's matching, the
# Close reply and the send side, each one condition removed.
plant ws-server-version-unchecked src/http/ws_handshake.c testWs_handshake \
  'WsServerHandshake.EachWayAHandshakeCanBeWrongIsRefusedWithItsStatus' \
  '  if (!(vn == 2 && memcmp(v, "13", 2) == 0)) {' \
  '  if (!(vn == 2 && memcmp(v, "13", 2) == 0) && 0) {'

plant ws-duplicate-key-accepted src/http/ws_handshake.c testWs_handshake \
  'WsServerHandshake.EachWayAHandshakeCanBeWrongIsRefusedWithItsStatus' \
  '  if (i == GHTTP_HEADERS_NPOS || count_fields(h, name) != 1) {' \
  '  if (i == GHTTP_HEADERS_NPOS) {'

plant ws-host-not-required src/http/ws_handshake.c testWs_handshake \
  'WsServerHandshake.EachWayAHandshakeCanBeWrongIsRefusedWithItsStatus' \
  '  if (!single_field(h, "host", &host, &host_len)) {' \
  '  if (!single_field(h, "host", &host, &host_len) && 0) {'

plant ws-duplicate-protocol-accepted src/http/ws_handshake.c testWs_handshake \
  'WsServerHandshake.ARepeatedOrMalformedSubprotocolListIsRefused' \
  '    if (o->lens[i] == n && memcmp(o->names[i], t, n) == 0) {' \
  '    if (o->lens[i] == n && memcmp(o->names[i], t, n) == 0 && 0) {'

plant ws-duplicate-extension-chosen src/http/ws_handshake.c testWs_handshake \
  'WsExtensionNegotiation.AnExtensionOfferedTwiceIsChosenOnce' \
  '            && !name_chosen(ext_text, ext_len, reply.text, (size_t)(name_end - reply.text))' \
  '            && !(name_chosen(ext_text, ext_len, reply.text, (size_t)(name_end - reply.text)) && 0)'

plant ws-hook-reply-not-checked src/http/ws_handshake.c testWs_handshake \
  'WsExtensionNegotiation.AHookReplyThatIsNotOneExtensionIsAnErrorAndNeverReachesTheHeader' \
  '        if (!reply_text_valid(reply.text, &name_end)) {' \
  '        if (!reply_text_valid(reply.text, &name_end) && 0) {'

plant ws-client-accepts-wider-server-window src/http/ws_deflate.c testWs_handshake \
  'WsDeflateParams.ClientVerificationHoldsTheServerToTheOffer' \
  '      && (!s.smwb || s.smwb_value > offered->server_max_window_bits)) {' \
  '      && (!s.smwb || 0)) {'

plant ws-close-reply-without-the-code src/http/ws_conn.c testWs_conn \
  'WsAutobahn.Case7_7_AValidCloseCodeIsReportedAndEchoed' \
  '        c->ctl_len >= 2 ? 2 : 0, kp, true);' \
  '        0, kp, true);'

plant ws-close-reason-not-checked-as-utf8 src/http/ws_conn.c testWs_conn \
  'WsAutobahn.Case7_5_1_AReasonThatIsNotUtf8ClosesWith1007' \
  '    reason_len = c->ctl_len - 2;
    GHTTP_WsUtf8 v;
    ghttp_ws_utf8_init(&v);
    if (ghttp_ws_utf8_feed(&v, reason, reason_len) != GHTTP_OK
        || !ghttp_ws_utf8_complete(&v)) {' \
  '    reason_len = c->ctl_len - 2;
    GHTTP_WsUtf8 v;
    ghttp_ws_utf8_init(&v);
    if ((ghttp_ws_utf8_feed(&v, reason, reason_len) != GHTTP_OK
        || !ghttp_ws_utf8_complete(&v)) && 0) {'

plant ws-close-of-one-octet-accepted src/http/ws_conn.c testWs_conn \
  'WsAutobahn.Case7_3_2_ACloseWithAOneOctetBodyClosesWith1002' \
  '  if (c->ctl_len == 1) {' \
  '  if (c->ctl_len == 1 && 0) {'

plant ws-send-message-limit-ignored src/http/ws_conn.c testWs_conn \
  'WsLimitsConn.AMessageLargerThanTheMessageLimitCannotBeSent' \
  '  if (total > c->limits.max_message_bytes) {' \
  '  if (total > c->limits.max_message_bytes && 0) {'

plant ws-send-text-not-checked-for-utf8 src/http/ws_conn.c testWs_conn \
  'WsSend.ATextMessageThatIsNotUtf8IsRefusedWhereverItIsCut' \
  '        || (fin && !ghttp_ws_utf8_complete(&v))) {' \
  '        || (fin && !ghttp_ws_utf8_complete(&v) && 0)) {'

plant ws-send-queue-limit-ignored src/http/ws_conn.c testWs_deflate \
  'WsDeflate.ACompressedSendThatWouldOverfillTheQueueIsRefusedBeforeTheCompressorIsTouched' \
  '  if (len > room || extra > room - len) {' \
  '  if ((len > room || extra > room - len) && 0) {'

plant ws-pongs-not-coalesced src/http/ws_conn.c testWs_conn \
  'WsConn.PingsThatArriveBeforeTheLastPongIsWrittenAreAnsweredByOnePongOfTheLatest' \
  '        if (c->pong_pending) {
          ghttp_buffer_erase' \
  '        if (c->pong_pending && 0) {
          ghttp_buffer_erase'

plant ws-truncated-block-delivered src/http/ws_deflate.c testWs_deflate \
  'WsDeflate.DataCutOffInsideABlockIsNotDeliveredAsAMessage' \
  '    if (dst.used != 0 || src.used != src.size) {' \
  '    if ((dst.used != 0 || src.used != src.size) && 0) {'

plant ws-zero-ratio-is-the-slack src/http/ws_deflate.c testWs_deflate \
  'WsDeflate.ARatioOfZeroIsNoRatioLimitAndTheMessageLimitStillApplies' \
  '  if (d->max_ratio == 0
      || d->in_total > (UINT64_MAX - RATIO_SLACK) / d->max_ratio) {
    by_ratio = UINT64_MAX;
  } else {
    by_ratio = d->max_ratio * d->in_total + RATIO_SLACK;
  }
  return by_ratio < cap ? by_ratio : cap;' \
  '  if (d->in_total > (UINT64_MAX - RATIO_SLACK) / (d->max_ratio ? d->max_ratio : 1)) {
    by_ratio = UINT64_MAX;
  } else {
    by_ratio = d->max_ratio * d->in_total + RATIO_SLACK;
  }
  return by_ratio < cap ? by_ratio : cap;'

plant ws-compressed-frame-without-slack src/http/ws_conn.c testWs_deflate \
  'WsDeflate.AnIncompressibleMessageOfTheMessageLimitFitsAFrameOfTheFrameLimit' \
  '  uint64_t frame_cap = frame_compressed ? wire_cap(c->limits.max_frame_payload)
                                        : c->limits.max_frame_payload;' \
  '  uint64_t frame_cap = c->limits.max_frame_payload + 0 * (uint64_t)frame_compressed;'

plant ws-window-bits-swapped src/http/ws_conn.c testWs_deflate \
  'WsDeflate.ASmallWindowLimitsWhatTheCompressorCanReachBackTo' \
  '      server ? p->server_max_window_bits : p->client_max_window_bits,' \
  '      server ? p->client_max_window_bits : p->server_max_window_bits,'

plant ws-close-after-close-not-left-unread src/http/ws_conn.c testWs_conn \
  'WsAutobahn.Case7_1_2To7_1_5_AnythingAfterTheCloseIsLeftUnreadAndTheClosureStaysClean' \
  '  if (c->close_received) {
    // The peer' \
  '  if (c->close_received && 0) {
    // The peer'

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
