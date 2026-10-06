/**
 * @file
 *
 * libFuzzer harness for the WebSocket connection: framing, fragmentation,
 * control frames, the closing handshake, UTF-8 validation, permessage-deflate
 * and the limits, driven by arbitrary bytes from the peer.
 *
 * Byte 0 is the options byte: bit 0 chooses the role, bits 1-3 a limit
 * profile, bit 4 whether permessage-deflate is negotiated (byte 2 then picks
 * its variant), bit 5 whether to run the allocation-failure pass, bit 6
 * whether messages are echoed (which runs the sender and the compressor), bit
 * 7 whether the first frame is made to be of the right masking for the role
 * so that the fuzzer reaches past the first check. Byte 1 seeds the split. The
 * rest is the byte stream from the peer.
 *
 * The invariants: whole, byte by byte and in pseudo-random pieces the input
 * gives one transcript, one output and one result; only the documented
 * results; an error is sticky and writes nothing more; everything written is
 * whole frames of the right masking with valid close codes; text delivered is
 * UTF-8; a message is never over the limit; a refused allocation is OOM or
 * changes nothing, and nothing leaks.
 *
 * Build with: make fuzz-ws-conn
 * Run:        make fuzz-run-ws-conn FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_ws_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 3) {
    return 0;
  }
  uint8_t options = data[0];
  uint8_t split_seed = data[1];
  uint8_t variant = data[2];
  std::string input(reinterpret_cast<const char *>(data + 3), size - 3);
  GHTTP_WsRole role = (options & 1) ? GHTTP_WS_CLIENT : GHTTP_WS_SERVER;
  GHTTP_WsLimits limits = fuzz::ws_limits_for(static_cast<uint8_t>(options >> 1));
  GHTTP_WsNegotiated neg;
  ghttp_ws_negotiated_default(&neg);
  if (options & 0x10) {
    neg = fuzz::ws_negotiated_for(static_cast<uint8_t>(variant | 1));
  } else if (variant & 0x40) {
    neg.extension_rsv = GHTTP_WS_RSV2;
  }
  bool echo = (options & 0x40) != 0;
  if ((options & 0x80) && !input.empty()) {
    // Make the first octet of the masking bit what the role needs: a server
    // is sent masked frames and a client unmasked, so a frame that starts
    // well gets as far as its payload.
    if (input.size() >= 2) {
      uint8_t b1 = static_cast<uint8_t>(input[1]);
      input[1] = static_cast<char>(role == GHTTP_WS_SERVER ? (b1 | 0x80) : (b1 & 0x7f));
    }
  }

  fuzz::WsFuzzRun whole = fuzz::ws_run(role, limits, neg, {input}, nullptr, echo);
  fuzz::WsFuzzRun bytes = [&] {
    std::vector<std::string> v;
    for (char c : input) {
      v.emplace_back(1, c);
    }
    return fuzz::ws_run(role, limits, neg, v, nullptr, echo);
  }();
  fuzz::WsFuzzRun random = fuzz::ws_run(role, limits, neg, fuzz::random_pieces(input, split_seed), nullptr, echo);
  REQUIRE(whole.result == bytes.result, "result depends on byte-wise split");
  REQUIRE(whole.code == bytes.code, "close code depends on byte-wise split");
  REQUIRE(whole.transcript == bytes.transcript, "events depend on byte-wise split");
  REQUIRE(whole.output == bytes.output, "output depends on byte-wise split");
  REQUIRE(whole.result == random.result, "result depends on random split");
  REQUIRE(whole.code == random.code, "close code depends on random split");
  REQUIRE(whole.transcript == random.transcript, "events depend on random split");
  REQUIRE(whole.output == random.output, "output depends on random split");

  if (options & 0x20) {
    ghttptest::FailingAllocator count(static_cast<size_t>(-1));
    fuzz::ws_run(role, limits, neg, {input}, count.get(), echo);
    size_t total = count.requests();
    size_t step = total > 48 ? total / 48 : 1;
    for (size_t k = 0; k <= total; k += step) {
      ghttptest::FailingAllocator fa(k, 0);
      fuzz::WsFuzzRun got = fuzz::ws_run(role, limits, neg, {input}, fa.get(), echo);
      REQUIRE(fa.live() == 0, "leak after an allocation failure");
      if (!fa.failed()) {
        REQUIRE(got.result == whole.result && got.transcript == whole.transcript && got.output == whole.output,
            "an unrefused run differs from the baseline");
      } else if (!got.oom && got.result != GHTTP_ERR_OOM) {
        // The one thing an unreported refusal may take is the Close of a
        // failed connection: queueing it is best effort (ws_conn.h), and the
        // error itself is still the one the input earned.
        bool same_but_close = got.result == whole.result && got.transcript == whole.transcript
            && whole.result != GHTTP_OK && got.code == whole.code
            && whole.output.compare(0, got.output.size(), got.output) == 0;
        REQUIRE((got.result == whole.result && got.transcript == whole.transcript && got.output == whole.output)
                || same_but_close,
            "a refused allocation changed the answer without being reported");
      }
    }
  }
  return 0;
}
