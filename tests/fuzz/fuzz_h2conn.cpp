/**
 * @file
 *
 * libFuzzer harness for the HTTP/2 connection: the frame layer, the stream
 * and connection state machines, the message rules and flow control, driven by
 * arbitrary bytes.
 *
 * Byte 0 is the options byte: bit 0 chooses the role, bits 1-3 a limit profile,
 * bit 4 whether the input is preceded by a valid preface and SETTINGS so that
 * the fuzzer reaches past it, bit 5 whether to run the allocation-failure
 * pass, bit 6 whether a client opens a stream first, bit 7 (a server) whether Extended CONNECT is enabled. Byte 1 seeds the split.
 * The rest is the byte stream from the peer.
 *
 * The invariants: whole, byte by byte and in pseudo-random pieces the input
 * gives one transcript, one output and one result; only the documented results;
 * an error is sticky and writes nothing more; everything written is a sequence
 * of frames the frame parser accepts; windows stay in range; a refused
 * allocation is OOM or changes nothing, and nothing leaks.
 *
 * Build with: make fuzz-h2conn
 * Run:        make fuzz-run-h2conn FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_h2_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  uint8_t options = data[0];
  uint8_t split_seed = data[1];
  std::string input(reinterpret_cast<const char *>(data + 2), size - 2);
  GHTTP_H2Role role = (options & 1) ? GHTTP_H2_CLIENT : GHTTP_H2_SERVER;
  GHTTP_H2Limits limits = fuzz::h2_limits_for(static_cast<uint8_t>(options >> 1));
  bool send_first = (options & 0x40) != 0;
  if ((options & 0x80) && role == GHTTP_H2_SERVER) {
    limits.enable_connect_protocol = 1;  // Extended CONNECT (RFC 8441) is accepted
    limits.max_protocol_bytes = 12;
  }
  if (options & 0x10) {
    // SETTINGS (empty), as a peer's preface ends.
    std::string open = role == GHTTP_H2_SERVER ? std::string(GHTTP_H2_PREFACE) : std::string();
    open += std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9);
    input = open + input;
  }

  fuzz::H2Run whole = fuzz::h2_run(role, limits, {input}, nullptr, send_first);
  fuzz::H2Run bytes = [&] {
    std::vector<std::string> v;
    for (char c : input) {
      v.emplace_back(1, c);
    }
    return fuzz::h2_run(role, limits, v, nullptr, send_first);
  }();
  fuzz::H2Run random = fuzz::h2_run(
      role, limits, fuzz::random_pieces(input, split_seed), nullptr, send_first);
  REQUIRE(whole.result == bytes.result, "result depends on byte-wise split");
  REQUIRE(whole.transcript == bytes.transcript, "events depend on byte-wise split");
  REQUIRE(whole.output == bytes.output, "output depends on byte-wise split");
  REQUIRE(whole.result == random.result, "result depends on random split");
  REQUIRE(whole.transcript == random.transcript, "events depend on random split");
  REQUIRE(whole.output == random.output, "output depends on random split");

  if (options & 0x20) {
    ghttptest::FailingAllocator count(static_cast<size_t>(-1));
    fuzz::h2_run(role, limits, {input}, count.get(), send_first);
    size_t total = count.requests();
    size_t step = total > 48 ? total / 48 : 1;
    for (size_t k = 0; k <= total; k += step) {
      ghttptest::FailingAllocator fa(k, 0);
      fuzz::H2Run got = fuzz::h2_run(role, limits, {input}, fa.get(), send_first);
      REQUIRE(fa.live() == 0, "leak after an allocation failure");
      if (!fa.failed()) {
        REQUIRE(got.result == whole.result && got.transcript == whole.transcript
                && got.output == whole.output,
            "an unrefused run differs from the baseline");
      } else if (!got.oom && got.result != GHTTP_ERR_OOM) {
        REQUIRE(got.result == whole.result && got.transcript == whole.transcript
                && got.output == whole.output,
            "a refused allocation changed the answer without being reported");
      }
    }
  }
  return 0;
}
