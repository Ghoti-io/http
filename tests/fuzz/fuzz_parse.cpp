/**
 * @file
 *
 * libFuzzer harness for the parser.
 *
 * Byte 0 is the options byte: bit 0 chooses requests or responses, bits 1-3
 * a limit profile, bit 4 whether to signal the end of the stream, bit 5
 * whether to run the allocation-failure pass. Byte 1 seeds the split. The rest
 * is the message stream.
 *
 * The invariants: the input parsed whole, byte by byte and in pseudo-random
 * pieces gives one transcript and one result; no result but the documented
 * ones; a refused allocation is OOM or changes nothing, and nothing leaks.
 *
 * Build with: make fuzz-parse
 * Run:        make fuzz-run-parse FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  uint8_t options = data[0];
  uint8_t split_seed = data[1];
  std::string input(reinterpret_cast<const char *>(data + 2), size - 2);
  GHTTP_ParserKind kind =
      (options & 1) ? GHTTP_PARSE_RESPONSE : GHTTP_PARSE_REQUEST;
  GHTTP_Limits limits = fuzz::limits_for(static_cast<uint8_t>(options >> 1));
  bool finish = (options & 0x10) != 0;

  fuzz::Parsed whole = fuzz::parse(kind, limits, {input}, finish);
  fuzz::Parsed bytes = [&] {
    std::vector<std::string> v;
    for (char c : input) {
      v.emplace_back(1, c);
    }
    return fuzz::parse(kind, limits, v, finish);
  }();
  fuzz::Parsed random = fuzz::parse(
      kind, limits, fuzz::random_pieces(input, split_seed), finish);
  REQUIRE(whole.result == bytes.result, "result depends on byte-wise split");
  REQUIRE(whole.transcript == bytes.transcript,
      "transcript depends on byte-wise split");
  REQUIRE(whole.result == random.result, "result depends on random split");
  REQUIRE(whole.transcript == random.transcript,
      "transcript depends on random split");

  if (options & 0x20) {
    // Refuse allocation number n and every one after it. The sweep is bounded
    // so that a long input does not make one run slow.
    ghttptest::FailingAllocator count(static_cast<size_t>(-1));
    fuzz::parse(kind, limits, {input}, finish, count.get());
    size_t total = count.requests();
    size_t step = total > 64 ? total / 64 : 1;
    for (size_t k = 0; k <= total; k += step) {
      ghttptest::FailingAllocator fa(k, 0);
      fuzz::Parsed got = fuzz::parse(kind, limits, {input}, finish, fa.get());
      REQUIRE(fa.live() == 0, "leak after an allocation failure");
      if (!fa.failed()) {
        REQUIRE(got.result == whole.result && got.transcript == whole.transcript,
            "an unrefused run differs from the baseline");
      } else if (got.result != GHTTP_ERR_OOM) {
        REQUIRE(got.result == whole.result && got.transcript == whole.transcript,
            "a refused allocation changed the answer without being reported");
      }
    }
  }
  return 0;
}
