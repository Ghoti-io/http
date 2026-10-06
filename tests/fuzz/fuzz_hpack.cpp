/**
 * @file
 *
 * libFuzzer harness for the HPACK decoder.
 *
 * Byte 0 is the options byte: bits 0-2 a limit profile, bit 3 whether to run
 * the allocation-failure pass, bit 4 whether the decoder's table starts small.
 * The rest is a series of header blocks, each preceded by a one-octet length
 * (0 to 255), decoded in order by one decoder, as one connection's blocks are.
 *
 * The invariants: only the documented results; a failed decoder stays failed;
 * the table is never larger than its maximum, and its size is the sum of its
 * entries; a block that decodes is one a fresh encoder's output for the same
 * list decodes to the same list (so the decoder never accepts a list it
 * cannot reproduce); a refused allocation is OOM or changes nothing; nothing
 * leaks.
 *
 * Build with: make fuzz-hpack
 * Run:        make fuzz-run-hpack FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_common.h"

namespace {

GHTTP_HpackLimits limits_for(uint8_t p) {
  GHTTP_HpackLimits l;
  ghttp_hpack_limits_default(&l);
  switch (p & 7) {
    case 1: l.max_header_count = 3; break;
    case 2: l.max_header_list_bytes = 120; break;
    case 3: l.max_field_bytes = 8; break;
    case 4: l.max_table_size = 64; break;
    case 5: l.max_table_size = 0; break;
    case 6: l.max_header_count = 1; l.max_field_bytes = 2; break;
    default: break;
  }
  return l;
}

struct Result {
  GHTTP_Result result = GHTTP_OK;
  std::string transcript;
};

std::string table_text(GHTTP_HpackDecoder * d) {
  std::string t;
  size_t sum = 0;
  size_t n = ghttp_hpack_decoder_table_count(d);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    REQUIRE(ghttp_hpack_decoder_table_entry(d, i, &f) == GHTTP_OK, "table entry");
    t.append(f.name, f.name_len).append("=").append(f.value, f.value_len).append(";");
    sum += f.name_len + f.value_len + 32;
  }
  REQUIRE(sum == ghttp_hpack_decoder_table_size(d), "table size is not the sum of its entries");
  REQUIRE(sum <= ghttp_hpack_decoder_table_max(d), "table over its maximum");
  return t;
}

Result run(const GHTTP_HpackLimits & lim, size_t table, const std::vector<std::string> & blocks,
    const GHTTP_Allocator * alloc, bool check_reencode) {
  Result out;
  GHTTP_HpackDecoder * d = nullptr;
  out.result = ghttp_hpack_decoder_create(alloc, &lim, table, &d);
  if (out.result != GHTTP_OK) {
    REQUIRE(out.result == GHTTP_ERR_OOM, "create failed other than by OOM");
    return out;
  }
  for (const std::string & b : blocks) {
    GHTTP_Headers * h = nullptr;
    GHTTP_Result r = ghttp_headers_create(alloc, &h);
    if (r != GHTTP_OK) {
      out.result = r;
      break;
    }
    r = ghttp_hpack_decode(d, b.data(), b.size(), h);
    REQUIRE(r == GHTTP_OK || r == GHTTP_ERR_CORRUPT || r == GHTTP_ERR_LIMIT || r == GHTTP_ERR_OOM,
        "decode returned an unexpected result");
    out.transcript += "R" + std::to_string(r) + "\n";
    std::string list;
    for (size_t i = 0; i < ghttp_headers_count(h); i++) {
      GHTTP_Field f;
      REQUIRE(ghttp_headers_at(h, i, &f) == GHTTP_OK, "field");
      list.append(f.name, f.name_len).append(":").append(f.value, f.value_len).append("\n");
    }
    if (r == GHTTP_OK) {
      out.transcript += list + table_text(d);
      if (check_reencode) {
        // Encode the decoded list with a fresh encoder and decode that: the
        // same list must come back.
        GHTTP_HpackEncoder * e = nullptr;
        GHTTP_HpackDecoder * d2 = nullptr;
        GHTTP_Buffer * buf = nullptr;
        GHTTP_HpackLimits big;
        ghttp_hpack_limits_default(&big);
        big.max_header_list_bytes = SIZE_MAX / 2;
        big.max_field_bytes = SIZE_MAX / 2;
        big.max_header_count = SIZE_MAX / 2;
        REQUIRE(ghttp_hpack_encoder_create(nullptr, &big, 4096, &e) == GHTTP_OK, "encoder");
        REQUIRE(ghttp_hpack_decoder_create(nullptr, &big, 4096, &d2) == GHTTP_OK, "decoder");
        REQUIRE(ghttp_buffer_create(nullptr, &buf) == GHTTP_OK, "buffer");
        REQUIRE(ghttp_hpack_encode(e, h, buf) == GHTTP_OK, "re-encode");
        GHTTP_Headers * h2 = nullptr;
        REQUIRE(ghttp_headers_create(nullptr, &h2) == GHTTP_OK, "headers");
        REQUIRE(ghttp_hpack_decode(d2, ghttp_buffer_data(buf), ghttp_buffer_size(buf), h2) == GHTTP_OK,
            "the encoder wrote a block its decoder refuses");
        REQUIRE(ghttp_headers_count(h2) == ghttp_headers_count(h), "re-encoded list differs in length");
        for (size_t i = 0; i < ghttp_headers_count(h); i++) {
          GHTTP_Field a, c;
          ghttp_headers_at(h, i, &a);
          ghttp_headers_at(h2, i, &c);
          REQUIRE(a.name_len == c.name_len && a.value_len == c.value_len
                  && memcmp(a.name, c.name, a.name_len) == 0
                  && memcmp(a.value, c.value, a.value_len) == 0,
              "re-encoded list differs");
        }
        ghttp_headers_destroy(h2);
        ghttp_buffer_destroy(buf);
        ghttp_hpack_decoder_destroy(d2);
        ghttp_hpack_encoder_destroy(e);
      }
    }
    ghttp_headers_destroy(h);
    if (r != GHTTP_OK) {
      out.result = r;
      REQUIRE(ghttp_hpack_decoder_failed(d), "a failed decode left the decoder usable");
      GHTTP_Headers * h3 = nullptr;
      if (ghttp_headers_create(alloc, &h3) == GHTTP_OK) {
        REQUIRE(ghttp_hpack_decode(d, "\x82", 1, h3) == r, "a failed decoder did not stay failed");
        ghttp_headers_destroy(h3);
      }
      break;
    }
  }
  ghttp_hpack_decoder_destroy(d);
  return out;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  uint8_t options = data[0];
  GHTTP_HpackLimits lim = limits_for(options);
  size_t table = (options & 0x10) ? 100 : 4096;
  std::vector<std::string> blocks;
  size_t pos = 1;
  while (pos < size && blocks.size() < 16) {
    size_t n = data[pos++];
    if (n > size - pos) {
      n = size - pos;
    }
    blocks.emplace_back(reinterpret_cast<const char *>(data + pos), n);
    pos += n;
  }
  Result base = run(lim, table, blocks, nullptr, true);
  if (options & 0x08) {
    ghttptest::FailingAllocator count(static_cast<size_t>(-1));
    run(lim, table, blocks, count.get(), false);
    size_t total = count.requests();
    size_t step = total > 48 ? total / 48 : 1;
    for (size_t k = 0; k <= total; k += step) {
      ghttptest::FailingAllocator fa(k, 0);
      Result got = run(lim, table, blocks, fa.get(), false);
      REQUIRE(fa.live() == 0, "leak after an allocation failure");
      if (!fa.failed() || got.result != GHTTP_ERR_OOM) {
        REQUIRE(got.result == base.result && got.transcript == base.transcript,
            "a refused allocation changed the answer without being reported");
      }
    }
  }
  return 0;
}
