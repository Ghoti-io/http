/**
 * @file
 *
 * libFuzzer harness for HPACK encode, decode.
 *
 * The input is read as a program: each field is a name (an index into a pool
 * of the static table's names, or octets of the input), a value, an indexing
 * mode and a Huffman mode; between fields the program may end the block or
 * change the table size the peer is said to allow. Every block is encoded,
 * decoded by a second, independent context and compared with what was
 * encoded, and after every block the encoder's table and the decoder's must
 * be identical.
 *
 * What this cannot see: an encoder and decoder that agree on a wrong coding
 * (the RFC 7541 Appendix C vectors in the unit tests, and the differential
 * against other implementations, hold the bytes).
 *
 * Build with: make fuzz-hpack-roundtrip
 * Run:        make fuzz-run-hpack-roundtrip FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_common.h"

namespace {

const char * kNames[] = {":method", ":path", ":status", "accept-encoding",
    "cache-control", "cookie", "content-length", "date", "host", "location",
    "set-cookie", "user-agent", "x-a", "x-b", "x-c", "authorization"};

struct Reader {
  const uint8_t * p;
  size_t n;
  uint8_t byte() { return n ? (n--, *p++) : 0; }
  bool done() const { return n == 0; }
  std::string take(size_t k) {
    if (k > n) k = n;
    std::string s(reinterpret_cast<const char *>(p), k);
    p += k;
    n -= k;
    return s;
  }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  Reader in{data + 1, size - 1};
  size_t cap = (data[0] & 1) ? 256 : 4096;
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_table_size = cap;
  lim.max_field_bytes = 4096;
  lim.max_header_list_bytes = 1 << 20;
  lim.max_header_count = 1000;
  GHTTP_HpackEncoder * e = nullptr;
  GHTTP_HpackDecoder * d = nullptr;
  REQUIRE(ghttp_hpack_encoder_create(nullptr, &lim, 4096, &e) == GHTTP_OK, "encoder");
  REQUIRE(ghttp_hpack_decoder_create(nullptr, &lim, 4096, &d) == GHTTP_OK, "decoder");
  GHTTP_Buffer * buf = nullptr;
  REQUIRE(ghttp_buffer_create(nullptr, &buf) == GHTTP_OK, "buffer");

  std::vector<std::pair<std::string, std::string>> sent;
  // A size change is announced by the next block that has a field in it; until
  // then the encoder's table is smaller than the decoder's, by design.
  bool announced = true;
  auto flush = [&]() {
    GHTTP_Headers * h = nullptr;
    REQUIRE(ghttp_headers_create(nullptr, &h) == GHTTP_OK, "headers");
    GHTTP_Result r = ghttp_hpack_decode(d, ghttp_buffer_data(buf), ghttp_buffer_size(buf), h);
    REQUIRE(r == GHTTP_OK, "the decoder refused a block the encoder wrote");
    REQUIRE(ghttp_headers_count(h) == sent.size(), "decoded a different number of fields");
    for (size_t i = 0; i < sent.size(); i++) {
      GHTTP_Field f;
      REQUIRE(ghttp_headers_at(h, i, &f) == GHTTP_OK, "field");
      REQUIRE(std::string(f.name, f.name_len) == sent[i].first
              && std::string(f.value, f.value_len) == sent[i].second,
          "decoded a different field");
    }
    ghttp_headers_destroy(h);
    if (!sent.empty()) {
      announced = true;
    }
    if (announced) {
    REQUIRE(ghttp_hpack_encoder_table_count(e) == ghttp_hpack_decoder_table_count(d),
        "the tables hold a different number of entries");
    REQUIRE(ghttp_hpack_encoder_table_size(e) == ghttp_hpack_decoder_table_size(d),
        "the tables are of different sizes");
    for (size_t i = 0; i < ghttp_hpack_encoder_table_count(e); i++) {
      GHTTP_Field a, b;
      REQUIRE(ghttp_hpack_encoder_table_entry(e, i, &a) == GHTTP_OK, "entry");
      REQUIRE(ghttp_hpack_decoder_table_entry(d, i, &b) == GHTTP_OK, "entry");
      REQUIRE(a.name_len == b.name_len && a.value_len == b.value_len
              && memcmp(a.name, b.name, a.name_len) == 0 && memcmp(a.value, b.value, a.value_len) == 0,
          "the tables differ");
    }
    }
    ghttp_buffer_clear(buf);
    sent.clear();
  };

  int ops = 0;
  while (!in.done() && ops++ < 400) {
    uint8_t op = in.byte();
    switch (op >> 6) {
      case 0: {  // end the block
        flush();
        break;
      }
      case 1: {  // the peer's table size changes, between blocks
        flush();
        announced = false;
        size_t sz = (static_cast<size_t>(in.byte()) << 4) | (op & 15);
        REQUIRE(ghttp_hpack_encoder_set_peer_table_size(e, sz) == GHTTP_OK, "set size");
        break;
      }
      default: {  // a field
        std::string name = (op & 0x10) ? std::string(kNames[op & 15])
                                       : in.take(1 + (in.byte() & 15));
        std::string value = in.take(in.byte() % 40);
        GHTTP_HpackIndexing ix = static_cast<GHTTP_HpackIndexing>(op & 3);
        GHTTP_HpackHuffman hf = static_cast<GHTTP_HpackHuffman>((op >> 2) % 3);
        if (sent.size() >= 500) {
          flush();
        }
        REQUIRE(ghttp_hpack_encode_field(e, name.data(), name.size(), value.data(),
                    value.size(), ix, hf, buf) == GHTTP_OK,
            "encode_field");
        sent.emplace_back(name, value);
        break;
      }
    }
  }
  flush();
  ghttp_buffer_destroy(buf);
  ghttp_hpack_decoder_destroy(d);
  ghttp_hpack_encoder_destroy(e);
  return 0;
}
