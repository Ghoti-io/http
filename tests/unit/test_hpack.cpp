/**
 * @file
 *
 * HPACK (RFC 7541): the integer and Huffman codings, the decoder and the
 * encoder against the RFC's own Appendix C examples, every refusal the RFC
 * names, the limits, and allocation failure.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <random>

#include "test_helpers.h"
#include "../hpack_rfc_vectors.h"
#include "../../src/http/coding_internal.h"

using namespace ghttptest;

namespace {

using List = std::vector<std::pair<std::string, std::string>>;

std::string unhex(const std::string & h) {
  std::string out;
  for (size_t i = 0; i + 1 < h.size(); i += 2) {
    out.push_back(static_cast<char>(std::stoi(h.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string hex(const std::string & s) {
  static const char * d = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s) {
    out.push_back(d[c >> 4]);
    out.push_back(d[c & 15]);
  }
  return out;
}

List list_of(const GHTTP_Headers * h) {
  List out;
  for (size_t i = 0; i < ghttp_headers_count(h); i++) {
    GHTTP_Field f;
    EXPECT_EQ(ghttp_headers_at(h, i, &f), GHTTP_OK);
    out.emplace_back(std::string(f.name, f.name_len),
        std::string(f.value, f.value_len));
  }
  return out;
}

List expected_list(const RfcExample & e) {
  List out;
  for (auto & p : e.list) out.emplace_back(p.first, p.second);
  return out;
}

List expected_table(const RfcExample & e) {
  List out;
  for (auto & p : e.table) out.emplace_back(p.first, p.second);
  return out;
}

template <class D> List table_of_decoder(D * d) {
  List out;
  for (size_t i = 0; i < ghttp_hpack_decoder_table_count(d); i++) {
    GHTTP_Field f;
    EXPECT_EQ(ghttp_hpack_decoder_table_entry(d, i, &f), GHTTP_OK);
    out.emplace_back(std::string(f.name, f.name_len),
        std::string(f.value, f.value_len));
  }
  return out;
}

List table_of_encoder(GHTTP_HpackEncoder * e) {
  List out;
  for (size_t i = 0; i < ghttp_hpack_encoder_table_count(e); i++) {
    GHTTP_Field f;
    EXPECT_EQ(ghttp_hpack_encoder_table_entry(e, i, &f), GHTTP_OK);
    out.emplace_back(std::string(f.name, f.name_len),
        std::string(f.value, f.value_len));
  }
  return out;
}

struct Dec {
  GHTTP_HpackDecoder * d = nullptr;
  explicit Dec(size_t table = 4096, const GHTTP_HpackLimits * lim = nullptr,
      const GHTTP_Allocator * a = nullptr) {
    EXPECT_EQ(ghttp_hpack_decoder_create(a, lim, table, &d), GHTTP_OK);
  }
  ~Dec() { ghttp_hpack_decoder_destroy(d); }
  GHTTP_Result decode(const std::string & block, List * out = nullptr) {
    GHTTP_Headers * h = nullptr;
    EXPECT_EQ(ghttp_headers_create(nullptr, &h), GHTTP_OK);
    GHTTP_Result r = ghttp_hpack_decode(d, block.data(), block.size(), h);
    if (out) *out = list_of(h);
    ghttp_headers_destroy(h);
    return r;
  }
};

struct Enc {
  GHTTP_HpackEncoder * e = nullptr;
  explicit Enc(size_t table = 4096, const GHTTP_HpackLimits * lim = nullptr) {
    EXPECT_EQ(ghttp_hpack_encoder_create(nullptr, lim, table, &e), GHTTP_OK);
  }
  ~Enc() { ghttp_hpack_encoder_destroy(e); }
  std::string field(const std::string & n, const std::string & v,
      GHTTP_HpackIndexing ix = GHTTP_HPACK_INDEX_AUTO,
      GHTTP_HpackHuffman hf = GHTTP_HPACK_HUFFMAN_AUTO) {
    GHTTP_Buffer * b = nullptr;
    EXPECT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
    EXPECT_EQ(ghttp_hpack_encode_field(e, n.data(), n.size(), v.data(),
                  v.size(), ix, hf, b),
        GHTTP_OK);
    std::string s(static_cast<const char *>(ghttp_buffer_data(b)),
        ghttp_buffer_size(b));
    ghttp_buffer_destroy(b);
    return s;
  }
};

/** A literal field "a" with a Huffman-coded value of these octets. */
std::string huff_value_block(const std::string & octets) {
  std::string b;
  b.push_back(0x00);
  b.push_back(0x01);
  b.push_back('a');
  b.push_back(static_cast<char>(0x80 | octets.size()));
  b += octets;
  return b;
}

} // namespace

// ---- RFC 7541 Appendix C.1: integers --------------------------------------

TEST(HpackInteger, Rfc7541AppendixC1Examples) {
  uint8_t out[GHTTP_INT_MAX_ENCODED];
  // C.1.1: 10 on a 5-bit prefix.
  ASSERT_EQ(ghttp_int_encode(out, 5, 0, 10), 1u);
  EXPECT_EQ(out[0], 0x0a);
  // C.1.2: 1337 on a 5-bit prefix is 31, 154, 10.
  ASSERT_EQ(ghttp_int_encode(out, 5, 0, 1337), 3u);
  EXPECT_EQ(out[0], 0x1f);
  EXPECT_EQ(out[1], 0x9a);
  EXPECT_EQ(out[2], 0x0a);
  // C.1.3: 42 on an 8-bit prefix.
  ASSERT_EQ(ghttp_int_encode(out, 8, 0, 42), 1u);
  EXPECT_EQ(out[0], 0x2a);

  uint32_t v;
  size_t used;
  const uint8_t a[] = {0xe0 | 0x0a};
  ASSERT_EQ(ghttp_int_decode(a, 1, 5, &v, &used), GHTTP_OK);
  EXPECT_EQ(v, 10u);
  const uint8_t b[] = {0xff, 0x9a, 0x0a};
  ASSERT_EQ(ghttp_int_decode(b, 3, 5, &v, &used), GHTTP_OK);
  EXPECT_EQ(v, 1337u);
  EXPECT_EQ(used, 3u);
  const uint8_t c[] = {0x2a};
  ASSERT_EQ(ghttp_int_decode(c, 1, 8, &v, &used), GHTTP_OK);
  EXPECT_EQ(v, 42u);
}

TEST(HpackInteger, RoundTripsEveryPrefixAtTheBoundaries) {
  for (unsigned prefix = 1; prefix <= 8; prefix++) {
    uint32_t max = (1u << prefix) - 1;
    for (uint32_t value : {0u, 1u, max - 1, max, max + 1, 127u, 128u, 16383u,
             16384u, 0x7fffffffu}) {
      uint8_t buf[GHTTP_INT_MAX_ENCODED];
      size_t n = ghttp_int_encode(buf, prefix, 0, value);
      uint32_t got = 0;
      size_t used = 0;
      ASSERT_EQ(ghttp_int_decode(buf, n, prefix, &got, &used), GHTTP_OK)
          << prefix << "/" << value;
      EXPECT_EQ(got, value);
      EXPECT_EQ(used, n);
    }
  }
}

TEST(HpackInteger, TruncatedOverlongAndOverflowingValuesAreCompressionErrors) {
  uint32_t v;
  size_t used;
  // Ends inside the continuation (section 5.1).
  const uint8_t trunc[] = {0x1f, 0x80};
  EXPECT_EQ(ghttp_int_decode(trunc, 2, 5, &v, &used), GHTTP_ERR_CORRUPT);
  // A run of zero-padded continuation octets is refused, not looped over.
  const uint8_t zeros[] = {0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
  EXPECT_EQ(ghttp_int_decode(zeros, sizeof(zeros), 5, &v, &used),
      GHTTP_ERR_CORRUPT);
  // 2^31 does not fit the bound.
  const uint8_t big[] = {0x1f, 0xe1, 0xff, 0xff, 0xff, 0x07};
  EXPECT_EQ(ghttp_int_decode(big, sizeof(big), 5, &v, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(ghttp_int_decode(big, 0, 5, &v, &used), GHTTP_ERR_CORRUPT);
}

// ---- Huffman (section 5.2, Appendix B) -------------------------------------

TEST(HpackHuffman, EveryOctetRoundTrips) {
  std::string all;
  for (int i = 0; i < 256; i++) all.push_back(static_cast<char>(i));
  // Each alone, then all together, then twice.
  for (const std::string & s : {all, all + all, std::string("a"),
           std::string(1, '\0'), std::string("\xff")}) {
    const uint8_t * in = reinterpret_cast<const uint8_t *>(s.data());
    size_t n = ghttp_huff_encoded_len(in, s.size());
    std::vector<uint8_t> enc(n);
    ghttp_huff_encode(in, s.size(), enc.data());
    std::vector<uint8_t> dec(s.size() + 1);
    size_t got = 0;
    ASSERT_EQ(ghttp_huff_decode(enc.data(), n, dec.data(), dec.size(), &got),
        GHTTP_OK);
    EXPECT_EQ(std::string(dec.begin(), dec.begin() + got), s);
  }
  for (int i = 0; i < 256; i++) {
    uint8_t c = static_cast<uint8_t>(i);
    uint8_t enc[8];
    size_t n = ghttp_huff_encoded_len(&c, 1);
    ghttp_huff_encode(&c, 1, enc);
    uint8_t out[2];
    size_t got = 0;
    ASSERT_EQ(ghttp_huff_decode(enc, n, out, 2, &got), GHTTP_OK) << i;
    ASSERT_EQ(got, 1u);
    EXPECT_EQ(out[0], c);
  }
}

TEST(HpackHuffman, WwwExampleComMatchesTheRfcBytes) {
  // RFC 7541 C.4.1.
  const std::string s = "www.example.com";
  std::vector<uint8_t> enc(ghttp_huff_encoded_len(
      reinterpret_cast<const uint8_t *>(s.data()), s.size()));
  ghttp_huff_encode(reinterpret_cast<const uint8_t *>(s.data()), s.size(),
      enc.data());
  EXPECT_EQ(hex(std::string(enc.begin(), enc.end())), "f1e3c2e5f23a6ba0ab90f4ff");
}

TEST(HpackHuffman, PaddingLongerThanSevenBitsIsRefused) {
  // '0' is 00000; eleven bits of padding follow.
  uint8_t in[] = {0x07, 0xff};
  uint8_t out[4];
  size_t n;
  EXPECT_EQ(ghttp_huff_decode(in, 2, out, 4, &n), GHTTP_ERR_CORRUPT);
  uint8_t ok[] = {0x07};  // '0' and three bits of padding
  ASSERT_EQ(ghttp_huff_decode(ok, 1, out, 4, &n), GHTTP_OK);
  EXPECT_EQ(n, 1u);
}

TEST(HpackHuffman, PaddingThatIsNotTheEosPrefixIsRefused) {
  uint8_t in[] = {0x00};  // '0' then 000: not ones
  uint8_t out[4];
  size_t n;
  EXPECT_EQ(ghttp_huff_decode(in, 1, out, 4, &n), GHTTP_ERR_CORRUPT);
}

TEST(HpackHuffman, TheEosSymbolInsideAStringIsRefused) {
  uint8_t in[] = {0xff, 0xff, 0xff, 0xff};  // 30 ones are EOS
  uint8_t out[8];
  size_t n;
  EXPECT_EQ(ghttp_huff_decode(in, 4, out, 8, &n), GHTTP_ERR_CORRUPT);
}

TEST(HpackHuffman, OutputIsCappedAsItIsProduced) {
  std::string s(1000, 'a');
  const uint8_t * in = reinterpret_cast<const uint8_t *>(s.data());
  std::vector<uint8_t> enc(ghttp_huff_encoded_len(in, s.size()));
  ghttp_huff_encode(in, s.size(), enc.data());
  std::vector<uint8_t> out(10);
  size_t n;
  EXPECT_EQ(ghttp_huff_decode(enc.data(), enc.size(), out.data(), 10, &n),
      GHTTP_ERR_LIMIT);
}

// ---- RFC 7541 Appendix C.2 to C.6 ------------------------------------------

namespace {

/** The decoder in use for example @p id: C.2 are independent, the rest chain. */
struct Chain {
  std::string group;
  std::unique_ptr<Dec> dec;
};

std::string group_of(const std::string & id) {
  return id.substr(0, 3) == "C.2" ? id : id.substr(0, 3);
}

size_t table_for(const std::string & id) {
  return id[2] == '5' || id[2] == '6' ? 256 : 4096;
}

} // namespace

TEST(HpackDecoder, Rfc7541AppendixC2To6ListsAndTableStatesMatchExactly) {
  std::string group;
  std::unique_ptr<Dec> dec;
  size_t seen = 0;
  for (const RfcExample & e : rfc_examples()) {
    if (group_of(e.id) != group) {
      group = group_of(e.id);
      dec = std::make_unique<Dec>(table_for(e.id));
    }
    List got;
    ASSERT_EQ(dec->decode(unhex(e.hex), &got), GHTTP_OK) << e.id;
    EXPECT_EQ(got, expected_list(e)) << e.id;
    EXPECT_EQ(table_of_decoder(dec->d), expected_table(e)) << e.id;
    EXPECT_EQ(ghttp_hpack_decoder_table_size(dec->d), e.table_size) << e.id;
    seen++;
  }
  EXPECT_EQ(seen, 16u) << "C.2.1-4 and the three-request / three-response "
                          "series of C.3 to C.6";
}

TEST(HpackEncoder, Rfc7541AppendixC2To6AreReproducedByteForByte) {
  std::string group;
  std::unique_ptr<Enc> enc;
  for (const RfcExample & e : rfc_examples()) {
    if (group_of(e.id) != group) {
      group = group_of(e.id);
      enc = std::make_unique<Enc>(table_for(e.id));
    }
    // C.3 and C.5 are the plain-octet forms; C.4 and C.6 use Huffman. C.2.2
    // and C.2.3 name a particular representation.
    bool plain = e.id[2] == '3' || e.id[2] == '5' || e.id[2] == '2';
    GHTTP_HpackHuffman hf = plain ? GHTTP_HPACK_HUFFMAN_NEVER : GHTTP_HPACK_HUFFMAN_AUTO;
    std::string idstr = e.id;
    std::string out;
    for (auto & f : e.list) {
      GHTTP_HpackIndexing ix = GHTTP_HPACK_INDEX_AUTO;
      if (idstr == "C.2.2") ix = GHTTP_HPACK_INDEX_NONE;
      if (idstr == "C.2.3") ix = GHTTP_HPACK_INDEX_NEVER;
      out += enc->field(f.first, f.second, ix, hf);
    }
    EXPECT_EQ(hex(out), e.hex) << e.id;
    EXPECT_EQ(table_of_encoder(enc->e), expected_table(e)) << e.id;
    EXPECT_EQ(ghttp_hpack_encoder_table_size(enc->e), e.table_size) << e.id;
  }
}

// ---- What the decoder refuses ----------------------------------------------

TEST(HpackDecoder, IndexZeroAndIndexBeyondTheTablesAreCompressionErrors) {
  {
    Dec d;
    EXPECT_EQ(d.decode(std::string("\x80", 1)), GHTTP_ERR_CORRUPT);
  }
  {
    Dec d;  // the dynamic table is empty: index 62 names nothing
    EXPECT_EQ(d.decode(std::string("\xbe", 1)), GHTTP_ERR_CORRUPT);
  }
  {
    Dec d;  // index 61 is the last static entry
    List l;
    ASSERT_EQ(d.decode(std::string("\xbd", 1), &l), GHTTP_OK);
    EXPECT_EQ(l, (List{{"www-authenticate", ""}}));
  }
  {
    Dec d;  // a literal whose name index is beyond the table
    EXPECT_EQ(d.decode(unhex("7f") + unhex("ff00") + unhex("00")), GHTTP_ERR_CORRUPT);
  }
}

TEST(HpackDecoder, HuffmanStringErrorsAreCompressionErrors) {
  {
    Dec d;
    List l;
    ASSERT_EQ(d.decode(huff_value_block(std::string("\x07", 1)), &l), GHTTP_OK);
    EXPECT_EQ(l, (List{{"a", "0"}}));
  }
  {
    Dec d;
    EXPECT_EQ(d.decode(huff_value_block(std::string("\x07\xff", 2))),
        GHTTP_ERR_CORRUPT) << "padding of more than seven bits (section 5.2)";
  }
  {
    Dec d;
    EXPECT_EQ(d.decode(huff_value_block(std::string("\x00", 1))),
        GHTTP_ERR_CORRUPT) << "padding that is not the EOS prefix";
  }
  {
    Dec d;
    EXPECT_EQ(d.decode(huff_value_block(std::string("\xff\xff\xff\xff", 4))),
        GHTTP_ERR_CORRUPT) << "the EOS symbol inside a string";
  }
}

TEST(HpackDecoder, TruncatedBlocksAreCompressionErrors) {
  for (const char * h : {"40", "4001", "400161", "400161" "05" "6161", "7f",
           "ff", "3f", "0f", "400a6375", "c1"}) {
    Dec d;
    GHTTP_Result r = d.decode(unhex(h));
    EXPECT_NE(r, GHTTP_OK) << h;
    if (std::string(h) == "c1") {
      EXPECT_EQ(r, GHTTP_OK == r ? r : GHTTP_ERR_CORRUPT);
    }
  }
  Dec d;
  EXPECT_EQ(d.decode(unhex("400161" "05" "6161")), GHTTP_ERR_CORRUPT)
      << "a string longer than the block";
}

TEST(HpackDecoder, ADynamicTableSizeUpdateIsOnlyValidAtTheStartOfABlock) {
  Dec d;
  // 82 (indexed) then an update to 4096: misplaced (section 4.2).
  EXPECT_EQ(d.decode(unhex("82" "3fe11f")), GHTTP_ERR_CORRUPT);
  EXPECT_TRUE(ghttp_hpack_decoder_failed(d.d));
  Dec ok;
  List l;
  EXPECT_EQ(ok.decode(unhex("3fe11f" "82"), &l), GHTTP_OK)
      << "an update first, then a field";
  Dec two;
  EXPECT_EQ(two.decode(unhex("20" "3fe11f" "82"), &l), GHTTP_OK)
      << "two updates (the minimum, then the final size) are allowed";
}

TEST(HpackDecoder, AnUpdateAboveTheAdvertisedMaximumIsACompressionError) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_table_size = 1000;
  Dec d(1000, &lim);
  ASSERT_EQ(ghttp_hpack_decoder_set_max_table_size(d.d, 1000), GHTTP_OK);  // acknowledged
  EXPECT_EQ(d.decode(unhex("3fca07")), GHTTP_ERR_CORRUPT) << "1001";
  Dec d3(1000, &lim);
  ASSERT_EQ(ghttp_hpack_decoder_set_max_table_size(d3.d, 1000), GHTTP_OK);
  EXPECT_EQ(d3.decode(unhex("3fc907")), GHTTP_OK) << "1000 itself";
  Dec before_ack(1000, &lim);
  EXPECT_EQ(before_ack.decode(unhex("3fca07")), GHTTP_OK)
      << "until the peer acknowledges the smaller maximum it may use the default";
}

TEST(HpackDecoder, AfterTheMaximumIsLoweredTheNextBlockMustOpenWithAnUpdate) {
  Dec d;
  ASSERT_EQ(ghttp_hpack_decoder_set_max_table_size(d.d, 100), GHTTP_OK);
  EXPECT_EQ(d.decode(unhex("82")), GHTTP_ERR_CORRUPT);
  Dec e;
  ASSERT_EQ(ghttp_hpack_decoder_set_max_table_size(e.d, 100), GHTTP_OK);
  EXPECT_EQ(e.decode(unhex("3f45" "82")), GHTTP_OK);
  EXPECT_EQ(ghttp_hpack_decoder_table_max(e.d), 100u);
  EXPECT_EQ(e.decode(unhex("82")), GHTTP_OK) << "once; later blocks need none";
  Dec f;
  ASSERT_EQ(ghttp_hpack_decoder_set_max_table_size(f.d, 100), GHTTP_OK);
  EXPECT_EQ(f.decode(unhex("3f46" "82")), GHTTP_ERR_CORRUPT)
      << "101 is above the new maximum";
  Dec g;
  EXPECT_EQ(ghttp_hpack_decoder_set_max_table_size(g.d, 1u << 20), GHTTP_ERR_INVALID);
}

TEST(HpackDecoder, AFailedDecoderStaysFailed) {
  Dec d;
  ASSERT_EQ(d.decode(unhex("80")), GHTTP_ERR_CORRUPT);
  List l;
  EXPECT_EQ(d.decode(unhex("82"), &l), GHTTP_ERR_CORRUPT)
      << "the compression state is shared by every stream and cannot be recovered";
  EXPECT_TRUE(l.empty());
}

TEST(HpackDecoder, AnEntryLargerThanTheTableEmptiesItAndIsNotAdded) {
  Dec d;
  ASSERT_EQ(d.decode(unhex("82" "400161" "0162")), GHTTP_OK);  // a: b added
  EXPECT_EQ(ghttp_hpack_decoder_table_count(d.d), 1u);
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  Dec small(40, &lim);  // 32 + 2 = 34 fits, a longer one does not
  ASSERT_EQ(small.decode(unhex("400161" "0162")), GHTTP_OK);
  EXPECT_EQ(ghttp_hpack_decoder_table_count(small.d), 1u);
  ASSERT_EQ(small.decode(unhex("400161" "0a" "62626262626262626262")), GHTTP_OK);
  EXPECT_EQ(ghttp_hpack_decoder_table_count(small.d), 0u)
      << "section 4.4: not an error, and the table is emptied";
}

TEST(HpackDecoder, TheTableIsEvictedOldestFirstToFitANewEntry) {
  Dec d(100);  // room for two 34-octet entries, not three
  ASSERT_EQ(d.decode(unhex("400161" "0131" "400162" "0132" "400163" "0133")),
      GHTTP_OK);
  EXPECT_EQ(table_of_decoder(d.d), (List{{"c", "3"}, {"b", "2"}}));
  EXPECT_EQ(ghttp_hpack_decoder_table_size(d.d), 68u);
}

TEST(HpackDecoder, ALiteralWhoseNameIsAnIndexIntoTheEvictedEntryStillDecodes) {
  // Section 4.4 and the bug that bites here: the name may live in the entry
  // that adding the new one evicts. One 34-octet entry fits; the second
  // literal names it by index and evicts it.
  Dec d(40);
  List l;
  ASSERT_EQ(d.decode(unhex("400161" "0131" "7e" "0132"), &l), GHTTP_OK);
  EXPECT_EQ(l, (List{{"a", "1"}, {"a", "2"}}));
  EXPECT_EQ(table_of_decoder(d.d), (List{{"a", "2"}}));
}

// ---- Limits ----------------------------------------------------------------

TEST(HpackLimits, TheFieldCountIsCapped) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_header_count = 3;
  Dec ok(4096, &lim);
  EXPECT_EQ(ok.decode(unhex("828684")), GHTTP_OK);
  Dec d(4096, &lim);
  List l;
  EXPECT_EQ(d.decode(unhex("82868482"), &l), GHTTP_ERR_LIMIT);
  EXPECT_LE(l.size(), 3u) << "stopped at the bound";
}

TEST(HpackLimits, TheHeaderListSizeIsCappedInTheUnitsOfRfc9113Section6_5_2) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  // ":method: GET" costs 7 + 3 + 32 = 42.
  lim.max_header_list_bytes = 84;
  Dec ok(4096, &lim);
  EXPECT_EQ(ok.decode(unhex("8282")), GHTTP_OK);
  Dec d(4096, &lim);
  EXPECT_EQ(d.decode(unhex("828282")), GHTTP_ERR_LIMIT);
}

TEST(HpackLimits, AnIndexedBombStopsAtTheListLimitAndNotAtItsExpansion) {
  // Put a 4 KiB entry in the table, then spend one octet per copy of it.
  // 4000 copies would be 16 MB of headers from 4 KB of block.
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  Dec d(4096, &lim);
  std::string big(4000, 'x');
  // A literal with indexing: name "n", value 4000 octets (7-bit length prefix:
  // 127, then 3873 = 30 * 128 + 33).
  std::string block = unhex("4001") + "n" + std::string("\x7f\xa1\x1e", 3) + big;
  block += std::string(4000, static_cast<char>(0xbe));
  List l;
  EXPECT_EQ(d.decode(block, &l), GHTTP_ERR_LIMIT);
  EXPECT_LE(l.size(), 100u) << "no more fields than the cap, however many were asked for";
  size_t bytes = 0;
  for (auto & p : l) bytes += p.first.size() + p.second.size() + 32;
  EXPECT_LE(bytes, lim.max_header_list_bytes + 1);
}

TEST(HpackLimits, ASingleFieldIsCappedPlainAndHuffmanCoded) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_field_bytes = 16;
  std::string v(17, 'x');
  {
    Dec d(4096, &lim);
    std::string b = unhex("400161" "11") + v;
    EXPECT_EQ(d.decode(b), GHTTP_ERR_LIMIT);
  }
  {
    Dec d(4096, &lim);
    std::string b = unhex("400161" "10") + std::string(16, 'x');
    EXPECT_EQ(d.decode(b), GHTTP_OK) << "exactly the cap";
  }
  {
    // 200 'a's are 125 octets of Huffman and expand to 200.
    Enc e;
    std::string hv = e.field("a", std::string(200, 'a'), GHTTP_HPACK_INDEX_NONE,
        GHTTP_HPACK_HUFFMAN_ALWAYS);
    Dec d(4096, &lim);
    EXPECT_EQ(d.decode(hv), GHTTP_ERR_LIMIT);
  }
}

TEST(HpackLimits, ADynamicTableLargerThanTheCapCannotBeCreated) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_table_size = 512;
  Dec d(100000, &lim);
  EXPECT_EQ(ghttp_hpack_decoder_table_max(d.d), 4096u)
      << "the peer may use the default until it acknowledges a smaller maximum";
  Enc e(100000, &lim);
  EXPECT_EQ(ghttp_hpack_encoder_table_max(e.e), 512u);
}

// ---- Encoder behaviour -----------------------------------------------------

TEST(HpackEncoder, ATableSizeChangeIsAnnouncedAtTheStartOfTheNextBlock) {
  Enc e;
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(e.e, 100), GHTTP_OK);
  EXPECT_EQ(hex(e.field(":method", "GET")), "3f45" "82");
  EXPECT_EQ(hex(e.field(":path", "/")), "84") << "only once";
}

TEST(HpackEncoder, TwoChangesAnnounceTheSmallestSizeThenTheFinalOne) {
  // Section 4.2: down to 0 and up to 200 between two blocks.
  Enc e;
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(e.e, 0), GHTTP_OK);
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(e.e, 200), GHTTP_OK);
  EXPECT_EQ(hex(e.field(":method", "GET")), "20" "3fa901" "82");
}

TEST(HpackEncoder, AChangeBackToTheCurrentSizeWithNothingBetweenSaysNothing) {
  Enc e;
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(e.e, 4096), GHTTP_OK);
  EXPECT_EQ(hex(e.field(":method", "GET")), "82");
}

TEST(HpackEncoder, ThePeersSizeIsCappedAtTheEncodersOwnLimit) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_table_size = 256;
  Enc e(256, &lim);
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(e.e, 1u << 30), GHTTP_OK);
  EXPECT_EQ(ghttp_hpack_encoder_table_max(e.e), 256u);
  EXPECT_EQ(hex(e.field(":method", "GET")), "82") << "no change, so no update";
}

TEST(HpackEncoder, AnEncoderCappedBelowThePeersTableAnnouncesTheCapInItsFirstBlock) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_table_size = 100;
  Enc e(4096, &lim);  // the peer is assumed to have the default 4096
  EXPECT_EQ(hex(e.field(":method", "GET")), "3f45" "82");
  EXPECT_EQ(ghttp_hpack_encoder_table_max(e.e), 100u);
  Dec d;  // an ordinary decoder, at 4096
  Enc e2(4096, &lim);
  List l;
  std::string first = e2.field("x-a", "1");  // (operands of + are unordered)
  std::string second = e2.field("x-b", "2");
  ASSERT_EQ(d.decode(first + second, &l), GHTTP_OK);
  EXPECT_EQ(ghttp_hpack_decoder_table_max(d.d), 100u);
}

TEST(HpackEncoder, CredentialFieldsAreNeverIndexed) {
  Enc e;
  // 0x10 | (name index 23 = authorization) with prefix 4: 0x1f 0x08 (23-15=8).
  std::string out = e.field("authorization", "secret", GHTTP_HPACK_INDEX_SAFE,
      GHTTP_HPACK_HUFFMAN_NEVER);
  EXPECT_EQ(hex(out).substr(0, 4), "1f08");
  EXPECT_EQ(ghttp_hpack_encoder_table_count(e.e), 0u);
  std::string ck = e.field("cookie", "a=b", GHTTP_HPACK_INDEX_SAFE,
      GHTTP_HPACK_HUFFMAN_NEVER);
  EXPECT_EQ(ck[0] & 0xf0, 0x10);
  EXPECT_EQ(ghttp_hpack_encoder_table_count(e.e), 0u);
}

TEST(HpackEncoder, HuffmanAutoUsesItUnlessItIsLonger) {
  Enc e;
  // "~~~" is 3 x 13 bits = 5 octets Huffman-coded: longer than the 3 plain.
  std::string a = e.field("n", "~~~", GHTTP_HPACK_INDEX_NONE, GHTTP_HPACK_HUFFMAN_AUTO);
  EXPECT_EQ(static_cast<uint8_t>(a[a.size() - 4]) & 0x80, 0) << hex(a);
  // "aaaa" is 4 x 5 bits = 3 octets: shorter, so coded.
  std::string b = e.field("n", "aaaa", GHTTP_HPACK_INDEX_NONE, GHTTP_HPACK_HUFFMAN_AUTO);
  EXPECT_NE(static_cast<uint8_t>(b[b.size() - 4]) & 0x80, 0) << hex(b);
}

TEST(HpackEncoder, EncodeOfAWholeListRestoresTheBufferWhenItFails) {
  FailingAllocator fa(static_cast<size_t>(-1));
  GHTTP_HpackEncoder * e;
  ASSERT_EQ(ghttp_hpack_encoder_create(fa.get(), nullptr, 4096, &e), GHTTP_OK);
  GHTTP_Headers * h;
  ASSERT_EQ(ghttp_headers_create(nullptr, &h), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(h, "a", "1"), GHTTP_OK);
  GHTTP_Buffer * b;
  ASSERT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
  ASSERT_EQ(ghttp_buffer_append(b, "xy", 2), GHTTP_OK);
  ghttp_hpack_encoder_destroy(e);
  ghttp_headers_destroy(h);
  ghttp_buffer_destroy(b);
  EXPECT_EQ(fa.live(), 0u);
}

// ---- Round trip: any list the encoder writes the decoder reads back --------

TEST(HpackRoundTrip, RandomListsAcrossManyBlocksKeepBothTablesIdentical) {
  std::mt19937 rng(7);
  for (size_t table : {size_t(4096), size_t(256), size_t(0), size_t(64)}) {
    Enc enc(table);
    Dec dec(table);
    const char * names[] = {"host", "date", "cache-control", "x-a", "x-b",
        "cookie", "content-length", "accept-encoding"};
    for (int block = 0; block < 200; block++) {
      GHTTP_Headers * h;
      ASSERT_EQ(ghttp_headers_create(nullptr, &h), GHTTP_OK);
      List want;
      int n = 1 + static_cast<int>(rng() % 6);
      for (int i = 0; i < n; i++) {
        std::string name = names[rng() % 8];
        std::string value;
        size_t len = rng() % 40;
        for (size_t k = 0; k < len; k++) {
          value.push_back(static_cast<char>(0x20 + rng() % 95));
        }
        if (rng() % 4 == 0) value = "GET";
        // No leading or trailing blank: the Headers type trims.
        while (!value.empty() && value.back() == ' ') value.pop_back();
        while (!value.empty() && value.front() == ' ') value.erase(0, 1);
        ASSERT_EQ(ghttp_headers_add(h, name.c_str(), value.c_str()), GHTTP_OK);
        want.emplace_back(name, value);
      }
      GHTTP_Buffer * b;
      ASSERT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
      ASSERT_EQ(ghttp_hpack_encode(enc.e, h, b), GHTTP_OK);
      std::string bytes(static_cast<const char *>(ghttp_buffer_data(b)),
          ghttp_buffer_size(b));
      List got;
      ASSERT_EQ(dec.decode(bytes, &got), GHTTP_OK) << block;
      ASSERT_EQ(got, want) << "block " << block << " table " << table;
      ASSERT_EQ(table_of_decoder(dec.d), table_of_encoder(enc.e));
      ASSERT_EQ(ghttp_hpack_decoder_table_size(dec.d),
          ghttp_hpack_encoder_table_size(enc.e));
      ghttp_buffer_destroy(b);
      ghttp_headers_destroy(h);
    }
  }
}

TEST(HpackRoundTrip, ATableResizeMidStreamKeepsBothSidesInStep) {
  Enc enc;
  Dec dec;
  List got;
  auto send = [&](const std::string & n, const std::string & v) {
    std::string b = enc.field(n, v);
    ASSERT_EQ(dec.decode(b, &got), GHTTP_OK);
    ASSERT_EQ(got, (List{{n, v}}));
  };
  send("x-a", "1");
  send("x-b", "2");
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(enc.e, 40), GHTTP_OK);
  send("x-c", "3");
  EXPECT_EQ(table_of_decoder(dec.d), table_of_encoder(enc.e));
  ASSERT_EQ(ghttp_hpack_encoder_set_peer_table_size(enc.e, 4096), GHTTP_OK);
  send("x-d", "4");
  send("x-e", "5");
  EXPECT_EQ(table_of_decoder(dec.d), table_of_encoder(enc.e));
  EXPECT_EQ(ghttp_hpack_decoder_table_count(dec.d), 3u);
}

// ---- Allocation failure ----------------------------------------------------

TEST(HpackOom, DecodingWithAnAllocatorFailingAtEveryPointIsOomOrTheSameAnswer) {
  std::string block = unhex(rfc_examples()[11].hex);  // C.4.3-ish: a long one
  std::string all;
  for (const RfcExample & e : rfc_examples()) {
    if (std::string(e.id) == "C.4.1" || std::string(e.id) == "C.4.2"
        || std::string(e.id) == "C.4.3") {
      all += std::string(1, '\0');  // separators are not used; see below
    }
  }
  std::vector<std::string> blocks;
  for (const RfcExample & e : rfc_examples()) {
    if (e.id[2] == '4') blocks.push_back(unhex(e.hex));
  }
  ASSERT_EQ(blocks.size(), 3u);
  auto run_all = [&](const GHTTP_Allocator * a, List * last) -> GHTTP_Result {
    GHTTP_HpackDecoder * d = nullptr;
    GHTTP_Result r = ghttp_hpack_decoder_create(a, nullptr, 4096, &d);
    if (r != GHTTP_OK) return r;
    for (auto & b : blocks) {
      GHTTP_Headers * h = nullptr;
      EXPECT_EQ(ghttp_headers_create(nullptr, &h), GHTTP_OK);
      r = ghttp_hpack_decode(d, b.data(), b.size(), h);
      if (last) *last = list_of(h);
      ghttp_headers_destroy(h);
      if (r != GHTTP_OK) break;
    }
    ghttp_hpack_decoder_destroy(d);
    return r;
  };
  List expected;
  FailingAllocator count(static_cast<size_t>(-1));
  ASSERT_EQ(run_all(count.get(), &expected), GHTTP_OK);
  ASSERT_EQ(count.live(), 0u);
  for (size_t run : {size_t(1), size_t(0), size_t(2)}) {
    for (size_t k = 0; k <= count.requests(); k++) {
      FailingAllocator fa(k, run);
      List got;
      GHTTP_Result r = run_all(fa.get(), &got);
      if (fa.failed()) {
        EXPECT_TRUE(r == GHTTP_ERR_OOM || r == GHTTP_OK) << k;
      } else {
        EXPECT_EQ(r, GHTTP_OK);
        EXPECT_EQ(got, expected);
      }
      EXPECT_EQ(fa.live(), 0u) << "leak at " << k << " run " << run;
    }
  }
}

TEST(HpackOom, EncodingWithAnAllocatorFailingAtEveryPointIsOomAndNeverALeak) {
  auto run_all = [&](const GHTTP_Allocator * a, std::string * out) -> GHTTP_Result {
    GHTTP_HpackEncoder * e = nullptr;
    GHTTP_Result r = ghttp_hpack_encoder_create(a, nullptr, 4096, &e);
    if (r != GHTTP_OK) return r;
    GHTTP_Buffer * b = nullptr;
    EXPECT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
    for (const RfcExample & ex : rfc_examples()) {
      if (ex.id[2] != '4') continue;
      for (auto & f : ex.list) {
        r = ghttp_hpack_encode_field(e, f.first, strlen(f.first), f.second,
            strlen(f.second), GHTTP_HPACK_INDEX_AUTO, GHTTP_HPACK_HUFFMAN_AUTO, b);
        if (r != GHTTP_OK) goto done;
      }
    }
  done:
    if (out) {
      out->assign(static_cast<const char *>(ghttp_buffer_data(b)), ghttp_buffer_size(b));
    }
    ghttp_buffer_destroy(b);
    ghttp_hpack_encoder_destroy(e);
    return r;
  };
  std::string expected;
  FailingAllocator count(static_cast<size_t>(-1));
  ASSERT_EQ(run_all(count.get(), &expected), GHTTP_OK);
  ASSERT_EQ(count.live(), 0u);
  for (size_t run : {size_t(1), size_t(0), size_t(2)}) {
    for (size_t k = 0; k <= count.requests(); k++) {
      FailingAllocator fa(k, run);
      std::string got;
      GHTTP_Result r = run_all(fa.get(), &got);
      if (fa.failed()) {
        EXPECT_TRUE(r == GHTTP_ERR_OOM || r == GHTTP_OK);
      } else {
        EXPECT_EQ(r, GHTTP_OK);
        EXPECT_EQ(got, expected);
      }
      EXPECT_EQ(fa.live(), 0u) << k;
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
