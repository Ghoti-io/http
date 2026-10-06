/**
 * @file
 *
 * HTTP/2 frames (RFC 9113 sections 4 and 6): header coding, the validation
 * every frame type needs, and the writers.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <functional>
#include <memory>
#include <random>

#include "test_helpers.h"

using namespace ghttptest;

namespace {

std::string be32(uint32_t v) {
  std::string s;
  s.push_back(static_cast<char>(v >> 24));
  s.push_back(static_cast<char>(v >> 16));
  s.push_back(static_cast<char>(v >> 8));
  s.push_back(static_cast<char>(v));
  return s;
}

struct Parsed {
  GHTTP_Result r;
  GHTTP_H2Frame f;
  GHTTP_H2FrameError err;
  /** The frame refers into its payload, which must outlive it. */
  std::shared_ptr<std::string> keep;
};

Parsed parse(uint8_t type, uint8_t flags, uint32_t stream, const std::string & payload,
    size_t max = 16384) {
  Parsed p{};
  p.keep = std::make_shared<std::string>(payload);
  GHTTP_H2FrameHeader h{static_cast<uint32_t>(payload.size()), type, flags, stream};
  p.r = ghttp_h2_frame_parse(&h, reinterpret_cast<const uint8_t *>(p.keep->data()),
      max, &p.f, &p.err);
  return p;
}

std::string hexs(const std::string & s) {
  static const char * d = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s) {
    out.push_back(d[c >> 4]);
    out.push_back(d[c & 15]);
  }
  return out;
}

std::string written(const std::function<GHTTP_Result(GHTTP_Buffer *)> & f) {
  GHTTP_Buffer * b = nullptr;
  EXPECT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
  EXPECT_EQ(f(b), GHTTP_OK);
  std::string s(static_cast<const char *>(ghttp_buffer_data(b)), ghttp_buffer_size(b));
  ghttp_buffer_destroy(b);
  return s;
}

} // namespace

TEST(H2FrameHeader, RoundTripsAndDropsTheReservedBit_Rfc9113Section4_1) {
  std::mt19937 rng(3);
  for (int i = 0; i < 1000; i++) {
    GHTTP_H2FrameHeader h{static_cast<uint32_t>(rng() & 0xffffff),
        static_cast<uint8_t>(rng()), static_cast<uint8_t>(rng()),
        static_cast<uint32_t>(rng() & 0x7fffffff)};
    uint8_t b[9];
    ghttp_h2_frame_header_write(&h, b);
    GHTTP_H2FrameHeader g;
    ghttp_h2_frame_header_parse(b, &g);
    EXPECT_EQ(g.length, h.length);
    EXPECT_EQ(g.type, h.type);
    EXPECT_EQ(g.flags, h.flags);
    EXPECT_EQ(g.stream_id, h.stream_id);
  }
  // The reserved bit set on the wire is ignored on receipt.
  const uint8_t wire[9] = {0, 0, 4, 8, 0, 0x80, 0, 0, 1};
  GHTTP_H2FrameHeader g;
  ghttp_h2_frame_header_parse(wire, &g);
  EXPECT_EQ(g.stream_id, 1u);
  // And is zero on writing, whatever the caller put in the field.
  GHTTP_H2FrameHeader h{0, 0, 0, 0xffffffffu};
  uint8_t b[9];
  ghttp_h2_frame_header_write(&h, b);
  EXPECT_EQ(b[5] & 0x80, 0);
}

TEST(H2FrameHeader, NamesForTypesAndErrorCodes) {
  EXPECT_STREQ(ghttp_h2_frame_type_string(GHTTP_H2_CONTINUATION), "CONTINUATION");
  EXPECT_STREQ(ghttp_h2_frame_type_string(0xee), "UNKNOWN");
  EXPECT_STREQ(ghttp_h2_error_string(GHTTP_H2_ENHANCE_YOUR_CALM), "ENHANCE_YOUR_CALM");
  EXPECT_STREQ(ghttp_h2_error_string(0x99), "UNKNOWN");
  for (uint32_t c = 0; c <= 0xd; c++) {
    EXPECT_STRNE(ghttp_h2_error_string(c), "UNKNOWN") << c;
  }
  for (uint8_t t = 0; t <= 9; t++) {
    EXPECT_STRNE(ghttp_h2_frame_type_string(t), "UNKNOWN") << int(t);
  }
}

namespace {

struct Bad {
  const char * what;
  uint8_t type;
  uint8_t flags;
  uint32_t stream;
  std::string payload;
  uint32_t code;
  bool connection;
};

} // namespace

TEST(H2FrameParse, EveryFrameThatIsWrongCarriesTheErrorTheRfcNames) {
  const uint32_t P = GHTTP_H2_PROTOCOL_ERROR, S = GHTTP_H2_FRAME_SIZE_ERROR;
  const std::vector<Bad> bad = {
    {"6.1 DATA on stream 0", GHTTP_H2_DATA, 0, 0, "x", P, true},
    {"6.1 PADDED DATA with no Pad Length", GHTTP_H2_DATA, 8, 1, "", S, true},
    {"6.1 padding as long as the payload", GHTTP_H2_DATA, 8, 1, std::string("\x05" "abcd", 5), P, true},
    {"6.1 padding longer than the payload", GHTTP_H2_DATA, 8, 1, std::string("\xff" "ab", 3), P, true},
    {"6.2 HEADERS on stream 0", GHTTP_H2_HEADERS, 4, 0, "x", P, true},
    {"6.2 PRIORITY flag, payload under 5", GHTTP_H2_HEADERS, 0x24, 1, "abcd", S, true},
    {"6.2 PADDED and PRIORITY, payload under 6", GHTTP_H2_HEADERS, 0x2c, 1, "abcde", S, true},
    {"6.2 padding over the fragment", GHTTP_H2_HEADERS, 0x0c, 1, std::string("\x02" "a", 2), P, true},
    {"6.3 PRIORITY on stream 0", GHTTP_H2_PRIORITY, 0, 0, std::string(5, 'x'), P, true},
    {"6.3 PRIORITY of 4 octets is a stream error", GHTTP_H2_PRIORITY, 0, 3, "abcd", S, false},
    {"6.3 PRIORITY of 6 octets is a stream error", GHTTP_H2_PRIORITY, 0, 3, "abcdef", S, false},
    {"6.4 RST_STREAM on stream 0", GHTTP_H2_RST_STREAM, 0, 0, "abcd", P, true},
    {"6.4 RST_STREAM of 5 octets", GHTTP_H2_RST_STREAM, 0, 1, "abcde", S, true},
    {"6.4 RST_STREAM of 3 octets", GHTTP_H2_RST_STREAM, 0, 1, "abc", S, true},
    {"6.5 SETTINGS on a stream", GHTTP_H2_SETTINGS, 0, 1, "", P, true},
    {"6.5 SETTINGS ACK with a payload", GHTTP_H2_SETTINGS, 1, 0, std::string(6, 'x'), S, true},
    {"6.5 SETTINGS of 5 octets", GHTTP_H2_SETTINGS, 0, 0, "abcde", S, true},
    {"6.5 SETTINGS of 7 octets", GHTTP_H2_SETTINGS, 0, 0, "abcdefg", S, true},
    {"6.6 PUSH_PROMISE on stream 0", GHTTP_H2_PUSH_PROMISE, 4, 0, "abcd", P, true},
    {"6.6 PUSH_PROMISE under 4 octets", GHTTP_H2_PUSH_PROMISE, 4, 1, "abc", S, true},
    {"6.7 PING on a stream", GHTTP_H2_PING, 0, 1, std::string(8, 'x'), P, true},
    {"6.7 PING of 7 octets", GHTTP_H2_PING, 0, 0, std::string(7, 'x'), S, true},
    {"6.7 PING of 9 octets", GHTTP_H2_PING, 0, 0, std::string(9, 'x'), S, true},
    {"6.8 GOAWAY on a stream", GHTTP_H2_GOAWAY, 0, 1, std::string(8, 'x'), P, true},
    {"6.8 GOAWAY under 8 octets", GHTTP_H2_GOAWAY, 0, 0, std::string(7, 'x'), S, true},
    {"6.9 WINDOW_UPDATE of 3 octets", GHTTP_H2_WINDOW_UPDATE, 0, 0, "abc", S, true},
    {"6.9 WINDOW_UPDATE of 5 octets", GHTTP_H2_WINDOW_UPDATE, 0, 1, "abcde", S, true},
    {"6.9 zero increment on a stream is a stream error", GHTTP_H2_WINDOW_UPDATE, 0, 5, be32(0), P, false},
    {"6.9 zero increment on the connection", GHTTP_H2_WINDOW_UPDATE, 0, 0, be32(0), P, true},
    {"6.9 the reserved bit alone is a zero increment", GHTTP_H2_WINDOW_UPDATE, 0, 0, be32(0x80000000u), P, true},
    {"6.10 CONTINUATION on stream 0", GHTTP_H2_CONTINUATION, 4, 0, "a", P, true},
  };
  for (const Bad & b : bad) {
    Parsed p = parse(b.type, b.flags, b.stream, b.payload);
    EXPECT_EQ(p.r, GHTTP_ERR_CORRUPT) << b.what;
    EXPECT_EQ(p.err.code, b.code) << b.what << ": "
        << ghttp_h2_error_string(p.err.code);
    EXPECT_EQ(p.err.connection != 0, b.connection) << b.what;
    if (!b.connection) {
      EXPECT_EQ(p.err.stream_id, b.stream) << b.what;
    }
  }
}

TEST(H2FrameParse, ALengthOverTheLimitIsAFrameSizeErrorOfTheConnection_Rfc9113Section4_2) {
  Parsed p = parse(GHTTP_H2_DATA, 0, 1, std::string(100, 'x'), 99);
  EXPECT_EQ(p.r, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(p.err.code, GHTTP_H2_FRAME_SIZE_ERROR);
  EXPECT_TRUE(p.err.connection);
  EXPECT_EQ(parse(GHTTP_H2_DATA, 0, 1, std::string(99, 'x'), 99).r, GHTTP_OK);
  // The header alone shows it, so a payload need not be buffered first.
  GHTTP_H2FrameHeader h{20000, GHTTP_H2_DATA, 0, 1};
  GHTTP_H2FrameError err;
  EXPECT_EQ(ghttp_h2_frame_header_check(&h, 16384, &err), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(err.code, GHTTP_H2_FRAME_SIZE_ERROR);
  EXPECT_EQ(ghttp_h2_frame_header_check(&h, 20000, &err), GHTTP_OK);
}

TEST(H2FrameParse, DataIsReturnedWithoutItsPadding) {
  Parsed p = parse(GHTTP_H2_DATA, GHTTP_H2_FLAG_PADDED | GHTTP_H2_FLAG_END_STREAM, 3,
      std::string("\x03" "hello" "\0\0\0", 9));
  ASSERT_EQ(p.r, GHTTP_OK);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(p.f.data), p.f.data_len), "hello");
  EXPECT_EQ(p.f.padding, 4u) << "the Pad Length field and the padding";
  EXPECT_TRUE(p.f.end_stream);
  Parsed q = parse(GHTTP_H2_DATA, GHTTP_H2_FLAG_PADDED, 3, std::string("\x00", 1));
  ASSERT_EQ(q.r, GHTTP_OK) << "a Pad Length of zero is legal and the data empty";
  EXPECT_EQ(q.f.data_len, 0u);
}

TEST(H2FrameParse, HeadersCarriesPaddingPriorityAndTheFragment) {
  std::string payload;
  payload.push_back(2);                                   // Pad Length
  payload += be32(0x80000007u);                           // exclusive, depends on 7
  payload.push_back(static_cast<char>(200));              // weight - 1
  payload += "FRAG";
  payload += std::string(2, '\0');
  Parsed p = parse(GHTTP_H2_HEADERS,
      GHTTP_H2_FLAG_PADDED | GHTTP_H2_FLAG_PRIORITY | GHTTP_H2_FLAG_END_HEADERS
          | GHTTP_H2_FLAG_END_STREAM,
      9, payload);
  ASSERT_EQ(p.r, GHTTP_OK);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(p.f.data), p.f.data_len), "FRAG");
  EXPECT_TRUE(p.f.has_priority);
  EXPECT_TRUE(p.f.priority.exclusive);
  EXPECT_EQ(p.f.priority.dependency, 7u);
  EXPECT_EQ(p.f.priority.weight, 200);
  EXPECT_TRUE(p.f.end_headers);
  EXPECT_TRUE(p.f.end_stream);
}

TEST(H2FrameParse, SettingsEntriesAreReadInOrder) {
  std::string payload;
  payload += std::string("\x00\x03", 2) + be32(100);
  payload += std::string("\x00\x04", 2) + be32(65535);
  payload += std::string("\xff\xee", 2) + be32(7);
  Parsed p = parse(GHTTP_H2_SETTINGS, 0, 0, payload);
  ASSERT_EQ(p.r, GHTTP_OK);
  ASSERT_EQ(p.f.settings_count, 3u);
  uint16_t id;
  uint32_t v;
  ASSERT_EQ(ghttp_h2_frame_setting_at(&p.f, 2, &id, &v), GHTTP_OK);
  EXPECT_EQ(id, 0xffee);
  EXPECT_EQ(v, 7u);
  EXPECT_EQ(ghttp_h2_frame_setting_at(&p.f, 3, &id, &v), GHTTP_ERR_INVALID);
  Parsed ack = parse(GHTTP_H2_SETTINGS, GHTTP_H2_FLAG_ACK, 0, "");
  ASSERT_EQ(ack.r, GHTTP_OK);
  EXPECT_TRUE(ack.f.ack);
  EXPECT_EQ(parse(GHTTP_H2_SETTINGS, 0, 0, "").f.settings_count, 0u);
}

TEST(H2FrameParse, GoawayPingWindowUpdateAndRstCarryTheirFields) {
  Parsed g = parse(GHTTP_H2_GOAWAY, 0, 0, be32(0x80000009u) + be32(11) + "dbg");
  ASSERT_EQ(g.r, GHTTP_OK);
  EXPECT_EQ(g.f.last_stream_id, 9u) << "the reserved bit is dropped";
  EXPECT_EQ(g.f.error_code, 11u);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(g.f.data), g.f.data_len), "dbg");
  Parsed w = parse(GHTTP_H2_WINDOW_UPDATE, 0, 3, be32(0x80001234u));
  ASSERT_EQ(w.r, GHTTP_OK);
  EXPECT_EQ(w.f.increment, 0x1234u);
  Parsed r = parse(GHTTP_H2_RST_STREAM, 0, 3, be32(8));
  ASSERT_EQ(r.r, GHTTP_OK);
  EXPECT_EQ(r.f.error_code, 8u);
  Parsed pg = parse(GHTTP_H2_PING, GHTTP_H2_FLAG_ACK, 0, "12345678");
  ASSERT_EQ(pg.r, GHTTP_OK);
  EXPECT_TRUE(pg.f.ack);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(pg.f.ping), 8), "12345678");
  Parsed pp = parse(GHTTP_H2_PUSH_PROMISE, GHTTP_H2_FLAG_END_HEADERS, 1,
      be32(0x80000002u) + "blk");
  ASSERT_EQ(pp.r, GHTTP_OK);
  EXPECT_EQ(pp.f.promised_stream_id, 2u);
  Parsed pr = parse(GHTTP_H2_PRIORITY, 0, 1, be32(3) + std::string("\x10", 1));
  ASSERT_EQ(pr.r, GHTTP_OK);
  EXPECT_EQ(pr.f.priority.dependency, 3u);
  EXPECT_EQ(pr.f.priority.weight, 0x10);
}

TEST(H2FrameParse, AnUnknownTypeIsAcceptedWholeAndUnknownFlagsAreIgnored_Rfc9113Section4_1_5_5) {
  Parsed p = parse(0xee, 0xff, 0, "payload");
  ASSERT_EQ(p.r, GHTTP_OK);
  EXPECT_FALSE(p.f.known);
  EXPECT_EQ(p.f.data_len, 7u);
  Parsed on_stream = parse(0xee, 0, 77, "");
  EXPECT_EQ(on_stream.r, GHTTP_OK) << "no rule about its stream: its semantics are unknown";
  Parsed d = parse(GHTTP_H2_DATA, 0xf6, 1, "x");  // none of END_STREAM or PADDED
  ASSERT_EQ(d.r, GHTTP_OK);
  EXPECT_FALSE(d.f.end_stream);
  EXPECT_EQ(d.f.data_len, 1u);
}

TEST(H2FrameWrite, EachFrameIsTheBytesTheRfcShows) {
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_data(b, 1, "abc", 3, 1, 0, 0);
  })), "000003" "00" "01" "00000001" "616263");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_data(b, 3, "ab", 2, 0, 1, 2);
  })), "000005" "00" "08" "00000003" "02" "6162" "0000");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_rst_stream(b, 5, 8);
  })), "000004" "03" "00" "00000005" "00000008");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_window_update(b, 0, 65535);
  })), "000004" "08" "00" "00000000" "0000ffff");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_ping(b, reinterpret_cast<const uint8_t *>("abcdefgh"), 1);
  })), "000008" "06" "01" "00000000" "6162636465666768");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_goaway(b, 7, 11, "no", 2);
  })), "00000a" "07" "00" "00000000" "00000007" "0000000b" "6e6f");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_settings(b, nullptr, nullptr, 0, 1);
  })), "000000" "04" "01" "00000000");
  uint16_t ids[] = {3, 4};
  uint32_t vals[] = {100, 65535};
  EXPECT_EQ(hexs(written([&](GHTTP_Buffer * b) {
    return ghttp_h2_write_settings(b, ids, vals, 2, 0);
  })), "00000c" "04" "00" "00000000" "0003" "00000064" "0004" "0000ffff");
  GHTTP_H2Priority pr{3, 1, 15};
  EXPECT_EQ(hexs(written([&](GHTTP_Buffer * b) {
    return ghttp_h2_write_priority(b, 1, &pr);
  })), "000005" "02" "00" "00000001" "80000003" "0f");
  EXPECT_EQ(hexs(written([](GHTTP_Buffer * b) {
    return ghttp_h2_write_frame(b, 0xee, 0x5, 9, "zz", 2);
  })), "000002" "ee" "05" "00000009" "7a7a");
}

TEST(H2FrameWrite, AHeaderBlockLargerThanTheFrameLimitContinues_Rfc9113Section6_2_6_10) {
  std::string block(40000, 'b');
  std::string out = written([&](GHTTP_Buffer * b) {
    return ghttp_h2_write_header_block(b, 7, block.data(), block.size(), 1, 16384);
  });
  // 16384 + 16384 + 7232
  ASSERT_EQ(out.size(), 40000u + 3 * 9);
  GHTTP_H2FrameHeader h;
  ghttp_h2_frame_header_parse(reinterpret_cast<const uint8_t *>(out.data()), &h);
  EXPECT_EQ(h.type, GHTTP_H2_HEADERS);
  EXPECT_EQ(h.length, 16384u);
  EXPECT_EQ(h.flags, GHTTP_H2_FLAG_END_STREAM) << "END_STREAM on HEADERS, no END_HEADERS yet";
  ghttp_h2_frame_header_parse(reinterpret_cast<const uint8_t *>(out.data()) + 9 + 16384, &h);
  EXPECT_EQ(h.type, GHTTP_H2_CONTINUATION);
  EXPECT_EQ(h.flags, 0);
  EXPECT_EQ(h.stream_id, 7u);
  ghttp_h2_frame_header_parse(
      reinterpret_cast<const uint8_t *>(out.data()) + 18 + 2 * 16384, &h);
  EXPECT_EQ(h.type, GHTTP_H2_CONTINUATION);
  EXPECT_EQ(h.length, 7232u);
  EXPECT_EQ(h.flags, GHTTP_H2_FLAG_END_HEADERS);
  // A block that fits is one HEADERS frame with END_HEADERS; an empty one too.
  std::string one = written([&](GHTTP_Buffer * b) {
    return ghttp_h2_write_header_block(b, 1, "abc", 3, 0, 16384);
  });
  EXPECT_EQ(hexs(one), "000003" "01" "04" "00000001" "616263");
  std::string none = written([&](GHTTP_Buffer * b) {
    return ghttp_h2_write_header_block(b, 1, nullptr, 0, 1, 16384);
  });
  EXPECT_EQ(hexs(none), "000000" "01" "05" "00000001");
  // A block of exactly the limit is one frame.
  std::string exact(16384, 'x');
  std::string e = written([&](GHTTP_Buffer * b) {
    return ghttp_h2_write_header_block(b, 1, exact.data(), exact.size(), 0, 16384);
  });
  EXPECT_EQ(e.size(), 16384u + 9);
}

TEST(H2FrameWrite, ArgumentsThatCannotBeFramedAreRefused) {
  GHTTP_Buffer * b;
  ASSERT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
  EXPECT_EQ(ghttp_h2_write_data(b, 0, "x", 1, 0, 0, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_data(b, 0x80000000u, "x", 1, 0, 0, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_rst_stream(b, 0, 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_window_update(b, 1, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_window_update(b, 1, 0x80000000u), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_header_block(b, 0, "x", 1, 0, 16384), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_header_block(b, 1, "x", 1, 0, 100), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_goaway(b, 0x80000000u, 0, nullptr, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_write_settings(b, nullptr, nullptr, 1, 1), GHTTP_ERR_INVALID);
  std::string huge(1u << 24, 'x');
  EXPECT_EQ(ghttp_h2_write_frame(b, 0xee, 0, 0, huge.data(), huge.size()), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_buffer_size(b), 0u) << "a refusal writes nothing";
  ghttp_buffer_destroy(b);
}

TEST(H2FrameWrite, AWriteThatFailsLeavesTheBufferAsItWas) {
  for (size_t k = 0; k < 8; k++) {
    for (size_t run : {size_t(1), size_t(0)}) {
      FailingAllocator fa(k, run);
      GHTTP_Buffer * b = nullptr;
      if (ghttp_buffer_create(fa.get(), &b) != GHTTP_OK) {
        continue;
      }
      if (ghttp_buffer_append(b, "pre", 3) != GHTTP_OK) {
        fa.stop_failing();
        ghttp_buffer_destroy(b);
        continue;
      }
      size_t before = ghttp_buffer_size(b);
      std::string big(20000, 'z');
      GHTTP_Result r = ghttp_h2_write_header_block(b, 1, big.data(), big.size(), 0, 16384);
      if (r != GHTTP_OK) {
        EXPECT_EQ(ghttp_buffer_size(b), before) << k;
        EXPECT_EQ(r, GHTTP_ERR_OOM);
      }
      fa.stop_failing();
      ghttp_buffer_destroy(b);
      EXPECT_EQ(fa.live(), 0u);
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
