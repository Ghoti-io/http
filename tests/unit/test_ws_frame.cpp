/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io HTTP.
 *
 * Ghoti.io HTTP is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io HTTP is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * WebSocket frame headers, masking, UTF-8 and close codes: RFC 6455 sections
 * 5.2, 5.3, 5.5, 7.4 and 8.1. The expected octets are written out from the
 * RFC, not produced by the code under test.
 */

#include <cstring>
#include <string>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "ws_helpers.h"

using namespace ghttptest;

namespace {

GHTTP_Result parse(const std::string & s, GHTTP_WsFrameHeader * h, size_t * used) {
  return ghttp_ws_frame_header_parse(s.data(), s.size(), h, used);
}

std::string hex(const uint8_t * p, size_t n) {
  static const char * d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}

} // namespace

// ---- The header: section 5.2 --------------------------------------------------

TEST(WsFrameHeader, ASmallUnmaskedTextFrameIsTwoOctets) {
  // Section 5.7: "a single-frame unmasked text message" is 0x81 0x05 "Hello".
  GHTTP_WsFrameHeader h;
  size_t used = 99;
  ASSERT_EQ(parse(std::string("\x81\x05Hello", 7), &h, &used), GHTTP_OK);
  EXPECT_EQ(used, 2u);
  EXPECT_TRUE(h.fin);
  EXPECT_EQ(h.opcode, GHTTP_WS_OP_TEXT);
  EXPECT_FALSE(h.masked);
  EXPECT_EQ(h.payload_len, 5u);
  EXPECT_EQ(h.header_len, 2u);
}

TEST(WsFrameHeader, AMaskedFrameCarriesItsKey) {
  // Section 5.7: the masked "Hello" is 0x81 0x85 37 fa 21 3d 7f 9f 4d 51 58.
  GHTTP_WsFrameHeader h;
  size_t used;
  std::string wire("\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", 11);
  ASSERT_EQ(parse(wire, &h, &used), GHTTP_OK);
  EXPECT_EQ(used, 6u);
  EXPECT_TRUE(h.masked);
  EXPECT_EQ(hex(h.mask_key, 4), "37fa213d");
  EXPECT_EQ(h.payload_len, 5u);
}

TEST(WsFrameHeader, TheThreeLengthEncodingsMeetAtTheirBoundaries) {
  struct Case { uint64_t len; size_t header; };
  for (Case c : {Case{0, 2}, Case{125, 2}, Case{126, 4}, Case{65535, 4}, Case{65536, 10},
           Case{(uint64_t)1 << 40, 10}}) {
    std::string wire = wsf_header_only(GHTTP_WS_OP_BINARY, c.len, true, false);
    GHTTP_WsFrameHeader h;
    size_t used;
    ASSERT_EQ(parse(wire, &h, &used), GHTTP_OK) << c.len;
    EXPECT_EQ(used, c.header) << c.len;
    EXPECT_EQ(h.payload_len, c.len);
    // And the writer produces exactly those octets.
    uint8_t out[GHTTP_WS_MAX_HEADER_LEN];
    size_t n;
    ASSERT_EQ(ghttp_ws_frame_header_write(&h, out, &n), GHTTP_OK);
    EXPECT_EQ(std::string(reinterpret_cast<char *>(out), n), wire) << c.len;
  }
}

TEST(WsFrameHeader, ALengthNotInItsShortestEncodingIsRefused) {
  GHTTP_WsFrameHeader h;
  size_t used;
  // 5 in the 16-bit form; 125 in the 16-bit form; 65535 in the 64-bit form.
  EXPECT_EQ(parse(wsf(2, std::string(5, 'x'), true, false, 0, 0, 16), &h, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(parse(wsf(2, std::string(125, 'x'), true, false, 0, 0, 16), &h, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(parse(wsf(2, std::string(65535, 'x'), true, false, 0, 0, 64), &h, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(parse(wsf(2, std::string(126, 'x'), true, false, 0, 0, 16), &h, &used), GHTTP_OK);
  EXPECT_EQ(parse(wsf(2, std::string(65536, 'x'), true, false, 0, 0, 64), &h, &used), GHTTP_OK);
}

TEST(WsFrameHeader, ASixtyFourBitLengthWithTheTopBitSetIsRefused) {
  GHTTP_WsFrameHeader h;
  size_t used;
  std::string wire("\x82\x7f\x80\x00\x00\x00\x00\x01\x00\x00", 10);
  EXPECT_EQ(parse(wire, &h, &used), GHTTP_ERR_CORRUPT);
  // The top bit is refused as soon as it is seen, whatever follows.
  EXPECT_EQ(parse(std::string("\x82\x7f\x80", 3), &h, &used), GHTTP_ERR_CORRUPT);
}

TEST(WsFrameHeader, ControlFramesAreFinalAndAtMost125Octets) {
  GHTTP_WsFrameHeader h;
  size_t used;
  for (int op : {8, 9, 10}) {
    EXPECT_EQ(parse(wsf_header_only(op, 125, true, false), &h, &used), GHTTP_OK) << op;
    EXPECT_EQ(parse(wsf_header_only(op, 126, true, false), &h, &used), GHTTP_ERR_CORRUPT) << op;
    EXPECT_EQ(parse(wsf_header_only(op, 5, false, false), &h, &used), GHTTP_ERR_CORRUPT) << op;
  }
}

TEST(WsFrameHeader, UndefinedOpcodesAreRefused) {
  GHTTP_WsFrameHeader h;
  size_t used;
  for (int op : {3, 4, 5, 6, 7, 11, 12, 13, 14, 15}) {
    std::string wire;
    wire.push_back(static_cast<char>(0x80 | op));
    wire.push_back(0);
    EXPECT_EQ(parse(wire, &h, &used), GHTTP_ERR_CORRUPT) << op;
    EXPECT_EQ(ghttp_ws_opcode_is_defined(static_cast<uint8_t>(op)), 0) << op;
  }
  for (int op : {0, 1, 2, 8, 9, 10}) EXPECT_EQ(ghttp_ws_opcode_is_defined(static_cast<uint8_t>(op)), 1) << op;
}

TEST(WsFrameHeader, ARefusalIsDecidedAtTheOctetThatDecidesIt) {
  // Never on how much was offered: an undefined opcode is known from one
  // octet, a long control frame from two, a non-minimal length from four.
  GHTTP_WsFrameHeader h;
  size_t used;
  EXPECT_EQ(parse(std::string("\x83", 1), &h, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(parse(std::string("\x09", 1), &h, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(parse(std::string("\x89\x7e", 2), &h, &used), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(parse(std::string("\x82\x7e\x00\x05", 4), &h, &used), GHTTP_ERR_CORRUPT);
  // And a good prefix is "not yet", with nothing used.
  for (const char * prefix : {"", "\x82", "\x82\x7e", "\x82\x7e\x01", "\x82\x7f\x00\x00", "\x82\x85\x01\x02"}) {
    std::string pre(prefix);
    ASSERT_EQ(parse(pre, &h, &used), GHTTP_OK);
    EXPECT_EQ(used, 0u) << pre.size();
  }
}

TEST(WsFrameHeader, ReservedBitsAreReportedForTheConnectionToJudge) {
  GHTTP_WsFrameHeader h;
  size_t used;
  ASSERT_EQ(parse(wsf(1, "", true, false, 5), &h, &used), GHTTP_OK);
  EXPECT_TRUE(h.rsv1);
  EXPECT_FALSE(h.rsv2);
  EXPECT_TRUE(h.rsv3);
}

TEST(WsFrameHeader, TheWriterRefusesWhatTheParserWould) {
  GHTTP_WsFrameHeader h;
  memset(&h, 0, sizeof(h));
  uint8_t out[GHTTP_WS_MAX_HEADER_LEN];
  size_t n;
  h.fin = 1;
  h.opcode = 3;
  EXPECT_EQ(ghttp_ws_frame_header_write(&h, out, &n), GHTTP_ERR_INVALID);
  h.opcode = GHTTP_WS_OP_PING;
  h.payload_len = 126;
  EXPECT_EQ(ghttp_ws_frame_header_write(&h, out, &n), GHTTP_ERR_INVALID);
  h.payload_len = 5;
  h.fin = 0;
  EXPECT_EQ(ghttp_ws_frame_header_write(&h, out, &n), GHTTP_ERR_INVALID);
  h.opcode = GHTTP_WS_OP_BINARY;
  h.payload_len = (uint64_t)1 << 63;
  EXPECT_EQ(ghttp_ws_frame_header_write(&h, out, &n), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_frame_header_write(nullptr, out, &n), GHTTP_ERR_INVALID);
}

TEST(WsFrameHeader, NullArgumentsAreInvalid) {
  GHTTP_WsFrameHeader h;
  size_t used;
  EXPECT_EQ(ghttp_ws_frame_header_parse(nullptr, 0, &h, &used), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_frame_header_parse("a", 1, nullptr, &used), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_frame_header_parse("a", 1, &h, nullptr), GHTTP_ERR_INVALID);
}

// ---- Masking: section 5.3 ---------------------------------------------------

TEST(WsMask, TheRfcExampleUnmasksToHello) {
  uint8_t key[4] = {0x37, 0xfa, 0x21, 0x3d};
  uint8_t data[5] = {0x7f, 0x9f, 0x4d, 0x51, 0x58};
  ghttp_ws_mask(data, 5, key, 0);
  EXPECT_EQ(std::string(reinterpret_cast<char *>(data), 5), "Hello");
}

TEST(WsMask, MaskingIsItsOwnInverseAtEveryLengthAndOffset) {
  uint8_t key[4] = {0x12, 0x34, 0x56, 0x78};
  std::string plain = ws_random_bytes(300);
  for (size_t len : {0u, 1u, 2u, 3u, 4u, 5u, 7u, 8u, 9u, 63u, 64u, 300u}) {
    for (uint64_t off : {0u, 1u, 2u, 3u, 4u, 7u}) {
      std::string d = plain.substr(0, len);
      ghttp_ws_mask(d.data(), d.size(), key, off);
      for (size_t i = 0; i < len; i++) {
        EXPECT_EQ(static_cast<uint8_t>(d[i]), static_cast<uint8_t>(plain[i] ^ key[(off + i) % 4]))
            << len << " " << off << " " << i;
      }
      ghttp_ws_mask(d.data(), d.size(), key, off);
      EXPECT_EQ(d, plain.substr(0, len));
    }
  }
}

TEST(WsMask, AMaskedInPiecesGivesTheWholesResult) {
  uint8_t key[4] = {0xde, 0xad, 0xbe, 0xef};
  std::string whole = ws_random_bytes(101);
  std::string pieces = whole;
  ghttp_ws_mask(whole.data(), whole.size(), key, 0);
  size_t off = 0;
  for (size_t step : {1u, 2u, 3u, 5u, 17u, 73u}) {
    size_t n = std::min(step, pieces.size() - off);
    ghttp_ws_mask(pieces.data() + off, n, key, off);
    off += n;
  }
  EXPECT_EQ(pieces, whole);
}

TEST(WsMask, UnalignedBuffersGiveTheSameAnswer) {
  uint8_t key[4] = {1, 2, 3, 4};
  std::string base = ws_random_bytes(64);
  for (size_t shift = 0; shift < 8; shift++) {
    std::string buf(80, 'x');
    memcpy(&buf[shift], base.data(), base.size());
    ghttp_ws_mask(&buf[shift], base.size(), key, 0);
    std::string expect = base;
    for (size_t i = 0; i < expect.size(); i++) expect[i] = static_cast<char>(expect[i] ^ key[i % 4]);
    EXPECT_EQ(buf.substr(shift, base.size()), expect) << shift;
  }
}

// ---- UTF-8: section 8.1 and RFC 3629 -----------------------------------------

namespace {

bool valid_utf8(const std::string & s) {
  GHTTP_WsUtf8 v;
  ghttp_ws_utf8_init(&v);
  return ghttp_ws_utf8_feed(&v, s.data(), s.size()) == GHTTP_OK && ghttp_ws_utf8_complete(&v);
}

} // namespace

TEST(WsUtf8, ValidTextOfEveryLengthOfCodePointIsAccepted) {
  EXPECT_TRUE(valid_utf8(""));
  EXPECT_TRUE(valid_utf8("hello"));
  EXPECT_TRUE(valid_utf8("\x7f"));
  EXPECT_TRUE(valid_utf8("\xc2\x80"));              // U+0080
  EXPECT_TRUE(valid_utf8("\xdf\xbf"));              // U+07FF
  EXPECT_TRUE(valid_utf8("\xe0\xa0\x80"));          // U+0800
  EXPECT_TRUE(valid_utf8("\xed\x9f\xbf"));          // U+D7FF
  EXPECT_TRUE(valid_utf8("\xee\x80\x80"));          // U+E000
  EXPECT_TRUE(valid_utf8("\xef\xbf\xbd"));          // U+FFFD
  EXPECT_TRUE(valid_utf8("\xf0\x90\x80\x80"));      // U+10000
  EXPECT_TRUE(valid_utf8("\xf4\x8f\xbf\xbf"));      // U+10FFFF
  EXPECT_TRUE(valid_utf8("\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5"));  // the Autobahn "kosme"
}

TEST(WsUtf8, EveryInvalidFormTheStandardNamesIsRefused) {
  EXPECT_FALSE(valid_utf8("\x80"));                 // a continuation with no lead
  EXPECT_FALSE(valid_utf8("\xbf"));
  EXPECT_FALSE(valid_utf8("\xc0\x80"));             // overlong NUL
  EXPECT_FALSE(valid_utf8("\xc1\xbf"));             // overlong
  EXPECT_FALSE(valid_utf8("\xe0\x80\x80"));         // overlong
  EXPECT_FALSE(valid_utf8("\xe0\x9f\xbf"));
  EXPECT_FALSE(valid_utf8("\xf0\x80\x80\x80"));     // overlong
  EXPECT_FALSE(valid_utf8("\xf0\x8f\xbf\xbf"));
  EXPECT_FALSE(valid_utf8("\xed\xa0\x80"));         // U+D800, a surrogate
  EXPECT_FALSE(valid_utf8("\xed\xbf\xbf"));         // U+DFFF
  EXPECT_FALSE(valid_utf8("\xf4\x90\x80\x80"));     // U+110000
  EXPECT_FALSE(valid_utf8("\xf5\x80\x80\x80"));
  EXPECT_FALSE(valid_utf8("\xf8\x88\x80\x80\x80")); // five octets
  EXPECT_FALSE(valid_utf8("\xfe"));
  EXPECT_FALSE(valid_utf8("\xff"));
  EXPECT_FALSE(valid_utf8("\xc2"));                 // truncated: not complete
  EXPECT_FALSE(valid_utf8("\xe2\x82"));
  EXPECT_FALSE(valid_utf8("\xc2\x41"));             // a lead followed by ASCII
  EXPECT_FALSE(valid_utf8("\xe2\x82\x41"));
}

TEST(WsUtf8, ACodePointMayBeCutAnywhereAndTheAnswerIsTheSame) {
  const std::string text = "a\xc2\x80" "b\xe2\x82\xac" "c\xf0\x9f\x98\x80" "d\xf4\x8f\xbf\xbf";
  for (size_t cut = 0; cut <= text.size(); cut++) {
    GHTTP_WsUtf8 v;
    ghttp_ws_utf8_init(&v);
    EXPECT_EQ(ghttp_ws_utf8_feed(&v, text.data(), cut), GHTTP_OK) << cut;
    EXPECT_EQ(ghttp_ws_utf8_feed(&v, text.data() + cut, text.size() - cut), GHTTP_OK) << cut;
    EXPECT_TRUE(ghttp_ws_utf8_complete(&v)) << cut;
  }
  // And a byte at a time, for a bad one: the same octet is the first refused.
  const std::string bad = "ab\xed\xa0\x80" "cd";
  GHTTP_WsUtf8 v;
  ghttp_ws_utf8_init(&v);
  size_t refused_at = bad.size();
  for (size_t i = 0; i < bad.size(); i++) {
    if (ghttp_ws_utf8_feed(&v, &bad[i], 1) != GHTTP_OK) {
      refused_at = i;
      break;
    }
  }
  EXPECT_EQ(refused_at, 3u);  // the A0 after ED, and not the end of the code point
}

TEST(WsUtf8, EveryScalarValueIsAcceptedAndEveryOtherSequenceOfOneToFourOctetsIsNot) {
  // The definition, checked exhaustively for the one- and two-octet forms and
  // sampled across the rest, against an independent encoder.
  auto encode = [](uint32_t cp, std::string * out) {
    out->clear();
    if (cp < 0x80) {
      out->push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out->push_back(static_cast<char>(0xc0 | (cp >> 6)));
      out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
      out->push_back(static_cast<char>(0xe0 | (cp >> 12)));
      out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
      out->push_back(static_cast<char>(0xf0 | (cp >> 18)));
      out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
      out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
  };
  std::string s;
  for (uint32_t cp = 0; cp <= 0x10ffff; cp++) {
    encode(cp, &s);
    bool surrogate = cp >= 0xd800 && cp <= 0xdfff;
    ASSERT_EQ(valid_utf8(s), !surrogate) << std::hex << cp;
  }
  // Every two-octet string of non-ASCII octets that is not a valid sequence.
  for (int a = 0x80; a < 0x100; a++) {
    for (int b = 0; b < 0x100; b++) {
      std::string two;
      two.push_back(static_cast<char>(a));
      two.push_back(static_cast<char>(b));
      bool ok = a >= 0xc2 && a <= 0xdf && b >= 0x80 && b <= 0xbf;
      ASSERT_EQ(valid_utf8(two), ok) << a << " " << b;
    }
  }
}

// ---- Close codes: section 7.4 -------------------------------------------------

TEST(WsCloseCode, TheCodesThatMayBeOnTheWireAreExactlyThoseTheRfcAndTheRegistryAllow) {
  for (int c : {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999}) {
    EXPECT_EQ(ghttp_ws_close_code_is_valid(static_cast<uint16_t>(c)), 1) << c;
  }
  for (int c : {0, 1, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535}) {
    EXPECT_EQ(ghttp_ws_close_code_is_valid(static_cast<uint16_t>(c)), 0) << c;
  }
}

TEST(WsLimits, TheDefaultsAreTheDocumentedOnes) {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  EXPECT_EQ(l.size, sizeof(l));
  EXPECT_EQ(l.max_frame_payload, GHTTP_WS_DEFAULT_MAX_FRAME_PAYLOAD);
  EXPECT_EQ(l.max_message_bytes, GHTTP_WS_DEFAULT_MAX_MESSAGE_BYTES);
  EXPECT_EQ(l.max_fragments, 1024u);
  EXPECT_EQ(l.max_control_per_interval, 128u);
  EXPECT_EQ(l.max_expansion_ratio, 1032u);
  ghttp_ws_limits_default(nullptr);  // must not crash
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
