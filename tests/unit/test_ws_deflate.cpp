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
 * permessage-deflate on a connection: RFC 7692 sections 7.2.1 to 7.2.3 and
 * the bounds this library puts on inflate. The compressed octets of the RFC's
 * examples are written out here; Autobahn|Testsuite cases 12 and 13 are the
 * round trips.
 */

#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"
#include "ws_helpers.h"
#include "../../src/http/ws_internal.h"

using namespace ghttptest;

namespace {

using Events = std::vector<WsEv>;

std::string bytes(std::initializer_list<int> l) {
  std::string s;
  for (int b : l) s.push_back(static_cast<char>(b));
  return s;
}

/** The payload of the first frame in a stream of output. */
WsFrame first_frame(const std::string & wire) {
  auto f = ws_parse_frames(wire);
  EXPECT_FALSE(f.empty());
  return f.empty() ? WsFrame{} : f[0];
}

/** What a sender wrote for a message of @p type, in a connection with @p neg. */
std::string sent(GHTTP_WsRole role, const GHTTP_WsNegotiated & neg, GHTTP_WsMessageType type,
    const std::string & msg, GHTTP_WsLimits * l = nullptr) {
  // Room enough for the largest message a test makes: the point is what was
  // written, not the queue's limit.
  GHTTP_WsLimits big;
  ghttp_ws_limits_default(&big);
  big.max_buffered_bytes = 64 << 20;
  big.max_message_bytes = 64 << 20;
  WsSide s(role, l ? l : &big, &neg);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), type, msg.data(), msg.size()), GHTTP_OK);
  return s.take_output();
}

GHTTP_WsLimits limits() {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  return l;
}

} // namespace

// ---- The RFC's own octets: section 7.2.3 --------------------------------------------------------------

TEST(WsDeflate, The_Hello_ExampleIsCompressedToTheRfcsOctetsAndTheirTrailerIsNotSent) {
  // RFC 7692 section 7.2.3.1: "Hello" is f2 48 cd c9 c9 07 00 on the wire.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsFrame f = first_frame(sent(GHTTP_WS_SERVER, neg, GHTTP_WS_MESSAGE_TEXT, "Hello"));
  EXPECT_EQ(f.payload, bytes({0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}));
  EXPECT_EQ(f.rsv, 4);  // RSV1
  EXPECT_TRUE(f.fin);
}

TEST(WsDeflate, TheRfcsCompressedHelloIsDecompressedWhenSentByAClientAndAServer) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  std::string payload = bytes({0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00});
  WsSide server(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun a = server.feed(wsf(1, payload, true, true, 4));
  EXPECT_EQ(a.events, (Events{ev_text("Hello", 1, true)}));
  WsSide client(GHTTP_WS_CLIENT, nullptr, &neg);
  WsRun b = client.feed(wsf(1, payload, true, false, 4));
  EXPECT_EQ(b.events, (Events{ev_text("Hello", 1, true)}));
}

TEST(WsDeflate, ContextTakeoverGivesTheRfcsSecondMessageWhichReferencesTheFirst) {
  // Section 7.2.3.2: the second "Hello" on the same context is f2 00 11 00 00.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "Hello", 5), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "Hello", 5), GHTTP_OK);
  auto f = ws_parse_frames(s.take_output());
  ASSERT_EQ(f.size(), 2u);
  EXPECT_EQ(f[0].payload, bytes({0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}));
  EXPECT_EQ(f[1].payload, bytes({0xf2, 0x00, 0x11, 0x00, 0x00}));
  // And the receiver, with takeover, reads both.
  WsSide r(GHTTP_WS_CLIENT, nullptr, &neg);
  WsRun run = r.feed(wsf(1, f[0].payload, true, false, 4) + wsf(1, f[1].payload, true, false, 4));
  EXPECT_EQ(run.events, (Events{ev_text("Hello", 1, true), ev_text("Hello", 1, true)}));
}

TEST(WsDeflate, WithoutContextTakeoverEveryMessageIsTheSameOctets) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  for (int i = 0; i < 3; i++) ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "Hello", 5), GHTTP_OK);
  auto f = ws_parse_frames(s.take_output());
  ASSERT_EQ(f.size(), 3u);
  for (auto & fr : f) EXPECT_EQ(fr.payload, bytes({0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}));
}

TEST(WsDeflate, ABlockWithBfinalSetIsReadAndTheNextMessageStartsAfresh) {
  // Section 7.2.3.4: the same "Hello", in a block whose BFINAL is 1.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  std::string final_block = bytes({0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00});
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun r = s.feed(wsf(1, final_block, true, true, 4) + wsf(1, final_block, true, true, 4)
      + wsf(1, bytes({0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}), true, true, 4));
  EXPECT_EQ(r.events, (Events{ev_text("Hello", 1, true), ev_text("Hello", 1, true), ev_text("Hello", 1, true)}));
  EXPECT_EQ(r.result, GHTTP_OK);
}

TEST(WsDeflate, TheRfcsFinalBlockFollowedByItsPaddingOctetIsRead) {
  // Section 7.2.3.4 gives f3 48 cd c9 c9 07 00 00: the octet after the final
  // block is the empty stored block the receiver's appended trailer completes.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun r = s.feed(wsf(1, bytes({0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00}), true, true, 4));
  EXPECT_EQ(r.events, (Events{ev_text("Hello", 1, true)}));
  EXPECT_EQ(r.result, GHTTP_OK);
  WsSide t(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun q = t.feed(wsf(1, bytes({0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x01}), true, true, 4));
  EXPECT_EQ(q.code, 1007);
}

TEST(WsDeflate, AnIncompressibleMessageOfTheMessageLimitFitsAFrameOfTheFrameLimit) {
  // Compressed, it is a little larger than the limit both are set to.
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 100000;
  l.max_frame_payload = 100000;
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsPair p(&neg, &l);
  std::string msg = ws_random_bytes(100000);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.client.get(), GHTTP_WS_MESSAGE_BINARY, msg.data(), msg.size()), GHTTP_OK);
  p.pump();
  ASSERT_EQ(p.server_events.size(), 1u);
  EXPECT_EQ(p.server_result, GHTTP_OK);
}

TEST(WsDeflate, ADataFrameAfterAFinalBlockInTheSameMessageIsAnError) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  std::string final_block = bytes({0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00});
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun r = s.feed(wsf(1, final_block, false, true, 4) + wsf(0, "more", true, true, 0));
  EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(r.code, 1007);
}

TEST(WsDeflate, DataCutOffInsideABlockIsNotDeliveredAsAMessage) {
  // The appended trailer completes an empty stored block only where the data
  // ended at a block boundary. Cut inside a block it would be read as more of
  // the block, and the cut-off message was delivered.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string msg = ws_lorem(3000, 3);
  WsFrame f = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_TEXT, msg));
  int delivered = 0;
  for (size_t cut : {size_t(1), size_t(2), size_t(5), f.payload.size() / 3, f.payload.size() / 2,
           f.payload.size() - 3, f.payload.size() - 1}) {
    WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
    WsRun r = s.feed(wsf(1, f.payload.substr(0, cut), true, true, 4));
    if (!r.events.empty()) delivered++;
    EXPECT_EQ(r.code, 1007) << cut;
  }
  EXPECT_EQ(delivered, 0);
  // The whole payload is still read.
  WsSide ok(GHTTP_WS_SERVER, nullptr, &neg);
  EXPECT_EQ(ok.feed(wsf(1, f.payload, true, true, 4)).events.size(), 1u);
}

TEST(WsDeflate, OnlyAFewZeroOctetsMayFollowAFinalBlock) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  std::string final_block = bytes({0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00});
  for (size_t zeros : {size_t(0), size_t(1), size_t(4)}) {
    WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
    EXPECT_EQ(s.feed(wsf(1, final_block + std::string(zeros, '\0'), true, true, 4)).events.size(), 1u) << zeros;
  }
  WsSide t(GHTTP_WS_SERVER, nullptr, &neg);
  EXPECT_EQ(t.feed(wsf(1, final_block + std::string(5, '\0'), true, true, 4)).code, 1007);
  // And not by spreading them over frames either.
  WsSide u(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun r = u.feed(wsf(1, final_block + std::string(3, '\0'), false, true, 4) + wsf(0, std::string(3, '\0'), true, true, 0));
  EXPECT_EQ(r.code, 1007);
}

TEST(WsDeflate, AnEmptyMessageIsOneZeroOctetOnTheWireAndComesBackEmpty) {
  // Section 7.2.3.6: an empty message compresses to a single 0x00.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsFrame f = first_frame(sent(GHTTP_WS_SERVER, neg, GHTTP_WS_MESSAGE_TEXT, ""));
  EXPECT_EQ(f.payload, std::string("\x00", 1));
  WsSide r(GHTTP_WS_CLIENT, nullptr, &neg);
  EXPECT_EQ(r.feed(wsf(1, std::string("\x00", 1), true, false, 4)).events, (Events{ev_text("", 1, true)}));
  EXPECT_EQ(r.feed(wsf(2, std::string("\x00", 1), true, false, 4)).events, (Events{ev_binary("", 1, true)}));
}

// ---- Round trips: Autobahn 12 and 13 ------------------------------------------------------------------------------

namespace {

struct Variant {
  const char * name;
  bool server_nct, client_nct;
  int server_bits, client_bits;
};

const Variant VARIANTS[] = {
    {"takeover", false, false, 0, 0},
    {"no takeover", true, true, 0, 0},
    {"server alone resets", true, false, 0, 0},
    {"client alone resets", false, true, 0, 0},
    {"small windows", false, false, 9, 8},
    {"small windows, no takeover", true, true, 10, 11},
};

} // namespace

TEST(WsAutobahn, Case12And13_EveryMessageSizeRoundTripsInEveryNegotiationInBothDirections) {
  for (const Variant & v : VARIANTS) {
    GHTTP_WsNegotiated neg = ws_deflate_negotiated(v.server_nct, v.client_nct, v.server_bits, v.client_bits);
    WsPair p(&neg);
    for (size_t n : {size_t(0), size_t(1), size_t(10), size_t(125), size_t(126), size_t(1000), size_t(4096),
             size_t(65535), size_t(65536), size_t(200000)}) {
      for (bool is_text : {true, false}) {
        std::string msg = is_text ? ws_lorem(n, static_cast<uint32_t>(n + 1)) : ws_random_bytes(n, static_cast<uint32_t>(n + 3));
        GHTTP_WsMessageType t = is_text ? GHTTP_WS_MESSAGE_TEXT : GHTTP_WS_MESSAGE_BINARY;
        p.client_events.clear();
        p.server_events.clear();
        ASSERT_EQ(ghttp_ws_conn_send_message(p.client.get(), t, msg.data(), msg.size()), GHTTP_OK) << v.name << " " << n << (is_text ? " text" : " binary");
        p.pump();
        ASSERT_EQ(p.server_events.size(), 1u) << v.name << " " << n;
        EXPECT_EQ(p.server_events[0].data, msg) << v.name << " " << n;
        EXPECT_TRUE(p.server_events[0].compressed);
        ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), t, msg.data(), msg.size()), GHTTP_OK);
        p.pump();
        ASSERT_EQ(p.client_events.size(), 1u) << v.name << " " << n;
        EXPECT_EQ(p.client_events[0].data, msg) << v.name << " " << n;
      }
    }
    EXPECT_EQ(p.client_result, GHTTP_OK) << v.name;
    EXPECT_EQ(p.server_result, GHTTP_OK) << v.name;
  }
}

TEST(WsDeflate, AnEmptyFirstMessageDoesNotUndersizeTheCompressorForTheNextOnes) {
  // The compressor sizes its staging buffer at the first call that reaches it;
  // a flush with nothing before it must not be that call (see prime_encoder).
  for (bool reset : {false, true}) {
    GHTTP_WsNegotiated neg = ws_deflate_negotiated(reset, reset);
    WsPair p(&neg);
    std::string big = ws_random_bytes(100000);
    for (const std::string & m : {std::string(), big, std::string(), big, ws_lorem(70000)}) {
      p.server_events.clear();
      ASSERT_EQ(ghttp_ws_conn_send_message(p.client.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), m.size()), GHTTP_OK) << reset;
      p.pump();
      ASSERT_EQ(p.server_events.size(), 1u);
      EXPECT_EQ(p.server_events[0].data, m);
    }
    EXPECT_EQ(p.client_result, GHTTP_OK);
    EXPECT_EQ(p.server_result, GHTTP_OK);
  }
}

TEST(WsDeflate, ARepetitiveMessageIsSmallerOnTheWireAndTakeoverMakesTheSecondSmallerStill) {
  std::string msg = ws_lorem(2000);
  GHTTP_WsNegotiated keep = ws_deflate_negotiated();
  WsSide a(GHTTP_WS_SERVER, nullptr, &keep);
  ASSERT_EQ(ghttp_ws_conn_send_message(a.get(), GHTTP_WS_MESSAGE_TEXT, msg.data(), msg.size()), GHTTP_OK);
  size_t first = a.take_output().size();
  ASSERT_EQ(ghttp_ws_conn_send_message(a.get(), GHTTP_WS_MESSAGE_TEXT, msg.data(), msg.size()), GHTTP_OK);
  size_t second = a.take_output().size();
  EXPECT_LT(first, msg.size() / 2);
  EXPECT_LT(second, first / 4) << "the second copy should be a reference to the first";
  GHTTP_WsNegotiated drop = ws_deflate_negotiated(true, true);
  WsSide b(GHTTP_WS_SERVER, nullptr, &drop);
  ASSERT_EQ(ghttp_ws_conn_send_message(b.get(), GHTTP_WS_MESSAGE_TEXT, msg.data(), msg.size()), GHTTP_OK);
  size_t f1 = b.take_output().size();
  ASSERT_EQ(ghttp_ws_conn_send_message(b.get(), GHTTP_WS_MESSAGE_TEXT, msg.data(), msg.size()), GHTTP_OK);
  size_t f2 = b.take_output().size();
  EXPECT_EQ(f1, f2);
}

TEST(WsDeflate, ASmallWindowLimitsWhatTheCompressorCanReachBackTo) {
  // A message whose second half repeats its first, 3000 octets back: a 2^8
  // window cannot use that and a 2^15 one can. Window bits 8 is a real
  // 256-octet window in the compress library (measured: a repeat 300 octets
  // back is not found at 8 bits, is at 9), so it is negotiated as asked.
  std::string a = ws_random_bytes(3000, 11);
  std::string msg = a + a;
  auto size_with = [&](GHTTP_WsRole role, int server_bits, int client_bits) {
    GHTTP_WsNegotiated neg = ws_deflate_negotiated(false, false, server_bits, client_bits);
    return sent(role, neg, GHTTP_WS_MESSAGE_BINARY, msg).size();
  };
  EXPECT_GT(size_with(GHTTP_WS_SERVER, 8, 0), 5500u);
  EXPECT_LT(size_with(GHTTP_WS_SERVER, 15, 0), 3300u);
  // The client's compressor is the one client_max_window_bits limits...
  EXPECT_GT(size_with(GHTTP_WS_CLIENT, 0, 8), 5500u);
  EXPECT_LT(size_with(GHTTP_WS_CLIENT, 0, 15), 3300u);
  // ...and each end ignores the other's window: swapped, nothing is limited.
  EXPECT_LT(size_with(GHTTP_WS_SERVER, 0, 8), 3300u);
  EXPECT_LT(size_with(GHTTP_WS_CLIENT, 8, 0), 3300u);
}

TEST(WsDeflate, ARepeatJustBeyondTheWindowIsFoundOnlyWithTheBiggerOne) {
  std::string x = ws_random_bytes(400, 5);
  std::string msg = x + x.substr(0, 100);  // 100 octets repeated 400 back
  auto size_with = [&](int bits) {
    GHTTP_WsNegotiated neg = ws_deflate_negotiated(false, false, bits, 0);
    return sent(GHTTP_WS_SERVER, neg, GHTTP_WS_MESSAGE_BINARY, msg).size();
  };
  EXPECT_GT(size_with(8), size_with(9) + 50);  // 8 bits is 256 octets, not zlib's silent 512
}

TEST(WsDeflate, AMessageThatIsNotWorthCompressingIsSentPlainAndTheContextIsUndisturbed) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsPair p(&neg);
  ghttp_ws_conn_set_compress_min(p.server.get(), 100);
  std::string big = ws_lorem(1000);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_TEXT, big.data(), big.size()), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_TEXT, "tiny", 4), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_TEXT, big.data(), big.size()), GHTTP_OK);
  p.pump();
  ASSERT_EQ(p.client_events.size(), 3u);
  EXPECT_TRUE(p.client_events[0].compressed);
  EXPECT_FALSE(p.client_events[1].compressed);
  EXPECT_EQ(p.client_events[1].data, "tiny");
  EXPECT_TRUE(p.client_events[2].compressed);
  EXPECT_EQ(p.client_events[2].data, big);
  EXPECT_EQ(p.client_result, GHTTP_OK);
}

TEST(WsDeflate, FragmentsOfOneMessageAreCompressedAsOneAndTheOtherEndReadsThemAsOne) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsPair p(&neg);
  std::string msg = ws_lorem(5000);
  size_t off = 0;
  for (size_t step : {size_t(1), size_t(10), size_t(1000), size_t(3989)}) {
    bool last = off + step >= msg.size();
    size_t n = std::min(step, msg.size() - off);
    ASSERT_EQ(ghttp_ws_conn_send_fragment(p.client.get(), GHTTP_WS_MESSAGE_TEXT, msg.data() + off, n, last), GHTTP_OK);
    off += n;
  }
  ASSERT_EQ(off, msg.size());
  std::string wire = p.client.take_output();
  auto frames = ws_parse_frames(wire);
  ASSERT_EQ(frames.size(), 4u);
  EXPECT_EQ(frames[0].rsv, 4);
  EXPECT_EQ(frames[1].rsv, 0);  // RSV1 is on the first frame only
  EXPECT_EQ(frames[0].opcode, 1);
  EXPECT_EQ(frames[1].opcode, 0);
  p.to_server = wire;
  p.pump();
  ASSERT_EQ(p.server_events.size(), 1u);
  EXPECT_EQ(p.server_events[0].data, msg);
  EXPECT_EQ(p.server_events[0].fragments, 4u);
}

TEST(WsDeflate, ControlFramesAreNeverCompressedAndMayInterleave) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsPair p(&neg);
  ASSERT_EQ(ghttp_ws_conn_send_fragment(p.client.get(), GHTTP_WS_MESSAGE_TEXT, "Hel", 3, 0), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_ping(p.client.get(), "ping", 4), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_fragment(p.client.get(), GHTTP_WS_MESSAGE_TEXT, "lo", 2, 1), GHTTP_OK);
  auto frames = ws_parse_frames(p.client.take_output());
  ASSERT_EQ(frames.size(), 3u);
  EXPECT_EQ(frames[1].opcode, 9);
  EXPECT_EQ(frames[1].rsv, 0);
  EXPECT_EQ(frames[1].payload, "ping");
}

// ---- Where RSV1 may and may not be ---------------------------------------------------------------------------------

TEST(WsDeflate, Rsv1WithoutTheExtensionIsAnError) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(wsf(1, std::string("\x00", 1), true, true, 4));
  EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(r.code, 1002);
}

TEST(WsDeflate, Rsv1OnAControlFrameOrAContinuationIsAnError) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  for (int op : {8, 9, 10}) {
    WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
    WsRun r = s.feed(wsf(op, op == 8 ? std::string("\x03\xe8", 2) : "", true, true, 4));
    EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT) << op;
    EXPECT_EQ(r.code, 1002) << op;
  }
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun r = s.feed(wsf(1, std::string("\xf2", 1), false, true, 4) + wsf(0, std::string("\x00", 1), true, true, 4));
  EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(r.code, 1002);
}

TEST(WsDeflate, AnUncompressedMessageIsFineOnAConnectionThatNegotiatedDeflate) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  EXPECT_EQ(s.feed(text("plain")).events, (Events{ev_text("plain", 1, false)}));
}

// ---- Bad and hostile compressed data ---------------------------------------------------------------------------------

TEST(WsDeflate, DataThatIsNotDeflateClosesWith1007) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  for (std::string bad : {std::string("\xff\xff\xff\xff"), std::string("\x07"), std::string("\x01\x05\x00\x00\x00", 5)}) {
    WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
    WsRun r = s.feed(wsf(2, bad, true, true, 4));
    EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT) << bad.size();
    EXPECT_EQ(r.code, 1007) << bad.size();
  }
}

TEST(WsDeflate, ATextMessageThatInflatesToInvalidUtf8ClosesWith1007) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string bad = "ok\xed\xa0\x80" "tail";
  std::string wire = sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, bad);
  WsFrame f = first_frame(wire);
  WsSide s(GHTTP_WS_SERVER, nullptr, &neg);
  WsRun r = s.feed(wsf(1, f.payload, true, true, 4));
  EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(r.code, 1007);
  // The same bytes as a binary message are only bytes.
  WsSide t(GHTTP_WS_SERVER, nullptr, &neg);
  EXPECT_EQ(t.feed(wsf(2, f.payload, true, true, 4)).events, (Events{ev_binary(bad, 1, true)}));
}

TEST(WsDeflate, APeerThatKeepsContextItWasToldToDropIsRefused) {
  // The server was told client_no_context_takeover; a client that sends
  // the second message as a reference to the first has broken the agreement.
  GHTTP_WsNegotiated takeover = ws_deflate_negotiated();
  GHTTP_WsNegotiated none = ws_deflate_negotiated(false, true);
  std::string msg = ws_lorem(500);
  WsSide c(GHTTP_WS_CLIENT, nullptr, &takeover);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, msg.data(), msg.size()), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, msg.data(), msg.size()), GHTTP_OK);
  std::string wire = c.take_output();
  WsSide s(GHTTP_WS_SERVER, nullptr, &none);
  WsRun r = s.feed(wire);
  EXPECT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(r.code, 1007);
}

TEST(WsDeflate, ABombIsStoppedAtTheMessageLimitBeforeItsOutputIsHeld) {
  // 4 MiB of zeros is a few kilobytes of deflate.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string zeros(4 << 20, '\0');
  std::string wire = sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, zeros);
  WsFrame f = first_frame(wire);
  ASSERT_LT(f.payload.size(), 8192u);
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 100000;
  l.max_frame_payload = 100000;
  l.max_expansion_ratio = 0;  // no ratio limit: the size limit is the one under test
  WsSide s(GHTTP_WS_SERVER, &l, &neg);
  WsRun r = s.feed(wsf(2, f.payload, true, true, 4));
  EXPECT_EQ(r.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(r.code, 1009);
  EXPECT_TRUE(r.events.empty());
  auto frames = ws_parse_frames(r.output);
  ASSERT_EQ(frames.size(), 1u);
  EXPECT_EQ(ws_close_code(frames[0]), 1009);
  // Which limit fired, not just that one did: the size limit, with the ratio
  // switched off (0 is "no ratio limit"), and not the ratio.
  const char * why = nullptr;
  ghttp_ws_conn_error(s.get(), nullptr, &why);
  EXPECT_STREQ(why, "a message inflates past the message size limit");
}

TEST(WsDeflate, TheInflateNeverHoldsMoreThanTheLimitAndOneOctet) {
  // The bound itself, below the connection: the buffer is never appended past it.
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string zeros(1 << 20, '\0');
  WsFrame f = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, zeros));
  for (uint64_t limit : {uint64_t(0), uint64_t(1), uint64_t(255), uint64_t(256), uint64_t(8191), uint64_t(8192), uint64_t(100000)}) {
    GHTTP_WsDeflate * d = nullptr;
    ASSERT_EQ(ghttp_ws_deflate_open(nullptr, 0, true, true, limit, 0, &d), GHTTP_OK);
    GHTTP_Buffer * out = nullptr;
    ASSERT_EQ(ghttp_buffer_create(nullptr, &out), GHTTP_OK);
    ghttp_ws_inflate_begin(d);
    // ratio 0 would allow only the slack: use a ratio large enough to leave the size limit in charge
    ghttp_ws_deflate_close(d);
    ASSERT_EQ(ghttp_ws_deflate_open(nullptr, 0, true, true, limit, 100000000, &d), GHTTP_OK);
    ghttp_ws_inflate_begin(d);
    GHTTP_Result r = ghttp_ws_inflate_update(d, f.payload.data(), f.payload.size(), out);
    if (r == GHTTP_OK) r = ghttp_ws_inflate_end(d, out);
    EXPECT_EQ(r, GHTTP_ERR_LIMIT) << limit;
    EXPECT_LE(ghttp_buffer_size(out), limit) << limit;
    ghttp_buffer_destroy(out);
    ghttp_ws_deflate_close(d);
  }
}

TEST(WsDeflate, AMessageOfExactlyTheLimitInflatesAndOneOctetMoreDoesNot) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  for (size_t n : {size_t(1000), size_t(8192), size_t(8193), size_t(20000)}) {
    std::string msg(n, 'a');
    WsFrame f = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, msg));
    GHTTP_WsLimits l = limits();
    l.max_expansion_ratio = 100000;
    l.max_message_bytes = n;
    l.max_frame_payload = n;
    l.max_frame_payload = std::min(l.max_frame_payload, l.max_message_bytes);
    WsSide ok(GHTTP_WS_SERVER, &l, &neg);
    EXPECT_EQ(ok.feed(wsf(2, f.payload, true, true, 4)).events.size(), 1u) << n;
    l.max_message_bytes = n - 1;
    l.max_frame_payload = n - 1;
    l.max_frame_payload = std::min(l.max_frame_payload, l.max_message_bytes);
    WsSide over(GHTTP_WS_SERVER, &l, &neg);
    WsRun r = over.feed(wsf(2, f.payload, true, true, 4));
    EXPECT_EQ(r.result, GHTTP_ERR_LIMIT) << n;
    EXPECT_EQ(r.code, 1009) << n;
  }
}

TEST(WsDeflate, TheExpansionRatioStopsAMessageThatGrowsMoreThanItMayPerOctetOfInput) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string zeros(100000, '\0');
  WsFrame f = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, zeros));
  // About 100 octets of input give 100,000 of output: a ratio near 1000.
  GHTTP_WsLimits l = limits();
  l.max_expansion_ratio = 20;
  WsSide strict(GHTTP_WS_SERVER, &l, &neg);
  WsRun r = strict.feed(wsf(2, f.payload, true, true, 4));
  EXPECT_EQ(r.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(r.code, 1009);
  const char * why = nullptr;
  ghttp_ws_conn_error(strict.get(), nullptr, &why);
  EXPECT_STREQ(why, "a message inflates past the expansion ratio limit");  // and not the size limit
  l.max_expansion_ratio = 1032;
  WsSide fine(GHTTP_WS_SERVER, &l, &neg);
  EXPECT_EQ(fine.feed(wsf(2, f.payload, true, true, 4)).events.size(), 1u);
  // An ordinary message is nowhere near a ratio of 20.
  std::string text = ws_lorem(100000);
  WsFrame g = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_TEXT, text));
  l.max_expansion_ratio = 20;
  WsSide ordinary(GHTTP_WS_SERVER, &l, &neg);
  EXPECT_EQ(ordinary.feed(wsf(1, g.payload, true, true, 4)).events.size(), 1u);
}

TEST(WsDeflate, ARatioOfZeroIsNoRatioLimitAndTheMessageLimitStillApplies) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string zeros(100000, '\0');
  WsFrame f = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, zeros));
  GHTTP_WsLimits l = limits();
  l.max_expansion_ratio = 0;
  WsSide s(GHTTP_WS_SERVER, &l, &neg);
  WsRun r = s.feed(wsf(2, f.payload, true, true, 4));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].data.size(), 100000u);
  l.max_message_bytes = 50000;
  l.max_frame_payload = 50000;
  WsSide t(GHTTP_WS_SERVER, &l, &neg);
  WsRun q = t.feed(wsf(2, f.payload, true, true, 4));
  EXPECT_EQ(q.code, 1009);
  const char * why = nullptr;
  ghttp_ws_conn_error(t.get(), nullptr, &why);
  EXPECT_STREQ(why, "a message inflates past the message size limit");
}

TEST(WsDeflate, TheRatioIsHeldOnAMessageTheSameWayWhateverTheFeedBoundaries) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated(true, true);
  std::string zeros(100000, '\0');
  WsFrame f = first_frame(sent(GHTTP_WS_CLIENT, neg, GHTTP_WS_MESSAGE_BINARY, zeros));
  GHTTP_WsLimits l = limits();
  l.max_expansion_ratio = 20;
  std::string in = wsf(2, f.payload, true, true, 4);
  WsSide a(GHTTP_WS_SERVER, &l, &neg);
  WsSide b(GHTTP_WS_SERVER, &l, &neg);
  WsRun ra = a.feed(in);
  WsRun rb = b.feed_bytes(in);
  EXPECT_EQ(ra, rb);
  EXPECT_EQ(ra.result, GHTTP_ERR_LIMIT);
}

TEST(WsDeflate, ACompressedMessageLargerThanTheLimitPlusItsOverheadIsRefusedAtItsHeader) {
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 1000;
  l.max_frame_payload = 1000;
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  // 1000 + 1000/64 + 16 = 1031 octets may arrive; 1032 may not.
  WsSide ok(GHTTP_WS_SERVER, &l, &neg);
  EXPECT_EQ(ok.feed(wsf_header_only(2, 1031, true, true, 4)).result, GHTTP_OK);
  WsSide s(GHTTP_WS_SERVER, &l, &neg);
  WsRun r = s.feed(wsf_header_only(2, 1032, true, true, 4));
  EXPECT_EQ(r.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(r.code, 1009);
}

TEST(WsDeflate, AFragmentFloodOfCompressedFramesIsStoppedAtTheLimit) {
  GHTTP_WsLimits l = limits();
  l.max_fragments = 3;
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsSide s(GHTTP_WS_SERVER, &l, &neg);
  WsRun r = s.feed(wsf(2, std::string("\xf2", 1), false, true, 4) + wsf(0, "", false) + wsf(0, "", false) + wsf(0, "", false));
  EXPECT_EQ(r.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(r.code, 1009);
}

// ---- The same events however the input is cut ----------------------------------------------------------------------------------

TEST(WsDeflate, ACompressedStreamGivesTheSameEventsWholeAndByteByByteAndInTwoParts) {
  for (const Variant & v : {VARIANTS[0], VARIANTS[1], VARIANTS[5]}) {
    GHTTP_WsNegotiated neg = ws_deflate_negotiated(v.server_nct, v.client_nct, v.server_bits, v.client_bits);
    WsSide c(GHTTP_WS_CLIENT, nullptr, &neg);
    std::string a = ws_lorem(3000, 5), b = ws_random_bytes(500), cc = ws_lorem(70000, 9);
    ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, a.data(), a.size()), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_BINARY, b.data(), b.size()), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_send_ping(c.get(), "p", 1), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_send_fragment(c.get(), GHTTP_WS_MESSAGE_TEXT, cc.data(), 30000, 0), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_send_fragment(c.get(), GHTTP_WS_MESSAGE_TEXT, cc.data() + 30000, cc.size() - 30000, 1), GHTTP_OK);
    std::string wire = c.take_output();
    WsSide whole(GHTTP_WS_SERVER, nullptr, &neg);
    WsRun w = whole.feed(wire);
    ASSERT_EQ(w.events.size(), 4u) << v.name;
    EXPECT_EQ(w.events[0].data, a);
    EXPECT_EQ(w.events[3].data, cc);
    WsSide bytewise(GHTTP_WS_SERVER, nullptr, &neg);
    EXPECT_EQ(bytewise.feed_bytes(wire), w) << v.name;
    for (size_t cut : {size_t(1), size_t(7), size_t(1000), wire.size() / 2, wire.size() - 1}) {
      WsSide two(GHTTP_WS_SERVER, nullptr, &neg);
      WsRun r1 = two.feed(wire.substr(0, cut));
      WsRun r2 = two.feed(wire.substr(cut));
      WsRun joined = r1;
      joined.events.insert(joined.events.end(), r2.events.begin(), r2.events.end());
      joined.output += r2.output;
      joined.result = r2.result;
      EXPECT_EQ(joined, w) << v.name << " cut " << cut;
    }
  }
}

// ---- Allocation failure ------------------------------------------------------------------------------------------------------------

TEST(WsDeflate, AnAllocationFailingAtEachPointIsOomOrAnUnchangedAnswerAndNeverALeak) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  std::string a = ws_lorem(3000, 5);
  // The wire is made once with the default allocator.
  WsSide c(GHTTP_WS_CLIENT, nullptr, &neg);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, a.data(), a.size()), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_BINARY, a.data(), 100), GHTTP_OK);
  std::string wire = c.take_output();
  auto receive = [&](const GHTTP_Allocator * alloc, size_t * allocs) {
    WsSide s(GHTTP_WS_SERVER, nullptr, &neg, alloc);
    EXPECT_EQ(s.created(), GHTTP_OK);
    WsRun r = s.feed(wire);
    if (allocs) *allocs = 0;
    return r;
  };
  FailingAllocator counter(static_cast<size_t>(-1));
  WsRun expected = receive(counter.get(), nullptr);
  ASSERT_EQ(expected.events.size(), 2u);
  EXPECT_EQ(counter.live(), 0u);
  size_t total = counter.requests();
  ASSERT_GT(total, 5u);
  size_t oom = 0;
  for (size_t run : {size_t(1), size_t(0), size_t(2)}) {
    for (size_t k = 0; k <= total + 1; k++) {
      FailingAllocator fa(k, run);
      {
        WsSide s(GHTTP_WS_SERVER, nullptr, &neg, fa.get());
        if (s.created() == GHTTP_OK) {
          WsRun r = s.feed(wire);
          if (fa.failed()) {
            if (r.result == GHTTP_ERR_OOM) {
              oom++;
            } else {
              EXPECT_EQ(r.events, expected.events) << k;
            }
          } else {
            EXPECT_EQ(r.events, expected.events) << k;
          }
          fa.stop_failing();
        } else {
          EXPECT_EQ(s.created(), GHTTP_ERR_OOM);
        }
      }
      EXPECT_EQ(fa.live(), 0u) << k << " run " << run;
    }
  }
  EXPECT_GT(oom, 0u);
}

TEST(WsDeflate, SendingUnderAllocationFailureIsOomAndLeaksNothing) {
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  std::string a = ws_lorem(3000, 5);
  FailingAllocator counter(static_cast<size_t>(-1));
  {
    WsSide s(GHTTP_WS_SERVER, nullptr, &neg, counter.get());
    ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, a.data(), a.size()), GHTTP_OK);
  }
  EXPECT_EQ(counter.live(), 0u);
  size_t total = counter.requests();
  size_t oom = 0;
  for (size_t run : {size_t(1), size_t(0)}) {
    for (size_t k = 0; k <= total; k++) {
      FailingAllocator fa(k, run);
      {
        WsSide s(GHTTP_WS_SERVER, nullptr, &neg, fa.get());
        if (s.created() == GHTTP_OK) {
          GHTTP_Result r = ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, a.data(), a.size());
          if (fa.failed() && r != GHTTP_OK) {
            EXPECT_EQ(r, GHTTP_ERR_OOM) << k;
            oom++;
          }
          fa.stop_failing();
        }
      }
      EXPECT_EQ(fa.live(), 0u) << k << " run " << run;
    }
  }
  EXPECT_GT(oom, 0u);
}

TEST(WsDeflate, ACompressedSendThatWouldOverfillTheQueueIsRefusedBeforeTheCompressorIsTouched) {
  // The compressor cannot give back what it has taken, so the queue's limit is
  // judged first, on a bound: a refused send leaves the connection open and
  // its history as it was (the next send still decodes at the other end).
  GHTTP_WsLimits l = limits();
  l.max_buffered_bytes = 1000;
  GHTTP_WsNegotiated neg = ws_deflate_negotiated();
  WsPair p(&neg, &l);
  std::string big = ws_lorem(2000);
  EXPECT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_TEXT, big.data(), big.size()), GHTTP_ERR_LIMIT);
  EXPECT_EQ(ghttp_ws_conn_state(p.server.get()), GHTTP_WS_STATE_OPEN);
  EXPECT_EQ(ghttp_ws_conn_output_size(p.server.get()), 0u);
  std::string ok = ws_lorem(300);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_TEXT, ok.data(), ok.size()), GHTTP_OK);
  p.pump();
  ASSERT_EQ(p.client_events.size(), 1u);
  EXPECT_EQ(p.client_events[0].data, ok);
}

TEST(WsDeflate, AWindowOutsideEightToFifteenIsInvalidWhereverItIsGiven) {
  GHTTP_WsDeflate * d = nullptr;
  EXPECT_EQ(ghttp_ws_deflate_open(nullptr, 7, false, false, 100, 100, &d), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_deflate_open(nullptr, 16, false, false, 100, 100, &d), GHTTP_ERR_INVALID);
  ASSERT_EQ(ghttp_ws_deflate_open(nullptr, 8, false, false, 100, 100, &d), GHTTP_OK);
  ghttp_ws_deflate_close(d);
  for (int bad : {7, 16, 255}) {
    GHTTP_WsNegotiated n = ws_deflate_negotiated(false, false, bad, 0);
    GHTTP_WsConn * c = nullptr;
    EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, nullptr, &n, &c), GHTTP_ERR_INVALID) << bad;
    GHTTP_WsNegotiated m = ws_deflate_negotiated(false, false, 0, bad);
    EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_CLIENT, nullptr, &m, &c), GHTTP_ERR_INVALID) << bad;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
