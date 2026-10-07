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
 * The WebSocket connection without extensions: messages, fragmentation,
 * control frames, the closing handshake, masking, UTF-8, and the failures.
 * Test names that carry an Autobahn|Testsuite case number say which of its
 * cases they stand for, so that a run of the suite and a run of these cover
 * the same ground (documentation/rfc6455.md has the whole table).
 */

#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"
#include "ws_helpers.h"

using namespace ghttptest;

namespace {

using Events = std::vector<WsEv>;

/** The connection failed with this result and this close code, and said so in its output. */
void expect_failed(const WsRun & r, GHTTP_Result result, int code,
    const std::string & what, bool expect_close_frame = true) {
  EXPECT_EQ(r.result, result) << what;
  EXPECT_EQ(r.code, code) << what;
  if (expect_close_frame) {
    auto frames = ws_parse_frames(r.output);
    ASSERT_FALSE(frames.empty()) << what;
    EXPECT_EQ(frames.back().opcode, 8) << what;
    EXPECT_EQ(ws_close_code(frames.back()), code) << what;
  }
}

GHTTP_WsLimits limits() {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  return l;
}

/** Feed everything and report the events, never taking the output until the end: a writer that is slow. */
Events feed_without_draining(WsSide & s, const std::string & in, std::string * output) {
  Events events;
  size_t off = 0;
  for (;;) {
    size_t used = 0;
    GHTTP_WsEvent e;
    if (ghttp_ws_conn_feed(s.get(), in.data() + off, in.size() - off, &used, &e) != GHTTP_OK) break;
    off += used;
    if (e.type == GHTTP_WS_EVENT_NEED_MORE) break;
    WsEv we;
    we.type = e.type;
    if (e.data_len) we.data.assign(reinterpret_cast<const char *>(e.data), e.data_len);
    events.push_back(we);
  }
  *output = s.take_output();
  return events;
}

std::string fragment(int opcode, const std::string & p, bool fin) { return wsf(opcode, p, fin); }

} // namespace

// ---- Construction -------------------------------------------------------------------

TEST(WsConnCreate, ARoleIsRequiredAndALimitThatCannotWorkIsRefused) {
  GHTTP_WsConn * c = nullptr;
  EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, nullptr, nullptr, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_create(nullptr, static_cast<GHTTP_WsRole>(7), nullptr, nullptr, &c), GHTTP_ERR_INVALID);
  GHTTP_WsLimits l = limits();
  l.size = 0;
  EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &l, nullptr, &c), GHTTP_ERR_INVALID);
  l = limits();
  l.max_buffered_bytes = 130;  // a masked control frame is 131 octets
  EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &l, nullptr, &c), GHTTP_ERR_INVALID);
  l.max_buffered_bytes = 131;
  ASSERT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &l, nullptr, &c), GHTTP_OK);
  ghttp_ws_conn_destroy(c);
  ghttp_ws_conn_destroy(nullptr);
}

TEST(WsConnCreate, EveryLimitThatMustBeNonZeroIsRefusedAtZeroAndAFrameMayNotOutgrowItsMessage) {
  struct Case { const char * name; void (*set)(GHTTP_WsLimits *); };
  Case cases[] = {
      {"max_frame_payload", [](GHTTP_WsLimits * l) { l->max_frame_payload = 0; }},
      {"max_message_bytes", [](GHTTP_WsLimits * l) { l->max_message_bytes = 0; }},
      {"max_fragments", [](GHTTP_WsLimits * l) { l->max_fragments = 0; }},
      {"max_control_per_interval", [](GHTTP_WsLimits * l) { l->max_control_per_interval = 0; }},
      {"interval_ms", [](GHTTP_WsLimits * l) { l->interval_ms = 0; }},
      {"max_buffered_bytes", [](GHTTP_WsLimits * l) { l->max_buffered_bytes = 0; }},
      {"max_handshake_bytes", [](GHTTP_WsLimits * l) { l->max_handshake_bytes = 0; }},
      {"max_extension_offers", [](GHTTP_WsLimits * l) { l->max_extension_offers = 0; }},
      {"max_extension_params", [](GHTTP_WsLimits * l) { l->max_extension_params = 0; }},
      {"frame over message", [](GHTTP_WsLimits * l) { l->max_frame_payload = 101; l->max_message_bytes = 100; }},
  };
  for (auto & c : cases) {
    GHTTP_WsLimits l = limits();
    c.set(&l);
    GHTTP_WsConn * conn = nullptr;
    EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &l, nullptr, &conn), GHTTP_ERR_INVALID) << c.name;
    EXPECT_EQ(conn, nullptr) << c.name;
  }
  // A ratio of 0 is not a refusal: it is "no ratio limit".
  GHTTP_WsLimits l = limits();
  l.max_expansion_ratio = 0;
  GHTTP_WsConn * conn = nullptr;
  EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &l, nullptr, &conn), GHTTP_OK);
  ghttp_ws_conn_destroy(conn);
}

TEST(WsConnCreate, ANegotiatedStructWithNoSizeIsInvalidAndANullConnectionIsReportedFailed) {
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  n.size = 0;
  GHTTP_WsConn * c = nullptr;
  EXPECT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, nullptr, &n, &c), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_state(nullptr), GHTTP_WS_STATE_FAILED);
}

TEST(WsConnCreate, ANullArgumentToFeedIsInvalidAndNotSticky) {
  WsSide s(GHTTP_WS_SERVER);
  size_t used;
  GHTTP_WsEvent e;
  EXPECT_EQ(ghttp_ws_conn_feed(nullptr, "", 0, &used, &e), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_feed(s.get(), nullptr, 1, &used, &e), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_feed(s.get(), "", 0, nullptr, &e), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_feed(s.get(), "", 0, &used, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(s.feed(text("ok")).events, (Events{ev_text("ok")}));
}

TEST(WsConnCreate, ANewConnectionIsOpenAndEmpty) {
  WsSide s(GHTTP_WS_SERVER);
  EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_OPEN);
  EXPECT_EQ(ghttp_ws_conn_output_size(s.get()), 0u);
  EXPECT_EQ(ghttp_ws_conn_deflate_active(s.get()), 0);
  uint16_t code = 9;
  const char * reason = nullptr;
  EXPECT_EQ(ghttp_ws_conn_error(s.get(), &code, &reason), GHTTP_OK);
  EXPECT_EQ(code, 0);
  EXPECT_STREQ(reason, "");
}

// ---- Autobahn 1.x: text and binary messages of every size class ----------------------------

TEST(WsAutobahn, Case1_1And1_2_EveryMessageSizeClassEchoesIntactInBothDirectionsAndBothKinds) {
  for (size_t n : {size_t(0), size_t(1), size_t(125), size_t(126), size_t(127), size_t(128),
           size_t(65535), size_t(65536), size_t(262144)}) {
    for (bool is_text : {true, false}) {
      WsPair p;
      std::string msg = is_text ? ws_lorem(n) : ws_random_bytes(n);
      GHTTP_WsMessageType t = is_text ? GHTTP_WS_MESSAGE_TEXT : GHTTP_WS_MESSAGE_BINARY;
      ASSERT_EQ(ghttp_ws_conn_send_message(p.client.get(), t, msg.data(), msg.size()), GHTTP_OK) << n;
      p.pump();
      ASSERT_EQ(p.server_events.size(), 1u) << n;
      EXPECT_EQ(p.server_events[0].type, is_text ? GHTTP_WS_EVENT_TEXT : GHTTP_WS_EVENT_BINARY);
      EXPECT_EQ(p.server_events[0].data, msg) << n;
      // The server echoes it.
      ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), t, msg.data(), msg.size()), GHTTP_OK) << n;
      p.pump();
      ASSERT_EQ(p.client_events.size(), 1u) << n;
      EXPECT_EQ(p.client_events[0].data, msg) << n;
      EXPECT_EQ(p.client_result, GHTTP_OK);
      EXPECT_EQ(p.server_result, GHTTP_OK);
    }
  }
}

TEST(WsConn, ASingleFrameMessageIsOneEventWithOneFragment) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(text("Hello"));
  EXPECT_EQ(r.events, (Events{ev_text("Hello", 1)}));
  EXPECT_EQ(r.output, "");
}

TEST(WsConn, TheRfcSingleFrameMaskedExampleIsHello) {
  // RFC 6455 section 5.7.
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(std::string("\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", 11));
  EXPECT_EQ(r.events, (Events{ev_text("Hello")}));
}

TEST(WsConn, TheRfcFragmentedExampleIsHelAndLo) {
  // Section 5.7: "Hel" with FIN clear, then "lo" as a final continuation.
  WsSide s(GHTTP_WS_CLIENT);
  WsRun r = s.feed(std::string("\x01\x03Hel\x80\x02lo", 9));
  EXPECT_EQ(r.events, (Events{ev_text("Hello", 2)}));
}

TEST(WsConn, ThePingAndPongOfTheRfcExampleCarryHello) {
  WsSide s(GHTTP_WS_CLIENT);
  WsRun r = s.feed(std::string("\x89\x05Hello", 7));
  EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PING, "Hello")}));
  // The reply is a Pong with the same body, and masked, as a client's frame.
  auto f = ws_parse_frames(r.output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].opcode, 10);
  EXPECT_EQ(f[0].payload, "Hello");
  EXPECT_TRUE(f[0].masked);
}

TEST(WsConn, The256ByteAnd64KibFramesOfTheRfcExamplesUseTheirLengthForms) {
  WsPair p;
  std::string b256(256, 'x');
  ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_BINARY, b256.data(), 256), GHTTP_OK);
  std::string out = p.server.take_output();
  EXPECT_EQ(out.substr(0, 4), std::string("\x82\x7e\x01\x00", 4));
  std::string b64k(65536, 'y');
  ASSERT_EQ(ghttp_ws_conn_send_message(p.server.get(), GHTTP_WS_MESSAGE_BINARY, b64k.data(), 65536), GHTTP_OK);
  out = p.server.take_output();
  EXPECT_EQ(out.substr(0, 10), std::string("\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x00", 10));
}

// ---- Autobahn 2.x: Ping and Pong ----------------------------------------------------------------

TEST(WsAutobahn, Case2_1To2_4_APingIsAnsweredWithAPongOfTheSamePayload) {
  for (std::string payload : {std::string(), std::string("Hello, world!"), std::string("\x00\xff\xfe\xfd\xfc\xfb\x00\xff", 8), std::string(125, '*')}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(ping(payload));
    EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PING, payload)})) << payload.size();
    auto f = ws_parse_frames(r.output);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].opcode, 10);
    EXPECT_TRUE(f[0].fin);
    EXPECT_EQ(f[0].payload, payload);
    EXPECT_FALSE(f[0].masked);
  }
}

TEST(WsAutobahn, Case2_5_APingOf126OctetsClosesWith1002) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(ping(std::string(126, '*')));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "ping of 126");
}

TEST(WsAutobahn, Case2_6_APingSentOneOctetAtATimeIsStillAnswered) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed_bytes(ping("Hello, world!"));
  EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PING, "Hello, world!")}));
  EXPECT_EQ(ws_parse_frames(r.output).size(), 1u);
}

TEST(WsAutobahn, Case2_7And2_8_AnUnsolicitedPongIsDeliveredAndAnsweredWithNothing) {
  for (std::string payload : {std::string(), std::string("ping payload")}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(pong(payload));
    EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PONG, payload)}));
    EXPECT_EQ(r.output, "");
    EXPECT_EQ(r.result, GHTTP_OK);
  }
}

TEST(WsAutobahn, Case2_9_APongThenAPingThenTheMessagesAfterThemAreAllDelivered) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(pong("a") + ping("b") + text("c"));
  EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PONG, "a"), ev(GHTTP_WS_EVENT_PING, "b"), ev_text("c")}));
  auto f = ws_parse_frames(r.output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].payload, "b");
}

TEST(WsAutobahn, Case2_10And2_11_ManyPingsAreAnsweredInOrderOnePongEachWhenTheWriterKeepsUp) {
  WsSide s(GHTTP_WS_SERVER);
  std::string out;
  for (int i = 0; i < 10; i++) {
    std::string p = "ping" + std::to_string(i);
    WsRun r = s.feed(ping(p));  // the helper takes the output after each feed
    EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PING, p)}));
    out += r.output;
  }
  auto f = ws_parse_frames(out);
  ASSERT_EQ(f.size(), 10u);
  for (int i = 0; i < 10; i++) EXPECT_EQ(f[i].payload, "ping" + std::to_string(i));
}

TEST(WsConn, PingsThatArriveBeforeTheLastPongIsWrittenAreAnsweredByOnePongOfTheLatest) {
  // RFC 6455 section 5.5.3: a Pong may answer only the most recent Ping. Every
  // Ping is still reported; a slow reader is not made to queue one Pong each.
  WsSide s(GHTTP_WS_SERVER);
  std::string in;
  Events want;
  for (int i = 0; i < 10; i++) {
    std::string p = "ping" + std::to_string(i);
    in += ping(p);
    want.push_back(ev(GHTTP_WS_EVENT_PING, p));
  }
  std::string output;
  EXPECT_EQ(feed_without_draining(s, in, &output), want);
  auto f = ws_parse_frames(output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].payload, "ping9");
}

TEST(WsConn, APongThatHasBegunToBeWrittenIsNotReplaced) {
  GHTTP_WsConn * c = nullptr;
  ASSERT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, nullptr, nullptr, &c), GHTTP_OK);
  std::string in = ping("first");
  size_t used;
  GHTTP_WsEvent e;
  ASSERT_EQ(ghttp_ws_conn_feed(c, in.data(), in.size(), &used, &e), GHTTP_OK);
  ASSERT_EQ(e.type, GHTTP_WS_EVENT_PING);
  ghttp_ws_conn_output_consume(c, 3);  // the writer took part of it
  std::string in2 = ping("second");
  ASSERT_EQ(ghttp_ws_conn_feed(c, in2.data(), in2.size(), &used, &e), GHTTP_OK);
  size_t n;
  const uint8_t * out = ghttp_ws_conn_output(c, &n);
  std::string rest(reinterpret_cast<const char *>(out), n);
  // "first"'s Pong is 7 octets: 3 gone, 4 left, then the whole Pong of "second".
  EXPECT_EQ(rest.size(), 4u + 8u);
  EXPECT_EQ(rest.substr(4), std::string("\x8a\x06second", 8) + "");
  ghttp_ws_conn_destroy(c);
}

TEST(WsConn, PingsWhileALargeMessageIsQueuedDoNotFillTheQueueWithPongs) {
  GHTTP_WsLimits l = limits();
  l.max_buffered_bytes = 2000;
  l.max_control_per_interval = 100000;
  GHTTP_WsConn * c = nullptr;
  ASSERT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &l, nullptr, &c), GHTTP_OK);
  std::string big(1500, 'x');
  ASSERT_EQ(ghttp_ws_conn_send_message(c, GHTTP_WS_MESSAGE_BINARY, big.data(), big.size()), GHTTP_OK);
  std::string p(120, 'p');
  std::string in;
  for (int i = 0; i < 1000; i++) in += ping(p);
  size_t off = 0;
  int pings = 0;
  while (off < in.size()) {
    size_t used;
    GHTTP_WsEvent e;
    ASSERT_EQ(ghttp_ws_conn_feed(c, in.data() + off, in.size() - off, &used, &e), GHTTP_OK);
    off += used;
    if (e.type == GHTTP_WS_EVENT_PING) pings++;
  }
  EXPECT_EQ(pings, 1000);
  EXPECT_EQ(ghttp_ws_conn_state(c), GHTTP_WS_STATE_OPEN);
  EXPECT_EQ(ghttp_ws_conn_output_size(c), 1504u + 122u);  // the message and one Pong
  ghttp_ws_conn_destroy(c);
}

// ---- Autobahn 3.x: reserved bits ---------------------------------------------------------------------

TEST(WsAutobahn, Case3_1To3_7_AReservedBitOnAnyFrameClosesWith1002) {
  for (int op : {1, 2, 8, 9, 10}) {
    for (int rsv = 1; rsv <= 7; rsv++) {
      WsSide s(GHTTP_WS_SERVER);
      std::string payload = op == 8 ? std::string("\x03\xe8", 2) : "payload";
      WsRun r = s.feed(wsf(op, payload, true, true, rsv));
      expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "op " + std::to_string(op) + " rsv " + std::to_string(rsv));
      EXPECT_TRUE(r.events.empty());
    }
  }
}

TEST(WsAutobahn, Case3_3_AValidMessageBeforeTheReservedBitIsStillDelivered) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(text("ok") + wsf(1, "bad", true, true, 2));
  EXPECT_EQ(r.events, (Events{ev_text("ok")}));
  EXPECT_EQ(r.code, 1002);
}

TEST(WsConn, AReservedBitOnAContinuationFrameIsAnErrorEvenWhenTheStartHadNone) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "a", false) + wsf(0, "b", true, true, 4));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "rsv on continuation");
}

// ---- Autobahn 4.x: opcodes ------------------------------------------------------------------------------

TEST(WsAutobahn, Case4_1And4_2_AReservedOpcodeClosesWith1002) {
  for (int op : {3, 4, 5, 6, 7, 11, 12, 13, 14, 15}) {
    for (std::string payload : {std::string(), std::string("reserved opcode payload")}) {
      WsSide s(GHTTP_WS_SERVER);
      WsRun r = s.feed(wsf(op, payload));
      expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "opcode " + std::to_string(op));
    }
  }
}

TEST(WsAutobahn, Case4_1_3To4_1_5_AReservedOpcodeAfterAValidMessageDeliversTheMessageFirst) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(text("valid") + ping("p") + wsf(5, "x"));
  EXPECT_EQ(r.events, (Events{ev_text("valid"), ev(GHTTP_WS_EVENT_PING, "p")}));
  EXPECT_EQ(r.code, 1002);
}

// ---- Autobahn 5.x: fragmentation ----------------------------------------------------------------------------

TEST(WsAutobahn, Case5_1And5_2_AFragmentedControlFrameClosesWith1002) {
  for (int op : {9, 10}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(fragment(op, "fragment1", false) + fragment(0, "fragment2", true));
    expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "fragmented control");
    // Refused at the first frame: not delivered, not answered, and not
    // left to be caught as an orphan continuation by the second.
    EXPECT_TRUE(r.events.empty()) << op;
    EXPECT_EQ(ws_parse_frames(r.output).size(), 1u) << op;
  }
}

TEST(WsAutobahn, Case5_3To5_5_ATextMessageInThreeFramesIsOneMessage) {
  std::string in = fragment(1, "fragment1", false) + fragment(0, "fragment2", false) + fragment(0, "fragment3", true);
  for (size_t piece : {size_t(0), size_t(1), size_t(7)}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(in, piece);
    EXPECT_EQ(r.events, (Events{ev_text("fragment1fragment2fragment3", 3)})) << piece;
  }
}

TEST(WsAutobahn, Case5_4_5_5And5_6_EmptyFramesInAFragmentedMessageAreFragmentsToo) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "", false) + fragment(0, "fragment1", false) + fragment(0, "", false)
      + fragment(0, "fragment2", true));
  EXPECT_EQ(r.events, (Events{ev_text("fragment1fragment2", 4)}));
}

TEST(WsAutobahn, Case5_6To5_8_APingBetweenFragmentsIsAnsweredAndTheMessageStillCompletes) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "fragment1", false) + ping("pongme!") + fragment(0, "fragment2", true));
  EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PING, "pongme!"), ev_text("fragment1fragment2", 2)}));
  auto f = ws_parse_frames(r.output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].opcode, 10);
  EXPECT_EQ(f[0].payload, "pongme!");
}

TEST(WsAutobahn, Case5_9To5_12_AContinuationWithNothingToContinueClosesWith1002) {
  for (bool fin : {true, false}) {
    for (std::string payload : {std::string("non-continuation payload"), std::string()}) {
      WsSide s(GHTTP_WS_SERVER);
      WsRun r = s.feed(fragment(0, payload, fin));
      expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "orphan continuation");
    }
  }
}

TEST(WsAutobahn, Case5_13To5_15_AContinuationAfterAFinishedMessageClosesWith1002) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "fragment1", false) + fragment(0, "fragment2", true)
      + fragment(0, "fragment3", true));
  EXPECT_EQ(r.events, (Events{ev_text("fragment1fragment2", 2)}));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "continuation after fin");
}

TEST(WsAutobahn, Case5_16To5_18_ANewMessageInTheMiddleOfAFragmentedOneClosesWith1002) {
  for (int op : {1, 2}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(fragment(1, "fragment1", false) + fragment(op, "fragment2", true));
    expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "new message inside fragmented");
    EXPECT_TRUE(r.events.empty());
  }
}

TEST(WsAutobahn, Case5_19And5_20_ControlFramesInterleavedWithFragmentsAllWork) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "fragment1", false) + fragment(0, "fragment2", false) + ping("pongme 1!")
      + fragment(0, "fragment3", false) + fragment(0, "fragment4", false) + ping("pongme 2!")
      + fragment(0, "fragment5", true));
  EXPECT_EQ(r.events.size(), 3u);
  EXPECT_EQ(r.events[2], ev_text("fragment1fragment2fragment3fragment4fragment5", 5));
  // The writer took each Pong as it came (the loop does), so there are two.
  EXPECT_EQ(ws_parse_frames(r.output).size(), 2u);
}

TEST(WsConn, ABinaryMessageFragmentsAreReassembledToo) {
  WsSide s(GHTTP_WS_CLIENT);
  WsRun r = s.feed(wsf(2, std::string("\x00\x01", 2), false, false) + wsf(0, std::string("\x02\x03", 2), true, false));
  EXPECT_EQ(r.events, (Events{ev_binary(std::string("\x00\x01\x02\x03", 4), 2)}));
}

TEST(WsConn, AMessageBetweenTwoMessagesDoesNotInheritTheFirstsFragmentCount) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "a", false) + fragment(0, "b", true) + text("c"));
  EXPECT_EQ(r.events, (Events{ev_text("ab", 2), ev_text("c", 1)}));
}

// ---- Autobahn 6.x: UTF-8 ----------------------------------------------------------------------------------------

TEST(WsAutobahn, Case6_1_EmptyTextMessagesInAnyNumberOfFramesAreValid) {
  WsSide a(GHTTP_WS_SERVER);
  EXPECT_EQ(a.feed(text("")).events, (Events{ev_text("")}));
  WsSide b(GHTTP_WS_SERVER);
  EXPECT_EQ(b.feed(fragment(1, "", false) + fragment(0, "", false) + fragment(0, "", true)).events,
      (Events{ev_text("", 3)}));
  WsSide c(GHTTP_WS_SERVER);
  EXPECT_EQ(c.feed(fragment(1, "", false) + fragment(0, "abc", false) + fragment(0, "", true)).events,
      (Events{ev_text("abc", 3)}));
}

TEST(WsAutobahn, Case6_2_ValidUtf8SplitAtEveryOctetOfTheMessageIsDeliveredWhole) {
  const std::string msg = "Hello-\xc2\xb5@\xc3\x9f\xc3\xb6\xc3\xa4\xc3\xbc\xc3\xa0\xc3\xa1-UTF-8!!";
  for (size_t cut = 0; cut <= msg.size(); cut++) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(fragment(1, msg.substr(0, cut), false) + fragment(0, msg.substr(cut), true));
    ASSERT_EQ(r.events.size(), 1u) << cut;
    EXPECT_EQ(r.events[0].data, msg) << cut;
    EXPECT_EQ(r.result, GHTTP_OK);
  }
}

TEST(WsAutobahn, Case6_3_InvalidUtf8ClosesWith1007) {
  for (std::string bad : {std::string("\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80\x65\x64\x69\x74\x65\x64"),
           std::string("\xff"), std::string("\xc0\x80"), std::string("\xf4\x90\x80\x80"),
           std::string("\xed\xa0\x80"), std::string("\xed\xbf\xbf"), std::string("\xe2\x82"),
           std::string("abc\xc3")}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(text(bad));
    expect_failed(r, GHTTP_ERR_CORRUPT, 1007, "invalid text");
    EXPECT_TRUE(r.events.empty());
  }
}

TEST(WsAutobahn, Case6_4_AnInvalidOctetFailsTheConnectionAtThatOctetAndNotAtTheEndOfTheMessage) {
  // Fragment one is good, fragment two ends with the bad octet, and fragment
  // three never arrives: the failure must not wait for it.
  std::string good = "\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5";
  WsSide s(GHTTP_WS_SERVER);
  EXPECT_EQ(s.feed(fragment(1, good, false)).result, GHTTP_OK);
  WsRun r = s.feed(fragment(0, "\xf4\x90\x80\x80", false));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1007, "fail fast");
  // The same inside one frame whose payload has not all arrived: the header
  // and the bad octets are enough.
  WsSide t(GHTTP_WS_SERVER);
  std::string frame_whole = wsf(1, "abc\xff" "defghijklmnop");
  WsRun r2 = t.feed(frame_whole.substr(0, 6 + 4));  // header, "abc", then the 0xff
  expect_failed(r2, GHTTP_ERR_CORRUPT, 1007, "fail fast in a frame");
}

TEST(WsAutobahn, Case6_4_3_TheFailureIsTheSameWhateverTheFeedBoundaries) {
  std::string in = fragment(1, "\xce\xba\xe1\xbd\xb9", false) + fragment(0, "\xf4\x90\x80\x80", false)
      + fragment(0, "tail", true);
  WsSide whole(GHTTP_WS_SERVER);
  WsRun a = whole.feed(in);
  WsSide bytes(GHTTP_WS_SERVER);
  WsRun b = bytes.feed_bytes(in);
  EXPECT_EQ(a, b);
  EXPECT_EQ(a.code, 1007);
}

TEST(WsAutobahn, Case6_5To6_22_ABoundaryCodePointIsValidAndTheOctetsAroundItAreNot) {
  struct Case { std::string bytes; bool valid; };
  std::vector<Case> cases = {
      {"\x7f", true}, {"\xc2\x80", true}, {"\xdf\xbf", true}, {"\xe0\xa0\x80", true},
      {"\xef\xbf\xbf", true}, {"\xf0\x90\x80\x80", true}, {"\xf4\x8f\xbf\xbf", true},
      {"\xed\x9f\xbf", true}, {"\xee\x80\x80", true}, {"\xef\xbf\xbd", true},
      {"\xef\xbf\xbe", true},  // U+FFFE: a noncharacter is not invalid UTF-8
      {"\x80", false}, {"\xbf", false}, {"\xc0\xaf", false}, {"\xe0\x80\xaf", false},
      {"\xf0\x80\x80\xaf", false}, {"\xf8\x80\x80\x80\xaf", false}, {"\xed\xa0\x80", false},
      {"\xed\xaf\xbf", false}, {"\xed\xb0\x80", false}, {"\xf4\x90\x80\x80", false},
      {"\xc2", false}, {"\xe0\xa0", false}, {"\xf0\x90\x80", false}, {"\xfe", false}, {"\xff", false},
  };
  for (auto & c : cases) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(text(c.bytes));
    if (c.valid) {
      EXPECT_EQ(r.events, (Events{ev_text(c.bytes)})) << c.bytes.size();
    } else {
      expect_failed(r, GHTTP_ERR_CORRUPT, 1007, "case");
    }
  }
}

TEST(WsConn, ACodePointSplitAcrossFramesAndAcrossFeedsIsAcceptedAtEveryBoundary) {
  const std::string msg = "a\xc2\xb5" "b\xe2\x82\xac" "c\xf0\x9f\x98\x80" "d";
  for (size_t cut = 0; cut <= msg.size(); cut++) {
    std::string in = fragment(1, msg.substr(0, cut), false) + fragment(0, msg.substr(cut), true);
    for (size_t piece : {size_t(0), size_t(1), size_t(2), size_t(3)}) {
      WsSide s(GHTTP_WS_SERVER);
      WsRun r = s.feed(in, piece);
      ASSERT_EQ(r.events.size(), 1u) << cut << " " << piece;
      EXPECT_EQ(r.events[0].data, msg);
    }
  }
}

TEST(WsConn, ATextMessageThatEndsInsideACodePointIsInvalidEvenIfItsFramesWereFine) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "a\xe2\x82", false) + fragment(0, "", true));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1007, "ends in a code point");
}

TEST(WsConn, BinaryMessagesAreNotCheckedForUtf8) {
  WsSide s(GHTTP_WS_SERVER);
  EXPECT_EQ(s.feed(binary("\xff\xfe\xed\xa0\x80")).events, (Events{ev_binary("\xff\xfe\xed\xa0\x80")}));
}

// ---- Autobahn 7.x: closing ---------------------------------------------------------------------------------------------

TEST(WsAutobahn, Case7_1_1_ACloseFromThePeerIsReportedAndEchoedAndTheHandshakeIsComplete) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(close_frame(1000, "Hello World!"));
  EXPECT_EQ(r.events, (Events{ev_close(1000, "Hello World!")}));
  auto f = ws_parse_frames(r.output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].opcode, 8);
  EXPECT_EQ(ws_close_code(f[0]), 1000);
  EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_CLOSED);
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_OK);
}

TEST(WsAutobahn, Case7_1_2To7_1_5_AnythingAfterTheCloseFailsTheConnectionWith1002) {
  // The peer's Close ended what it may say; the matrix's "bad code or frame after
  // close closes 1002". The Close itself was echoed, so the failure queues
  // nothing, and the connection is no longer a clean closure.
  for (std::string after : {close_frame(1000), text("x"), ping("p"), fragment(1, "x", false), pong(""),
           std::string("\x81"), std::string("x")}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun first = s.feed(close_frame(1000));
    EXPECT_EQ(first.events, (Events{ev_close(1000)}));
    EXPECT_EQ(ws_parse_frames(first.output).size(), 1u);
    EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_OK);
    size_t used = 99;
    GHTTP_WsEvent e;
    EXPECT_EQ(ghttp_ws_conn_feed(s.get(), after.data(), after.size(), &used, &e), GHTTP_ERR_CORRUPT);
    uint16_t code = 0;
    const char * reason = nullptr;
    EXPECT_EQ(ghttp_ws_conn_error(s.get(), &code, &reason), GHTTP_ERR_CORRUPT);
    EXPECT_EQ(code, 1002);
    EXPECT_NE(std::string(reason).find("after a Close"), std::string::npos);
    EXPECT_EQ(ghttp_ws_conn_output_size(s.get()), 0u);
    EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_FAILED);
    EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_ERR_CORRUPT);
  }
}

TEST(WsAutobahn, Case7_1_2_TrailingBytesInTheSameReadAsTheCloseGiveTheCloseThenFail1002) {
  // One read holds the Close and more. The Close is reported (and consumed alone);
  // the next feed, which offers the rest, fails.
  for (std::string rest : {close_frame(1000), text("x"), std::string("\x88")}) {
    WsSide s(GHTTP_WS_SERVER);
    std::string in = close_frame(1000) + rest;
    size_t used;
    GHTTP_WsEvent e;
    ASSERT_EQ(ghttp_ws_conn_feed(s.get(), in.data(), in.size(), &used, &e), GHTTP_OK);
    EXPECT_EQ(e.type, GHTTP_WS_EVENT_CLOSE);
    EXPECT_EQ(used, close_frame(1000).size());
    EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_CLOSED);
    size_t used2;
    EXPECT_EQ(ghttp_ws_conn_feed(s.get(), in.data() + used, in.size() - used, &used2, &e), GHTTP_ERR_CORRUPT);
    uint16_t code = 0;
    ghttp_ws_conn_error(s.get(), &code, nullptr);
    EXPECT_EQ(code, 1002);
    EXPECT_EQ(ws_parse_frames(s.take_output()).size(), 1u);  // only the echo
    EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_FAILED);
  }
}

TEST(WsAutobahn, Case7_1_1_ACloseWithNothingAfterItIsACleanFinish) {
  // And when this end closed first, the peer's Close completes it; nothing follows.
  WsSide s(GHTTP_WS_CLIENT);
  ASSERT_EQ(ghttp_ws_conn_close(s.get(), 1000, "bye", 3), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_ERR_CORRUPT);  // the peer has not answered
  std::string reply = wsf(8, std::string("\x03\xe8", 2), true, false);
  WsRun r = s.feed(reply);
  EXPECT_EQ(r.events, (Events{ev_close(1000)}));
  EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_CLOSED);
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_OK);
}

TEST(WsAutobahn, Case7_3_1_ACloseWithNoBodyIsReportedAs1005AndAnsweredWithNoBody) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(close_frame());
  EXPECT_EQ(r.events, (Events{ev_close(1005)}));
  auto f = ws_parse_frames(r.output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].opcode, 8);
  EXPECT_EQ(f[0].payload, "");
}

TEST(WsAutobahn, Case7_3_2_ACloseWithAOneOctetBodyClosesWith1002) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(wsf(8, "\x03"));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "one octet");
}

TEST(WsAutobahn, Case7_3_3To7_3_6_ACodeAloneAReasonAndTheLongestReason) {
  WsSide a(GHTTP_WS_SERVER);
  EXPECT_EQ(a.feed(close_frame(1000)).events, (Events{ev_close(1000)}));
  WsSide b(GHTTP_WS_SERVER);
  EXPECT_EQ(b.feed(close_frame(1000, "Hello World!")).events, (Events{ev_close(1000, "Hello World!")}));
  std::string r123(123, 'r');
  WsSide c(GHTTP_WS_SERVER);
  EXPECT_EQ(c.feed(close_frame(1000, r123)).events, (Events{ev_close(1000, r123)}));
  WsSide d(GHTTP_WS_SERVER);
  WsRun r = d.feed(close_frame(1000, std::string(124, 'r')));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "reason of 124");
}

TEST(WsAutobahn, Case7_5_1_AReasonThatIsNotUtf8ClosesWith1007) {
  for (std::string bad : {std::string("\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80\x65\x64\x69\x74\x65\x64"),
           std::string("\xff"), std::string("ab\xc3")}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(close_frame(1000, bad));
    expect_failed(r, GHTTP_ERR_CORRUPT, 1007, "reason");
    EXPECT_TRUE(r.events.empty());
  }
}

TEST(WsAutobahn, Case7_7_AValidCloseCodeIsReportedAndEchoed) {
  for (int code : {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999}) {
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(close_frame(static_cast<uint16_t>(code)));
    EXPECT_EQ(r.events, (Events{ev_close(static_cast<uint16_t>(code))})) << code;
    auto f = ws_parse_frames(r.output);
    ASSERT_EQ(f.size(), 1u) << code;
    EXPECT_EQ(ws_close_code(f[0]), code);
  }
}

TEST(WsAutobahn, Case7_9_And7_13_AnInvalidCloseCodeClosesWith1002) {
  for (int code : {0, 1, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535}) {
    WsSide s(GHTTP_WS_SERVER);
    std::string body;
    body.push_back(static_cast<char>(code >> 8));
    body.push_back(static_cast<char>(code));
    WsRun r = s.feed(wsf(8, body));
    expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "code " + std::to_string(code));
    EXPECT_TRUE(r.events.empty());
  }
}

TEST(WsConn, TheClosingHandshakeStartedHereWaitsForThePeersCloseAndMessagesStillArrive) {
  WsPair p;
  ASSERT_EQ(ghttp_ws_conn_close(p.server.get(), 1001, "going away", 10), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_state(p.server.get()), GHTTP_WS_STATE_CLOSING);
  // Before the client has seen the Close it sends a message; the server,
  // closing, still delivers it.
  ASSERT_EQ(ghttp_ws_conn_send_message(p.client.get(), GHTTP_WS_MESSAGE_TEXT, "late", 4), GHTTP_OK);
  std::string c = p.client.take_output();
  std::string close_on_the_wire = p.server.take_output();
  WsRun s1 = p.server.feed(c);
  EXPECT_EQ(s1.events, (Events{ev_text("late")}));
  // Now the Close reaches the client, which answers.
  p.to_client = close_on_the_wire;
  p.pump();
  EXPECT_EQ(p.client_events, (Events{ev_close(1001, "going away")}));
  EXPECT_EQ(p.server_events, (Events{ev_close(1001)}));
  EXPECT_EQ(ghttp_ws_conn_state(p.server.get()), GHTTP_WS_STATE_CLOSED);
  EXPECT_EQ(ghttp_ws_conn_state(p.client.get()), GHTTP_WS_STATE_CLOSED);
  EXPECT_EQ(ghttp_ws_conn_finish(p.server.get()), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_finish(p.client.get()), GHTTP_OK);
}

TEST(WsConn, ACloseSentWithNoCodeIsAnEmptyFrameAndThePeerSees1005) {
  WsPair p;
  ASSERT_EQ(ghttp_ws_conn_close(p.client.get(), 0, nullptr, 0), GHTTP_OK);
  p.pump();
  EXPECT_EQ(p.server_events, (Events{ev_close(1005)}));
  EXPECT_EQ(ghttp_ws_conn_state(p.client.get()), GHTTP_WS_STATE_CLOSED);
}

TEST(WsConn, ACloseIsSentOnceAndNothingElseAfterIt) {
  WsSide s(GHTTP_WS_SERVER);
  ASSERT_EQ(ghttp_ws_conn_close(s.get(), 1000, nullptr, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 1000, nullptr, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "x", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_ping(s.get(), "x", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_pong(s.get(), "x", 1), GHTTP_ERR_INVALID);
  // And a Ping from the peer after our Close is answered with nothing.
  s.take_output();
  WsRun r = s.feed(ping("late"));
  EXPECT_EQ(r.events, (Events{ev(GHTTP_WS_EVENT_PING, "late")}));
  EXPECT_EQ(r.output, "");
}

TEST(WsConn, ACloseTheCallerSendsIsCheckedLikeTheOneItWouldReceive) {
  WsSide s(GHTTP_WS_SERVER);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 1005, nullptr, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 1006, nullptr, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 999, nullptr, 0), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 1000, "\xff", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 1000, std::string(124, 'x').data(), 124), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 0, "x", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_close(s.get(), 1000, std::string(123, 'x').data(), 123), GHTTP_OK);
}

TEST(WsConn, FinishReportsAnAbnormalEndWhenTheCloseHandshakeDidNotComplete) {
  WsSide s(GHTTP_WS_SERVER);
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_ERR_CORRUPT);
  ASSERT_EQ(ghttp_ws_conn_close(s.get(), 1000, nullptr, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_ERR_CORRUPT);
  s.feed(close_frame(1000));
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_finish(nullptr), GHTTP_ERR_INVALID);
}

TEST(WsConn, ACloseDiscardsAMessageThatWasInProgress) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(fragment(1, "partial", false) + close_frame(1000));
  EXPECT_EQ(r.events, (Events{ev_close(1000)}));
}

// ---- Masking -----------------------------------------------------------------------------------------------------------------

TEST(WsConn, AServerRefusesAnUnmaskedClientFrameWith1002) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(text("Hello", false));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "unmasked");
  EXPECT_TRUE(r.events.empty());
  // The close it sends is not masked: it is the server's frame.
  auto frames = ws_parse_frames(r.output);
  ASSERT_FALSE(frames.empty());
  EXPECT_FALSE(frames.back().masked);
}

TEST(WsConn, AClientRefusesAMaskedServerFrameWith1002AndMasksItsOwnClose) {
  WsSide c(GHTTP_WS_CLIENT);
  WsRun r = c.feed(text("Hello", true));
  expect_failed(r, GHTTP_ERR_CORRUPT, 1002, "masked");
  auto frames = ws_parse_frames(r.output);
  ASSERT_FALSE(frames.empty());
  EXPECT_TRUE(frames.back().masked);
}

TEST(WsConn, EveryFrameAClientSendsIsMaskedWithAFreshKey) {
  WsSide c(GHTTP_WS_CLIENT);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, "same", 4), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, "same", 4), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_ping(c.get(), "same", 4), GHTTP_OK);
  std::string out = c.take_output();
  auto f = ws_parse_frames(out);
  ASSERT_EQ(f.size(), 3u);
  for (auto & fr : f) {
    EXPECT_TRUE(fr.masked);
    EXPECT_EQ(fr.payload, "same");
  }
  // Same payload, different bytes on the wire: the keys differ.
  EXPECT_NE(out.substr(0, 10), out.substr(10, 10));
}

TEST(WsConn, TheMaskingKeyComesFromTheSourceItWasGiven) {
  WsSide c(GHTTP_WS_CLIENT);
  struct Fixed { static GHTTP_Result f(void *, void * out, size_t n) {
    static const uint8_t k[4] = {0x37, 0xfa, 0x21, 0x3d};
    memcpy(out, k, n);
    return GHTTP_OK;
  } };
  ghttp_ws_conn_set_random(c.get(), Fixed::f, nullptr);
  ASSERT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, "Hello", 5), GHTTP_OK);
  // The RFC's own example, to the octet.
  EXPECT_EQ(c.take_output(), std::string("\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", 11));
}

TEST(WsConn, AFailingRandomSourceIsAnIoErrorAndQueuesNothing) {
  WsSide c(GHTTP_WS_CLIENT);
  struct Broken { static GHTTP_Result f(void *, void *, size_t) { return GHTTP_ERR_IO; } };
  ghttp_ws_conn_set_random(c.get(), Broken::f, nullptr);
  EXPECT_EQ(ghttp_ws_conn_send_message(c.get(), GHTTP_WS_MESSAGE_TEXT, "x", 1), GHTTP_ERR_IO);
  EXPECT_EQ(ghttp_ws_conn_send_ping(c.get(), "x", 1), GHTTP_ERR_IO);
  EXPECT_EQ(ghttp_ws_conn_close(c.get(), 1000, nullptr, 0), GHTTP_ERR_IO);
  EXPECT_EQ(ghttp_ws_conn_output_size(c.get()), 0u);
  EXPECT_EQ(ghttp_ws_conn_state(c.get()), GHTTP_WS_STATE_OPEN);
}

TEST(WsConn, AServerSendsUnmaskedFrames) {
  WsSide s(GHTTP_WS_SERVER);
  ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "Hello", 5), GHTTP_OK);
  EXPECT_EQ(s.take_output(), std::string("\x81\x05Hello", 7));
}

// ---- Sending ---------------------------------------------------------------------------------------------------------------------------

TEST(WsSend, FragmentsAreFramedAsContinuationsAndEndWithFin) {
  WsSide s(GHTTP_WS_SERVER);
  ASSERT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "Hel", 3, 0), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_ping(s.get(), "p", 1), GHTTP_OK);  // control frames may interleave
  ASSERT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "lo", 2, 1), GHTTP_OK);
  EXPECT_EQ(s.take_output(), std::string("\x01\x03Hel\x89\x01p\x80\x02lo", 12));
}

TEST(WsSend, ATextMessageThatIsNotUtf8IsRefusedWhereverItIsCut) {
  WsSide s(GHTTP_WS_SERVER);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "\xff", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "\xe2\x82", 2), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_BINARY, "\xff", 1), GHTTP_OK);
  EXPECT_EQ(s.take_output().size(), 3u);
  // A code point split over fragments is fine; one that never ends is not.
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "\xe2\x82", 2, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "\xac", 1, 1), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "\xe2", 1, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "", 0, 1), GHTTP_ERR_INVALID);
}

TEST(WsSend, AFragmentedMessageInProgressRefusesAWholeOneAndAChangeOfType) {
  WsSide s(GHTTP_WS_SERVER);
  ASSERT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "a", 1, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "b", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_BINARY, "b", 1, 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_TEXT, "b", 1, 1), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "c", 1), GHTTP_OK);
}

TEST(WsSend, ControlPayloadsAreAtMost125OctetsAndArgumentsAreChecked) {
  WsSide s(GHTTP_WS_SERVER);
  std::string p125(125, 'x');
  EXPECT_EQ(ghttp_ws_conn_send_ping(s.get(), p125.data(), 125), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_ping(s.get(), p125.data(), 126), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_pong(s.get(), nullptr, 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_ping(s.get(), nullptr, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), static_cast<GHTTP_WsMessageType>(3), "x", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, nullptr, 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, nullptr, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_message(nullptr, GHTTP_WS_MESSAGE_TEXT, "x", 1), GHTTP_ERR_INVALID);
}

TEST(WsSend, AnEmptyMessageIsAFrameOfNoPayload) {
  WsSide s(GHTTP_WS_SERVER);
  ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_BINARY, nullptr, 0), GHTTP_OK);
  EXPECT_EQ(s.take_output(), std::string("\x82\x00", 2));
}

// ---- Events and extensions ---------------------------------------------------------------------------------------------------------------

TEST(WsConn, AReservedBitAnExtensionClaimedIsLetThroughAndReported) {
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  n.extension_rsv = GHTTP_WS_RSV2;
  WsSide s(GHTTP_WS_SERVER, nullptr, &n);
  WsRun r = s.feed(wsf(1, "x", true, true, 2));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rsv, GHTTP_WS_RSV2);
  EXPECT_EQ(r.events[0].data, "x");
  // RSV3 was not claimed.
  WsSide t(GHTTP_WS_SERVER, nullptr, &n);
  expect_failed(t.feed(wsf(1, "x", true, true, 1)), GHTTP_ERR_CORRUPT, 1002, "rsv3");
  // And RSV1 is permessage-deflate's, which was not negotiated.
  WsSide u(GHTTP_WS_SERVER, nullptr, &n);
  expect_failed(u.feed(wsf(1, "x", true, true, 4)), GHTTP_ERR_CORRUPT, 1002, "rsv1");
}

TEST(WsConn, AReservedBitAnExtensionClaimedIsLetThroughOnContinuationsAndReportedForTheFirstFrameOnly) {
  // RFC 6455 section 5.2: a reserved bit means what a negotiated extension says
  // it means, on any frame. Here that is: allowed on every frame, control
  // frames included, and reported with the message by its first frame's bits.
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  n.extension_rsv = GHTTP_WS_RSV2;
  WsSide s(GHTTP_WS_SERVER, nullptr, &n);
  WsRun r = s.feed(wsf(1, "a", false, true, 2) + wsf(0, "b", false, true, 2) + wsf(9, "p", true, true, 2)
      + wsf(0, "c", true, true, 0));
  ASSERT_EQ(r.events.size(), 2u);
  EXPECT_EQ(r.events[0].type, GHTTP_WS_EVENT_PING);
  EXPECT_EQ(r.events[1].data, "abc");
  EXPECT_EQ(r.events[1].rsv, GHTTP_WS_RSV2);
  // One that nobody claimed is refused on a continuation as anywhere.
  WsSide t(GHTTP_WS_SERVER, nullptr, &n);
  WsRun q = t.feed(wsf(1, "a", false, true, 2) + wsf(0, "b", true, true, 1));
  EXPECT_EQ(q.code, 1002);
}

TEST(WsConn, TheFragmentCountOfAMessageIsReported) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(text("a") + fragment(2, "b", false) + fragment(0, "c", false) + fragment(0, "d", true));
  EXPECT_EQ(r.events, (Events{ev_text("a", 1), ev_binary("bcd", 3)}));
}

TEST(WsConn, AMessageIsLentUntilTheNextFeedAndAnEventDataIsNeverNull) {
  WsSide s(GHTTP_WS_SERVER);
  size_t used;
  GHTTP_WsEvent e;
  std::string in = text("hello") + text("");
  ASSERT_EQ(ghttp_ws_conn_feed(s.get(), in.data(), in.size(), &used, &e), GHTTP_OK);
  ASSERT_EQ(e.type, GHTTP_WS_EVENT_TEXT);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(e.data), e.data_len), "hello");
  size_t used2;
  ASSERT_EQ(ghttp_ws_conn_feed(s.get(), in.data() + used, in.size() - used, &used2, &e), GHTTP_OK);
  ASSERT_EQ(e.type, GHTTP_WS_EVENT_TEXT);
  EXPECT_EQ(e.data_len, 0u);
  EXPECT_NE(e.data, nullptr);
  EXPECT_EQ(e.size, sizeof(e));
}

TEST(WsConn, AFailedConnectionStaysFailedAndSendsNothingMore) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(text("x", false));
  EXPECT_EQ(r.result, GHTTP_ERR_CORRUPT);
  WsRun again = s.feed(text("fine"));
  EXPECT_EQ(again.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(again.output, "");
  EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_FAILED);
  uint16_t code;
  const char * reason;
  EXPECT_EQ(ghttp_ws_conn_error(s.get(), &code, &reason), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(code, 1002);
  EXPECT_NE(std::string(reason), "");
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "x", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_ERR_CORRUPT);
}

TEST(WsConn, TheCloseSentOnAFailureCarriesTheCodeAndAReasonThatFitsAControlFrame) {
  WsSide s(GHTTP_WS_SERVER);
  WsRun r = s.feed(wsf(11, ""));
  auto f = ws_parse_frames(r.output);
  ASSERT_EQ(f.size(), 1u);
  EXPECT_LE(f[0].payload.size(), 125u);
  GHTTP_WsUtf8 v;
  ghttp_ws_utf8_init(&v);
  EXPECT_EQ(ghttp_ws_utf8_feed(&v, f[0].payload.data() + 2, f[0].payload.size() - 2), GHTTP_OK);
}

TEST(WsConn, ATruncatedFrameIsNotAnErrorUntilTheInputEnds) {
  WsSide s(GHTTP_WS_SERVER);
  std::string f = text("hello world");
  WsRun r = s.feed(f.substr(0, f.size() - 1));
  EXPECT_EQ(r.result, GHTTP_OK);
  EXPECT_TRUE(r.events.empty());
  EXPECT_EQ(ghttp_ws_conn_finish(s.get()), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(s.feed(f.substr(f.size() - 1)).events, (Events{ev_text("hello world")}));
}

// ---- Limits -------------------------------------------------------------------------------------------------------------------------------------

TEST(WsLimitsConn, AFrameOverTheFrameLimitIsRefusedAtItsHeader) {
  GHTTP_WsLimits l = limits();
  l.max_frame_payload = 100;
  WsSide ok(GHTTP_WS_SERVER, &l);
  EXPECT_EQ(ok.feed(binary(std::string(100, 'x'))).events.size(), 1u);
  WsSide s(GHTTP_WS_SERVER, &l);
  // Only the header: the payload never has to arrive.
  WsRun r = s.feed(wsf_header_only(2, 101));
  expect_failed(r, GHTTP_ERR_LIMIT, 1009, "frame");
}

TEST(WsLimitsConn, AMessageOverTheMessageLimitIsRefusedBeforeItsLastFrameArrives) {
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 100; l.max_frame_payload = 100;
  WsSide ok(GHTTP_WS_SERVER, &l);
  EXPECT_EQ(ok.feed(fragment(2, std::string(60, 'x'), false) + fragment(0, std::string(40, 'y'), true)).events.size(), 1u);
  WsSide s(GHTTP_WS_SERVER, &l);
  EXPECT_EQ(s.feed(fragment(2, std::string(60, 'x'), false)).result, GHTTP_OK);
  // The second header says 41 more: 101 in all. It is refused at the header.
  WsRun r = s.feed(wsf_header_only(0, 41));
  expect_failed(r, GHTTP_ERR_LIMIT, 1009, "message");
}

TEST(WsLimitsConn, AMessageOfExactlyTheLimitIsAcceptedAndOneOctetMoreIsNot) {
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 1000; l.max_frame_payload = 1000;
  WsSide a(GHTTP_WS_SERVER, &l);
  EXPECT_EQ(a.feed(binary(std::string(1000, 'x'))).events.size(), 1u);
  WsSide b(GHTTP_WS_SERVER, &l);
  expect_failed(b.feed(binary(std::string(1001, 'x'))), GHTTP_ERR_LIMIT, 1009, "one over");
}

TEST(WsLimitsConn, AFragmentFloodIsStoppedAtTheLimitNotOneFragmentLater) {
  GHTTP_WsLimits l = limits();
  l.max_fragments = 5;
  WsSide s(GHTTP_WS_SERVER, &l);
  std::string in = fragment(2, "a", false);
  for (int i = 0; i < 3; i++) in += fragment(0, "a", false);
  EXPECT_EQ(s.feed(in).result, GHTTP_OK);  // four so far
  EXPECT_EQ(s.feed(fragment(0, "a", false)).result, GHTTP_OK);  // the fifth
  WsRun r = s.feed(fragment(0, "a", false));
  expect_failed(r, GHTTP_ERR_LIMIT, 1009, "sixth fragment");
  // Five fragments that end the message are fine.
  WsSide t(GHTTP_WS_SERVER, &l);
  std::string five = fragment(2, "a", false) + fragment(0, "a", false) + fragment(0, "a", false)
      + fragment(0, "a", false) + fragment(0, "a", true);
  EXPECT_EQ(t.feed(five).events, (Events{ev_binary("aaaaa", 5)}));
}

TEST(WsLimitsConn, ControlFramesPerIntervalAreCountedAndTheIntervalRenews) {
  GHTTP_WsLimits l = limits();
  l.max_control_per_interval = 3;
  l.interval_ms = 1000;
  WsSide s(GHTTP_WS_SERVER, &l);
  ghttp_ws_conn_tick(s.get(), 0);
  EXPECT_EQ(s.feed(ping("1") + pong("2") + ping("3")).result, GHTTP_OK);
  ghttp_ws_conn_tick(s.get(), 999);  // not yet a new interval
  WsRun over = s.feed(ping("4"));
  expect_failed(over, GHTTP_ERR_LIMIT, 1008, "fourth control frame", false);
  WsSide t(GHTTP_WS_SERVER, &l);
  ghttp_ws_conn_tick(t.get(), 0);
  EXPECT_EQ(t.feed(ping("1") + ping("2") + ping("3")).result, GHTTP_OK);
  ghttp_ws_conn_tick(t.get(), 1000);
  EXPECT_EQ(t.feed(ping("1") + ping("2") + ping("3")).result, GHTTP_OK);
  ghttp_ws_conn_tick(t.get(), 5);  // a clock that ran backwards starts an interval too
  EXPECT_EQ(t.feed(ping("1") + ping("2") + ping("3")).result, GHTTP_OK);
}

TEST(WsLimitsConn, DataFramesAreNotControlFrames) {
  GHTTP_WsLimits l = limits();
  l.max_control_per_interval = 1;
  WsSide s(GHTTP_WS_SERVER, &l);
  std::string in;
  for (int i = 0; i < 50; i++) in += text("x");
  EXPECT_EQ(s.feed(in).events.size(), 50u);
}

TEST(WsLimitsConn, ANeverTickedConnectionCountsControlFramesOverItsWholeLife) {
  // Without ghttp_ws_conn_tick() the interval never starts, so the cap is a
  // total for the connection (documented in ws_frame.h): safe, because nothing
  // is unbounded, and wrong for a connection that lives long.
  GHTTP_WsLimits l = limits();
  l.max_control_per_interval = 5;
  WsSide s(GHTTP_WS_SERVER, &l);
  for (int i = 0; i < 5; i++) EXPECT_EQ(s.feed(ping("p")).result, GHTTP_OK) << i;
  WsRun r = s.feed(ping("p"));
  expect_failed(r, GHTTP_ERR_LIMIT, 1008, "the sixth control frame of a never-ticked connection", false);
  WsSide t(GHTTP_WS_SERVER, &l);
  for (int round = 0; round < 3; round++) {
    ghttp_ws_conn_tick(t.get(), static_cast<uint64_t>(round) * 20000);
    for (int i = 0; i < 5; i++) EXPECT_EQ(t.feed(ping("p")).result, GHTTP_OK) << round;
  }
}

TEST(WsLimitsConn, ASendThatWouldOverfillTheQueueIsRefusedWithNothingQueued) {
  GHTTP_WsLimits l = limits();
  l.max_buffered_bytes = 300;
  WsSide s(GHTTP_WS_SERVER, &l);
  std::string m(200, 'x');
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), m.size()), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), m.size()), GHTTP_ERR_LIMIT);
  EXPECT_EQ(ghttp_ws_conn_output_size(s.get()), 204u);
  EXPECT_EQ(ghttp_ws_conn_send_ping(s.get(), m.data(), 100), GHTTP_ERR_LIMIT);
  EXPECT_EQ(ghttp_ws_conn_output_size(s.get()), 204u);
  EXPECT_EQ(ghttp_ws_conn_state(s.get()), GHTTP_WS_STATE_OPEN);
  EXPECT_EQ(ghttp_ws_conn_send_ping(s.get(), "ok", 2), GHTTP_OK);
}

TEST(WsLimitsConn, AMessageLargerThanTheMessageLimitCannotBeSent) {
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 100; l.max_frame_payload = 100;
  WsSide s(GHTTP_WS_SERVER, &l);
  std::string m(101, 'x');
  EXPECT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), m.size()), GHTTP_ERR_LIMIT);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), 60, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), 41, 1), GHTTP_ERR_LIMIT);
  EXPECT_EQ(ghttp_ws_conn_send_fragment(s.get(), GHTTP_WS_MESSAGE_BINARY, m.data(), 40, 1), GHTTP_OK);
}

TEST(WsLimitsConn, ALimitsStructFromAnOlderCallerIsReadAsFarAsItGoes) {
  // Only the fields it has: the rest are the defaults.
  GHTTP_WsLimits l = limits();
  l.size = offsetof(GHTTP_WsLimits, max_fragments);
  l.max_frame_payload = 50;
  l.max_fragments = 1;  // beyond what its size says: ignored
  WsSide s(GHTTP_WS_SERVER, &l);
  EXPECT_EQ(s.feed(fragment(2, "a", false) + fragment(0, "b", true)).events.size(), 1u);
  expect_failed(WsSide(GHTTP_WS_SERVER, &l).feed(binary(std::string(51, 'x'))), GHTTP_ERR_LIMIT, 1009, "frame");
}

TEST(WsLimitsConn, TheMessageLimitIsEnforcedOnABytewiseFeedToo) {
  GHTTP_WsLimits l = limits();
  l.max_message_bytes = 10; l.max_frame_payload = 10;
  WsSide s(GHTTP_WS_SERVER, &l);
  WsRun r = s.feed_bytes(binary(std::string(11, 'x')));
  expect_failed(r, GHTTP_ERR_LIMIT, 1009, "bytewise");
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
