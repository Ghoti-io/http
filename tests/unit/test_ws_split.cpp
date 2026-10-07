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
 * The connection gives the same events, the same output and the same error
 * however its input is cut, and a refused allocation is OOM or no change and
 * never a leak.
 */

#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"
#include "ws_helpers.h"

using namespace ghttptest;

namespace {

/** Run @p stream into a fresh connection every way it can be cut, and require one answer. */
void expect_split_independent(GHTTP_WsRole role, const std::string & stream,
    const GHTTP_WsLimits * limits, const GHTTP_WsNegotiated * neg, const std::string & what) {
  WsSide whole(role, limits, neg);
  WsRun expected = whole.feed(stream);
  for (size_t piece : {size_t(1), size_t(2), size_t(3), size_t(5), size_t(7), size_t(64)}) {
    WsSide s(role, limits, neg);
    EXPECT_EQ(s.feed(stream, piece), expected) << what << " piece " << piece;
  }
  // Every two-way split.
  for (size_t cut = 0; cut <= stream.size(); cut++) {
    WsSide s(role, limits, neg);
    WsRun a = s.feed(stream.substr(0, cut));
    WsRun b = a.result == GHTTP_OK ? s.feed(stream.substr(cut)) : WsRun{};
    WsRun joined = a;
    joined.events.insert(joined.events.end(), b.events.begin(), b.events.end());
    joined.output += b.output;
    if (a.result == GHTTP_OK) {
      joined.result = b.result;
      joined.code = b.code;
    }
    EXPECT_EQ(joined, expected) << what << " cut " << cut;
    if (!(joined == expected)) break;
  }
}

std::string valid_stream() {
  return text("Hello") + binary(ws_random_bytes(300)) + ping("p") + wsf(1, "Hel", false) + pong("q")
      + wsf(0, "lo ", false) + wsf(0, "\xc2\xb5", false) + wsf(0, "", true)
      + text(ws_lorem(2000)) + text("") + wsf(2, "a", false) + wsf(0, "b", true) + close_frame(1000, "bye");
}

} // namespace

TEST(WsSplit, AValidStreamGivesTheSameAnswerCutAnywhereAtEitherRole) {
  expect_split_independent(GHTTP_WS_SERVER, valid_stream(), nullptr, nullptr, "server");
  // As a client reads it: unmasked.
  std::string s = text("Hello", false) + binary(ws_random_bytes(300), false) + ping("p", false)
      + wsf(1, "Hel", false, false) + wsf(0, "lo", true, false) + close_frame(1001, "", false);
  expect_split_independent(GHTTP_WS_CLIENT, s, nullptr, nullptr, "client");
}

TEST(WsSplit, EachKindOfBadStreamGivesTheSameAnswerCutAnywhere) {
  std::vector<std::pair<std::string, std::string>> bad = {
      {"unmasked", text("x", false)},
      {"reserved bit", text("ok") + wsf(1, "x", true, true, 2)},
      {"reserved opcode", text("ok") + wsf(3, "x")},
      {"fragmented ping", wsf(9, "x", false)},
      {"long ping", ping(std::string(126, 'x'))},
      {"orphan continuation", wsf(0, "x", true)},
      {"new message in fragments", wsf(1, "a", false) + wsf(1, "b", true)},
      {"bad utf-8", text("ab\xff")},
      {"bad utf-8 split", wsf(1, "a\xe2", false) + wsf(0, "\x28", true)},
      {"utf-8 ends early", wsf(1, "a\xe2\x82", true)},
      {"close one octet", wsf(8, "\x01")},
      {"close bad code", close_frame(1005)},
      {"close bad reason", close_frame(1000, "\xff")},
      {"non-minimal length", wsf(2, std::string(5, 'x'), true, true, 0, 0x01020304, 16)},
      {"length top bit", std::string("\x82\xff\x80\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04", 14)},
  };
  for (auto & b : bad) {
    expect_split_independent(GHTTP_WS_SERVER, b.second, nullptr, nullptr, b.first);
    WsSide s(GHTTP_WS_SERVER);
    WsRun r = s.feed(b.second);
    EXPECT_NE(r.result, GHTTP_OK) << b.first;
  }
}

TEST(WsSplit, TheLimitsStopAtTheSamePlaceWhateverTheCut) {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  l.max_frame_payload = 50;
  l.max_message_bytes = 80;
  l.max_fragments = 4;
  l.max_control_per_interval = 3;
  expect_split_independent(GHTTP_WS_SERVER, binary(std::string(51, 'x')), &l, nullptr, "frame");
  expect_split_independent(GHTTP_WS_SERVER, wsf(2, std::string(50, 'a'), false) + wsf(0, std::string(31, 'b'), true), &l, nullptr, "message");
  expect_split_independent(GHTTP_WS_SERVER, wsf(2, "a", false) + wsf(0, "a", false) + wsf(0, "a", false) + wsf(0, "a", false) + wsf(0, "a", true), &l, nullptr, "fragments");
  expect_split_independent(GHTTP_WS_SERVER, ping("a") + ping("b") + ping("c") + ping("d"), &l, nullptr, "control");
}

TEST(WsSplit, RandomStreamsOfValidAndInvalidFramesGiveTheSameAnswerWholeAndByteByByte) {
  std::mt19937 rng(20261006);
  const std::vector<std::string> pieces = {
      text("hello"), text(""), binary("\x00\x01\xff"), ping("pp"), pong(""), wsf(1, "frag", false),
      wsf(0, "ment", false), wsf(0, "end", true), wsf(2, "bin", false), wsf(0, "ary", true),
      text("\xe2\x82\xac"), wsf(1, "\xe2", false), wsf(0, "\x82\xac", true), text("\xff"),
      wsf(3, "x"), wsf(1, "x", true, true, 1), text("x", false), close_frame(1000),
      close_frame(), wsf(8, "\x03"), wsf(0, "x", true), std::string("\x81"), std::string("\x81\x85"),
  };
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  l.max_fragments = 3;
  l.max_control_per_interval = 4;
  for (int trial = 0; trial < 3000; trial++) {
    std::string stream;
    int n = 1 + static_cast<int>(rng() % 8);
    for (int i = 0; i < n; i++) stream += pieces[rng() % pieces.size()];
    WsSide a(GHTTP_WS_SERVER, &l);
    WsSide b(GHTTP_WS_SERVER, &l);
    WsRun whole = a.feed(stream);
    WsRun bytes = b.feed_bytes(stream);
    ASSERT_EQ(whole, bytes) << "trial " << trial << " stream of " << stream.size() << " bytes";
    size_t cut = rng() % (stream.size() + 1);
    WsSide c(GHTTP_WS_SERVER, &l);
    WsRun r1 = c.feed(stream.substr(0, cut));
    WsRun r2 = r1.result == GHTTP_OK ? c.feed(stream.substr(cut)) : WsRun{};
    WsRun joined = r1;
    joined.events.insert(joined.events.end(), r2.events.begin(), r2.events.end());
    joined.output += r2.output;
    if (r1.result == GHTTP_OK) {
      joined.result = r2.result;
      joined.code = r2.code;
    }
    ASSERT_EQ(whole, joined) << "trial " << trial << " cut " << cut;
  }
}

// ---- Allocation failure ------------------------------------------------------------------------------------

TEST(WsOom, EveryAllocationFailingInTurnIsOomOrTheSameAnswerAndNeverALeak) {
  std::string stream = text("Hello") + wsf(1, "frag", false) + ping("p") + wsf(0, "ment", true)
      + binary(ws_random_bytes(1000)) + close_frame(1000, "bye");
  FailingAllocator counter(static_cast<size_t>(-1));
  WsRun expected;
  {
    WsSide s(GHTTP_WS_SERVER, nullptr, nullptr, counter.get());
    ASSERT_EQ(s.created(), GHTTP_OK);
    expected = s.feed(stream);
  }
  ASSERT_EQ(expected.events.size(), 5u);
  EXPECT_EQ(counter.live(), 0u);
  size_t total = counter.requests();
  ASSERT_GT(total, 3u);
  size_t oom = 0;
  for (size_t run : {size_t(1), size_t(0), size_t(2)}) {
    for (size_t k = 0; k <= total + 1; k++) {
      FailingAllocator fa(k, run);
      {
        WsSide s(GHTTP_WS_SERVER, nullptr, nullptr, fa.get());
        if (s.created() == GHTTP_OK) {
          WsRun r = s.feed(stream);
          if (fa.failed()) {
            if (r.result == GHTTP_ERR_OOM) {
              oom++;
            } else {
              EXPECT_EQ(r.events, expected.events) << k;
            }
          } else {
            EXPECT_EQ(r, expected) << k;
          }
          fa.stop_failing();
        } else {
          EXPECT_EQ(s.created(), GHTTP_ERR_OOM);
        }
      }
      EXPECT_EQ(fa.live(), 0u) << "k " << k << " run " << run;
    }
  }
  EXPECT_GT(oom, 0u);
}

TEST(WsOom, SendingAndClosingUnderAllocationFailureIsOomAndLeavesTheQueueIntact) {
  FailingAllocator counter(static_cast<size_t>(-1));
  {
    WsSide s(GHTTP_WS_CLIENT, nullptr, nullptr, counter.get());
    ASSERT_EQ(ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "hello", 5), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_send_ping(s.get(), "p", 1), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_close(s.get(), 1000, "x", 1), GHTTP_OK);
  }
  EXPECT_EQ(counter.live(), 0u);
  size_t total = counter.requests();
  for (size_t k = 0; k <= total; k++) {
    FailingAllocator fa(k, 0);
    {
      WsSide s(GHTTP_WS_CLIENT, nullptr, nullptr, fa.get());
      if (s.created() != GHTTP_OK) continue;
      size_t before = 0;
      for (int step = 0; step < 3; step++) {
        GHTTP_Result r = step == 0 ? ghttp_ws_conn_send_message(s.get(), GHTTP_WS_MESSAGE_TEXT, "hello", 5)
            : step == 1 ? ghttp_ws_conn_send_ping(s.get(), "p", 1)
                        : ghttp_ws_conn_close(s.get(), 1000, "x", 1);
        size_t now = ghttp_ws_conn_output_size(s.get());
        if (r != GHTTP_OK) {
          EXPECT_EQ(r, GHTTP_ERR_OOM) << k;
          EXPECT_EQ(now, before) << "a refused send changed the queue: " << k;
        } else {
          EXPECT_GT(now, before);
        }
        before = now;
      }
    }
    EXPECT_EQ(fa.live(), 0u) << k;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
