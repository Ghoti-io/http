/**
 * @file
 *
 * A client and a server wired together in memory: whole exchanges, flow
 * control with bodies larger than any window, many streams at once, the
 * same bytes cut every way, and an allocator that fails at every point.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <algorithm>
#include <map>
#include <random>

#include "test_helpers.h"
#include "h2_helpers.h"

using namespace ghttptest;

namespace {

using Events = std::vector<std::string>;

struct Pair {
  Side c;
  Side s;
  Pair(const GHTTP_H2Limits * cl = nullptr, const GHTTP_H2Limits * sl = nullptr)
      : c(GHTTP_H2_CLIENT, cl), s(GHTTP_H2_SERVER, sl) {
    pump(c, s);
  }
  void pump_all() { pump(c, s); }
};

GHTTP_Request * make_request(const char * method, const char * target,
    const HList & fields = {}) {
  GHTTP_Request * r;
  EXPECT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_method(r, method), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_target(r, target), GHTTP_OK);
  for (auto & f : fields) {
    EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(r), f.first.c_str(), f.second.c_str()), GHTTP_OK);
  }
  return r;
}

GHTTP_Response * make_response(int status, const HList & fields = {}) {
  GHTTP_Response * r;
  EXPECT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_response_set_status(r, status, ""), GHTTP_OK);
  for (auto & f : fields) {
    EXPECT_EQ(ghttp_headers_add(ghttp_response_headers(r), f.first.c_str(), f.second.c_str()), GHTTP_OK);
  }
  return r;
}

uint32_t open_stream(Side & c, const char * method, const char * target,
    const HList & fields = {}, bool end = true, const char * scheme = "https") {
  GHTTP_Request * r = make_request(method, target, fields);
  uint32_t id = 0;
  EXPECT_EQ(ghttp_h2_conn_send_request(c.c, r, scheme, end, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  return id;
}

void respond(Side & s, uint32_t id, int status, const HList & fields = {}, bool end = true) {
  GHTTP_Response * r = make_response(status, fields);
  EXPECT_EQ(ghttp_h2_conn_send_response(s.c, id, r, end), GHTTP_OK);
  ghttp_response_destroy(r);
}

/** Send all of @p d on @p id as the windows allow, pumping as needed; returns false if it stalls. */
bool send_all(Pair & p, Side & from, uint32_t id, const std::string & d, bool end) {
  size_t off = 0;
  for (int guard = 0; guard < 100000; guard++) {
    size_t n = 0;
    GHTTP_Result r = ghttp_h2_conn_send_data(from.c, id, d.data() + off, d.size() - off,
        end && true, &n);
    EXPECT_EQ(r, GHTTP_OK);
    off += n;
    // Windows are never negative from normal operation.
    EXPECT_GE(ghttp_h2_conn_connection_send_window(from.c), 0);
    p.pump_all();
    if (off == d.size()) return true;
    if (n == 0 && ghttp_h2_conn_send_window(from.c, id) == 0) {
      // Waiting for a WINDOW_UPDATE that pump should already have delivered.
      p.pump_all();
      if (ghttp_h2_conn_send_window(from.c, id) == 0) return false;
    }
  }
  return false;
}

std::string collect(const Events & ev, uint32_t stream) {
  std::string out;
  std::string pre = "DATA " + std::to_string(stream) + " ";
  for (auto & e : ev) {
    if (e.rfind(pre, 0) != 0) continue;
    size_t q = e.find('"');
    size_t qe = e.rfind('"');
    out += e.substr(q + 1, qe - q - 1);
  }
  return out;
}

} // namespace

TEST(H2Interop, ARequestAndResponseCrossBetweenTheTwoRoles) {
  Pair p;
  EXPECT_EQ(p.c.events, (Events{"SETTINGS", "SETTINGS_ACK"}));
  EXPECT_EQ(p.s.events, (Events{"SETTINGS", "SETTINGS_ACK"}));
  p.c.events.clear();
  p.s.events.clear();
  uint32_t id = open_stream(p.c, "GET", "/index.html?q=1", {{"accept", "text/html"}});
  EXPECT_EQ(id, 1u);
  p.pump_all();
  EXPECT_EQ(p.s.events, (Events{"HEADERS 1 end GET /index.html?q=1 [accept: text/html] scheme=https authority=-"}));
  respond(p.s, 1, 200, {{"content-type", "text/plain"}, {"content-length", "5"}}, false);
  size_t n;
  ASSERT_EQ(ghttp_h2_conn_send_data(p.s.c, 1, "hello", 5, 1, &n), GHTTP_OK);
  EXPECT_EQ(n, 5u);
  p.pump_all();
  EXPECT_EQ(p.c.events, (Events{"HEADERS 1 200 [content-type: text/plain] [content-length: 5]", "DATA 1 end \"hello\""}));
  EXPECT_EQ(ghttp_h2_conn_stream_count(p.c.c), 0u);
  EXPECT_EQ(ghttp_h2_conn_stream_count(p.s.c), 0u);
}

TEST(H2Interop, AuthorityComesFromTheHostFieldAndNamesAreLowerCased_Section8_3_1) {
  Pair p;
  p.s.events.clear();
  open_stream(p.c, "GET", "/", {{"Host", "example.org:8443"}, {"X-Mixed-Case", "V"}});
  p.pump_all();
  EXPECT_EQ(p.s.events, (Events{"HEADERS 1 end GET / [host: example.org:8443] [x-mixed-case: V] scheme=https authority=example.org:8443"}));
}

TEST(H2Interop, AnAbsoluteFormTargetGivesSchemeAuthorityAndPath_Section8_3_1) {
  Pair p;
  p.s.events.clear();
  open_stream(p.c, "GET", "http://example.org:8080/a/b?c=d", {}, true);
  open_stream(p.c, "GET", "http://example.org", {}, true);
  open_stream(p.c, "GET", "http://example.org?x=1", {}, true);
  p.pump_all();
  EXPECT_EQ(p.s.events, (Events{
      "HEADERS 1 end GET /a/b?c=d [host: example.org:8080] scheme=http authority=example.org:8080",
      "HEADERS 3 end GET / [host: example.org] scheme=http authority=example.org",
      "HEADERS 5 end GET /?x=1 [host: example.org] scheme=http authority=example.org"}));
}

TEST(H2Interop, OptionsAsteriskAndConnect) {
  Pair p;
  p.s.events.clear();
  open_stream(p.c, "OPTIONS", "*", {{"host", "h"}});
  open_stream(p.c, "CONNECT", "proxy.example:443", {}, false);
  p.pump_all();
  EXPECT_EQ(p.s.events, (Events{
      "HEADERS 1 end OPTIONS * [host: h] scheme=https authority=h",
      "HEADERS 3 CONNECT proxy.example:443 [host: proxy.example:443] scheme=- authority=proxy.example:443"}));
}

TEST(H2Interop, ATunnelCarriesDataBothWaysAndEndsOnEndStream_Section8_5) {
  Pair p;
  uint32_t id = open_stream(p.c, "CONNECT", "origin:443", {}, false);
  p.pump_all();
  respond(p.s, id, 200, {}, false);
  p.pump_all();
  p.c.events.clear();
  p.s.events.clear();
  size_t n;
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.c, id, "to-origin", 9, 0, &n), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_data(p.s.c, id, "from-origin", 11, 0, &n), GHTTP_OK);
  p.pump_all();
  EXPECT_EQ(p.s.events, (Events{"DATA 1 \"to-origin\""}));
  EXPECT_EQ(p.c.events, (Events{"DATA 1 \"from-origin\""}));
  GHTTP_H2StreamMode m;
  ASSERT_EQ(ghttp_h2_conn_stream_mode(p.c.c, id, &m), GHTTP_OK);
  EXPECT_EQ(m, GHTTP_H2_STREAM_TUNNEL);
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.c, id, "", 0, 1, &n), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_data(p.s.c, id, "", 0, 1, &n), GHTTP_OK);
  p.pump_all();
  EXPECT_EQ(ghttp_h2_conn_stream_count(p.c.c), 0u);
  EXPECT_EQ(ghttp_h2_conn_stream_count(p.s.c), 0u);
}

TEST(H2Interop, InterimResponsesTrailersAndAHeadResponse_Section8_1) {
  Pair p;
  uint32_t id = open_stream(p.c, "POST", "/up", {}, false);
  size_t n;
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.c, id, "body", 4, 0, &n), GHTTP_OK);
  GHTTP_Headers * t;
  ASSERT_EQ(ghttp_headers_create(nullptr, &t), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t, "X-Checksum", "abc"), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_trailers(p.c.c, id, t), GHTTP_OK);
  p.pump_all();
  EXPECT_EQ(p.s.events.back(), "TRAILERS 1 [x-checksum: abc]");
  respond(p.s, id, 103, {{"link", "</s.css>; rel=preload"}}, false);
  respond(p.s, id, 200, {}, false);
  ASSERT_EQ(ghttp_h2_conn_send_data(p.s.c, id, "ok", 2, 0, &n), GHTTP_OK);
  ghttp_headers_clear(t);
  ASSERT_EQ(ghttp_headers_add(t, "x-done", "1"), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_trailers(p.s.c, id, t), GHTTP_OK);
  ghttp_headers_destroy(t);
  p.pump_all();
  EXPECT_EQ(p.c.events[p.c.events.size() - 4], "HEADERS 1 interim 103 [link: </s.css>; rel=preload]");
  EXPECT_EQ(p.c.events[p.c.events.size() - 3], "HEADERS 1 200");
  EXPECT_EQ(p.c.events[p.c.events.size() - 2], "DATA 1 \"ok\"");
  EXPECT_EQ(p.c.events[p.c.events.size() - 1], "TRAILERS 1 [x-done: 1]");
  // HEAD: the response carries a length and no body.
  p.c.events.clear();
  p.s.events.clear();
  uint32_t h = open_stream(p.c, "HEAD", "/");
  p.pump_all();
  respond(p.s, h, 200, {{"content-length", "12345"}}, true);
  p.pump_all();
  EXPECT_EQ(p.c.events, (Events{"HEADERS 3 end 200 [content-length: 12345]"}));
}

TEST(H2Interop, BodiesLargerThanEveryWindowArriveWhole_Section6_9) {
  // 400,000 octets each way: six windows' worth, in 16 KiB frames, with the
  // credit coming back as the other side consumes.
  Pair p;
  std::string up(400000, 0);
  std::mt19937 rng(11);
  for (auto & ch : up) ch = static_cast<char>('a' + rng() % 26);
  std::string down(400000, 0);
  for (auto & ch : down) ch = static_cast<char>('A' + rng() % 26);
  uint32_t id = open_stream(p.c, "POST", "/big", {}, false);
  p.pump_all();
  p.s.events.clear();
  ASSERT_TRUE(send_all(p, p.c, id, up, true));
  EXPECT_EQ(collect(p.s.events, id), up);
  EXPECT_EQ(p.s.result, GHTTP_OK);
  EXPECT_EQ(p.c.result, GHTTP_OK);
  respond(p.s, id, 200, {}, false);
  p.c.events.clear();
  ASSERT_TRUE(send_all(p, p.s, id, down, true));
  EXPECT_EQ(collect(p.c.events, id), down);
  EXPECT_EQ(p.s.result, GHTTP_OK);
  EXPECT_EQ(p.c.result, GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_stream_count(p.c.c), 0u);
  // No window is below zero or above 2^31 - 1 at the end either.
  EXPECT_GE(ghttp_h2_conn_connection_send_window(p.c.c), 0);
  EXPECT_GE(ghttp_h2_conn_connection_recv_window(p.s.c), 0);
}

TEST(H2Interop, BodiesWithManualFlowControlStallUntilTheReceiverConsumes) {
  GHTTP_H2Limits sl = limits();
  sl.manual_flow_control = 1;
  Pair p(nullptr, &sl);
  std::string up(200000, 'u');
  uint32_t id = open_stream(p.c, "POST", "/slow", {}, false);
  p.pump_all();
  size_t off = 0;
  size_t consumed = 0;
  for (int round = 0; round < 1000 && off < up.size(); round++) {
    size_t n = 0;
    ASSERT_EQ(ghttp_h2_conn_send_data(p.c.c, id, up.data() + off, up.size() - off, 1, &n), GHTTP_OK);
    off += n;
    p.pump_all();
    // The server's application takes what has been delivered, a piece at a time.
    std::string got = collect(p.s.events, id);
    if (got.size() > consumed) {
      size_t k = std::min<size_t>(got.size() - consumed, 20000);
      ASSERT_EQ(ghttp_h2_conn_consume(p.s.c, id, k), GHTTP_OK);
      consumed += k;
      p.pump_all();
    }
  }
  EXPECT_EQ(off, up.size());
  EXPECT_EQ(collect(p.s.events, id), up);
  EXPECT_EQ(p.s.result, GHTTP_OK);
  EXPECT_EQ(p.c.result, GHTTP_OK);
}

TEST(H2Interop, ManyStreamsInterleaveOnOneConnection) {
  Pair p;
  const int N = 12;
  std::vector<uint32_t> ids;
  std::map<uint32_t, std::string> bodies;
  std::mt19937 rng(5);
  for (int i = 0; i < N; i++) {
    uint32_t id = open_stream(p.c, "POST", ("/s" + std::to_string(i)).c_str(), {{"x-i", std::to_string(i)}}, false);
    ids.push_back(id);
    std::string b(30000 + rng() % 30000, 0);
    for (auto & ch : b) ch = static_cast<char>('a' + rng() % 26);
    bodies[id] = b;
  }
  p.pump_all();
  std::map<uint32_t, size_t> off;
  bool progress = true;
  while (progress) {
    progress = false;
    for (uint32_t id : ids) {
      std::string & b = bodies[id];
      if (off[id] >= b.size()) continue;
      size_t take = std::min<size_t>(b.size() - off[id], 1000);
      size_t n = 0;
      bool last = off[id] + take == b.size();
      ASSERT_EQ(ghttp_h2_conn_send_data(p.c.c, id, b.data() + off[id], take, last, &n), GHTTP_OK);
      off[id] += n;
      if (n > 0) progress = true;
      p.pump_all();
    }
    if (!progress) {
      // Everything refused: only a WINDOW_UPDATE can help, and pump delivered them.
      for (uint32_t id : ids) {
        if (off[id] < bodies[id].size() && ghttp_h2_conn_send_window(p.c.c, id) > 0) progress = true;
      }
    }
  }
  for (uint32_t id : ids) {
    EXPECT_EQ(off[id], bodies[id].size());
    EXPECT_EQ(collect(p.s.events, id), bodies[id]) << id;
  }
  EXPECT_EQ(p.s.result, GHTTP_OK);
  EXPECT_EQ(p.c.result, GHTTP_OK);
}

TEST(H2Interop, TheCompressionStateIsSharedAcrossStreamsAndSurvivesManyRequests) {
  Pair p;
  std::mt19937 rng(9);
  for (int i = 0; i < 300; i++) {
    HList f = {{"x-session", "abc" + std::to_string(i % 7)}, {"cookie", "k=" + std::to_string(rng() % 5)},
        {"user-agent", "ghoti/" + std::to_string(i % 3)}, {"x-n" + std::to_string(i % 11), std::to_string(i)}};
    p.s.events.clear();
    uint32_t id = open_stream(p.c, "GET", ("/p" + std::to_string(i)).c_str(), f, true);
    p.pump_all();
    ASSERT_EQ(p.s.events.size(), 1u) << i;
    EXPECT_NE(p.s.events[0].find("[x-session: abc" + std::to_string(i % 7) + "]"), std::string::npos) << p.s.events[0];
    EXPECT_NE(p.s.events[0].find("[x-n" + std::to_string(i % 11) + ": " + std::to_string(i) + "]"), std::string::npos);
    respond(p.s, id, 200, {{"x-resp", std::to_string(i % 4)}}, true);
    p.pump_all();
  }
  EXPECT_EQ(p.s.result, GHTTP_OK);
  EXPECT_EQ(p.c.result, GHTTP_OK);
}

TEST(H2Interop, ALargeHeaderSectionIsSplitIntoContinuationFramesAndJoinedAgain_Section6_10) {
  GHTTP_H2Limits sl = limits();
  sl.max_header_list_bytes = 100000;
  sl.max_header_block_bytes = 100000;
  sl.max_header_count = 200;
  sl.max_buffered_bytes = 1 << 22;
  Pair p(nullptr, &sl);
  HList f;
  std::mt19937 rng(21);  // incompressible, so the block really is large
  for (int i = 0; i < 100; i++) {
    std::string v(500, 0);
    for (auto & ch : v) ch = static_cast<char>(0x21 + rng() % 90);
    f.push_back({"x-h" + std::to_string(i), v});
  }
  p.c.mark();
  uint32_t id = open_stream(p.c, "GET", "/", f, true);
  ASSERT_EQ(id, 1u);
  auto frames = p.c.frames_since_mark();
  ASSERT_GE(frames.size(), 3u);
  EXPECT_EQ(frames[0].type, GHTTP_H2_HEADERS);
  EXPECT_EQ(frames[0].flags & END_HEADERS, 0) << "the block did not fit one frame";
  for (size_t i = 1; i < frames.size(); i++) EXPECT_EQ(frames[i].type, GHTTP_H2_CONTINUATION);
  EXPECT_EQ(frames.back().flags & END_HEADERS, END_HEADERS);
  p.s.events.clear();
  p.pump_all();
  // pump delivers `unsent`: the frames above were already queued, not yet sent.
  ASSERT_EQ(p.s.events.size(), 1u);
  EXPECT_NE(p.s.events[0].find("[x-h99: " + f[99].second + "]"), std::string::npos);
}

TEST(H2Interop, TheConcurrencyLimitOfThePeerIsHonouredByTheSender_Section5_1_2) {
  GHTTP_H2Limits sl = limits();
  sl.max_concurrent_streams = 2;
  Pair p(nullptr, &sl);
  uint32_t a = open_stream(p.c, "POST", "/a", {}, false);
  uint32_t b = open_stream(p.c, "POST", "/b", {}, false);
  EXPECT_FALSE(ghttp_h2_conn_can_open_stream(p.c.c));
  GHTTP_Request * r = make_request("GET", "/c");
  uint32_t id = 0;
  p.c.mark();
  EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_ERR_LIMIT);
  EXPECT_TRUE(p.c.frames_since_mark().empty()) << "nothing was sent";
  // Finish one; room appears.
  size_t n;
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.c, a, "", 0, 1, &n), GHTTP_OK);
  p.pump_all();
  respond(p.s, a, 200, {}, true);
  p.pump_all();
  EXPECT_TRUE(ghttp_h2_conn_can_open_stream(p.c.c));
  EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_OK);
  EXPECT_EQ(id, 5u);
  ghttp_request_destroy(r);
  (void)b;
}

TEST(H2Interop, ARequestLargerThanThePeersHeaderListLimitIsNotSent_Section6_5_2) {
  GHTTP_H2Limits sl = limits();
  sl.max_header_list_bytes = 300;
  Pair p(nullptr, &sl);
  GHTTP_Request * r = make_request("GET", "/", {{"x-big", std::string(400, 'v')}});
  p.c.mark();
  uint32_t id = 0;
  EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_ERR_LIMIT);
  EXPECT_TRUE(p.c.frames_since_mark().empty());
  ghttp_request_destroy(r);
  // And a smaller one still goes.
  EXPECT_EQ(open_stream(p.c, "GET", "/"), 1u) << "the refused request used no stream identifier";
}

TEST(H2Interop, WhatHttp2ForbidsIsRefusedWhenSending_Section8_2_2) {
  Pair p;
  for (const char * bad : {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"}) {
    GHTTP_Request * r = make_request("GET", "/", {{bad, "x"}});
    uint32_t id = 0;
    EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_ERR_INVALID) << bad;
    ghttp_request_destroy(r);
  }
  GHTTP_Request * r = make_request("GET", "/", {{"te", "gzip"}});
  uint32_t id = 0;
  EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_ERR_INVALID);
  ghttp_request_destroy(r);
  r = make_request("GET", "/", {{"te", "trailers"}});
  EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  EXPECT_EQ(id, 1u) << "the refusals consumed no identifiers";
  // Responses: 101, and an interim response that ends the stream.
  p.pump_all();
  GHTTP_Response * resp = make_response(101);
  EXPECT_EQ(ghttp_h2_conn_send_response(p.s.c, 1, resp, 0), GHTTP_ERR_INVALID);
  ghttp_response_destroy(resp);
  resp = make_response(103);
  EXPECT_EQ(ghttp_h2_conn_send_response(p.s.c, 1, resp, 1), GHTTP_ERR_INVALID);
  ghttp_response_destroy(resp);
  resp = make_response(200, {{"connection", "close"}});
  EXPECT_EQ(ghttp_h2_conn_send_response(p.s.c, 1, resp, 1), GHTTP_ERR_INVALID);
  ghttp_response_destroy(resp);
  // Trailers carrying framing fields.
  resp = make_response(200);
  ASSERT_EQ(ghttp_h2_conn_send_response(p.s.c, 1, resp, 0), GHTTP_OK);
  ghttp_response_destroy(resp);
  GHTTP_Headers * t;
  ASSERT_EQ(ghttp_headers_create(nullptr, &t), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t, "content-length", "5"), GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_send_trailers(p.s.c, 1, t), GHTTP_ERR_INVALID);
  ghttp_headers_destroy(t);
}

TEST(H2Interop, ARoleCannotCallTheOtherRolesFunctions) {
  Pair p;
  GHTTP_Request * r = make_request("GET", "/");
  uint32_t id;
  EXPECT_EQ(ghttp_h2_conn_send_request(p.s.c, r, "https", 1, &id), GHTTP_ERR_INVALID);
  ghttp_request_destroy(r);
  GHTTP_Response * resp = make_response(200);
  EXPECT_EQ(ghttp_h2_conn_send_response(p.c.c, 1, resp, 1), GHTTP_ERR_INVALID);
  ghttp_response_destroy(resp);
}

TEST(H2Interop, AGoawayStopsNewStreamsAndDropsTheUnprocessedOnes_Section6_8) {
  Pair p;
  uint32_t a = open_stream(p.c, "GET", "/a");
  p.pump_all();
  uint32_t b = open_stream(p.c, "GET", "/b");  // the server will not have seen this when it says goodbye
  ASSERT_EQ(ghttp_h2_conn_shutdown(p.s.c, GHTTP_H2_NO_ERROR, "", 0), GHTTP_OK);
  std::string bye = p.s.unsent();
  p.c.feed(bye);
  EXPECT_EQ(p.c.events.back(), "GOAWAY last=1 NO_ERROR \"\"");
  EXPECT_FALSE(ghttp_h2_conn_can_open_stream(p.c.c));
  EXPECT_TRUE(ghttp_h2_conn_stream_is_active(p.c.c, a));
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(p.c.c, b)) << "above the last stream identifier: it will not be answered";
  GHTTP_Request * r = make_request("GET", "/c");
  uint32_t id;
  EXPECT_EQ(ghttp_h2_conn_send_request(p.c.c, r, "https", 1, &id), GHTTP_ERR_INVALID);
  ghttp_request_destroy(r);
  // The server refuses what it was sent after the GOAWAY, still decoding it.
  p.s.feed(p.c.unsent());
  EXPECT_EQ(p.s.events.back(), "STREAM_ERROR 3 REFUSED_STREAM");
  EXPECT_EQ(p.s.result, GHTTP_OK);
}

TEST(H2Interop, TheHeaderTableSizeAnAdvertisedSmallerWorksBetweenTwoRealPeers_Section4_2) {
  GHTTP_H2Limits sl = limits();
  sl.max_table_size = 200;
  GHTTP_H2Limits cl = limits();
  cl.max_table_size = 300;
  Pair p(&cl, &sl);
  for (int i = 0; i < 40; i++) {
    uint32_t id = open_stream(p.c, "GET", "/", {{"x-a" + std::to_string(i % 5), std::string(40, 'a' + i % 26)}});
    p.pump_all();
    respond(p.s, id, 200, {{"x-b" + std::to_string(i % 3), std::string(30, 'z' - i % 26)}}, true);
    p.pump_all();
  }
  EXPECT_EQ(p.s.result, GHTTP_OK);
  EXPECT_EQ(p.c.result, GHTTP_OK);
}

// ---- Split independence: the same bytes cut every way ---------------------------------

namespace {

/** A rich client-to-server byte stream, recorded from a real client. */
std::string recorded_client_stream() {
  Side c(GHTTP_H2_CLIENT);
  Side s(GHTTP_H2_SERVER);
  pump(c, s);
  uint32_t a = open_stream(c, "POST", "/a", {{"x-one", "1"}, {"cookie", "a=b"}, {"cookie", "c=d"}}, false);
  uint32_t b = open_stream(c, "GET", "/b?q=2", {{"accept", "*/*"}});
  size_t n;
  ghttp_h2_conn_send_data(c.c, a, "first-", 6, 0, &n);
  uint8_t pingdata[8] = {'p', 'i', 'n', 'g', 'd', 'a', 't', 'a'};
  ghttp_h2_conn_ping(c.c, pingdata);
  ghttp_h2_conn_send_data(c.c, a, "second", 6, 0, &n);
  GHTTP_Headers * t;
  ghttp_headers_create(nullptr, &t);
  ghttp_headers_add(t, "x-trail", "t");
  ghttp_h2_conn_send_trailers(c.c, a, t);
  ghttp_headers_destroy(t);
  ghttp_h2_conn_reset_stream(c.c, b, GHTTP_H2_CANCEL);
  uint32_t d = open_stream(c, "CONNECT", "h:1", {}, false);
  ghttp_h2_conn_send_data(c.c, d, "tunnel", 6, 1, &n);
  ghttp_h2_conn_send_extension_frame(c.c, 0xee, 1, 0, "ext", 3);
  c.drain();
  return c.out;  // from the preface on
}

std::string recorded_server_stream() {
  Side c(GHTTP_H2_CLIENT);
  Side s(GHTTP_H2_SERVER);
  pump(c, s);
  uint32_t a = open_stream(c, "POST", "/a", {}, false);
  uint32_t h = open_stream(c, "HEAD", "/h", {}, true);
  pump(c, s);
  s.unsent();
  respond(s, a, 103, {{"link", "x"}}, false);
  respond(s, a, 200, {{"content-type", "t"}}, false);
  size_t n;
  ghttp_h2_conn_send_data(s.c, a, "response-body", 13, 0, &n);
  GHTTP_Headers * t;
  ghttp_headers_create(nullptr, &t);
  ghttp_headers_add(t, "x-t", "1");
  ghttp_h2_conn_send_trailers(s.c, a, t);
  ghttp_headers_destroy(t);
  respond(s, h, 200, {{"content-length", "9"}}, true);
  ghttp_h2_conn_ping(s.c, reinterpret_cast<const uint8_t *>("serverpg"));
  ghttp_h2_conn_shutdown(s.c, GHTTP_H2_NO_ERROR, "done", 4);
  s.drain();
  return s.out;  // from the server's own SETTINGS on
}

} // namespace

TEST(H2Split, TheServerSeesTheSameEventsAndWritesTheSameBytesHoweverTheInputIsCut) {
  std::string in = recorded_client_stream();
  Side whole(GHTTP_H2_SERVER);
  whole.feed(in);
  ASSERT_EQ(whole.result, GHTTP_OK);
  ASSERT_GE(whole.events.size(), 8u);
  Events expected = whole.events;
  std::string expected_out = whole.out;
  // Every two-way split.
  for (size_t k = 0; k <= in.size(); k++) {
    Side s(GHTTP_H2_SERVER);
    s.feed(cut(in, {k}));
    ASSERT_EQ(s.events, expected) << "split at " << k;
    ASSERT_EQ(s.out, expected_out) << "split at " << k;
  }
  // One octet at a time.
  {
    Side s(GHTTP_H2_SERVER);
    s.feed(bytewise(in));
    EXPECT_EQ(s.events, expected);
    EXPECT_EQ(s.out, expected_out);
  }
  // Random multi-way splits.
  std::mt19937 rng(13);
  for (int i = 0; i < 300; i++) {
    std::vector<size_t> at;
    size_t cuts = 1 + rng() % 8;
    for (size_t j = 0; j < cuts; j++) at.push_back(rng() % (in.size() + 1));
    std::sort(at.begin(), at.end());
    Side s(GHTTP_H2_SERVER);
    s.feed(cut(in, at));
    ASSERT_EQ(s.events, expected) << i;
    ASSERT_EQ(s.out, expected_out) << i;
  }
}

TEST(H2Split, TheClientSeesTheSameEventsHoweverTheInputIsCut) {
  std::string in = recorded_server_stream();
  // The client must have sent a request on streams 1 and 3 for these to be answers.
  auto fresh = [&](Side & c) {
    Side dummy(GHTTP_H2_SERVER);
    open_stream(c, "POST", "/a", {}, false);
    open_stream(c, "HEAD", "/h", {}, true);
    c.drain();
  };
  Side whole(GHTTP_H2_CLIENT);
  fresh(whole);
  whole.feed(in);
  ASSERT_EQ(whole.result, GHTTP_OK);
  ASSERT_GE(whole.events.size(), 8u);
  Events expected = whole.events;
  std::string expected_out = whole.out;
  for (size_t k = 0; k <= in.size(); k++) {
    Side c(GHTTP_H2_CLIENT);
    fresh(c);
    c.feed(cut(in, {k}));
    ASSERT_EQ(c.events, expected) << "split at " << k;
    ASSERT_EQ(c.out, expected_out) << "split at " << k;
  }
  Side c(GHTTP_H2_CLIENT);
  fresh(c);
  c.feed(bytewise(in));
  EXPECT_EQ(c.events, expected);
}

TEST(H2Split, AnErrorFallsAtTheSameFrameHoweverTheInputIsCut) {
  // A valid prefix, then a frame that ends the connection, then more.
  Block blk;
  std::string in = client_open() + settings_ack()
      + headers(1, blk(request_list("POST", "/")), END_HEADERS)
      + data(1, "abc") + window_update(1, 0x7fffffffu) + data(1, "never seen");
  Side whole(GHTTP_H2_SERVER);
  whole.feed(in);
  Events expected = whole.events;
  std::string expected_out = whole.out;
  ASSERT_FALSE(expected.empty());
  for (size_t k = 0; k <= in.size(); k++) {
    Side s(GHTTP_H2_SERVER);
    s.feed(cut(in, {k}));
    ASSERT_EQ(s.events, expected) << k;
    ASSERT_EQ(s.out, expected_out) << k;
  }
  Side b(GHTTP_H2_SERVER);
  b.feed(bytewise(in));
  EXPECT_EQ(b.events, expected);
  EXPECT_EQ(b.out, expected_out);
}

TEST(H2Split, ARefusalAtAFrameHeaderFallsAtTheSameEventHoweverItIsCut) {
  std::string bad = client_open() + frame(GHTTP_H2_DATA, 0, 1, std::string(16385, 'x'));
  Side whole(GHTTP_H2_SERVER);
  whole.feed(bad);
  Events expected = whole.events;
  ASSERT_EQ(expected.back(), "ERROR CORRUPT FRAME_SIZE_ERROR");
  for (size_t k = 0; k <= 80; k++) {
    Side s(GHTTP_H2_SERVER);
    s.feed(cut(bad, {k}));
    ASSERT_EQ(s.events, expected) << k;
  }
}

// ---- Allocation failure at every point ------------------------------------------------

namespace {

/** The whole conversation, with the given allocators; "" plus an error if one
 *  was refused. Never dereferences a connection that was not made. */
struct Convo {
  std::string transcript;
  bool oom = false;
};

Convo conversation(const GHTTP_Allocator * ca, const GHTTP_Allocator * sa) {
  Convo o;
  GHTTP_H2Limits l = limits();
  l.manual_flow_control = 0;
  Side c(GHTTP_H2_CLIENT, &l, ca, false);
  Side s(GHTTP_H2_SERVER, &l, sa, false);
  auto check = [&](GHTTP_Result r) {
    if (r != GHTTP_OK) o.oom = true;
    return r == GHTTP_OK;
  };
  if (!c.c || !s.c) { o.oom = true; return o; }
  pump(c, s);
  GHTTP_Request * rq = make_request("POST", "/oom", {{"x-a", "1"}, {"cookie", "a=b"}, {"cookie", "c=d"}});
  uint32_t id = 0;
  bool ok = check(ghttp_h2_conn_send_request(c.c, rq, "https", 0, &id));
  ghttp_request_destroy(rq);
  size_t n = 0;
  std::string body(30000, 'q');
  if (ok) ok = check(ghttp_h2_conn_send_data(c.c, id, body.data(), body.size(), 0, &n));
  GHTTP_Headers * t;
  ghttp_headers_create(nullptr, &t);
  ghttp_headers_add(t, "x-t", "1");
  if (ok) ok = check(ghttp_h2_conn_send_trailers(c.c, id, t));
  pump(c, s);
  if (ok && s.result == GHTTP_OK && c.result == GHTTP_OK) {
    GHTTP_Response * rs = make_response(200, {{"x-r", "1"}});
    ok = check(ghttp_h2_conn_send_response(s.c, id, rs, 0));
    ghttp_response_destroy(rs);
    if (ok) ok = check(ghttp_h2_conn_send_data(s.c, id, "done", 4, 0, &n));
    if (ok) ok = check(ghttp_h2_conn_send_trailers(s.c, id, t));
    uint8_t pg[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    if (ok) ok = check(ghttp_h2_conn_ping(c.c, pg));
    pump(c, s);
  }
  ghttp_headers_destroy(t);
  if (c.result == GHTTP_ERR_OOM || s.result == GHTTP_ERR_OOM) o.oom = true;
  std::string sev, cev;
  for (auto & e : s.events) sev += e.substr(0, 60) + "|";
  for (auto & e : c.events) cev += e.substr(0, 60) + "|";
  o.transcript = "S:" + sev + " C:" + cev;
  return o;
}

} // namespace

TEST(H2Oom, EveryAllocationRefusedInTurnIsOomOrTheSameConversationAndNeverALeak) {
  Convo base;
  size_t creq, sreq;
  {
    FailingAllocator ca(static_cast<size_t>(-1)), sa(static_cast<size_t>(-1));
    base = conversation(ca.get(), sa.get());
    ASSERT_FALSE(base.oom);
    ASSERT_EQ(ca.live(), 0u);
    ASSERT_EQ(sa.live(), 0u);
    creq = ca.requests();
    sreq = sa.requests();
  }
  ASSERT_GT(creq, 40u);
  ASSERT_GT(sreq, 40u);
  for (int side = 0; side < 2; side++) {
    size_t total = side == 0 ? creq : sreq;
    for (size_t run : {size_t(1), size_t(0), size_t(2)}) {
      for (size_t k = 0; k <= total + 1; k++) {
        FailingAllocator fail(k, run);
        FailingAllocator fine(static_cast<size_t>(-1));
        Convo got = side == 0 ? conversation(fail.get(), fine.get())
                                : conversation(fine.get(), fail.get());
        if (fail.failed()) {
          // Either the refusal was reported, or it fell on something that
          // does not change the answer (a refused growth that then retried).
          if (!got.oom) {
            EXPECT_EQ(got.transcript, base.transcript) << side << " " << k << " " << run;
          }
        } else {
          EXPECT_FALSE(got.oom);
          EXPECT_EQ(got.transcript, base.transcript);
        }
        fail.stop_failing();
        EXPECT_EQ(fail.live(), 0u) << "leak: side " << side << " request " << k << " run " << run;
        EXPECT_EQ(fine.live(), 0u);
      }
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
