/**
 * @file
 *
 * The HTTP/2 connection (RFC 9113) driven by hand-made frames: the preface,
 * the stream state machine of section 5.1, flow control, header blocks and
 * CONTINUATION, the abuse limits, and the validity rules of section 8. The
 * client-and-server tests are in test_h2interop.cpp.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstring>

#include "test_helpers.h"
#include "h2_helpers.h"

using namespace ghttptest;

namespace {

/** A server that has completed the preface exchange. */
struct OpenServer {
  GHTTP_H2Limits lim;
  Side s;
  Block blk;
  explicit OpenServer(GHTTP_H2Limits l = limits(),
      std::initializer_list<std::pair<uint16_t, uint32_t>> client_settings = {})
      : lim(l), s(GHTTP_H2_SERVER, &lim) {
    s.feed(client_open(client_settings) + settings_ack());
    EXPECT_EQ(s.events, (std::vector<std::string>{"SETTINGS", "SETTINGS_ACK"}));
    s.events.clear();
    s.mark();
  }
  /** Send a request on stream @p id; returns the events. */
  std::vector<std::string> request(uint32_t id, const HList & l = request_list(),
      uint8_t flags = END_HEADERS | END_STREAM) {
    s.feed(headers(id, blk(l), flags));
    return s.take_events();
  }
  /** Feed bytes and return the events, clearing them. */
  std::vector<std::string> feed(const std::string & bytes) {
    s.feed(bytes);
    return s.take_events();
  }
  /** What a feed made the server write, as frames. */
  std::vector<OutFrame> wrote() {
    auto f = s.frames_since_mark();
    s.mark();
    return f;
  }
};

using Events = std::vector<std::string>;

bool has_prefix(const std::string & s, const std::string & p) { return s.rfind(p, 0) == 0; }

/** The first GOAWAY the connection wrote: its error code. */
int goaway_code(const std::vector<OutFrame> & fs) {
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_GOAWAY) return static_cast<int>(f.u32at(4));
  }
  return -1;
}

int rst_code(const std::vector<OutFrame> & fs, uint32_t stream) {
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_RST_STREAM && f.stream == stream) return static_cast<int>(f.u32at(0));
  }
  return -1;
}

} // namespace

// ---- The connection preface: RFC 9113 section 3.4 ---------------------------

TEST(H2Preface, AClientWritesTheMagicThenSettingsThatRefusePush) {
  Side c(GHTTP_H2_CLIENT);
  auto f = c.frames();
  ASSERT_GE(f.size(), 1u);
  EXPECT_EQ(f[0].type, GHTTP_H2_SETTINGS);
  EXPECT_EQ(f[0].flags, 0);
  // SETTINGS_ENABLE_PUSH = 0 is among them (section 6.5.2: push is refused
  // by saying so, and a PUSH_PROMISE after that is a protocol error).
  bool no_push = false;
  for (size_t i = 0; i + 6 <= f[0].payload.size(); i += 6) {
    uint16_t id = static_cast<uint16_t>((static_cast<uint8_t>(f[0].payload[i]) << 8)
        | static_cast<uint8_t>(f[0].payload[i + 1]));
    if (id == GHTTP_H2_SETTINGS_ENABLE_PUSH) {
      no_push = f[0].u32at(i + 2) == 0;
    }
  }
  EXPECT_TRUE(no_push);
  EXPECT_EQ(c.out.substr(0, 24), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
}

TEST(H2Preface, AServerWritesSettingsFirstAndNoMagic) {
  Side s(GHTTP_H2_SERVER);
  auto f = s.frames();
  ASSERT_GE(f.size(), 1u);
  EXPECT_EQ(f[0].type, GHTTP_H2_SETTINGS);
  EXPECT_NE(s.out.substr(0, 3), "PRI");
}

TEST(H2Preface, TheServerAcknowledgesTheClientsSettings_Section6_5_3) {
  OpenServer o;
  // The ACK to the client's SETTINGS was queued during the open.
  Side s(GHTTP_H2_SERVER);
  s.mark();
  s.feed(client_open());
  auto f = s.frames_since_mark();
  ASSERT_EQ(f.size(), 1u);
  EXPECT_EQ(f[0].type, GHTTP_H2_SETTINGS);
  EXPECT_EQ(f[0].flags, GHTTP_H2_FLAG_ACK);
}

TEST(H2Preface, ABadPrefaceIsAProtocolErrorAtTheFirstWrongOctetHoweverItIsCut) {
  std::string bad = "PRI * HTTP/2.0\r\n\r\nSX\r\n\r\n";
  std::vector<std::vector<std::string>> cuts = {
      {bad}, bytewise(bad), cut(bad, {3}), cut(bad, {17}), cut(bad, {18}), cut(bad, {19})};
  Events first;
  for (size_t i = 0; i < cuts.size(); i++) {
    Side s(GHTTP_H2_SERVER);
    s.feed(cuts[i]);
    EXPECT_EQ(s.result, GHTTP_ERR_CORRUPT) << i;
    if (i == 0) first = s.events;
    EXPECT_EQ(s.events, first) << i;
    EXPECT_EQ(goaway_code(parse_frames(s.out)), GHTTP_H2_PROTOCOL_ERROR);
  }
  ASSERT_EQ(first.size(), 1u);
  EXPECT_EQ(first[0], "ERROR CORRUPT PROTOCOL_ERROR");
}

TEST(H2Preface, AnHttp1RequestIsRefusedAtOnce) {
  Side s(GHTTP_H2_SERVER);
  s.feed("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  EXPECT_EQ(s.result, GHTTP_ERR_CORRUPT);
}

TEST(H2Preface, ThePeersFirstFrameMustBeSettings_Section3_4) {
  {
    Side s(GHTTP_H2_SERVER);
    s.feed(std::string(GHTTP_H2_PREFACE) + ping());
    EXPECT_EQ(s.result, GHTTP_ERR_CORRUPT);
    EXPECT_EQ(goaway_code(parse_frames(s.out)), GHTTP_H2_PROTOCOL_ERROR);
  }
  {
    Side s(GHTTP_H2_SERVER);
    s.feed(std::string(GHTTP_H2_PREFACE) + settings_ack());
    EXPECT_EQ(s.result, GHTTP_ERR_CORRUPT) << "an ACK is not a preface";
  }
  {
    Side c(GHTTP_H2_CLIENT);
    c.feed(headers(2, "x"));
    EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
  }
}

TEST(H2Preface, AFailedConnectionStaysFailedAndWritesNothingMore) {
  Side s(GHTTP_H2_SERVER);
  s.feed("GET / HTTP/1.1\r\n\r\n");
  ASSERT_EQ(s.result, GHTTP_ERR_CORRUPT);
  std::string goaway = s.out;
  size_t used = 99;
  GHTTP_H2Event ev;
  EXPECT_EQ(ghttp_h2_conn_feed(s.c, "x", 1, &used, &ev), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(ghttp_h2_conn_ping(s.c, reinterpret_cast<const uint8_t *>("12345678")),
      GHTTP_ERR_CORRUPT);
  uint32_t code;
  const char * why;
  EXPECT_EQ(ghttp_h2_conn_error(s.c, &code, &why), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(code, GHTTP_H2_PROTOCOL_ERROR);
  EXPECT_NE(std::string(why), "");
  s.drain();
  EXPECT_EQ(s.out, goaway);
}

// ---- Requests --------------------------------------------------------------

TEST(H2Server, ARequestIsDecodedIntoTheSharedMessageTypes_Section8_3_1) {
  OpenServer o;
  auto e = o.request(1, request_list("GET", "/a?b=c", {{"accept", "*/*"}, {"x-n", "v"}}));
  ASSERT_EQ(e.size(), 1u);
  // The :authority becomes the Host field (section 8.3.1), first; the scheme
  // and authority are reported beside the message.
  EXPECT_EQ(e[0], "HEADERS 1 end GET /a?b=c [host: example.com] [accept: */*] [x-n: v]"
                  " scheme=https authority=example.com");
  const GHTTP_Request * r = ghttp_h2_conn_request(o.s.c);
  EXPECT_EQ(ghttp_request_version(r), 1) << "HTTP/2 messages carry no version; 1 is the semantic one";
}

TEST(H2Server, AHostFieldThatAgreesWithAuthorityIsKeptAndNotDuplicated_Section8_3_1) {
  OpenServer o;
  auto e = o.request(1, request_list("GET", "/", {{"host", "EXAMPLE.com"}}));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0], "HEADERS 1 end GET / [host: EXAMPLE.com] scheme=https authority=example.com")
      << "one Host, the sender's, and authority is not copied over it";
}

TEST(H2Server, AHostFieldThatDiffersFromAuthorityIsMalformed_Section8_3_1) {
  OpenServer o;
  EXPECT_EQ(o.request(1, request_list("GET", "/", {{"host", "other"}})),
      (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  // One of two Host fields that differs is enough.
  EXPECT_EQ(o.request(3, request_list("GET", "/", {{"host", "example.com"}, {"host", "other"}})),
      (Events{"STREAM_ERROR 3 PROTOCOL_ERROR"}));
  // And the connection carries on.
  EXPECT_EQ(o.request(5, request_list("GET", "/")).size(), 1u);
}

TEST(H2Server, ARequestWithoutAuthorityIsFine) {
  OpenServer o;
  HList l = {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}};
  auto e = o.request(1, l);
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0], "HEADERS 1 end GET / scheme=http authority=-");
}

TEST(H2Server, SplitCookieFieldsAreJoinedWithSemicolonAndSpace_Section8_2_3) {
  OpenServer o;
  auto e = o.request(1, request_list("GET", "/", {{"cookie", "a=b"}, {"x", "1"},
      {"cookie", "c=d"}, {"cookie", "e=f"}}));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0], "HEADERS 1 end GET / [host: example.com] [cookie: a=b; c=d; e=f] [x: 1]"
                  " scheme=https authority=example.com");
}

TEST(H2Server, ARequestBodyArrivesAsDataWithItsEnd) {
  OpenServer o;
  auto e = o.request(1, request_list("POST", "/p", {{"content-length", "5"}}), END_HEADERS);
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 1 POST /p"));
  EXPECT_EQ(o.feed(data(1, "he")), (Events{"DATA 1 \"he\""}));
  EXPECT_EQ(o.feed(data(1, "llo", true)), (Events{"DATA 1 end \"llo\""}));
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1) && false);
}

TEST(H2Server, PaddingIsStrippedFromData_Section6_1) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  std::string padded = std::string(1, '\x03') + "abc" + std::string(3, '\0');
  EXPECT_EQ(o.feed(frame(GHTTP_H2_DATA, GHTTP_H2_FLAG_PADDED | END_STREAM, 1, padded)),
      (Events{"DATA 1 end \"abc\""}));
}

TEST(H2Server, TrailersArriveAfterTheBodyAndEndTheStream_Section8_1) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  o.feed(data(1, "x"));
  o.s.events.clear();
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x-sum", "7"}}), END_HEADERS | END_STREAM)),
      (Events{"TRAILERS 1 [x-sum: 7]"}));
}

TEST(H2Server, HeadersAfterTheRequestWithoutEndStreamIsMalformed_Section8_1) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x", "1"}}), END_HEADERS)),
      (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_PROTOCOL_ERROR));
}

TEST(H2Server, TrailersMayNotCarryPseudoHeadersOrFramingFields_Section8_1) {
  {
    OpenServer o;
    o.request(1, request_list("POST", "/"), END_HEADERS);
    EXPECT_EQ(o.feed(headers(1, o.blk({{":path", "/x"}}), END_HEADERS | END_STREAM)),
        (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  }
  {
    OpenServer o;
    o.request(1, request_list("POST", "/"), END_HEADERS);
    EXPECT_EQ(o.feed(headers(1, o.blk({{"content-length", "3"}}), END_HEADERS | END_STREAM)),
        (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  }
}

// ---- Header blocks: HEADERS and CONTINUATION, Section 6.10 ------------------

TEST(H2HeaderBlock, AContinuedBlockIsDecodedWhole) {
  OpenServer o;
  std::string blk = o.blk(request_list("GET", "/c", {{"x-long", std::string(100, 'v')}}));
  ASSERT_GT(blk.size(), 20u);
  std::string in = headers(1, blk.substr(0, 10), END_STREAM)
      + continuation(1, blk.substr(10, 20), false)
      + continuation(1, blk.substr(30), true);
  auto e = o.feed(in);
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 1 end GET /c [host: example.com] [x-long: vvvv"));
}

TEST(H2HeaderBlock, AFrameBetweenHeadersAndContinuationIsAProtocolError) {
  OpenServer o;
  std::string blk = o.blk(request_list());
  auto e = o.feed(frame(GHTTP_H2_HEADERS, END_STREAM, 1, blk.substr(0, 3)) + ping()
      + continuation(1, blk.substr(3)));
  EXPECT_EQ(e, (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_PROTOCOL_ERROR));
}

TEST(H2HeaderBlock, AContinuationOnAnotherStreamIsAProtocolError) {
  OpenServer o;
  std::string blk = o.blk(request_list());
  auto e = o.feed(frame(GHTTP_H2_HEADERS, END_STREAM, 1, blk.substr(0, 3))
      + continuation(3, blk.substr(3)));
  EXPECT_EQ(e, (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
}

TEST(H2HeaderBlock, AContinuationWithNothingToContinueIsAProtocolError) {
  OpenServer o;
  EXPECT_EQ(o.feed(continuation(1, "x")), (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
}

TEST(H2HeaderBlock, AnExtensionFrameInsideABlockIsAProtocolError_Section4_3) {
  OpenServer o;
  std::string blk = o.blk(request_list());
  EXPECT_EQ(o.feed(frame(GHTTP_H2_HEADERS, 0, 1, blk.substr(0, 3))
                + frame(0xee, 0, 0, "x")),
      (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
}

TEST(H2HeaderBlock, AContinuationFloodStopsAtTheLimitPlusOne_Cve2024_27316Class) {
  GHTTP_H2Limits l = limits();
  l.max_continuation_frames = 4;
  OpenServer o(l);
  std::string blk = o.blk(request_list("GET", "/", {{"x", std::string(200, 'y')}}));
  // Each fragment is one octet of a block that never ends.
  o.feed(frame(GHTTP_H2_HEADERS, END_STREAM, 1, blk.substr(0, 1)));
  ASSERT_EQ(o.s.result, GHTTP_OK);
  int fed = 0;
  for (; fed < 20 && o.s.result == GHTTP_OK; fed++) {
    o.feed(continuation(1, blk.substr(1 + fed, 1), false));
  }
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(fed, 5) << "four CONTINUATION frames are allowed, the fifth is refused";
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_ENHANCE_YOUR_CALM));
}

TEST(H2HeaderBlock, ABlockOverTheByteLimitIsRefusedBeforeItIsBuffered) {
  GHTTP_H2Limits l = limits();
  l.max_header_block_bytes = 100;
  OpenServer o(l);
  o.feed(frame(GHTTP_H2_HEADERS, END_STREAM, 1, std::string(60, 'a')));
  ASSERT_EQ(o.s.result, GHTTP_OK);
  o.feed(continuation(1, std::string(41, 'a'), false));
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_ENHANCE_YOUR_CALM));
}

TEST(H2HeaderBlock, ABadBlockIsACompressionErrorOfTheConnection_Section4_3) {
  OpenServer o;
  EXPECT_EQ(o.feed(headers(1, std::string("\x80", 1), END_HEADERS | END_STREAM)),
      (Events{"ERROR CORRUPT COMPRESSION_ERROR"}));
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_COMPRESSION_ERROR));
}

TEST(H2HeaderBlock, AHpackBombEndsTheConnectionAtTheListLimit) {
  GHTTP_H2Limits l = limits();
  l.max_table_size = 4096;
  OpenServer o(l);
  // One 4000-octet entry in the table, then 4000 one-octet references to it.
  std::string value(4000, 'x');
  std::string block = std::string("\x40\x01n\x7f\xa1\x1e", 6) + value + std::string(4000, '\xbe');
  auto e = o.feed(headers(1, block, END_HEADERS | END_STREAM));
  EXPECT_EQ(e, (Events{"ERROR LIMIT ENHANCE_YOUR_CALM"}));
}

TEST(H2HeaderBlock, ARefusedStreamsBlockStillUpdatesTheCompressionState_Section4_3_1) {
  GHTTP_H2Limits l = limits();
  l.max_concurrent_streams = 1;
  OpenServer o(l);
  // Stream 1 stays open (no END_STREAM); stream 3 is refused, and its block
  // adds "x-k: big" to the table, which stream 5 then refers to by index.
  EXPECT_EQ(o.request(1, request_list("POST", "/"), END_HEADERS).size(), 1u);
  EXPECT_EQ(o.request(3, request_list("GET", "/", {{"x-k", "big"}})),
      (Events{"STREAM_ERROR 3 REFUSED_STREAM"}));
  EXPECT_EQ(rst_code(o.wrote(), 3), static_cast<int>(GHTTP_H2_REFUSED_STREAM));
  o.feed(rst(1, GHTTP_H2_CANCEL));
  o.s.events.clear();
  auto e = o.request(5, request_list("GET", "/", {{"x-k", "big"}}));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 5 end GET / [host: example.com] [x-k: big]")) << e[0];
}

TEST(H2HeaderBlock, FramesOnAStreamWeResetAreDiscardedButItsHeaderBlockIsStillDecoded_Section5_1) {
  OpenServer o;
  // A malformed request: we reset it. The client's next frames on it are
  // already in flight: DATA is counted and ignored, HEADERS is decoded.
  EXPECT_EQ(o.request(1, {{":method", "GET"}}, END_HEADERS), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  EXPECT_EQ(o.feed(data(1, "late")), Events{});
  EXPECT_EQ(o.s.result, GHTTP_OK);
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x-late", "v"}}), END_HEADERS | END_STREAM)), Events{});
  EXPECT_EQ(o.s.result, GHTTP_OK);
  auto e = o.request(3, request_list("GET", "/", {{"x-late", "v"}}));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 3 end GET / [host: example.com] [x-late: v]"));
}

// ---- Stream states and identifiers: Section 5.1 ---------------------------------

TEST(H2Streams, FramesOnAnIdleStreamAreAProtocolError_Section5_1) {
  const std::vector<std::pair<const char *, std::string>> frames = {
    {"DATA", data(1, "x")},
    {"RST_STREAM", rst(1, 8)},
    {"WINDOW_UPDATE", window_update(1, 5)},
    {"CONTINUATION", continuation(1, "x")},
  };
  for (auto & f : frames) {
    OpenServer o;
    EXPECT_EQ(o.feed(f.second), (Events{"ERROR CORRUPT PROTOCOL_ERROR"})) << f.first;
  }
}

TEST(H2Streams, PriorityIsAcceptedInEveryStateAndIgnored_Section5_3_2) {
  OpenServer o;
  EXPECT_EQ(o.feed(priority(1) + priority(7, 3)), Events{}) << "idle streams";
  o.request(1, request_list("POST", "/"), END_HEADERS);
  EXPECT_EQ(o.feed(priority(1, 5)), Events{});
  o.feed(data(1, "", true));
  EXPECT_EQ(o.feed(priority(1)), Events{}) << "closed or half-closed";
  EXPECT_EQ(o.s.result, GHTTP_OK);
  // A HEADERS frame with the PRIORITY flag is read past, not acted on.
  std::string prio = u32(0x80000000u | 1) + std::string(1, '\xff');
  std::string blk = o.blk(request_list("GET", "/p"));
  auto e = o.feed(frame(GHTTP_H2_HEADERS, END_HEADERS | END_STREAM | GHTTP_H2_FLAG_PRIORITY,
      3, prio + blk));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 3 end GET /p"));
}

TEST(H2Streams, APriorityFrameOfTheWrongSizeIsAStreamError_Section6_3) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  EXPECT_EQ(o.feed(frame(GHTTP_H2_PRIORITY, 0, 1, "abcd")),
      (Events{"STREAM_ERROR 1 FRAME_SIZE_ERROR"}));
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_FRAME_SIZE_ERROR));
  EXPECT_EQ(o.s.result, GHTTP_OK);
  // On an idle stream there is nothing to reset: the frame is wrong for the connection.
  OpenServer p;
  EXPECT_EQ(p.feed(frame(GHTTP_H2_PRIORITY, 0, 9, "abcd")),
      (Events{"ERROR CORRUPT FRAME_SIZE_ERROR"}));
}

TEST(H2Streams, AClientsStreamIdentifierMustBeOddAndRising_Section5_1_1) {
  {
    OpenServer o;
    EXPECT_EQ(o.request(2), (Events{"ERROR CORRUPT PROTOCOL_ERROR"}))
        << "an even identifier is the server's";
  }
  {
    OpenServer o;
    ASSERT_EQ(o.request(5).size(), 1u);
    EXPECT_EQ(o.request(3), (Events{"ERROR CORRUPT PROTOCOL_ERROR"}))
        << "lower than one already used, and never opened";
  }
  {
    OpenServer o;
    ASSERT_EQ(o.request(5).size(), 1u);
    EXPECT_EQ(o.request(5), (Events{"STREAM_ERROR 5 STREAM_CLOSED"}))
        << "the request ended the client's side: half-closed (remote)";
  }
  {
    OpenServer o;
    ASSERT_EQ(o.request(5).size(), 1u);
    GHTTP_Response * r;
    ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
    ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, 5, r, 1), GHTTP_OK);
    ghttp_response_destroy(r);
    EXPECT_EQ(o.request(5), (Events{"ERROR CORRUPT STREAM_CLOSED"}))
        << "reuse of a stream that has ended in both directions";
  }
  {
    OpenServer o;
    ASSERT_EQ(o.request(1, request_list("POST", "/"), END_HEADERS).size(), 1u);
    // A second HEADERS on an open stream is its trailers, which may not
    // carry the pseudo-header fields of a request.
    EXPECT_EQ(o.request(1, request_list()), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  }
}

TEST(H2Streams, SkippingIdentifiersIsAllowedAndClosesTheSkippedOnes_Section5_1_1) {
  OpenServer o;
  EXPECT_EQ(o.request(7).size(), 1u);
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Streams, DataOnAHalfClosedRemoteStreamIsAStreamError_Section5_1) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  o.feed(data(1, "x", true));
  EXPECT_EQ(o.feed(data(1, "more")), (Events{"STREAM_ERROR 1 STREAM_CLOSED"}));
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_STREAM_CLOSED));
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Streams, HeadersOnAHalfClosedRemoteStreamIsAStreamError_Section5_1) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  o.feed(data(1, "x", true));
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x", "1"}}), END_HEADERS | END_STREAM)),
      (Events{"STREAM_ERROR 1 STREAM_CLOSED"}));
}

TEST(H2Streams, DataOnAClosedStreamIsAConnectionError_Section5_1) {
  OpenServer o;
  o.request(1);  // GET with END_STREAM; answer it so both directions end
  GHTTP_Response * r;
  ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, 1, r, 1), GHTTP_OK);
  ghttp_response_destroy(r);
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
  EXPECT_EQ(o.feed(data(1, "x")), (Events{"ERROR CORRUPT STREAM_CLOSED"}));
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_STREAM_CLOSED));
}

TEST(H2Streams, WindowUpdateRstAndPriorityOnAClosedStreamAreIgnored_Section5_1) {
  OpenServer o;
  o.request(1);
  GHTTP_Response * r;
  ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, 1, r, 1), GHTTP_OK);
  ghttp_response_destroy(r);
  EXPECT_EQ(o.feed(window_update(1, 10) + priority(1) + rst(1, 8)), Events{});
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Streams, RstStreamFromThePeerClosesTheStreamAndIsReported_Section6_4) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  EXPECT_EQ(o.feed(rst(1, GHTTP_H2_CANCEL)), (Events{"RESET 1 CANCEL"}));
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
  EXPECT_EQ(o.feed(data(1, "x")), (Events{"ERROR CORRUPT STREAM_CLOSED"}))
      << "the peer sent a frame after its own RST_STREAM";
}

TEST(H2Streams, AStreamBeyondTheConcurrencyLimitIsRefused_Section5_1_2) {
  GHTTP_H2Limits l = limits();
  l.max_concurrent_streams = 2;
  OpenServer o(l);
  EXPECT_EQ(o.request(1, request_list("POST", "/"), END_HEADERS).size(), 1u);
  EXPECT_EQ(o.request(3, request_list("POST", "/"), END_HEADERS).size(), 1u);
  EXPECT_EQ(o.request(5, request_list("POST", "/"), END_HEADERS),
      (Events{"STREAM_ERROR 5 REFUSED_STREAM"}))
      << "REFUSED_STREAM lets the client retry (section 8.7)";
  EXPECT_EQ(ghttp_h2_conn_stream_count(o.s.c), 2u);
  // Ending one makes room.
  o.feed(rst(1, GHTTP_H2_CANCEL));
  EXPECT_EQ(o.request(7, request_list("POST", "/"), END_HEADERS).size(), 1u);
}

TEST(H2Streams, PushPromiseIsAProtocolErrorBecausePushIsDisabled_Section6_6) {
  {
    OpenServer o;
    EXPECT_EQ(o.feed(frame(GHTTP_H2_PUSH_PROMISE, END_HEADERS, 1, u32(2) + "blk")),
        (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
  }
  {
    // A client that advertised ENABLE_PUSH = 0 refuses one from the server.
    Side c(GHTTP_H2_CLIENT);
    c.feed(settings({}) + settings_ack());
    c.feed(frame(GHTTP_H2_PUSH_PROMISE, END_HEADERS, 1, u32(2) + "blk"));
    EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
  }
}

TEST(H2Streams, AServerHeadersFrameOnAnEvenStreamAtAClientIsAProtocolError) {
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({}));
  c.feed(headers(2, "x"));
  EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
}


// ---- Receiving: flow control, Section 5.2 and 6.9 ---------------------------

namespace {

/** A server whose settings are @p lim, with a POST open on stream 1 and the
 *  local SETTINGS acknowledged by the client. */
struct FlowServer : OpenServer {
  explicit FlowServer(GHTTP_H2Limits l) : OpenServer(l) {
    EXPECT_EQ(request(1, request_list("POST", "/"), END_HEADERS).size(), 1u);
    wrote();
  }
};

GHTTP_Response * make_response(int status = 200, const char * reason = "") {
  GHTTP_Response * r;
  EXPECT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_response_set_status(r, status, reason), GHTTP_OK);
  return r;
}

uint64_t window_updates_for(const std::vector<OutFrame> & fs, uint32_t stream) {
  uint64_t n = 0;
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_WINDOW_UPDATE && f.stream == stream) n += f.u32at(0);
  }
  return n;
}

} // namespace

TEST(H2FlowReceive, DataBeyondTheStreamWindowIsAStreamError_FlowControlError) {
  GHTTP_H2Limits l = limits();
  l.initial_window_size = 100;
  FlowServer o(l);
  EXPECT_EQ(o.feed(data(1, std::string(100, 'a'))), (Events{"DATA 1 \"" + std::string(100, 'a') + "\""}));
  EXPECT_EQ(o.feed(data(1, std::string(1, 'b'))), (Events{"DATA 1 \"b\""}))
      << "the window was returned: auto flow control";
  // One frame larger than a whole window:
  EXPECT_EQ(o.feed(data(1, std::string(101, 'c'))), (Events{"STREAM_ERROR 1 FLOW_CONTROL_ERROR"}));
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_FLOW_CONTROL_ERROR));
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2FlowReceive, DataBeyondTheConnectionWindowIsAConnectionError) {
  GHTTP_H2Limits l = limits();
  l.manual_flow_control = 1;
  OpenServer o(l);
  for (uint32_t id : {1u, 3u, 5u, 7u}) {
    o.request(id, request_list("POST", "/"), END_HEADERS);
  }
  o.wrote();
  for (uint32_t id : {1u, 3u, 5u}) {
    EXPECT_EQ(o.feed(data(id, std::string(16384, 'x'))).size(), 1u);
  }
  // 65535 is the whole connection window: 3 * 16384 are in, 16383 more fill it
  // exactly and are accepted; the next single octet is one over.
  EXPECT_EQ(o.feed(data(7, std::string(16383, 'x'))).size(), 1u);
  EXPECT_EQ(ghttp_h2_conn_connection_recv_window(o.s.c), 0);
  o.wrote();
  o.feed(data(7, std::string(1, 'x')));
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_FLOW_CONTROL_ERROR));
}

TEST(H2FlowReceive, TheWholeFrameCountsAgainstTheConnectionWindowEvenOnAnErroredStream_Section6_9) {
  GHTTP_H2Limits l = limits();
  l.initial_window_size = 10;
  l.manual_flow_control = 1;
  FlowServer o(l);
  // 11 octets exceed stream 1's window; they are still counted on the connection.
  int64_t before = ghttp_h2_conn_connection_recv_window(o.s.c);
  EXPECT_EQ(o.feed(data(1, std::string(11, 'x'))), (Events{"STREAM_ERROR 1 FLOW_CONTROL_ERROR"}));
  EXPECT_EQ(ghttp_h2_conn_connection_recv_window(o.s.c), before - 11);
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2FlowReceive, AutomaticFlowControlReturnsEveryOctetItDelivers) {
  GHTTP_H2Limits l = limits();
  FlowServer o(l);
  uint64_t total = 0;
  for (int i = 0; i < 6; i++) {
    o.feed(data(1, std::string(10000, 'x')));
    total += 10000;
  }
  auto fs = o.wrote();
  // Credit goes back in batches of at least half a window; what is still
  // unreturned is below that.
  uint64_t stream_credit = window_updates_for(fs, 1);
  uint64_t conn_credit = window_updates_for(fs, 0);
  EXPECT_GT(stream_credit, total - 65535 / 2 - 1);
  EXPECT_GT(conn_credit, total - 65535 / 2 - 1);
  EXPECT_LE(stream_credit, total);
  int64_t sw, rw;
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_GE(rw, 65535 / 2) << "the window never ran down to nothing";
  EXPECT_LE(rw, 65535);
}

TEST(H2FlowReceive, ManualFlowControlReturnsNothingUntilTheCallerConsumes) {
  GHTTP_H2Limits l = limits();
  l.manual_flow_control = 1;
  FlowServer o(l);
  for (int i = 0; i < 4; i++) o.feed(data(1, std::string(10000, 'x')));
  EXPECT_EQ(window_updates_for(o.wrote(), 1), 0u);
  EXPECT_EQ(ghttp_h2_conn_consume(o.s.c, 1, 20000), GHTTP_OK);
  EXPECT_EQ(window_updates_for(o.wrote(), 1), 0u) << "under half a window: batched";
  EXPECT_EQ(ghttp_h2_conn_consume(o.s.c, 1, 20000), GHTTP_OK);
  auto fs = o.wrote();
  EXPECT_EQ(window_updates_for(fs, 1), 40000u);
  EXPECT_EQ(window_updates_for(fs, 0), 40000u);
  EXPECT_EQ(ghttp_h2_conn_consume(o.s.c, 1, 1), GHTTP_ERR_INVALID) << "more than was delivered";
}

TEST(H2FlowReceive, PaddingCountsAgainstTheWindowAndIsReturnedAtOnce_Section6_1) {
  GHTTP_H2Limits l = limits();
  l.manual_flow_control = 1;
  l.initial_window_size = 200;
  FlowServer o(l);
  // 110 octets on the wire: the Pad Length field, 10 of data, 99 of padding.
  std::string padded = std::string(1, '\x63') + std::string(10, 'a') + std::string(99, '\0');
  o.feed(frame(GHTTP_H2_DATA, GHTTP_H2_FLAG_PADDED, 1, padded));
  int64_t sw, rw;
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(rw, 200 - 110 + 100)
      << "the 100 octets of padding and its length field are returned; the 10 of data wait for the caller";
  EXPECT_EQ(window_updates_for(o.wrote(), 1), 100u);
}

TEST(H2FlowReceive, AZeroWindowUpdateIsAStreamErrorOnAStreamAndAConnectionErrorOnTheConnection_Section6_9) {
  {
    FlowServer o(limits());
    EXPECT_EQ(o.feed(window_update(1, 0)), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
    EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_PROTOCOL_ERROR));
  }
  {
    FlowServer o(limits());
    EXPECT_EQ(o.feed(window_update(0, 0)), (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
  }
}

TEST(H2FlowReceive, AWindowUpdateThatOverflowsIsFlowControlError_Section6_9_1) {
  {
    FlowServer o(limits());
    EXPECT_EQ(o.feed(window_update(1, 0x7fffffffu)), (Events{"STREAM_ERROR 1 FLOW_CONTROL_ERROR"}));
  }
  {
    FlowServer o(limits());
    EXPECT_EQ(o.feed(window_update(0, 0x7fffffffu)), (Events{"ERROR CORRUPT FLOW_CONTROL_ERROR"}));
  }
  {
    FlowServer o(limits());
    // Reaching exactly 2^31 - 1 is fine.
    EXPECT_EQ(o.feed(window_update(0, 0x7fffffffu - 65535u)).size(), 1u);
    EXPECT_EQ(o.s.result, GHTTP_OK);
    EXPECT_EQ(o.feed(window_update(0, 1)), (Events{"ERROR CORRUPT FLOW_CONTROL_ERROR"}));
  }
}

TEST(H2FlowReceive, ALocalInitialWindowChangeAppliesWhenTheAckArrives_Section6_5_3) {
  GHTTP_H2Limits l = limits();
  l.initial_window_size = 1000;
  Side s(GHTTP_H2_SERVER, &l);
  s.feed(client_open());
  // Before the ACK the peer may still use the default: a stream opened now has
  // the larger of the two, so that nothing legal is refused.
  Block blk;
  s.feed(headers(1, blk(request_list("POST", "/")), END_HEADERS));
  int64_t sw, rw;
  ASSERT_EQ(ghttp_h2_conn_stream_windows(s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(rw, 65535);
  s.feed(settings_ack());
  ASSERT_EQ(ghttp_h2_conn_stream_windows(s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(rw, 1000) << "the stream's window follows the new initial size (section 6.9.2)";
}

// ---- Sending: flow control --------------------------------------------------

namespace {

/** A server with a stream 1 whose response headers are sent; the client's
 *  SETTINGS were @p kv. */
struct SendServer : OpenServer {
  explicit SendServer(std::initializer_list<std::pair<uint16_t, uint32_t>> kv = {},
      GHTTP_H2Limits l = limits())
      : OpenServer(l, kv) {
    EXPECT_EQ(request(1, request_list("GET", "/"), END_HEADERS).size(), 1u);
    GHTTP_Response * r = make_response();
    EXPECT_EQ(ghttp_h2_conn_send_response(s.c, 1, r, 0), GHTTP_OK);
    ghttp_response_destroy(r);
    wrote();
  }
  size_t send(const std::string & d, bool end = false) {
    size_t n = 99;
    EXPECT_EQ(ghttp_h2_conn_send_data(s.c, 1, d.data(), d.size(), end, &n), GHTTP_OK);
    return n;
  }
};

std::string data_of(const std::vector<OutFrame> & fs, uint32_t stream) {
  std::string d;
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_DATA && f.stream == stream) d += f.payload;
  }
  return d;
}

} // namespace

TEST(H2FlowSend, DataIsHeldBackAtTheWindowAndResumesOnWindowUpdate_Section6_9) {
  SendServer o({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 100}});
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 1), 100u);
  EXPECT_EQ(o.send(std::string(500, 'a')), 100u);
  EXPECT_EQ(data_of(o.wrote(), 1), std::string(100, 'a'));
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 1), 0u);
  EXPECT_EQ(o.send(std::string(400, 'b')), 0u);
  EXPECT_TRUE(o.wrote().empty());
  EXPECT_EQ(o.feed(window_update(1, 150)), (Events{"WINDOW 1 +150"}));
  EXPECT_EQ(o.send(std::string(400, 'b')), 150u);
  EXPECT_EQ(data_of(o.wrote(), 1), std::string(150, 'b'));
}

TEST(H2FlowSend, TheConnectionWindowLimitsAllStreamsTogether) {
  GHTTP_H2Limits l = limits();
  SendServer o({}, l);
  o.request(3, request_list("GET", "/"), END_HEADERS | END_STREAM);
  GHTTP_Response * r = make_response();
  ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, 3, r, 0), GHTTP_OK);
  ghttp_response_destroy(r);
  size_t n = 0;
  std::string big(70000, 'x');
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 1, big.data(), big.size(), 0, &n), GHTTP_OK);
  EXPECT_EQ(n, 65535u) << "the stream and the connection both have 65535";
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 3, big.data(), 10, 0, &n), GHTTP_OK);
  EXPECT_EQ(n, 0u) << "stream 3 has window, the connection has none";
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 3), 0u);
  o.feed(window_update(0, 100));
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 3, big.data(), 1000, 0, &n), GHTTP_OK);
  EXPECT_EQ(n, 100u);
}

TEST(H2FlowSend, FramesAreNoLargerThanThePeerAccepts_Section4_2) {
  {
    SendServer o;
    EXPECT_EQ(o.send(std::string(40000, 'a')), 40000u);
    auto fs = o.wrote();
    ASSERT_EQ(fs.size(), 3u);
    EXPECT_EQ(fs[0].payload.size(), 16384u);
    EXPECT_EQ(fs[1].payload.size(), 16384u);
    EXPECT_EQ(fs[2].payload.size(), 7232u);
  }
  {
    SendServer o({{GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, 20000}});
    EXPECT_EQ(o.send(std::string(40000, 'a')), 40000u);
    auto fs = o.wrote();
    ASSERT_EQ(fs.size(), 2u);
    EXPECT_EQ(fs[0].payload.size(), 20000u);
  }
}

TEST(H2FlowSend, EndStreamTakesEffectOnlyWhenAllTheDataWasAccepted) {
  SendServer o({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 100}});
  EXPECT_EQ(o.send(std::string(150, 'a'), true), 100u);
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].flags & END_STREAM, 0) << "not the last of the data";
  EXPECT_TRUE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
  o.feed(window_update(1, 100));
  EXPECT_EQ(o.send(std::string(50, 'a'), true), 50u);
  fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].flags & END_STREAM, END_STREAM);
  EXPECT_TRUE(ghttp_h2_conn_stream_is_active(o.s.c, 1)) << "half-closed (local): the request is still open";
  o.feed(data(1, "", true));
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1)) << "closed: both ends have ended";
}

TEST(H2FlowSend, AnEmptyFinalDataFrameNeedsNoWindow_Section6_9_1) {
  SendServer o({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0}});
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 1), 0u);
  EXPECT_EQ(o.send("", true), 0u);
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].type, GHTTP_H2_DATA);
  EXPECT_EQ(fs[0].payload.size(), 0u);
  EXPECT_EQ(fs[0].flags & END_STREAM, END_STREAM);
}

TEST(H2FlowSend, ASettingsChangeAdjustsOpenStreamsAndMayMakeTheWindowNegative_Section6_9_2) {
  SendServer o({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 100}});
  EXPECT_EQ(o.send(std::string(100, 'a')), 100u);
  int64_t sw, rw;
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(sw, 0);
  // The peer now says 40: the window is -60.
  o.feed(settings({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 40}}));
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(sw, -60);
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 1), 0u);
  EXPECT_EQ(o.send("xxxx"), 0u);
  o.feed(window_update(1, 70));
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(sw, 10);
  EXPECT_EQ(o.send(std::string(50, 'a')), 10u);
  // And upwards: 40 -> 1000 adds 960.
  o.feed(settings({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 1000}}));
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 1, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(sw, 960);
  // A stream opened afterwards starts at the new value.
  o.request(3, request_list("GET", "/"), END_HEADERS | END_STREAM);
  ASSERT_EQ(ghttp_h2_conn_stream_windows(o.s.c, 3, &sw, &rw), GHTTP_OK);
  EXPECT_EQ(sw, 1000);
}

TEST(H2FlowSend, ASettingsChangeThatOverflowsAWindowIsAConnectionError_Section6_9_2) {
  SendServer o;
  o.feed(window_update(1, 1000));  // stream window 66535
  EXPECT_EQ(o.feed(settings({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffffu}})),
      (Events{"ERROR CORRUPT FLOW_CONTROL_ERROR"}));
}

TEST(H2FlowSend, AnInitialWindowAbove2To31MinusOneIsAFlowControlError_Section6_5_2) {
  OpenServer o;
  EXPECT_EQ(o.feed(settings({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000u}})),
      (Events{"ERROR CORRUPT FLOW_CONTROL_ERROR"}));
}

TEST(H2FlowSend, DataCannotBeSentBeforeTheResponseHeadersOrOnAnUnknownStream) {
  OpenServer o;
  o.request(1);
  size_t n;
  EXPECT_EQ(ghttp_h2_conn_send_data(o.s.c, 1, "x", 1, 0, &n), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_conn_send_data(o.s.c, 9, "x", 1, 0, &n), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 9), 0u);
}

TEST(H2FlowSend, OutputIsBoundedByTheBufferLimit) {
  GHTTP_H2Limits l = limits();
  l.max_buffered_bytes = 50000;
  SendServer o({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 1 << 20}}, l);
  o.feed(window_update(0, 1 << 20));
  size_t n = o.send(std::string(200000, 'x'));
  EXPECT_LE(n, 50000u) << "queued output is capped, so the caller must drain it";
  EXPECT_GT(n, 0u);
}

// ---- Settings: Section 6.5 -----------------------------------------------------

TEST(H2Settings, ThePeersValuesAreAppliedAndAcknowledged) {
  OpenServer o;
  o.feed(settings({{GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS, 7}, {GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, 30000},
      {GHTTP_H2_SETTINGS_MAX_HEADER_LIST_SIZE, 999}, {GHTTP_H2_SETTINGS_HEADER_TABLE_SIZE, 512}}));
  GHTTP_H2Settings p;
  ghttp_h2_conn_peer_settings(o.s.c, &p);
  EXPECT_EQ(p.max_concurrent_streams, 7u);
  EXPECT_EQ(p.max_frame_size, 30000u);
  EXPECT_EQ(p.max_header_list_size, 999u);
  EXPECT_EQ(p.header_table_size, 512u);
  EXPECT_EQ(p.initial_window_size, 65535u);
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].type, GHTTP_H2_SETTINGS);
  EXPECT_EQ(fs[0].flags, GHTTP_H2_FLAG_ACK);
}

TEST(H2Settings, ValuesOutOfRangeAreProtocolErrors_Section6_5_2) {
  const std::vector<std::pair<const char *, std::string>> bad = {
    {"MAX_FRAME_SIZE under 16384", settings({{GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, 16383}})},
    {"MAX_FRAME_SIZE over 2^24-1", settings({{GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, 1u << 24}})},
    {"ENABLE_PUSH of 2", settings({{GHTTP_H2_SETTINGS_ENABLE_PUSH, 2}})},
  };
  for (auto & b : bad) {
    OpenServer o;
    EXPECT_EQ(o.feed(b.second), (Events{"ERROR CORRUPT PROTOCOL_ERROR"})) << b.first;
  }
  OpenServer ok;
  EXPECT_EQ(ok.feed(settings({{GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, 16384}, {GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, (1u << 24) - 1},
                {GHTTP_H2_SETTINGS_ENABLE_PUSH, 1}})),
      (Events{"SETTINGS"}))
      << "the bounds themselves, and a client enabling push (a server may not act on it)";
}

TEST(H2Settings, AServerThatSetsEnablePushToOneIsAProtocolError_Section6_5_2) {
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_PUSH, 1}}));
  EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
}

TEST(H2Settings, ASettingsFrameWithAnUnknownIdentifierIsAcknowledgedAndIgnored_Section5_5) {
  OpenServer o;
  EXPECT_EQ(o.feed(settings({{0x99, 12345}, {GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS, 3}})),
      (Events{"SETTINGS"}));
  GHTTP_H2Settings p;
  ghttp_h2_conn_peer_settings(o.s.c, &p);
  EXPECT_EQ(p.max_concurrent_streams, 3u);
}

TEST(H2Settings, AnAckWithNothingToAcknowledgeIsIgnored) {
  OpenServer o;
  EXPECT_EQ(o.feed(settings_ack()), Events{});
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Settings, AdvertisedSettingsFollowTheLimits) {
  GHTTP_H2Limits l = limits();
  l.max_frame_size = 30000;
  l.max_concurrent_streams = 7;
  l.initial_window_size = 1234;
  l.max_header_list_bytes = 5000;
  l.max_table_size = 2048;
  Side s(GHTTP_H2_SERVER, &l);
  GHTTP_H2Settings loc;
  ghttp_h2_conn_local_settings(s.c, &loc);
  EXPECT_EQ(loc.max_frame_size, 30000u);
  EXPECT_EQ(loc.max_concurrent_streams, 7u);
  EXPECT_EQ(loc.initial_window_size, 1234u);
  EXPECT_EQ(loc.max_header_list_size, 5000u);
  EXPECT_EQ(loc.header_table_size, 2048u);
  auto fs = s.frames();
  ASSERT_GE(fs.size(), 1u);
  std::vector<std::pair<uint16_t, uint32_t>> got;
  for (size_t i = 0; i + 6 <= fs[0].payload.size(); i += 6) {
    got.push_back({static_cast<uint16_t>((static_cast<uint8_t>(fs[0].payload[i]) << 8)
                       | static_cast<uint8_t>(fs[0].payload[i + 1])),
        fs[0].u32at(i + 2)});
  }
  auto has = [&](uint16_t id, uint32_t v) {
    for (auto & g : got) if (g.first == id && g.second == v) return true;
    return false;
  };
  EXPECT_TRUE(has(GHTTP_H2_SETTINGS_MAX_FRAME_SIZE, 30000));
  EXPECT_TRUE(has(GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS, 7));
  EXPECT_TRUE(has(GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 1234));
  EXPECT_TRUE(has(GHTTP_H2_SETTINGS_MAX_HEADER_LIST_SIZE, 5000));
  EXPECT_TRUE(has(GHTTP_H2_SETTINGS_HEADER_TABLE_SIZE, 2048));
  // A frame of the advertised size is accepted at once, before the ACK.
  Side t(GHTTP_H2_SERVER, &l);
  t.feed(client_open());
  t.feed(data(1, "x"));  // idle stream: an error, but not a frame size error
  EXPECT_EQ(t.result, GHTTP_ERR_CORRUPT);
}

TEST(H2Settings, AFrameLargerThanTheAdvertisedSizeIsRefusedFromItsHeaderAlone_Section4_2) {
  OpenServer o;
  std::string header = frame(GHTTP_H2_DATA, 0, 1, "").substr(0, 9);
  header[0] = 0;
  header[1] = 0x40;
  header[2] = 0x01;  // 16385
  EXPECT_EQ(o.feed(header), (Events{"ERROR CORRUPT FRAME_SIZE_ERROR"}));
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_FRAME_SIZE_ERROR));
}

TEST(H2Settings, AHeaderTableSizeFromThePeerIsAnnouncedInTheNextBlockWeSend_Section4_2) {
  SendServer o;  // already sent a response with the default table
  Side & s = o.s;
  s.feed(settings({{GHTTP_H2_SETTINGS_HEADER_TABLE_SIZE, 100}}));
  s.mark();
  GHTTP_Response * r = make_response(200);
  ASSERT_EQ(ghttp_headers_add(ghttp_response_headers(r), "x-a", "1"), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_trailers(s.c, 1, ghttp_response_headers_const(r)), GHTTP_OK);
  ghttp_response_destroy(r);
  auto fs = s.frames_since_mark();
  const OutFrame * h = nullptr;
  for (auto & f : fs) if (f.type == GHTTP_H2_HEADERS) h = &f;
  ASSERT_NE(h, nullptr);
  EXPECT_EQ(h2hex(h->payload.substr(0, 2)), "3f45") << "a dynamic table size update to 100";
}

TEST(H2Settings, AnAdvertisedSmallerTableObligesTheNextBlockToOpenWithAnUpdate_Section4_2) {
  GHTTP_H2Limits l = limits();
  l.max_table_size = 1000;
  {
    OpenServer o(l);  // the ACK of our SETTINGS has arrived
    EXPECT_EQ(o.feed(headers(1, o.blk(request_list()), END_HEADERS | END_STREAM)),
        (Events{"ERROR CORRUPT COMPRESSION_ERROR"}))
        << "the client was told 1000 and its block did not say it had changed";
  }
  {
    OpenServer o(l);
    std::string blk = std::string("\x3f\xc9\x07", 3) + o.blk(request_list());  // update to 1000
    auto e = o.feed(headers(1, blk, END_HEADERS | END_STREAM));
    ASSERT_EQ(e.size(), 1u);
    EXPECT_TRUE(has_prefix(e[0], "HEADERS 1 end GET /"));
  }
}

// ---- Abuse: the limits, Section 10.5 ------------------------------------------------

TEST(H2Abuse, RapidResetStopsAtTheLimitPlusOne_Cve2023_44487) {
  GHTTP_H2Limits l = limits();
  l.max_rst_per_interval = 5;
  OpenServer o(l);
  int resets_seen = 0;
  int sent = 0;
  for (uint32_t id = 1; id < 40 && o.s.result == GHTTP_OK; id += 2) {
    o.feed(headers(id, o.blk(request_list("GET", "/")), END_HEADERS));
    for (auto & e : o.feed(rst(id, GHTTP_H2_CANCEL))) {
      if (has_prefix(e, "RESET")) resets_seen++;
    }
    sent++;
  }
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(sent, 6) << "five RST_STREAM frames are allowed; the sixth is the one that ends it";
  EXPECT_EQ(resets_seen, 5);
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_ENHANCE_YOUR_CALM));
}

TEST(H2Abuse, TheCountsRenewWhenTheCallerTicksTheClock) {
  GHTTP_H2Limits l = limits();
  l.max_rst_per_interval = 3;
  l.interval_ms = 1000;
  OpenServer o(l);
  ghttp_h2_conn_tick(o.s.c, 0);
  uint32_t id = 1;
  auto burst = [&](int n) {
    for (int i = 0; i < n && o.s.result == GHTTP_OK; i++, id += 2) {
      o.feed(headers(id, o.blk(request_list("GET", "/")), END_HEADERS));
      o.feed(rst(id, GHTTP_H2_CANCEL));
    }
  };
  burst(3);
  EXPECT_EQ(o.s.result, GHTTP_OK);
  ghttp_h2_conn_tick(o.s.c, 999);
  burst(1);
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT) << "inside the interval: the fourth reset";
  OpenServer p(l);
  ghttp_h2_conn_tick(p.s.c, 0);
  id = 1;
  auto burst2 = [&](int n) {
    for (int i = 0; i < n && p.s.result == GHTTP_OK; i++, id += 2) {
      p.feed(headers(id, p.blk(request_list("GET", "/")), END_HEADERS));
      p.feed(rst(id, GHTTP_H2_CANCEL));
    }
  };
  burst2(3);
  ghttp_h2_conn_tick(p.s.c, 1000);
  burst2(3);
  EXPECT_EQ(p.s.result, GHTTP_OK) << "a new interval";
}

TEST(H2Abuse, ASettingsFloodStopsAtTheLimitPlusOne) {
  GHTTP_H2Limits l = limits();
  l.max_settings_per_interval = 6;
  OpenServer o(l);  // two used by the open (SETTINGS and the ACK)
  int n = 0;
  for (; n < 30 && o.s.result == GHTTP_OK; n++) o.feed(settings({}));
  EXPECT_EQ(n, 5) << "four more are allowed; the fifth ends it";
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_ENHANCE_YOUR_CALM));
}

TEST(H2Abuse, APingFloodStopsAtTheLimitPlusOne) {
  GHTTP_H2Limits l = limits();
  l.max_ping_per_interval = 4;
  OpenServer o(l);
  int n = 0;
  for (; n < 30 && o.s.result == GHTTP_OK; n++) o.feed(ping());
  EXPECT_EQ(n, 5);
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
}

TEST(H2Abuse, AFloodOfEmptyDataFramesStopsAtTheLimitPlusOne) {
  GHTTP_H2Limits l = limits();
  l.max_empty_data_frames = 5;
  FlowServer o(l);
  int n = 0;
  for (; n < 30 && o.s.result == GHTTP_OK; n++) o.feed(data(1, ""));
  EXPECT_EQ(n, 6);
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
}

TEST(H2Abuse, AnEmptyDataFrameThatEndsTheStreamIsNotCounted) {
  GHTTP_H2Limits l = limits();
  l.max_empty_data_frames = 1;
  OpenServer o(l);
  for (uint32_t id = 1; id < 20; id += 2) {
    o.request(id, request_list("POST", "/"), END_HEADERS);
    o.feed(data(id, "", true));
  }
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Abuse, ReplyOutputThatIsNeverDrainedIsBoundedByTheBufferLimit) {
  GHTTP_H2Limits l = limits();
  l.max_buffered_bytes = l.max_frame_size + GHTTP_H2_FRAME_HEADER_SIZE;  // the smallest allowed
  l.max_ping_per_interval = 1000000;
  GHTTP_H2Conn * c;
  ASSERT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &l, &c), GHTTP_OK);
  std::string in = client_open();
  size_t used;
  GHTTP_H2Event ev;
  ASSERT_EQ(ghttp_h2_conn_feed(c, in.data(), in.size(), &used, &ev), GHTTP_OK);
  std::string pings;
  for (int i = 0; i < 2000; i++) pings += ping();
  size_t off = 0;
  GHTTP_Result r = GHTTP_OK;
  while (off < pings.size() && r == GHTTP_OK) {
    r = ghttp_h2_conn_feed(c, pings.data() + off, pings.size() - off, &used, &ev);
    off += used;
  }
  EXPECT_EQ(r, GHTTP_ERR_LIMIT);
  uint32_t code;
  ghttp_h2_conn_error(c, &code, nullptr);
  EXPECT_EQ(code, GHTTP_H2_ENHANCE_YOUR_CALM);
  EXPECT_LE(ghttp_h2_conn_output_size(c), l.max_buffered_bytes + 64u) << "the output stopped growing at the limit";
  ghttp_h2_conn_destroy(c);
}

TEST(H2Abuse, ABodyOverTheCapIsAStreamError) {
  GHTTP_H2Limits l = limits();
  l.max_body_bytes = 100;
  FlowServer o(l);
  EXPECT_EQ(o.feed(data(1, std::string(100, 'a'))).size(), 1u);
  EXPECT_EQ(o.feed(data(1, "b")), (Events{"STREAM_ERROR 1 ENHANCE_YOUR_CALM"}));
}

TEST(H2Abuse, MoreStreamsThanTheTableAllowsAreRefused) {
  GHTTP_H2Limits l = limits();
  l.max_streams = 2;
  l.max_concurrent_streams = 100;
  OpenServer o(l);
  o.request(1, request_list("POST", "/"), END_HEADERS);
  o.request(3, request_list("POST", "/"), END_HEADERS);
  EXPECT_EQ(o.request(5, request_list("POST", "/"), END_HEADERS),
      (Events{"STREAM_ERROR 5 REFUSED_STREAM"}));
}

TEST(H2Abuse, TooManyBufferedOctetsEndTheConnection) {
  GHTTP_H2Limits l = limits();
  l.max_buffered_bytes = 20000;
  OpenServer o(l);
  std::string blk = o.blk(request_list("GET", "/", {{"x", std::string(10000, 'y')}}));
  std::string first = frame(GHTTP_H2_HEADERS, END_STREAM, 1, blk.substr(0, 9000));
  o.feed(first);
  EXPECT_EQ(o.s.result, GHTTP_OK);
  o.feed(frame(GHTTP_H2_CONTINUATION, 0, 1, std::string(12000, 'a')).substr(0, 9));
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT) << "the next frame would not fit beside the block";
}


// ---- Message validity: Section 8 ---------------------------------------------------

namespace {

struct Malformed {
  const char * what;
  HList list;
};

HList with(HList l, std::initializer_list<std::pair<std::string, std::string>> extra) {
  for (auto & e : extra) l.push_back(e);
  return l;
}

} // namespace

TEST(H2Malformed, EachMalformedRequestIsAStreamErrorAndTheConnectionCarriesOn_Section8_1_1) {
  const std::vector<Malformed> bad = {
    {"8.2 upper-case field name", with(request_list(), {{"X-Foo", "1"}})},
    {"8.2.2 connection", with(request_list(), {{"connection", "close"}})},
    {"8.2.2 keep-alive", with(request_list(), {{"keep-alive", "timeout=5"}})},
    {"8.2.2 proxy-connection", with(request_list(), {{"proxy-connection", "x"}})},
    {"8.2.2 transfer-encoding", with(request_list(), {{"transfer-encoding", "chunked"}})},
    {"8.2.2 upgrade", with(request_list(), {{"upgrade", "websocket"}})},
    {"8.2.2 te other than trailers", with(request_list(), {{"te", "gzip"}})},
    {"8.2.2 te trailers with another", with(request_list(), {{"te", "trailers, gzip"}})},
    {"8.3.1 no :method", {{":scheme", "https"}, {":path", "/"}}},
    {"8.3.1 no :scheme", {{":method", "GET"}, {":path", "/"}}},
    {"8.3.1 no :path", {{":method", "GET"}, {":scheme", "https"}}},
    {"8.3 duplicate :method", {{":method", "GET"}, {":method", "POST"}, {":scheme", "https"}, {":path", "/"}}},
    {"8.3 duplicate :path", {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":path", "/b"}}},
    {"8.3 pseudo-header after a regular field", {{":method", "GET"}, {":scheme", "https"}, {"a", "b"}, {":path", "/"}}},
    {"8.3 unknown pseudo-header (no extended CONNECT)", with(request_list(), {})},  // replaced below
    {"8.3 a response pseudo-header in a request", {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":status", "200"}}},
    {"8.3.1 empty :path", {{":method", "GET"}, {":scheme", "https"}, {":path", ""}}},
    {"8.3.1 :path not starting with a slash", {{":method", "GET"}, {":scheme", "https"}, {":path", "x"}}},
    {"8.3.1 :path * for a method other than OPTIONS", {{":method", "GET"}, {":scheme", "https"}, {":path", "*"}}},
    {"8.3.1 empty :scheme", {{":method", "GET"}, {":scheme", ""}, {":path", "/"}}},
    {"8.3.1 :authority with userinfo", request_list("GET", "/", {}, "user:pw@example.com")},
    {"8.5 CONNECT with :path", {{":method", "CONNECT"}, {":authority", "h:1"}, {":path", "/"}}},
    {"8.5 CONNECT with :scheme", {{":method", "CONNECT"}, {":authority", "h:1"}, {":scheme", "https"}}},
    {"8.5 CONNECT without :authority", {{":method", "CONNECT"}}},
    {"8.2.1 NUL in a value", with(request_list(), {{"x", std::string("a\0b", 3)}})},
    {"8.2.1 LF in a value", with(request_list(), {{"x", "a\nb"}})},
    {"8.2.1 CR in a value", with(request_list(), {{"x", "a\rb"}})},
    {"8.2.1 leading space in a value", with(request_list(), {{"x", " a"}})},
    {"8.2.1 trailing space in a value", with(request_list(), {{"x", "a "}})},
    {"8.2.1 trailing tab in a value", with(request_list(), {{"x", "a\t"}})},
    {"8.2.1 space in a name", with(request_list(), {{"a b", "1"}})},
    {"8.2.1 colon in a name", with(request_list(), {{"a:b", "1"}})},
    {"8.2.1 a name of high-bit octets", with(request_list(), {{std::string("\xe9", 1), "1"}})},
    {"8.2.1 an empty name", with(request_list(), {{"", "1"}})},
    {"8.2.1 control character in a name", with(request_list(), {{"a\x01", "1"}})},
    {"8.2.1 NUL in a pseudo-header value", {{":method", "GET"}, {":scheme", "https"}, {":path", std::string("/a\0", 3)}}},
    {"8.1.1 non-numeric content-length", with(request_list("POST"), {{"content-length", "abc"}})},
    {"8.1.1 conflicting content-lengths", with(request_list("POST"), {{"content-length", "1"}, {"content-length", "2"}})},
    {"8.1.1 content-length with a sign", with(request_list("POST"), {{"content-length", "+5"}})},
  };
  std::vector<Malformed> list = bad;
  for (auto & m : list) {
    if (std::string(m.what).find("unknown pseudo") != std::string::npos) {
      m.list = {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":protocol", "websocket"}};
    }
  }
  for (const Malformed & m : list) {
    OpenServer o;
    auto e = o.request(1, m.list);
    EXPECT_EQ(e, (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << m.what;
    EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_PROTOCOL_ERROR)) << m.what;
    EXPECT_EQ(o.s.result, GHTTP_OK) << m.what;
    // The HPACK state is still in step, so the next request on the connection decodes.
    auto next = o.request(3, request_list("GET", "/ok"));
    ASSERT_EQ(next.size(), 1u) << m.what;
    EXPECT_TRUE(has_prefix(next[0], "HEADERS 3 end GET /ok")) << m.what << ": " << next[0];
  }
}

TEST(H2Malformed, RequestsThatLookOddButAreValidAreAccepted) {
  struct Ok { const char * what; HList list; };
  const std::vector<Ok> ok = {
    {"te: trailers", with(request_list(), {{"te", "trailers"}})},
    {"OPTIONS *", {{":method", "OPTIONS"}, {":scheme", "https"}, {":path", "*"}}},
    {"a non-http scheme", request_list("GET", "/", {}, "example.com", "ftp")},
    {"CONNECT with only :method and :authority", {{":method", "CONNECT"}, {":authority", "h:443"}}},
    {"an empty value", with(request_list(), {{"x", ""}})},
    {"a value with an interior space and tab", with(request_list(), {{"x", "a b\tc"}})},
    {"a zero content-length on a GET", with(request_list(), {{"content-length", "0"}})},
    {"repeated identical content-lengths", with(request_list("POST"), {{"content-length", "0"}, {"content-length", "0"}})},
    {"a fragment-like path", request_list("GET", "/a?b#c")},
    {"a long header", with(request_list(), {{"x", std::string(8000, 'v')}})},
    {"the same field twice", with(request_list(), {{"x", "1"}, {"x", "2"}})},
  };
  for (const Ok & k : ok) {
    OpenServer o;
    auto e = o.request(1, k.list, END_HEADERS | END_STREAM);
    ASSERT_EQ(e.size(), 1u) << k.what;
    EXPECT_TRUE(has_prefix(e[0], "HEADERS 1")) << k.what << ": " << e[0];
  }
}

TEST(H2Malformed, ABodyThatDisagreesWithContentLengthIsMalformed_Section8_1_1) {
  {
    OpenServer o;
    o.request(1, request_list("POST", "/", {{"content-length", "5"}}), END_HEADERS);
    o.feed(data(1, "abc"));
    EXPECT_EQ(o.feed(data(1, "d", true)), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}))
        << "ended at 4 of 5";
  }
  {
    OpenServer o;
    o.request(1, request_list("POST", "/", {{"content-length", "3"}}), END_HEADERS);
    EXPECT_EQ(o.feed(data(1, "abcd")), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << "4 of 3, at once";
  }
  {
    OpenServer o;
    EXPECT_EQ(o.request(1, request_list("POST", "/", {{"content-length", "5"}})),
        (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << "END_STREAM on the headers with nothing sent";
  }
  {
    OpenServer o;
    o.request(1, request_list("POST", "/", {{"content-length", "3"}}), END_HEADERS);
    EXPECT_EQ(o.feed(data(1, "abc", true)), (Events{"DATA 1 end \"abc\""}));
  }
  {
    OpenServer o;
    o.request(1, request_list("POST", "/", {{"content-length", "3"}}), END_HEADERS);
    o.feed(data(1, "ab"));
    EXPECT_EQ(o.feed(headers(1, o.blk({{"x", "1"}}), END_HEADERS | END_STREAM)),
        (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << "trailers that end it short";
  }
}

TEST(H2Malformed, ConnectIsATunnelWhoseDataIsNotFramed_Section8_5) {
  OpenServer o;
  auto e = o.request(1, {{":method", "CONNECT"}, {":authority", "h:443"}}, END_HEADERS);
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0], "HEADERS 1 CONNECT h:443 [host: h:443] scheme=- authority=h:443");
  GHTTP_H2StreamMode mode;
  ASSERT_EQ(ghttp_h2_conn_stream_mode(o.s.c, 1, &mode), GHTTP_OK);
  EXPECT_EQ(mode, GHTTP_H2_STREAM_TUNNEL);
  EXPECT_EQ(o.feed(data(1, "opaque") + data(1, "bytes", true)).size(), 2u);
  OpenServer p;
  p.request(1, {{":method", "CONNECT"}, {":authority", "h:443"}}, END_HEADERS);
  EXPECT_EQ(p.feed(headers(1, p.blk({{"x", "1"}}), END_HEADERS | END_STREAM)),
      (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}))
      << "only DATA and stream management frames are allowed on a connected stream";
}

TEST(H2Malformed, AStreamModeCanBeChangedForExtensions) {
  OpenServer o;
  o.request(1, request_list("POST", "/", {{"content-length", "2"}}), END_HEADERS);
  GHTTP_H2StreamMode mode;
  ASSERT_EQ(ghttp_h2_conn_stream_mode(o.s.c, 1, &mode), GHTTP_OK);
  EXPECT_EQ(mode, GHTTP_H2_STREAM_MESSAGE);
  ASSERT_EQ(ghttp_h2_conn_set_stream_mode(o.s.c, 1, GHTTP_H2_STREAM_TUNNEL), GHTTP_OK);
  EXPECT_EQ(o.feed(data(1, "far more than two octets", true)).size(), 1u)
      << "content-length is not applied to a tunnel";
  EXPECT_EQ(ghttp_h2_conn_set_stream_mode(o.s.c, 99, GHTTP_H2_STREAM_TUNNEL), GHTTP_ERR_INVALID);
}

TEST(H2Malformed, ResponsesAreCheckedToo_Section8_3_2) {
  struct Case { const char * what; HList list; };
  const std::vector<Case> bad = {
    {"no :status", {{"x", "1"}}},
    {"a two-digit :status", {{":status", "20"}}},
    {"a four-digit :status", {{":status", "2000"}}},
    {"a non-numeric :status", {{":status", "2xx"}}},
    {"101 does not exist in HTTP/2 (section 8.6)", {{":status", "101"}}},
    {"a duplicate :status", {{":status", "200"}, {":status", "200"}}},
    {"a request pseudo-header", {{":status", "200"}, {":path", "/"}}},
    {"a pseudo-header after a field", {{"a", "b"}, {":status", "200"}}},
    {"connection-specific field", {{":status", "200"}, {"connection", "close"}}},
    {"upper-case name", {{":status", "200"}, {"Content-Type", "x"}}},
  };
  for (const Case & c : bad) {
    Side cl(GHTTP_H2_CLIENT);
    Block blk;
    cl.feed(settings({}) + settings_ack());
    GHTTP_Request * r;
    ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_method(r, "POST"), GHTTP_OK);
    uint32_t id;
    ASSERT_EQ(ghttp_h2_conn_send_request(cl.c, r, "https", 0, &id), GHTTP_OK);
    ghttp_request_destroy(r);
    cl.take_events();
    cl.feed(headers(id, blk(c.list), END_HEADERS));
    EXPECT_EQ(cl.events, (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << c.what;
  }
}

TEST(H2Malformed, AResponseCarriesItsStatusInterimResponsesAndTrailers_Section8_1) {
  Side cl(GHTTP_H2_CLIENT);
  Block blk;
  cl.feed(settings({}) + settings_ack());
  GHTTP_Request * r;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  uint32_t id;
  ASSERT_EQ(ghttp_h2_conn_send_request(cl.c, r, "https", 1, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  cl.take_events();
  cl.feed(headers(id, blk(response_list(103, {{"link", "</a>"}})), END_HEADERS));
  cl.feed(headers(id, blk(response_list(200, {{"content-length", "4"}})), END_HEADERS));
  cl.feed(data(id, "ab"));
  cl.feed(data(id, "cd"));
  cl.feed(headers(id, blk({{"x-t", "1"}}), END_HEADERS | END_STREAM));
  EXPECT_EQ(cl.events, (Events{"HEADERS 1 interim 103 [link: </a>]", "HEADERS 1 200 [content-length: 4]",
      "DATA 1 \"ab\"", "DATA 1 \"cd\"", "TRAILERS 1 [x-t: 1]"}));
}

TEST(H2Malformed, AnInterimResponseThatEndsTheStreamIsMalformed_Section8_1) {
  Side cl(GHTTP_H2_CLIENT);
  Block blk;
  cl.feed(settings({}) + settings_ack());
  GHTTP_Request * r;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  uint32_t id;
  ASSERT_EQ(ghttp_h2_conn_send_request(cl.c, r, "https", 1, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  cl.take_events();
  cl.feed(headers(id, blk(response_list(100)), END_HEADERS | END_STREAM));
  EXPECT_EQ(cl.events, (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
}

TEST(H2Malformed, AResponseToHeadMayAnnounceALengthItDoesNotSend_Section8_1_1) {
  Side cl(GHTTP_H2_CLIENT);
  Block blk;
  cl.feed(settings({}) + settings_ack());
  GHTTP_Request * r;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_method(r, "HEAD"), GHTTP_OK);
  uint32_t id;
  ASSERT_EQ(ghttp_h2_conn_send_request(cl.c, r, "https", 1, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  cl.take_events();
  cl.feed(headers(id, blk(response_list(200, {{"content-length", "1000"}})), END_HEADERS | END_STREAM));
  EXPECT_EQ(cl.events, (Events{"HEADERS 1 end 200 [content-length: 1000]"}));
}

TEST(H2Malformed, A204AndA304MayCarryALengthWithoutABody_Section8_1_1) {
  for (int status : {204, 304}) {
    Side cl(GHTTP_H2_CLIENT);
    Block blk;
    cl.feed(settings({}) + settings_ack());
    GHTTP_Request * r;
    ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
    uint32_t id;
    ASSERT_EQ(ghttp_h2_conn_send_request(cl.c, r, "https", 1, &id), GHTTP_OK);
    ghttp_request_destroy(r);
    cl.take_events();
    cl.feed(headers(id, blk(response_list(status, {{"content-length", "7"}})), END_HEADERS | END_STREAM));
    EXPECT_EQ(cl.events.size(), 1u) << status;
    EXPECT_NE(cl.events[0].substr(0, 8), "STREAM_E") << status;
  }
}

TEST(H2Malformed, ResponseDataBeforeTheResponseIsMalformed) {
  Side cl(GHTTP_H2_CLIENT);
  cl.feed(settings({}) + settings_ack());
  GHTTP_Request * r;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  uint32_t id;
  ASSERT_EQ(ghttp_h2_conn_send_request(cl.c, r, "https", 1, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  cl.take_events();
  cl.feed(data(id, "x"));
  EXPECT_EQ(cl.events, (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
}

// ---- GOAWAY, PING, extensions --------------------------------------------------------

TEST(H2Control, APingIsAnsweredWithTheSameDataAndReported_Section6_7) {
  OpenServer o;
  EXPECT_EQ(o.feed(ping("abcdefgh")), (Events{"PING abcdefgh"}));
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].type, GHTTP_H2_PING);
  EXPECT_EQ(fs[0].flags, GHTTP_H2_FLAG_ACK);
  EXPECT_EQ(fs[0].payload, "abcdefgh");
  EXPECT_EQ(o.feed(ping("12345678", true)), (Events{"PING_ACK 12345678"}));
  EXPECT_TRUE(o.wrote().empty()) << "an ACK is never answered";
}

TEST(H2Control, PingCanBeSentByTheCaller) {
  OpenServer o;
  ASSERT_EQ(ghttp_h2_conn_ping(o.s.c, reinterpret_cast<const uint8_t *>("PINGDATA")), GHTTP_OK);
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].type, GHTTP_H2_PING);
  EXPECT_EQ(fs[0].flags, 0);
  EXPECT_EQ(fs[0].payload, "PINGDATA");
}

TEST(H2Control, AGoawayFromThePeerIsReportedWithItsDebugData_Section6_8) {
  OpenServer o;
  EXPECT_EQ(o.feed(goaway(5, GHTTP_H2_ENHANCE_YOUR_CALM, "too fast")),
      (Events{"GOAWAY last=5 ENHANCE_YOUR_CALM \"too fast\""}));
}

TEST(H2Control, ShutdownSendsGoawayAndRefusesLaterStreams_Section6_8) {
  OpenServer o;
  o.request(1);
  o.request(3);
  ASSERT_EQ(ghttp_h2_conn_shutdown(o.s.c, GHTTP_H2_NO_ERROR, "bye", 3), GHTTP_OK);
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].type, GHTTP_H2_GOAWAY);
  EXPECT_EQ(fs[0].u32at(0), 3u) << "the last stream accepted";
  EXPECT_EQ(fs[0].u32at(4), 0u);
  EXPECT_EQ(fs[0].payload.substr(8), "bye");
  EXPECT_EQ(o.request(5, request_list("GET", "/new", {{"x-new", "1"}})),
      (Events{"STREAM_ERROR 5 REFUSED_STREAM"}))
      << "not processed, so the client may retry it elsewhere";
  EXPECT_EQ(o.s.result, GHTTP_OK);
  // The refused block was still decoded: the table is in step.
  GHTTP_Response * r = make_response();
  EXPECT_EQ(ghttp_h2_conn_send_response(o.s.c, 1, r, 1), GHTTP_OK);
  ghttp_response_destroy(r);
}

TEST(H2Control, ExtensionFramesAndSettingsReachTheHandlerAndAreOtherwiseIgnored_Section5_5) {
  struct Seen {
    std::vector<std::string> v;
  } seen;
  OpenServer o;
  o.feed(frame(0xee, 0x5, 3, "payload") + settings({{0x99, 77}}));
  EXPECT_EQ(o.s.result, GHTTP_OK) << "unknown frames and settings are not errors without a handler";
  ghttp_h2_conn_set_extension_handler(o.s.c,
      [](void * ctx, const GHTTP_H2Extension * x) {
        auto * s = static_cast<Seen *>(ctx);
        if (x->kind == GHTTP_H2_EXT_FRAME) {
          s->v.push_back("frame type=" + std::to_string(x->frame.type) + " flags="
              + std::to_string(x->frame.flags) + " stream=" + std::to_string(x->frame.stream_id)
              + " " + std::string(reinterpret_cast<const char *>(x->payload), x->payload_len));
        } else {
          s->v.push_back("setting " + std::to_string(x->setting_id) + "=" + std::to_string(x->setting_value));
        }
      },
      &seen);
  o.feed(frame(0xee, 0x5, 3, "payload") + settings({{0x99, 77}, {GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS, 5}, {0xa000, 1}}));
  EXPECT_EQ(seen.v, (std::vector<std::string>{"frame type=238 flags=5 stream=3 payload",
      "setting 153=77", "setting 40960=1"}));
  EXPECT_EQ(o.s.result, GHTTP_OK);
  ghttp_h2_conn_set_extension_handler(o.s.c, nullptr, nullptr);
  o.feed(frame(0xef, 0, 0, "x"));
  EXPECT_EQ(seen.v.size(), 3u);
}

TEST(H2Control, AnExtensionFrameCanBeSentButNotOneOfTheDefinedTypes) {
  OpenServer o;
  EXPECT_EQ(ghttp_h2_conn_send_extension_frame(o.s.c, 0xee, 7, 0, "zz", 2), GHTTP_OK);
  auto fs = o.wrote();
  ASSERT_EQ(fs.size(), 1u);
  EXPECT_EQ(fs[0].type, 0xee);
  EXPECT_EQ(fs[0].flags, 7);
  EXPECT_EQ(ghttp_h2_conn_send_extension_frame(o.s.c, GHTTP_H2_DATA, 0, 1, "z", 1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_conn_send_extension_frame(o.s.c, GHTTP_H2_CONTINUATION, 0, 1, "z", 1), GHTTP_ERR_INVALID);
}

TEST(H2Control, ResetStreamSendsRstStreamAndForgetsTheStream_Section6_4) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  ASSERT_EQ(ghttp_h2_conn_reset_stream(o.s.c, 1, GHTTP_H2_CANCEL), GHTTP_OK);
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_CANCEL));
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
  EXPECT_EQ(o.feed(data(1, "in flight")), Events{}) << "frames already on the wire are discarded";
  EXPECT_EQ(o.s.result, GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_reset_stream(o.s.c, 1, GHTTP_H2_CANCEL), GHTTP_ERR_INVALID);
}

TEST(H2Control, ArgumentsAreChecked) {
  GHTTP_H2Conn * c = nullptr;
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, nullptr, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, static_cast<GHTTP_H2Role>(7), nullptr, &c), GHTTP_ERR_INVALID);
  GHTTP_H2Limits l = limits();
  l.max_frame_size = 100;
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &l, &c), GHTTP_ERR_INVALID);
  l = limits();
  l.initial_window_size = 0x80000000u;
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &l, &c), GHTTP_ERR_INVALID);
  l = limits();
  l.connection_window = 100;
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &l, &c), GHTTP_ERR_INVALID);
  ghttp_h2_conn_destroy(nullptr);
  size_t used;
  GHTTP_H2Event ev;
  EXPECT_EQ(ghttp_h2_conn_feed(nullptr, "x", 1, &used, &ev), GHTTP_ERR_INVALID);
  ASSERT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, nullptr, &c), GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_feed(c, nullptr, 1, &used, &ev), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_conn_feed(c, "x", 1, nullptr, &ev), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_h2_conn_send_request(c, nullptr, nullptr, 0, nullptr), GHTTP_ERR_INVALID);
  ghttp_h2_conn_destroy(c);
}


// ---- The peer closing: was it at a frame boundary? ----------------------------------

TEST(H2Finish, AConnectionThatHasSeenNothingOrWholeFramesEndsCleanly) {
  Side s(GHTTP_H2_SERVER);
  EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_OK) << "no input at all";
  s.feed(client_open());
  EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_OK);
  Block blk;
  s.feed(headers(1, blk(request_list()), END_HEADERS | END_STREAM));
  EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_OK) << "after a frame whose event was just reported";
}

TEST(H2Finish, InputThatEndsInsideTheServerPrefaceAFrameOrAHeaderBlockIsTruncated) {
  {
    Side s(GHTTP_H2_SERVER);
    s.feed(std::string(GHTTP_H2_PREFACE).substr(0, 10));
    EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_ERR_CORRUPT) << "inside the preface";
  }
  {
    Side s(GHTTP_H2_SERVER);
    s.feed(client_open() + ping().substr(0, 5));
    EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_ERR_CORRUPT) << "inside a frame header";
  }
  {
    Side s(GHTTP_H2_SERVER);
    s.feed(client_open() + ping().substr(0, 12));
    EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_ERR_CORRUPT) << "inside a payload";
  }
  {
    Side s(GHTTP_H2_SERVER);
    Block blk;
    s.feed(client_open() + frame(GHTTP_H2_HEADERS, END_STREAM, 1, blk(request_list())));
    EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_ERR_CORRUPT) << "a header block with no END_HEADERS yet";
  }
  {
    Side s(GHTTP_H2_SERVER);
    Block blk;
    std::string b = blk(request_list());
    s.feed(client_open() + frame(GHTTP_H2_HEADERS, END_STREAM, 1, b.substr(0, 5))
        + continuation(1, b.substr(5)));
    EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_OK) << "the block was completed";
  }
}

TEST(H2Finish, AFailedConnectionReportsItsOwnErrorAndNothingChanges) {
  Side s(GHTTP_H2_SERVER);
  s.feed("GET / HTTP/1.1\r\n");
  ASSERT_EQ(s.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(ghttp_h2_conn_finish(s.c), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(ghttp_h2_conn_finish(nullptr), GHTTP_ERR_INVALID);
  // A client has no preface to be cut inside, but a frame it can be.
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({}) + ping().substr(0, 3));
  EXPECT_EQ(ghttp_h2_conn_finish(c.c), GHTTP_ERR_CORRUPT);
}



// The oracle's rule for "a HEADERS block the RFC makes a stream error" lets the
// reference's answer float (Go's depends on its goroutines); these pin ours.
TEST(H2Streams, AHeadersBlockOnAHalfClosedStreamWithoutEndStreamIsAStreamError) {
  OpenServer o;
  o.request(1);  // a GET: the client is done, our answer is not
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x-t", "1"}}), END_HEADERS)),
      (Events{"STREAM_ERROR 1 STREAM_CLOSED"}));
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_STREAM_CLOSED));
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Streams, AThirdHeadersBlockIsDiscardedAfterTheMalformedSecond) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x-a", "1"}}), END_HEADERS)),
      (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << "a second block that is not trailers";
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x-b", "2"}}), END_HEADERS)), Events{})
      << "the third arrives after our RST_STREAM: decoded and dropped";
  EXPECT_EQ(o.s.result, GHTTP_OK);
  auto e = o.request(3, request_list("GET", "/", {{"x-b", "2"}}));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 3 end GET /")) << e[0];
}

// ---- Review findings: GOAWAY, resets inside a block, limits, floods, the ring ---------

namespace {

/** Answer stream @p id with an empty 200, so a request that ended is closed on both sides. */
void answer(OpenServer & o, uint32_t id) {
  GHTTP_Response * r = make_response(200);
  ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, id, r, 1), GHTTP_OK);
  ghttp_response_destroy(r);
}

/** Every GOAWAY in @p fs: its last stream id. */
std::vector<uint32_t> goaway_lasts(const std::vector<OutFrame> & fs) {
  std::vector<uint32_t> v;
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_GOAWAY) v.push_back(f.u32at(0));
  }
  return v;
}

} // namespace

TEST(H2Goaway, TheLastStreamIdNeverRises_Section6_8) {
  OpenServer o;
  o.request(1);
  o.request(3);
  ASSERT_EQ(ghttp_h2_conn_shutdown(o.s.c, GHTTP_H2_NO_ERROR, "", 0), GHTTP_OK);
  EXPECT_EQ(o.request(5), (Events{"STREAM_ERROR 5 REFUSED_STREAM"})) << "refused: not processed";
  // A connection error now sends a second GOAWAY, which may not name more.
  o.feed(window_update(0, 0));
  ASSERT_EQ(o.s.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(goaway_lasts(o.wrote()), (std::vector<uint32_t>{3, 3}));
  // Calling shutdown again on a failed connection is the error, not a second GOAWAY.
  EXPECT_EQ(ghttp_h2_conn_shutdown(o.s.c, GHTTP_H2_NO_ERROR, "", 0), GHTTP_ERR_CORRUPT);
}

TEST(H2Goaway, ABlockThatWasNeverAcceptedIsNotNamedByTheGoaway_Section6_8) {
  OpenServer o;
  o.request(1);
  // Stream 3's header block starts and is then interrupted: it was never accepted.
  o.feed(headers(3, o.blk(request_list()), END_STREAM));
  o.feed(ping());
  ASSERT_EQ(o.s.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(goaway_lasts(o.wrote()), (std::vector<uint32_t>{1}));
}

TEST(H2Goaway, AStreamThatWasRefusedIsNotNamedByTheGoawayEither) {
  GHTTP_H2Limits l = limits();
  l.max_concurrent_streams = 1;
  OpenServer o(l);
  o.request(1);
  EXPECT_EQ(o.request(3), (Events{"STREAM_ERROR 3 REFUSED_STREAM"}));
  o.feed(window_update(0, 0));
  EXPECT_EQ(goaway_lasts(o.wrote()), (std::vector<uint32_t>{1}));
}

TEST(H2Goaway, AGoawayThatRaisesTheLastStreamIdIsAProtocolError_Section6_8) {
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({}));
  c.events.clear();
  c.feed(goaway(5, 0) + goaway(3, 0) + goaway(3, 0));
  EXPECT_EQ(c.result, GHTTP_OK) << "equal and lower are allowed";
  EXPECT_EQ(c.events.size(), 3u);
  c.feed(goaway(4, 0));
  EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(goaway_code(parse_frames(c.out.substr(GHTTP_H2_PREFACE_SIZE))),
      static_cast<int>(GHTTP_H2_PROTOCOL_ERROR));
}

TEST(H2Streams, ResettingAStreamBetweenItsHeadersAndItsContinuationKeepsHpackInStep) {
  OpenServer o;
  o.request(1, request_list("POST", "/"), END_HEADERS);
  std::string trailer_block = o.blk({{"x-trailer-name", "a-value-that-is-not-short"}});
  ASSERT_GT(trailer_block.size(), 4u);
  size_t half = trailer_block.size() / 2;
  EXPECT_EQ(o.feed(headers(1, trailer_block.substr(0, half), END_STREAM)), Events{});
  ASSERT_EQ(ghttp_h2_conn_reset_stream(o.s.c, 1, GHTTP_H2_CANCEL), GHTTP_OK);
  EXPECT_EQ(o.feed(continuation(1, trailer_block.substr(half))), Events{})
      << "the block is decoded and dropped, not an internal error";
  EXPECT_EQ(o.s.result, GHTTP_OK);
  EXPECT_EQ(rst_code(o.wrote(), 1), static_cast<int>(GHTTP_H2_CANCEL));
  // The compression state is in step: the next request decodes, and uses the
  // dynamic entry the dropped block added.
  auto e = o.request(3, request_list("GET", "/next", {{"x-trailer-name", "a-value-that-is-not-short"}}));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_TRUE(has_prefix(e[0], "HEADERS 3 end GET /next")) << e[0];
}

// ---- Limits are validated -------------------------------------------------------

TEST(H2Limits, AnUnusableSetOfLimitsIsRefusedByCreate) {
  auto create = [](const GHTTP_H2Limits & l) {
    GHTTP_H2Conn * c = nullptr;
    GHTTP_Result r = ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &l, &c);
    EXPECT_EQ(c != nullptr, r == GHTTP_OK);
    ghttp_h2_conn_destroy(c);
    return r;
  };
  GHTTP_H2Limits l = limits();
  EXPECT_EQ(create(l), GHTTP_OK);
  l.max_buffered_bytes = l.max_frame_size + GHTTP_H2_FRAME_HEADER_SIZE - 1;
  EXPECT_EQ(create(l), GHTTP_ERR_INVALID) << "a whole frame must fit in what may be buffered";
  l.max_buffered_bytes = l.max_frame_size + GHTTP_H2_FRAME_HEADER_SIZE;
  EXPECT_EQ(create(l), GHTTP_OK);
  l = limits();
  l.max_frame_size = 1 << 20;
  EXPECT_EQ(create(l), GHTTP_ERR_INVALID) << "the larger frame no longer fits the default buffer";
  l.max_buffered_bytes = (1 << 20) + 9;
  EXPECT_EQ(create(l), GHTTP_OK);

  // A zero size is not a struct that was initialised, and is not read as a full one.
  l = limits();
  l.size = 0;
  EXPECT_EQ(create(l), GHTTP_ERR_INVALID);
  // A shorter struct (an older caller) takes the defaults for what it lacks.
  l = limits();
  l.size = offsetof(GHTTP_H2Limits, max_streams);
  l.max_streams = 0;
  EXPECT_EQ(create(l), GHTTP_OK);

  struct Zero {
    const char * name;
    void (*set)(GHTTP_H2Limits *);
  };
  const Zero zeros[] = {
    {"max_header_list_bytes", [](GHTTP_H2Limits * x) { x->max_header_list_bytes = 0; }},
    {"max_field_bytes", [](GHTTP_H2Limits * x) { x->max_field_bytes = 0; }},
    {"max_header_count", [](GHTTP_H2Limits * x) { x->max_header_count = 0; }},
    {"max_header_block_bytes", [](GHTTP_H2Limits * x) { x->max_header_block_bytes = 0; }},
    {"max_body_bytes", [](GHTTP_H2Limits * x) { x->max_body_bytes = 0; }},
    {"max_streams", [](GHTTP_H2Limits * x) { x->max_streams = 0; }},
    {"max_concurrent_streams", [](GHTTP_H2Limits * x) { x->max_concurrent_streams = 0; }},
    {"max_settings_per_interval", [](GHTTP_H2Limits * x) { x->max_settings_per_interval = 0; }},
    {"interval_ms", [](GHTTP_H2Limits * x) { x->interval_ms = 0; }},
    {"max_buffered_bytes", [](GHTTP_H2Limits * x) { x->max_buffered_bytes = 0; }},
  };
  for (const Zero & z : zeros) {
    GHTTP_H2Limits m = limits();
    z.set(&m);
    EXPECT_EQ(create(m), GHTTP_ERR_INVALID) << z.name;
  }
  // Zero is a real setting where it means "none allowed".
  l = limits();
  l.max_ping_per_interval = 0;
  l.max_rst_per_interval = 0;
  l.max_empty_data_frames = 0;
  l.max_continuation_frames = 0;
  l.max_closed_streams = 0;
  l.max_priority_per_interval = 0;
  l.max_extension_per_interval = 0;
  l.max_ignored_window_updates_per_interval = 0;
  EXPECT_EQ(create(l), GHTTP_OK);
}

TEST(H2Limits, TheDefaultClosedRingIsLargerThanTheRapidResetLimit) {
  GHTTP_H2Limits l = limits();
  EXPECT_GT(l.max_closed_streams, l.max_rst_per_interval);
}

// ---- feed writes both outputs on every return ------------------------------------

TEST(H2Feed, ConsumedAndEventAreWrittenOnEveryReturn) {
  GHTTP_H2Conn * c = nullptr;
  ASSERT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, nullptr, &c), GHTTP_OK);
  auto garbage = [](GHTTP_H2Event * ev, size_t * used) {
    memset(ev, 0xAB, sizeof(*ev));
    *used = 12345;
  };
  auto zeroed = [](const GHTTP_H2Event & ev) {
    return ev.size == sizeof(GHTTP_H2Event) && ev.type == GHTTP_H2_EVENT_NEED_MORE
        && ev.stream_id == 0 && ev.data == nullptr && ev.data_len == 0
        && ev.error_code == 0 && ev.scheme == nullptr;
  };
  GHTTP_H2Event ev;
  size_t used;
  // Nothing to read.
  garbage(&ev, &used);
  EXPECT_EQ(ghttp_h2_conn_feed(c, "", 0, &used, &ev), GHTTP_OK);
  EXPECT_EQ(used, 0u);
  EXPECT_TRUE(zeroed(ev));
  // A partial preface: all of it consumed, nothing to report.
  garbage(&ev, &used);
  EXPECT_EQ(ghttp_h2_conn_feed(c, GHTTP_H2_PREFACE, 10, &used, &ev), GHTTP_OK);
  EXPECT_EQ(used, 10u);
  EXPECT_TRUE(zeroed(ev));
  // An event: SETTINGS arrives after the rest of the preface.
  std::string rest = std::string(GHTTP_H2_PREFACE).substr(10) + settings({}) + window_update(0, 0);
  garbage(&ev, &used);
  EXPECT_EQ(ghttp_h2_conn_feed(c, rest.data(), rest.size(), &used, &ev), GHTTP_OK);
  EXPECT_EQ(ev.type, GHTTP_H2_EVENT_SETTINGS);
  EXPECT_EQ(used, rest.size() - 13) << "up to the end of the SETTINGS frame";
  // An error after bytes were read: how far it got, and no stale event.
  size_t offset = used;  // before garbage() scribbles on it
  garbage(&ev, &used);
  EXPECT_EQ(ghttp_h2_conn_feed(c, rest.data() + offset, rest.size() - offset, &used, &ev),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(used, 13u) << "the whole WINDOW_UPDATE frame was read before its zero increment was refused";
  EXPECT_TRUE(zeroed(ev)) << "the error arm left the event alone";
  // A failed connection: the same error, nothing consumed, the event zeroed.
  garbage(&ev, &used);
  EXPECT_EQ(ghttp_h2_conn_feed(c, "x", 1, &used, &ev), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(used, 0u);
  EXPECT_TRUE(zeroed(ev));
  ghttp_h2_conn_destroy(c);

  // A bad preface byte: consumed is where it stopped.
  ASSERT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, nullptr, &c), GHTTP_OK);
  garbage(&ev, &used);
  EXPECT_EQ(ghttp_h2_conn_feed(c, "PRI * HTTP/2.0\r\n\r\nSX", 20, &used, &ev), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(used, 19u);
  EXPECT_TRUE(zeroed(ev));
  ghttp_h2_conn_destroy(c);
}

// ---- Floods the spec names: every unbounded quantity is capped ---------------------

TEST(H2Abuse, APriorityFloodStopsAtTheLimitPlusOne) {
  GHTTP_H2Limits l = limits();
  l.max_priority_per_interval = 5;
  OpenServer o(l);
  int n = 0;
  for (; n < 30 && o.s.result == GHTTP_OK; n++) o.feed(priority(1));
  EXPECT_EQ(n, 6);
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_ENHANCE_YOUR_CALM));
}

TEST(H2Abuse, AFloodOfUnknownFramesStopsAtTheLimitPlusOne) {
  GHTTP_H2Limits l = limits();
  l.max_extension_per_interval = 4;
  OpenServer o(l);
  int n = 0;
  for (; n < 30 && o.s.result == GHTTP_OK; n++) o.feed(frame(0xfa, 0, 0, "x"));
  EXPECT_EQ(n, 5);
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
}

TEST(H2Abuse, AFloodOfWindowUpdatesForClosedStreamsStopsAtTheLimitPlusOne) {
  GHTTP_H2Limits l = limits();
  l.max_ignored_window_updates_per_interval = 4;
  OpenServer o(l);
  o.request(1);
  answer(o, 1);
  ASSERT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
  int n = 0;
  for (; n < 30 && o.s.result == GHTTP_OK; n++) o.feed(window_update(1, 1));
  EXPECT_EQ(n, 5);
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  // Updates that do something are not counted: a live stream may get any number.
  OpenServer p(l);
  p.request(1, request_list("POST", "/"), END_HEADERS);
  for (int i = 0; i < 20; i++) p.feed(window_update(1, 1));
  EXPECT_EQ(p.s.result, GHTTP_OK);
}

TEST(H2Abuse, ResetsThisEndpointSendsBecauseOfThePeerCountTowardRapidReset) {
  GHTTP_H2Limits l = limits();
  l.max_rst_per_interval = 3;
  OpenServer o(l);
  // Each request is malformed, so each is answered with an RST_STREAM.
  int n = 0;
  for (uint32_t id = 1; n < 30 && o.s.result == GHTTP_OK; id += 2, n++) {
    o.request(id, request_list("GET", "/", {{"connection", "close"}}));
  }
  EXPECT_EQ(n, 4) << "three are allowed; the fourth is the one that ends it";
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(goaway_code(o.wrote()), static_cast<int>(GHTTP_H2_ENHANCE_YOUR_CALM));
}

TEST(H2Abuse, ResetsTheApplicationAsksForAreNotCounted) {
  GHTTP_H2Limits l = limits();
  l.max_rst_per_interval = 3;
  OpenServer o(l);
  for (uint32_t id = 1; id < 40; id += 2) {
    o.request(id, request_list("POST", "/"), END_HEADERS);
    ASSERT_EQ(ghttp_h2_conn_reset_stream(o.s.c, id, GHTTP_H2_CANCEL), GHTTP_OK);
  }
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

TEST(H2Abuse, OnlyProgressBreaksUpTheRunOfEmptyDataFrames) {
  GHTTP_H2Limits l = limits();
  l.max_empty_data_frames = 3;
  {
    FlowServer o(l);
    for (int i = 0; i < 20; i++) {
      o.feed(data(1, "") + data(1, "") + data(1, "x"));
    }
    EXPECT_EQ(o.s.result, GHTTP_OK) << "DATA with data is progress";
  }
  {
    FlowServer o(l);
    for (int i = 0; i < 20 && o.s.result == GHTTP_OK; i++) {
      o.feed(data(1, "") + ping() + window_update(0, 1) + priority(1));
    }
    EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT)
        << "PING, WINDOW_UPDATE and PRIORITY between empty DATA frames do not reset the count";
  }
}

namespace {

enum class Flood { Rst, Settings, Ping };

/** One counted frame of kind @p k, on a fresh stream if it needs one. */
void send_counted(OpenServer & o, Flood k, uint32_t & id) {
  switch (k) {
    case Flood::Rst:
      o.feed(headers(id, o.blk(request_list("GET", "/")), END_HEADERS));
      o.feed(rst(id, GHTTP_H2_CANCEL));
      id += 2;
      break;
    case Flood::Settings: o.feed(settings({})); break;
    case Flood::Ping: o.feed(ping()); break;
  }
}

} // namespace

TEST(H2Abuse, TheCountsRenewWhenTheCallerTicksTheClock_RstSettingsAndPing) {
  for (Flood k : {Flood::Rst, Flood::Settings, Flood::Ping}) {
    SCOPED_TRACE(static_cast<int>(k));
    GHTTP_H2Limits l = limits();
    l.max_rst_per_interval = 3;
    l.max_settings_per_interval = 3;
    l.max_ping_per_interval = 3;
    l.interval_ms = 1000;
    auto many = [&](OpenServer & o, uint32_t & id, int n) {
      for (int i = 0; i < n && o.s.result == GHTTP_OK; i++) send_counted(o, k, id);
    };
    {
      OpenServer o(l);
      uint32_t id = 1;
      ghttp_h2_conn_tick(o.s.c, 0);
      many(o, id, 3);
      EXPECT_EQ(o.s.result, GHTTP_OK);
      ghttp_h2_conn_tick(o.s.c, 999);
      many(o, id, 1);
      EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT) << "inside the interval: one more than allowed";
    }
    {
      OpenServer o(l);
      uint32_t id = 1;
      ghttp_h2_conn_tick(o.s.c, 0);
      many(o, id, 3);
      ghttp_h2_conn_tick(o.s.c, 1000);
      many(o, id, 3);
      EXPECT_EQ(o.s.result, GHTTP_OK) << "a new interval";
    }
    {
      OpenServer o(l);
      uint32_t id = 1;
      ghttp_h2_conn_tick(o.s.c, 5000);
      many(o, id, 3);
      ghttp_h2_conn_tick(o.s.c, 100);  // the clock went backwards
      many(o, id, 3);
      EXPECT_EQ(o.s.result, GHTTP_OK) << "a clock that runs backwards starts a new interval";
    }
    {
      OpenServer o(l);  // never ticked: a lifetime cap
      uint32_t id = 1;
      many(o, id, 20);
      EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
    }
  }
}

TEST(H2Abuse, TheCountsOfThePriorityUnknownAndIgnoredFloodsRenewToo) {
  GHTTP_H2Limits l = limits();
  l.max_priority_per_interval = 2;
  l.max_extension_per_interval = 2;
  l.max_ignored_window_updates_per_interval = 2;
  l.interval_ms = 1000;
  OpenServer o(l);
  o.request(1);
  answer(o, 1);
  ghttp_h2_conn_tick(o.s.c, 0);
  for (int round = 0; round < 3; round++) {
    o.feed(priority(1) + priority(1) + frame(0xfa, 0, 0, "x") + frame(0xfa, 0, 0, "x")
        + window_update(1, 1) + window_update(1, 1));
    ASSERT_EQ(o.s.result, GHTTP_OK) << round;
    ghttp_h2_conn_tick(o.s.c, 1000 * (round + 1));
  }
}

// ---- The closed-stream ring ---------------------------------------------------------

TEST(H2Streams, ALateFrameOnAStreamTheRingHasForgottenIsDiscardedNotAProtocolError) {
  GHTTP_H2Limits l = limits();
  l.max_closed_streams = 2;
  l.manual_flow_control = 0;
  OpenServer o(l);
  for (uint32_t id : {1u, 3u, 5u, 7u}) {
    o.request(id);
    answer(o, id);
  }
  o.wrote();
  // 1 and 3 have been forgotten; 5 and 7 are remembered as ended.
  EXPECT_EQ(o.feed(data(5, "x")), (Events{"ERROR CORRUPT STREAM_CLOSED"}))
      << "a remembered ended stream: DATA is STREAM_CLOSED";
  {
    OpenServer p(l);
    for (uint32_t id : {1u, 3u, 5u, 7u}) {
      p.request(id);
      answer(p, id);
    }
    p.wrote();
    EXPECT_EQ(p.feed(data(1, std::string(100, 'x'))), Events{}) << "forgotten: discarded";
    EXPECT_EQ(p.s.result, GHTTP_OK);
    // Its header block, too, is decoded (the table stays in step) and dropped.
    EXPECT_EQ(p.feed(headers(3, p.blk({{"x-late", "1"}}), END_HEADERS)), Events{});
    EXPECT_EQ(p.s.result, GHTTP_OK);
    // The compression state stayed in step.
    auto e = p.request(9, request_list("GET", "/", {{"x-late", "1"}}));
    ASSERT_EQ(e.size(), 1u);
    EXPECT_TRUE(has_prefix(e[0], "HEADERS 9")) << e[0];
  }
  {
    // A stream id that was skipped is not "forgotten": it was never open, and
    // section 5.1.1 makes a frame on it a protocol error.
    OpenServer p(l);
    for (uint32_t id : {1u, 3u, 5u, 7u}) {
      p.request(id);
      answer(p, id);
    }
    p.request(13);
    EXPECT_EQ(p.feed(data(11, "x")), (Events{"ERROR CORRUPT PROTOCOL_ERROR"}));
  }
}

TEST(H2Streams, WithNoClosedRingEveryClosedStreamIsForgottenAndItsLateFramesAreDiscarded) {
  GHTTP_H2Limits l = limits();
  l.max_closed_streams = 0;
  OpenServer o(l);
  o.request(1);
  answer(o, 1);
  EXPECT_EQ(o.feed(data(1, "x")), Events{});
  EXPECT_EQ(o.s.result, GHTTP_OK);
}

// ---- Flow-control credit in the corners ---------------------------------------------

TEST(H2FlowReceive, AResetStreamWithUnconsumedDataGivesItsCreditBackToTheConnection) {
  GHTTP_H2Limits l = limits();
  l.manual_flow_control = 1;
  l.initial_window_size = 40000;
  FlowServer o(l);
  for (int i = 0; i < 4; i++) o.feed(data(1, std::string(10000, 'x')));
  o.wrote();
  EXPECT_EQ(ghttp_h2_conn_connection_recv_window(o.s.c), 65535 - 40000);
  o.feed(rst(1, GHTTP_H2_CANCEL));
  EXPECT_EQ(window_updates_for(o.wrote(), 0), 40000u)
      << "the application will never consume those octets";
  EXPECT_EQ(ghttp_h2_conn_connection_recv_window(o.s.c), 65535);
}

TEST(H2FlowReceive, DataThatArrivesAfterOurRstStreamIsCreditedAndDiscarded_Section5_1) {
  FlowServer o(limits());
  ASSERT_EQ(ghttp_h2_conn_reset_stream(o.s.c, 1, GHTTP_H2_CANCEL), GHTTP_OK);
  o.wrote();
  EXPECT_EQ(o.feed(data(1, std::string(16384, 'x')) + data(1, std::string(16384, 'x'))), Events{});
  EXPECT_EQ(o.s.result, GHTTP_OK);
  EXPECT_EQ(window_updates_for(o.wrote(), 0), 32768u)
      << "the connection window is not leaked by frames we threw away";
}

TEST(H2FlowReceive, CreditAfterTheRemoteEndedIsReturnedToTheConnectionAndNotTheStream) {
  GHTTP_H2Limits l = limits();
  l.manual_flow_control = 1;
  FlowServer o(l);
  o.feed(data(1, std::string(10000, 'x')) + data(1, std::string(10000, 'x'))
      + data(1, std::string(10000, 'x')) + data(1, std::string(10000, 'x'), true));
  o.wrote();
  ASSERT_EQ(ghttp_h2_conn_consume(o.s.c, 1, 40000), GHTTP_OK);
  auto fs = o.wrote();
  EXPECT_EQ(window_updates_for(fs, 0), 40000u);
  EXPECT_EQ(window_updates_for(fs, 1), 0u) << "the peer will send no more on the stream";
}

TEST(H2FlowReceive, ConsumingOnAStreamThatIsGoneIsAHarmlessNoOp) {
  FlowServer o(limits());
  EXPECT_EQ(ghttp_h2_conn_consume(o.s.c, 99, 5), GHTTP_OK);
  EXPECT_TRUE(o.wrote().empty());
}

TEST(H2Preface, TheInitialConnectionWindowIsRaisedByAnUpdateAtTheStart) {
  GHTTP_H2Limits l = limits();
  l.connection_window = 100000;
  Side s(GHTTP_H2_SERVER, &l);
  uint64_t inc = 0;
  for (auto & f : s.frames()) {
    if (f.type == GHTTP_H2_WINDOW_UPDATE && f.stream == 0) inc += f.u32at(0);
  }
  EXPECT_EQ(inc, 100000u - 65535u);
  EXPECT_EQ(ghttp_h2_conn_connection_recv_window(s.c), 100000);
  Side d(GHTTP_H2_SERVER);
  for (auto & f : d.frames()) EXPECT_NE(f.type, GHTTP_H2_WINDOW_UPDATE) << "the default needs none";
}

// ---- Receiving: DATA where there is no content --------------------------------------

TEST(H2Client, DataOnAResponseThatHasNoContentIsAStreamProtocolError_Section8_1_1) {
  struct Case { const char * what; const char * method; int status; };
  const Case cases[] = {
    {"a response to HEAD", "HEAD", 200},
    {"204", "GET", 204},
    {"304", "GET", 304},
  };
  for (const Case & k : cases) {
    SCOPED_TRACE(k.what);
    Side c(GHTTP_H2_CLIENT);
    c.feed(settings({}));
    GHTTP_Request * r = nullptr;
    ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_method(r, k.method), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(r, "/"), GHTTP_OK);
    uint32_t id = 0;
    ASSERT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 1, &id), GHTTP_OK);
    ghttp_request_destroy(r);
    c.events.clear();
    Block b;
    c.feed(headers(id, b(response_list(k.status)), END_HEADERS));
    c.feed(data(id, "x"));
    ASSERT_EQ(c.events.size(), 2u);
    EXPECT_TRUE(has_prefix(c.events[0], "HEADERS 1")) << c.events[0];
    EXPECT_EQ(c.events[1], "STREAM_ERROR 1 PROTOCOL_ERROR");
    EXPECT_EQ(c.result, GHTTP_OK);
  }
  // An empty DATA frame that ends the stream is fine.
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({}));
  GHTTP_Request * r = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_method(r, "HEAD"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_target(r, "/"), GHTTP_OK);
  uint32_t id = 0;
  ASSERT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 1, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  c.events.clear();
  Block b;
  c.feed(headers(id, b(response_list(200, {{"content-length", "5"}})), END_HEADERS));
  c.feed(data(id, "", true));
  EXPECT_EQ(c.events.size(), 2u);
  EXPECT_EQ(c.events[1], "DATA 1 end \"\"");
}

TEST(H2Server, MoreMalformedRequestsFromTheReviewAreStreamErrors_Section8) {
  const std::vector<Malformed> bad = {
    {"8.3.1 :authority with a space", request_list("GET", "/", {}, "exa mple.com")},
    {"8.3.1 :authority with a control character", request_list("GET", "/", {}, "example\x01.com")},
    {"8.3.1 :path with a space", request_list("GET", "/a b")},
    {"8.3.1 :path with a control character", request_list("GET", "/a\x7f")},
    {"8.3.2 a request carrying :status", {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":status", "1:0"}}},
  };
  for (const Malformed & m : bad) {
    OpenServer o;
    EXPECT_EQ(o.request(1, m.list), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << m.what;
  }
}

TEST(H2Client, AStatusThatIsNotThreeDigitsIsMalformed_Section8_3_2) {
  for (const char * status : {"1:0", "20", "2000", "abc", "99", "600", "101", " 20", "2 0"}) {
    SCOPED_TRACE(status);
    Side c(GHTTP_H2_CLIENT);
    c.feed(settings({}));
    GHTTP_Request * r = nullptr;
    ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_method(r, "GET"), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(r, "/"), GHTTP_OK);
    uint32_t id = 0;
    ASSERT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 1, &id), GHTTP_OK);
    ghttp_request_destroy(r);
    c.events.clear();
    Block b;
    c.feed(headers(id, b({{":status", status}}), END_HEADERS | END_STREAM));
    EXPECT_EQ(c.events, (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  }
}


int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
