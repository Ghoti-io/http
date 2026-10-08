/**
 * @file
 *
 * Extended CONNECT (RFC 8441) in the HTTP/2 connection: the setting, the
 * `:protocol` pseudo-header field, and the tunnel a CONNECT stream becomes.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"
#include "h2_helpers.h"

using namespace ghttptest;

namespace {

using Events = std::vector<std::string>;

GHTTP_H2Limits server_limits(bool enable = true) {
  GHTTP_H2Limits l = limits();
  l.enable_connect_protocol = enable;
  return l;
}

/** The RFC 8441 section 4 request, pseudo-headers in the RFC's order. */
HList ws_request(const std::string & path = "/chat") {
  return {{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "https"},
      {":path", path}, {":authority", "server.example.com"},
      {"sec-websocket-protocol", "chat, superchat"},
      {"sec-websocket-extensions", "permessage-deflate"},
      {"sec-websocket-version", "13"}, {"origin", "http://www.example.com"}};
}

/** A server that has completed the preface exchange, the client's SETTINGS optionally carrying more. */
struct Srv {
  GHTTP_H2Limits lim;
  Side s;
  Block blk;
  explicit Srv(GHTTP_H2Limits l = server_limits())
      : lim(l), s(GHTTP_H2_SERVER, &lim) {
    s.feed(client_open() + settings_ack());
    s.events.clear();
    s.mark();
  }
  Events request(uint32_t id, const HList & l, uint8_t flags = END_HEADERS) {
    s.feed(headers(id, blk(l), flags));
    return s.take_events();
  }
  Events feed(const std::string & b) {
    s.feed(b);
    return s.take_events();
  }
  std::vector<OutFrame> wrote() {
    auto f = s.frames_since_mark();
    s.mark();
    return f;
  }
};

int rst_code_of(const std::vector<OutFrame> & fs, uint32_t stream) {
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_RST_STREAM && f.stream == stream) return static_cast<int>(f.u32at(0));
  }
  return -1;
}

int goaway_code_of(const std::vector<OutFrame> & fs) {
  for (auto & f : fs) {
    if (f.type == GHTTP_H2_GOAWAY) return static_cast<int>(f.u32at(4));
  }
  return -1;
}

/** The value of setting @p id in the first non-ACK SETTINGS frame, or -1. */
long setting_in(const std::vector<OutFrame> & fs, uint16_t id) {
  for (auto & f : fs) {
    if (f.type != GHTTP_H2_SETTINGS || (f.flags & 1)) continue;
    for (size_t i = 0; i + 6 <= f.payload.size(); i += 6) {
      uint16_t k = static_cast<uint16_t>((static_cast<uint8_t>(f.payload[i]) << 8)
          | static_cast<uint8_t>(f.payload[i + 1]));
      if (k == id) return static_cast<long>(f.u32at(i + 2));
    }
    return -1;
  }
  return -2;
}

}  // namespace

// ---------------------------------------------------------------------------
// RFC 8441 section 3: the setting
// ---------------------------------------------------------------------------

TEST(H2ConnectSetting, ADefaultServerDoesNotSendIt_Rfc8441_3) {
  Side s(GHTTP_H2_SERVER);
  EXPECT_EQ(setting_in(s.frames(), GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL), -1);
  GHTTP_H2Settings local;
  ghttp_h2_conn_local_settings(s.c, &local);
  EXPECT_EQ(local.enable_connect_protocol, 0u);
}

TEST(H2ConnectSetting, AnEnablingServerSendsItAndTheClientLearnsIt_Rfc8441_3) {
  GHTTP_H2Limits sl = server_limits();
  Side c(GHTTP_H2_CLIENT);
  Side s(GHTTP_H2_SERVER, &sl);
  EXPECT_EQ(setting_in(s.frames(), GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL), 1);
  EXPECT_FALSE(ghttp_h2_conn_can_send_extended_connect(c.c)) << "before the server's SETTINGS";
  pump(c, s);
  EXPECT_EQ(c.events, (Events{"SETTINGS", "SETTINGS_ACK"}));
  GHTTP_H2Settings peer;
  ghttp_h2_conn_peer_settings(c.c, &peer);
  EXPECT_EQ(peer.enable_connect_protocol, 1u);
  EXPECT_TRUE(ghttp_h2_conn_can_send_extended_connect(c.c));
  GHTTP_H2Settings sp;
  ghttp_h2_conn_peer_settings(s.c, &sp);
  EXPECT_EQ(sp.enable_connect_protocol, 0u) << "the client never says it";
  EXPECT_FALSE(ghttp_h2_conn_can_send_extended_connect(s.c));
}

TEST(H2ConnectSetting, AClientCannotEnableItAndTheLimitIsAFlag) {
  GHTTP_H2Limits l = limits();
  l.enable_connect_protocol = 1;
  GHTTP_H2Conn * c = nullptr;
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_CLIENT, &l, &c), GHTTP_ERR_INVALID);
  l.enable_connect_protocol = 2;
  EXPECT_EQ(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &l, &c), GHTTP_ERR_INVALID);
}

TEST(H2ConnectSetting, AClientThatSendsItIsAProtocolError_Rfc8441_3) {
  for (uint32_t v : {0u, 1u}) {
    GHTTP_H2Limits sl = server_limits();
    Side s(GHTTP_H2_SERVER, &sl);
    s.feed(client_open({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, v}}));
    EXPECT_NE(s.result, GHTTP_OK) << v;
    EXPECT_EQ(goaway_code_of(s.frames()), GHTTP_H2_PROTOCOL_ERROR) << v;
  }
}

TEST(H2ConnectSetting, AValueAboveOneIsAProtocolError_Rfc8441_3) {
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 2}}));
  EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
  EXPECT_EQ(goaway_code_of(c.frames()), GHTTP_H2_PROTOCOL_ERROR);
}

TEST(H2ConnectSetting, ChangingItFromOneToZeroIsAProtocolError_Rfc8441_3) {
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1}}));
  ASSERT_EQ(c.result, GHTTP_OK);
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1}}));
  EXPECT_EQ(c.result, GHTTP_OK) << "repeating 1 is allowed";
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 0}}));
  EXPECT_EQ(c.result, GHTTP_ERR_CORRUPT);
}

TEST(H2ConnectSetting, ZeroFirstIsAllowedAndMayBecomeOne) {
  Side c(GHTTP_H2_CLIENT);
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 0}}));
  c.feed(settings({{GHTTP_H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1}}));
  EXPECT_EQ(c.result, GHTTP_OK);
  EXPECT_TRUE(ghttp_h2_conn_can_send_extended_connect(c.c));
}

// ---------------------------------------------------------------------------
// RFC 8441 section 4: the request
// ---------------------------------------------------------------------------

TEST(H2ConnectRequest, TheSection4ExampleIsReadByAServer_Rfc8441_4) {
  Srv o;
  auto e = o.request(1, ws_request());
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0],
      "HEADERS 1 CONNECT /chat [host: server.example.com] [sec-websocket-protocol: chat, superchat]"
      " [sec-websocket-extensions: permessage-deflate] [sec-websocket-version: 13]"
      " [origin: http://www.example.com] scheme=https authority=server.example.com"
      " protocol=websocket");
  const GHTTP_Request * r = ghttp_h2_conn_request(o.s.c);
  EXPECT_STREQ(ghttp_request_protocol(r), "websocket");
  GHTTP_H2StreamMode mode;
  ASSERT_EQ(ghttp_h2_conn_stream_mode(o.s.c, 1, &mode), GHTTP_OK);
  EXPECT_EQ(mode, GHTTP_H2_STREAM_TUNNEL);
  EXPECT_TRUE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
  EXPECT_TRUE(ghttp_ws_is_h2_request(r));
}

TEST(H2ConnectRequest, TheEventSaysTunnelAndProtocol) {
  Srv o;
  o.s.feed(headers(1, o.blk(ws_request())));
  GHTTP_H2Event ev;
  size_t used;
  // The Side recorder has consumed the event; read it again with a fresh stream.
  std::string more = headers(3, o.blk(ws_request()));
  ASSERT_EQ(ghttp_h2_conn_feed(o.s.c, more.data(), more.size(), &used, &ev), GHTTP_OK);
  EXPECT_EQ(ev.type, GHTTP_H2_EVENT_HEADERS);
  EXPECT_EQ(ev.tunnel, 1);
  EXPECT_STREQ(ev.protocol, "websocket");
  EXPECT_STREQ(ev.scheme, "https");
  EXPECT_STREQ(ev.authority, "server.example.com");
}

TEST(H2ConnectRequest, AnyTokenIsReportedAndNeverInterpreted) {
  for (const char * p : {"connect-udp", "h2c", "HTTP/2.0", "x-foo/1", "w"}) {
    Srv o;
    HList l = ws_request();
    l[1].second = p;
    auto e = o.request(1, l);
    ASSERT_EQ(e.size(), 1u) << p;
    EXPECT_NE(e[0].find(std::string("protocol=") + p), std::string::npos) << e[0];
  }
}

TEST(H2ConnectRequest, WithoutTheSettingItIsMalformedAndTheConnectionStays_Rfc8441_4) {
  Srv o(server_limits(false));
  EXPECT_EQ(o.request(1, ws_request()), (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
  auto w = o.wrote();
  EXPECT_EQ(rst_code_of(w, 1), GHTTP_H2_PROTOCOL_ERROR);
  EXPECT_EQ(o.s.result, GHTTP_OK) << "a stream error, the connection carries on";
  Srv p(server_limits(false));
  p.request(1, ws_request());
  EXPECT_EQ(p.request(3, request_list("GET", "/")).size(), 1u);
}

TEST(H2ConnectRequest, EachMalformedFormIsAStreamErrorNotAConnectionError) {
  struct Case { const char * what; HList list; };
  HList base = ws_request();
  auto without = [&](const char * name) {
    HList l;
    for (auto & f : base) if (f.first != name) l.push_back(f);
    return l;
  };
  auto with = [&](const char * name, const char * value) {
    HList l = base;
    for (auto & f : l) if (f.first == name) f.second = value;
    return l;
  };
  HList dup = base;
  dup.insert(dup.begin() + 2, {":protocol", "websocket"});
  HList get = with(":method", "GET");
  HList post = with(":method", "POST");
  const std::vector<Case> bad = {
    {":protocol on GET", get},
    {":protocol on POST", post},
    {"no :path", without(":path")},
    {"no :scheme", without(":scheme")},
    {"no :authority", without(":authority")},
    {"empty :protocol", with(":protocol", "")},
    {":protocol with a space", with(":protocol", "web socket")},
    {":protocol with a comma", with(":protocol", "a,b")},
    {":protocol with two slashes", with(":protocol", "a/b/c")},
    {":protocol with a leading slash", with(":protocol", "/b")},
    {":protocol with a trailing slash", with(":protocol", "a/")},
    {"duplicate :protocol", dup},
    {":path not starting with /", with(":path", "chat")},
    {"empty :path", with(":path", "")},
    {"userinfo in :authority", with(":authority", "u@server.example.com")},
    {"Host differing from :authority", [&] { HList l = base; l.push_back({"host", "other"}); return l; }()},
  };
  for (const Case & c : bad) {
    Srv o;
    auto e = o.request(1, c.list);
    EXPECT_EQ(e, (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"})) << c.what;
    EXPECT_EQ(o.s.result, GHTTP_OK) << c.what;
    EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1)) << c.what;
  }
}

TEST(H2ConnectRequest, APlainConnectIsUnchangedAndStillRefusesSchemeAndPath_Rfc9113_8_5) {
  Srv o;
  auto e = o.request(1, {{":method", "CONNECT"}, {":authority", "h:443"}});
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0], "HEADERS 1 CONNECT h:443 [host: h:443] scheme=- authority=h:443");
  EXPECT_EQ(o.request(3, {{":method", "CONNECT"}, {":authority", "h:443"}, {":scheme", "https"}}),
      (Events{"STREAM_ERROR 3 PROTOCOL_ERROR"})) << ":scheme without :protocol";
  EXPECT_EQ(o.request(5, {{":method", "CONNECT"}, {":authority", "h:443"}, {":path", "/"}}),
      (Events{"STREAM_ERROR 5 PROTOCOL_ERROR"}));
  // And it works with the setting off, as it always did.
  Srv p(server_limits(false));
  EXPECT_EQ(p.request(1, {{":method", "CONNECT"}, {":authority", "h:443"}}).size(), 1u);
}

TEST(H2ConnectRequest, AHugeProtocolIsStoppedAtItsLimit) {
  GHTTP_H2Limits l = server_limits();
  l.max_protocol_bytes = 16;
  {
    Srv o(l);
    HList ok = ws_request();
    ok[1].second = std::string(16, 'a');
    EXPECT_EQ(o.request(1, ok).size(), 1u) << "exactly the limit";
    HList big = ws_request();
    big[1].second = std::string(17, 'a');
    EXPECT_EQ(o.request(3, big), (Events{"STREAM_ERROR 3 ENHANCE_YOUR_CALM"})) << "one over";
    EXPECT_EQ(o.s.result, GHTTP_OK);
  }
  {
    Srv o;  // the field limit of the decoder is the connection's limit
    HList big = ws_request();
    big[1].second = std::string(20000, 'a');
    o.s.feed(headers(1, o.blk(big), END_HEADERS));
    EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
    EXPECT_EQ(goaway_code_of(o.s.frames()), GHTTP_H2_ENHANCE_YOUR_CALM);
  }
}

// ---------------------------------------------------------------------------
// The tunnel
// ---------------------------------------------------------------------------

TEST(H2ConnectTunnel, DataIsOpaqueAndNoContentLengthApplies) {
  Srv o;
  HList l = ws_request();
  l.push_back({"content-length", "2"});
  ASSERT_EQ(o.request(1, l).size(), 1u);
  auto e = o.feed(data(1, "far more than two octets"));
  ASSERT_EQ(e.size(), 1u);
  EXPECT_EQ(e[0], "DATA 1 \"far more than two octets\"");
}

TEST(H2ConnectTunnel, TheBodyLimitDoesNotApplyToATunnel) {
  GHTTP_H2Limits l = server_limits();
  l.max_body_bytes = 10;
  Srv o(l);
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  EXPECT_EQ(o.feed(data(1, std::string(100, 'x'))), (Events{"DATA 1 \"" + std::string(100, 'x') + "\""}));
  // The control: an HTTP message of the same size is stopped.
  ASSERT_EQ(o.request(3, request_list("POST", "/", {}), END_HEADERS).size(), 1u);
  EXPECT_EQ(o.feed(data(3, std::string(100, 'x'))), (Events{"STREAM_ERROR 3 ENHANCE_YOUR_CALM"}));
}

TEST(H2ConnectTunnel, EndStreamHalfClosesAndTheOtherSideMayKeepSending) {
  Srv o;
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  EXPECT_EQ(o.feed(data(1, "bye", true)), (Events{"DATA 1 end \"bye\""}));
  EXPECT_TRUE(ghttp_h2_conn_stream_is_active(o.s.c, 1)) << "half-closed (remote)";
  GHTTP_Response * r;
  ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  ASSERT_EQ(ghttp_response_set_status(r, 200, ""), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, 1, r, 0), GHTTP_OK);
  ghttp_response_destroy(r);
  size_t acc = 0;
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 1, "still", 5, 0, &acc), GHTTP_OK);
  EXPECT_EQ(acc, 5u);
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 1, "", 0, 1, &acc), GHTTP_OK);
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1)) << "both sides ended";
}

TEST(H2ConnectTunnel, EndStreamOnTheRequestHeadersIsAHalfClose) {
  Srv o;
  auto e = o.request(1, ws_request(), END_HEADERS | END_STREAM);
  ASSERT_EQ(e.size(), 1u);
  EXPECT_NE(e[0].find("HEADERS 1 end CONNECT"), std::string::npos);
}

TEST(H2ConnectTunnel, AResetIsReportedWithItsCodeMidMessage) {
  Srv o;
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  EXPECT_EQ(o.feed(data(1, "partial") + rst(1, GHTTP_H2_CANCEL)),
      (Events{"DATA 1 \"partial\"", "RESET 1 CANCEL"}));
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(o.s.c, 1));
}

TEST(H2ConnectTunnel, TrailersAreMalformed) {
  Srv o;
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  EXPECT_EQ(o.feed(headers(1, o.blk({{"x", "1"}}), END_HEADERS | END_STREAM)),
      (Events{"STREAM_ERROR 1 PROTOCOL_ERROR"}));
}

TEST(H2ConnectTunnel, DataBeyondTheWindowIsAFlowControlError) {
  GHTTP_H2Limits l = server_limits();
  l.initial_window_size = 100;
  Srv o(l);
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  // The window is 65535 until the client has seen our SETTINGS acknowledged;
  // the Srv did that.
  EXPECT_EQ(o.feed(data(1, std::string(101, 'x'))), (Events{"STREAM_ERROR 1 FLOW_CONTROL_ERROR"}));
}

TEST(H2ConnectTunnel, TheWriterHoldsBackAtTheWindowAndResumes) {
  Srv o;
  o.s.feed(settings({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 10}}));
  o.s.events.clear();
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  GHTTP_Response * r;
  ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  ASSERT_EQ(ghttp_response_set_status(r, 200, ""), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_response(o.s.c, 1, r, 0), GHTTP_OK);
  ghttp_response_destroy(r);
  size_t acc = 0;
  std::string d(25, 'z');
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 1, d.data(), d.size(), 0, &acc), GHTTP_OK);
  EXPECT_EQ(acc, 10u);
  EXPECT_EQ(ghttp_h2_conn_send_window(o.s.c, 1), 0u);
  EXPECT_EQ(o.feed(window_update(1, 15)), (Events{"WINDOW 1 +15"}));
  ASSERT_EQ(ghttp_h2_conn_send_data(o.s.c, 1, d.data() + 10, 15, 0, &acc), GHTTP_OK);
  EXPECT_EQ(acc, 15u);
}

TEST(H2ConnectTunnel, TunnelsCountTowardConcurrentStreams) {
  GHTTP_H2Limits l = server_limits();
  l.max_concurrent_streams = 2;
  Srv o(l);
  EXPECT_EQ(o.request(1, ws_request()).size(), 1u);
  EXPECT_EQ(o.request(3, ws_request()).size(), 1u);
  EXPECT_EQ(o.request(5, ws_request()), (Events{"STREAM_ERROR 5 REFUSED_STREAM"}));
}

TEST(H2ConnectTunnel, ManyTunnelsOpenedAndResetStopAtTheRapidResetLimit_Cve2023_44487) {
  GHTTP_H2Limits l = server_limits();
  l.max_rst_per_interval = 10;
  Srv o(l);
  uint32_t id = 1;
  size_t resets = 0;
  for (; id < 200 && o.s.result == GHTTP_OK; id += 2) {
    o.s.feed(headers(id, o.blk(ws_request())) + rst(id, GHTTP_H2_CANCEL));
    resets++;
  }
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
  EXPECT_LE(resets, 11u) << "stopped within one reset of the limit";
  EXPECT_EQ(goaway_code_of(o.s.frames()), GHTTP_H2_ENHANCE_YOUR_CALM);
}

TEST(H2ConnectTunnel, ADataFloodOfEmptyFramesStopsAtItsLimit) {
  GHTTP_H2Limits l = server_limits();
  l.max_empty_data_frames = 5;
  Srv o(l);
  ASSERT_EQ(o.request(1, ws_request()).size(), 1u);
  for (int i = 0; i < 10 && o.s.result == GHTTP_OK; i++) o.s.feed(data(1, ""));
  EXPECT_EQ(o.s.result, GHTTP_ERR_LIMIT);
}

TEST(H2ConnectTunnel, ABlockSplitAtEveryByteGivesTheSameEvents) {
  auto run = [](bool bytewise_feed) {
    Srv o;
    std::string in = headers(1, o.blk(ws_request()), 0) ;
    // HEADERS without END_HEADERS followed by CONTINUATION, then data, then end.
    Block b2;
    std::string block = b2(ws_request());
    in = headers(1, block.substr(0, 7), 0) + continuation(1, block.substr(7))
        + data(1, "hello") + data(1, "", true);
    if (bytewise_feed) o.s.feed(bytewise(in)); else o.s.feed(in);
    return o.s.take_events();
  };
  Events whole = run(false);
  EXPECT_EQ(whole.size(), 3u);
  EXPECT_EQ(run(true), whole);
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

namespace {

GHTTP_Request * ws_connect_request(const char * path = "/chat") {
  GHTTP_Request * r;
  EXPECT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_method(r, "CONNECT"), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_target(r, path), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_protocol(r, "websocket"), GHTTP_OK);
  EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(r), "Host", "server.example.com"), GHTTP_OK);
  EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(r), "Sec-WebSocket-Version", "13"), GHTTP_OK);
  return r;
}

}  // namespace

TEST(H2ConnectClient, ARequestIsRefusedUntilTheServerHasEnabledIt) {
  Side c(GHTTP_H2_CLIENT);
  GHTTP_Request * r = ws_connect_request();
  uint32_t id = 0;
  EXPECT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_ERR_INVALID);
  GHTTP_H2Limits sl = server_limits(false);
  Side s(GHTTP_H2_SERVER, &sl);
  pump(c, s);
  EXPECT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_ERR_INVALID)
      << "a server that did not enable it";
  ghttp_request_destroy(r);
}

TEST(H2ConnectClient, TheRequestItSendsIsTheRfcExampleAfterDecoding) {
  GHTTP_H2Limits sl = server_limits();
  Side c(GHTTP_H2_CLIENT);
  Side s(GHTTP_H2_SERVER, &sl);
  pump(c, s);
  s.events.clear();
  GHTTP_Request * r = ws_connect_request();
  ASSERT_EQ(ghttp_headers_add(ghttp_request_headers(r), "Sec-WebSocket-Protocol", "chat, superchat"), GHTTP_OK);
  uint32_t id = 0;
  ASSERT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  EXPECT_EQ(id, 1u);
  // Decode what was written with an independent decoder.
  std::string wire = c.unsent();
  auto frames = parse_frames(wire, false);
  GHTTP_HpackDecoder * d;
  ASSERT_EQ(ghttp_hpack_decoder_create(nullptr, nullptr, 4096, &d), GHTTP_OK);
  GHTTP_Headers * list;
  ASSERT_EQ(ghttp_headers_create(nullptr, &list), GHTTP_OK);
  bool seen = false;
  for (auto & f : frames) {
    if (f.type != GHTTP_H2_HEADERS) continue;
    ASSERT_EQ(ghttp_hpack_decode(d, f.payload.data(), f.payload.size(), list), GHTTP_OK);
    seen = true;
  }
  ASSERT_TRUE(seen);
  EXPECT_EQ(fields_text(list),
      " [:method: CONNECT] [:protocol: websocket] [:scheme: https] [:path: /chat]"
      " [:authority: server.example.com] [sec-websocket-version: 13]"
      " [sec-websocket-protocol: chat, superchat]");
  ghttp_headers_destroy(list);
  ghttp_hpack_decoder_destroy(d);
}

TEST(H2ConnectClient, ANonConnectRequestWithAProtocolAndABadTargetAreRefused) {
  GHTTP_H2Limits sl = server_limits();
  Side c(GHTTP_H2_CLIENT);
  Side s(GHTTP_H2_SERVER, &sl);
  pump(c, s);
  uint32_t id = 0;
  GHTTP_Request * r = ws_connect_request();
  ASSERT_EQ(ghttp_request_set_method(r, "GET"), GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_ERR_INVALID);
  ASSERT_EQ(ghttp_request_set_method(r, "CONNECT"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_target(r, "host:443"), GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_ERR_INVALID)
      << "an authority-form target";
  ASSERT_EQ(ghttp_request_set_target(r, "/x"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_protocol(r, nullptr), GHTTP_OK);
  EXPECT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_ERR_INVALID)
      << "a plain CONNECT takes an authority";
  EXPECT_EQ(ghttp_request_set_protocol(r, "a b"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_protocol(r), nullptr);
  ghttp_request_destroy(r);
}

TEST(H2ConnectClient, AClientAndAServerOpenATunnelAndExchangeDataBothWays) {
  GHTTP_H2Limits sl = server_limits();
  Side c(GHTTP_H2_CLIENT);
  Side s(GHTTP_H2_SERVER, &sl);
  pump(c, s);
  c.events.clear();
  s.events.clear();
  GHTTP_Request * r = ws_connect_request();
  uint32_t id = 0;
  ASSERT_EQ(ghttp_h2_conn_send_request(c.c, r, "https", 0, &id), GHTTP_OK);
  ghttp_request_destroy(r);
  pump(c, s);
  ASSERT_EQ(s.events.size(), 1u);
  EXPECT_NE(s.events[0].find("protocol=websocket"), std::string::npos);
  GHTTP_Response * resp;
  ASSERT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
  ASSERT_EQ(ghttp_response_set_status(resp, 200, ""), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_response(s.c, id, resp, 0), GHTTP_OK);
  ghttp_response_destroy(resp);
  pump(c, s);
  GHTTP_H2StreamMode mode;
  ASSERT_EQ(ghttp_h2_conn_stream_mode(c.c, id, &mode), GHTTP_OK);
  EXPECT_EQ(mode, GHTTP_H2_STREAM_TUNNEL);
  size_t acc;
  ASSERT_EQ(ghttp_h2_conn_send_data(c.c, id, "ping", 4, 0, &acc), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_data(s.c, id, "pong", 4, 1, &acc), GHTTP_OK);
  pump(c, s);
  EXPECT_EQ(s.events.back(), "DATA 1 \"ping\"");
  EXPECT_EQ(c.events.back(), "DATA 1 end \"pong\"");
}

// ---------------------------------------------------------------------------
// Allocation failure and the version of the plain request
// ---------------------------------------------------------------------------

TEST(H2ConnectOom, EveryAllocationFailingInTurnIsOomOrTheSameAnswerAndNeverALeak) {
  auto run = [](const GHTTP_Allocator * a, GHTTP_Result * out) {
    GHTTP_H2Limits l = server_limits();
    GHTTP_H2Conn * c = nullptr;
    *out = ghttp_h2_conn_create(a, GHTTP_H2_SERVER, &l, &c);
    if (*out != GHTTP_OK) return std::string("create");
    Block b;
    std::string in = client_open() + settings_ack() + headers(1, b(ws_request()))
        + data(1, "hello") + data(1, "", true);
    std::string log;
    size_t off = 0;
    for (;;) {
      size_t used = 0;
      GHTTP_H2Event ev;
      GHTTP_Result r = ghttp_h2_conn_feed(c, in.data() + off, in.size() - off, &used, &ev);
      off += used;
      if (r != GHTTP_OK) {
        *out = r;
        log += "ERR";
        break;
      }
      if (ev.type == GHTTP_H2_EVENT_NEED_MORE) break;
      log += std::to_string(ev.type) + (ev.protocol ? ev.protocol : "") + ";";
    }
    ghttp_h2_conn_destroy(c);
    return log;
  };
  GHTTP_Result r0;
  std::string expected = run(nullptr, &r0);
  ASSERT_EQ(r0, GHTTP_OK);
  FailingAllocator counter(static_cast<size_t>(-1));
  GHTTP_Result rc;
  ASSERT_EQ(run(counter.get(), &rc), expected);
  size_t total = counter.requests();
  ASSERT_GT(total, 0u);
  size_t oom = 0;
  for (size_t runlen : {size_t(1), size_t(0), size_t(2)}) {
    for (size_t k = 0; k <= total + 1; k++) {
      FailingAllocator fa(k, runlen);
      GHTTP_Result r;
      std::string got = run(fa.get(), &r);
      if (fa.failed()) {
        if (r == GHTTP_ERR_OOM) oom++; else EXPECT_EQ(got, expected) << k;
      } else {
        EXPECT_EQ(got, expected) << k;
      }
      EXPECT_EQ(fa.live(), 0u) << "k=" << k << " run=" << runlen;
    }
  }
  EXPECT_GT(oom, 0u);
}

TEST(H2ConnectRequestObject, TheProtocolIsPartOfTheRequestLineAndTheH1WriterRefusesIt) {
  GHTTP_Request * r;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_request_protocol(r), nullptr);
  ASSERT_EQ(ghttp_request_set_protocol(r, "websocket"), GHTTP_OK);
  EXPECT_STREQ(ghttp_request_protocol(r), "websocket");
  ASSERT_EQ(ghttp_headers_add(ghttp_request_headers(r), "Host", "h"), GHTTP_OK);
  GHTTP_Buffer * b;
  ASSERT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
  EXPECT_NE(ghttp_write_request_head(b, r), GHTTP_OK) << "HTTP/1.1 has no :protocol";
  ASSERT_EQ(ghttp_request_set_protocol(r, nullptr), GHTTP_OK);
  ghttp_buffer_clear(b);
  EXPECT_EQ(ghttp_write_request_head(b, r), GHTTP_OK);
  ghttp_buffer_destroy(b);
  ghttp_request_destroy(r);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
