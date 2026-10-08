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
 * WebSocket over HTTP/2 (RFC 8441 sections 4 and 5): the handshake variants,
 * and a client and a server wired in memory through an h2 tunnel stream and
 * the adapter of ws_h2.h.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <list>

#include "test_helpers.h"
#include "h2_helpers.h"
// Both helper headers define ping(); the WebSocket one is renamed on the way in.
#define ping ws_ping_helper
#include "ws_helpers.h"
#undef ping

using namespace ghttptest;

namespace {

using Events = std::vector<std::string>;

GHTTP_Request * h2_request(const char * method = "CONNECT", const char * protocol = "websocket",
    std::initializer_list<std::pair<const char *, const char *>> fields = {
        {"host", "server.example.com"}, {"sec-websocket-version", "13"}}) {
  GHTTP_Request * r;
  EXPECT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_method(r, method), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_target(r, "/chat"), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_protocol(r, protocol), GHTTP_OK);
  for (auto & f : fields) {
    EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(r), f.first, f.second), GHTTP_OK);
  }
  return r;
}

struct Served {
  GHTTP_Response * resp = nullptr;
  GHTTP_WsServerResult res;
  GHTTP_Result r;
  Served(const GHTTP_Request * req, const GHTTP_WsServerOptions * o = nullptr) {
    EXPECT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
    r = ghttp_ws_server_handshake_h2(req, o, resp, &res);
  }
  ~Served() { ghttp_response_destroy(resp); }
  std::string header(const char * name) const {
    const GHTTP_Headers * h = ghttp_response_headers_const(resp);
    size_t i = ghttp_headers_find(h, name, 0);
    if (i == GHTTP_HEADERS_NPOS) return "<none>";
    GHTTP_Field f;
    ghttp_headers_at(h, i, &f);
    return std::string(f.value, f.value_len);
  }
};

}  // namespace

// ---------------------------------------------------------------------------
// The server's handshake
// ---------------------------------------------------------------------------

TEST(WsH2Handshake, AValidRequestIsAnswered200WithNoUpgradeConnectionOrAccept_Rfc8441_5) {
  GHTTP_Request * q = h2_request();
  Served s(q);
  ASSERT_EQ(s.r, GHTTP_OK);
  EXPECT_EQ(s.res.accepted, 1);
  EXPECT_EQ(s.res.status, 200);
  EXPECT_EQ(ghttp_response_status(s.resp), 200);
  EXPECT_EQ(s.header("upgrade"), "<none>");
  EXPECT_EQ(s.header("connection"), "<none>");
  EXPECT_EQ(s.header("sec-websocket-accept"), "<none>");
  EXPECT_EQ(ghttp_headers_count(ghttp_response_headers_const(s.resp)), 0u);
  ghttp_request_destroy(q);
}

TEST(WsH2Handshake, SubprotocolAndPermessageDeflateAreNegotiatedAsOverHttp1) {
  GHTTP_Request * q = h2_request("CONNECT", "websocket",
      {{"host", "h"}, {"sec-websocket-version", "13"},
       {"sec-websocket-protocol", "chat, superchat"},
       {"sec-websocket-extensions", "permessage-deflate; client_max_window_bits"},
       {"origin", "http://www.example.com"}});
  const char * protos[] = {"superchat", "other"};
  GHTTP_WsServerOptions o;
  ghttp_ws_server_options_default(&o);
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  o.enable_deflate = 1;
  Served s(q, &o);
  ASSERT_EQ(s.res.accepted, 1);
  EXPECT_EQ(s.header("sec-websocket-protocol"), "superchat");
  EXPECT_STREQ(s.res.negotiated.subprotocol, "superchat");
  EXPECT_EQ(s.res.negotiated.deflate, 1);
  EXPECT_NE(s.header("sec-websocket-extensions").find("permessage-deflate"), std::string::npos);
  EXPECT_EQ(s.res.has_origin, 1);
  // The same request over HTTP/1.1 agrees on every negotiated value.
  GHTTP_Request * h1;
  ASSERT_EQ(ghttp_request_create(nullptr, &h1), GHTTP_OK);
  for (auto & f : std::vector<std::pair<const char *, const char *>>{
           {"Host", "h"}, {"Upgrade", "websocket"}, {"Connection", "Upgrade"},
           {"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="}, {"Sec-WebSocket-Version", "13"},
           {"Sec-WebSocket-Protocol", "chat, superchat"},
           {"Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits"}}) {
    ghttp_headers_add(ghttp_request_headers(h1), f.first, f.second);
  }
  GHTTP_Response * resp;
  ghttp_response_create(nullptr, &resp);
  GHTTP_WsServerResult r1;
  ASSERT_EQ(ghttp_ws_server_handshake(h1, &o, resp, &r1), GHTTP_OK);
  ASSERT_EQ(r1.accepted, 1);
  EXPECT_EQ(r1.status, 101);
  EXPECT_STREQ(r1.negotiated.subprotocol, s.res.negotiated.subprotocol);
  EXPECT_EQ(r1.negotiated.deflate, s.res.negotiated.deflate);
  ghttp_response_destroy(resp);
  ghttp_request_destroy(h1);
  ghttp_request_destroy(q);
}

TEST(WsH2Handshake, ASecWebSocketKeyOverHttp2IsRefused_Rfc8441_5) {
  GHTTP_Request * q = h2_request("CONNECT", "websocket",
      {{"host", "h"}, {"sec-websocket-version", "13"},
       {"sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="}});
  Served s(q);
  EXPECT_EQ(s.res.accepted, 0);
  EXPECT_EQ(s.res.status, 400);
  EXPECT_EQ(s.header("connection"), "<none>") << "HTTP/2 has no Connection field";
  EXPECT_EQ(s.header("content-length"), "0");
  ghttp_request_destroy(q);
}

TEST(WsH2Handshake, EachWayARequestCanBeWrongIsRefusedWithItsStatus) {
  struct Case { const char * what; const char * method; const char * protocol;
      std::vector<std::pair<const char *, const char *>> fields; int status; };
  const std::vector<Case> cases = {
    {"GET with a :protocol", "GET", "websocket", {{"host", "h"}, {"sec-websocket-version", "13"}}, 405},
    {"another :protocol", "CONNECT", "connect-udp", {{"host", "h"}, {"sec-websocket-version", "13"}}, 400},
    {"no version", "CONNECT", "websocket", {{"host", "h"}}, 400},
    {"two versions", "CONNECT", "websocket", {{"host", "h"}, {"sec-websocket-version", "13"}, {"sec-websocket-version", "13"}}, 400},
    {"version 8", "CONNECT", "websocket", {{"host", "h"}, {"sec-websocket-version", "8"}}, 426},
    {"no host", "CONNECT", "websocket", {{"sec-websocket-version", "13"}}, 400},
    {"two origins", "CONNECT", "websocket", {{"host", "h"}, {"sec-websocket-version", "13"}, {"origin", "a"}, {"origin", "b"}}, 400},
    {"duplicate subprotocol", "CONNECT", "websocket", {{"host", "h"}, {"sec-websocket-version", "13"}, {"sec-websocket-protocol", "a, a"}}, 400},
    {"malformed extensions", "CONNECT", "websocket", {{"host", "h"}, {"sec-websocket-version", "13"}, {"sec-websocket-extensions", "x;;"}}, 400},
  };
  for (const Case & c : cases) {
    GHTTP_Request * q;
    ASSERT_EQ(ghttp_request_create(nullptr, &q), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_method(q, c.method), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(q, "/"), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_protocol(q, c.protocol), GHTTP_OK);
    for (auto & f : c.fields) ghttp_headers_add(ghttp_request_headers(q), f.first, f.second);
    Served s(q);
    EXPECT_EQ(s.r, GHTTP_OK) << c.what;
    EXPECT_EQ(s.res.accepted, 0) << c.what;
    EXPECT_EQ(s.res.status, c.status) << c.what;
    EXPECT_EQ(s.header("connection"), "<none>") << c.what;
    if (c.status == 426) { EXPECT_EQ(s.header("sec-websocket-version"), "13"); }
    if (c.status == 405) { EXPECT_EQ(s.header("allow"), "CONNECT"); }
    ghttp_request_destroy(q);
  }
}

TEST(WsH2Handshake, TheHttp1HandshakeStillWantsAKeyAndAnswers101) {
  GHTTP_Request * q = h2_request("GET", "websocket");  // a :protocol means nothing to it
  GHTTP_Response * resp;
  ghttp_response_create(nullptr, &resp);
  GHTTP_WsServerResult r;
  ASSERT_EQ(ghttp_ws_server_handshake(q, nullptr, resp, &r), GHTTP_OK);
  EXPECT_EQ(r.accepted, 0);
  EXPECT_EQ(r.status, 400) << "no Upgrade";
  ghttp_response_destroy(resp);
  ghttp_request_destroy(q);
}

// ---------------------------------------------------------------------------
// The client's handshake
// ---------------------------------------------------------------------------

namespace {

struct Cli {
  GHTTP_Request * req = nullptr;
  GHTTP_WsClientHandshake * hs = nullptr;
  Cli(const GHTTP_WsClientOptions & o) {
    EXPECT_EQ(ghttp_request_create(nullptr, &req), GHTTP_OK);
    EXPECT_EQ(ghttp_ws_client_handshake_create_h2(nullptr, &o, req, &hs), GHTTP_OK);
  }
  ~Cli() { ghttp_ws_client_handshake_destroy(hs); ghttp_request_destroy(req); }
  GHTTP_WsClientResult finish(GHTTP_Response * r, bool h2 = true) {
    GHTTP_WsClientResult res;
    GHTTP_Result k = h2 ? ghttp_ws_client_handshake_finish_h2(hs, r, &res)
                        : ghttp_ws_client_handshake_finish(hs, r, &res);
    last = k;
    return res;
  }
  GHTTP_Result last = GHTTP_OK;
};

GHTTP_Response * response(int status, std::initializer_list<std::pair<const char *, const char *>> f = {}) {
  GHTTP_Response * r;
  EXPECT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_response_set_status(r, status, ""), GHTTP_OK);
  for (auto & e : f) ghttp_headers_add(ghttp_response_headers(r), e.first, e.second);
  return r;
}

}  // namespace

TEST(WsH2ClientHandshake, TheRequestHasNoKeyUpgradeOrConnectionAndIsAConnectWithAProtocol_Rfc8441_4) {
  const char * protos[] = {"chat", "superchat"};
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "server.example.com";
  o.target = "/chat";
  o.origin = "http://www.example.com";
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  o.enable_deflate = 1;
  Cli c(o);
  EXPECT_STREQ(ghttp_request_method(c.req), "CONNECT");
  EXPECT_STREQ(ghttp_request_target(c.req), "/chat");
  EXPECT_STREQ(ghttp_request_protocol(c.req), "websocket");
  EXPECT_EQ(fields_text(ghttp_request_headers_const(c.req)),
      " [Host: server.example.com] [Sec-WebSocket-Version: 13] [Origin: http://www.example.com]"
      " [Sec-WebSocket-Protocol: chat, superchat]"
      " [Sec-WebSocket-Extensions: permessage-deflate]");
}

TEST(WsH2ClientHandshake, The200Section5ExampleIsAccepted) {
  const char * protos[] = {"chat", "superchat"};
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "server.example.com";
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  Cli c(o);
  GHTTP_Response * r = response(200, {{"sec-websocket-protocol", "chat"}});
  GHTTP_WsClientResult res = c.finish(r);
  EXPECT_EQ(res.accepted, 1) << res.reason;
  EXPECT_STREQ(res.negotiated.subprotocol, "chat");
  ghttp_response_destroy(r);
}

TEST(WsH2ClientHandshake, EachWayAResponseCanBeWrongIsRefused) {
  const char * protos[] = {"chat"};
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "h";
  o.subprotocols = protos;
  o.subprotocol_count = 1;
  Cli c(o);
  struct Case { const char * what; int status;
      std::vector<std::pair<const char *, const char *>> f; };
  const std::vector<Case> bad = {
    {"101", 101, {}},
    {"204", 204, {}},
    {"426", 426, {}},
    {"an accept value", 200, {{"sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}}},
    {"a protocol not offered", 200, {{"sec-websocket-protocol", "other"}}},
    {"two protocols", 200, {{"sec-websocket-protocol", "chat, chat"}}},
    {"an extension not offered", 200, {{"sec-websocket-extensions", "permessage-deflate"}}},
  };
  for (const Case & b : bad) {
    GHTTP_Response * r = response(b.status);
    for (auto & e : b.f) ghttp_headers_add(ghttp_response_headers(r), e.first, e.second);
    GHTTP_WsClientResult res = c.finish(r);
    EXPECT_EQ(res.accepted, 0) << b.what;
    EXPECT_STRNE(res.reason, "") << b.what;
    ghttp_response_destroy(r);
  }
  GHTTP_Response * ok = response(200);
  EXPECT_EQ(c.finish(ok).accepted, 1) << "no subprotocol is allowed";
  ghttp_response_destroy(ok);
}

TEST(WsH2ClientHandshake, AHandshakeFinishesOnTheCarrierItBeganOn) {
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "h";
  Cli c(o);
  GHTTP_Response * r = response(101);
  c.finish(r, false);
  EXPECT_EQ(c.last, GHTTP_ERR_INVALID);
  ghttp_response_destroy(r);
  GHTTP_Request * q;
  ghttp_request_create(nullptr, &q);
  GHTTP_WsClientHandshake * h1;
  ASSERT_EQ(ghttp_ws_client_handshake_create(nullptr, &o, q, &h1), GHTTP_OK);
  EXPECT_EQ(ghttp_request_protocol(q), nullptr) << "the HTTP/1.1 builder clears a :protocol";
  GHTTP_Response * r2 = response(200);
  GHTTP_WsClientResult res;
  EXPECT_EQ(ghttp_ws_client_handshake_finish_h2(h1, r2, &res), GHTTP_ERR_INVALID);
  ghttp_response_destroy(r2);
  ghttp_ws_client_handshake_destroy(h1);
  ghttp_request_destroy(q);
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

namespace {

/** One end: an h2 connection, and once the handshake is done a WebSocket on one stream. */
struct End {
  GHTTP_H2Role role;
  GHTTP_H2Conn * h2 = nullptr;
  GHTTP_WsConn * ws = nullptr;
  GHTTP_WsH2 * ad = nullptr;
  uint32_t stream = 0;
  std::vector<WsEv> got;
  GHTTP_Result h2_result = GHTTP_OK;
  GHTTP_Result ws_result = GHTTP_OK;
  std::vector<std::string> h2events;
  // handshake
  GHTTP_WsServerOptions sopt;
  GHTTP_WsClientOptions copt;
  GHTTP_WsClientHandshake * hs = nullptr;
  GHTTP_Request * req = nullptr;
  bool accepted = false;
  int refused = 0;
  bool deflate = false;
  bool no_pump = false;  // give the adapter the events and nothing else
  std::string seen_scheme, seen_authority, seen_target;

  End(GHTTP_H2Role r, const GHTTP_H2Limits * lim = nullptr, bool deflate_on = false)
      : role(r), deflate(deflate_on) {
    EXPECT_EQ(ghttp_h2_conn_create(nullptr, r, lim, &h2), GHTTP_OK);
    ghttp_ws_server_options_default(&sopt);
    sopt.enable_deflate = deflate_on;
    ghttp_ws_client_options_default(&copt);
    copt.host = "server.example.com";
    copt.enable_deflate = deflate_on;
  }
  ~End() {
    ghttp_ws_h2_destroy(ad);
    ghttp_ws_conn_destroy(ws);
    ghttp_ws_client_handshake_destroy(hs);
    ghttp_request_destroy(req);
    ghttp_h2_conn_destroy(h2);
  }
  std::string take() {
    size_t n = 0;
    const uint8_t * p = ghttp_h2_conn_output(h2, &n);
    std::string s(reinterpret_cast<const char *>(p), n);
    ghttp_h2_conn_output_consume(h2, n);
    return s;
  }
  void prepare() {
    ASSERT_EQ(role, GHTTP_H2_CLIENT);
    ASSERT_EQ(ghttp_request_create(nullptr, &req), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_client_handshake_create_h2(nullptr, &copt, req, &hs), GHTTP_OK);
  }
  void open() {
    prepare();
    ASSERT_EQ(ghttp_h2_conn_send_request(h2, req, "https", 0, &stream), GHTTP_OK);
  }
  void attach(const GHTTP_WsNegotiated * n, GHTTP_WsRole wr) {
    ASSERT_EQ(ghttp_ws_conn_create(nullptr, wr, nullptr, n, &ws), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_h2_create(nullptr, h2, stream, ws, &ad), GHTTP_OK);
  }
  void ws_events() {
    if (!ad) return;
    for (;;) {
      GHTTP_WsEvent e;
      GHTTP_Result r = ghttp_ws_h2_next(ad, &e);
      if (r != GHTTP_OK) { ws_result = r; break; }
      if (e.type == GHTTP_WS_EVENT_NEED_MORE) break;
      WsEv w;
      w.type = e.type;
      w.data.assign(reinterpret_cast<const char *>(e.data), e.data_len);
      w.code = e.code;
      got.push_back(w);
    }
    EXPECT_EQ(ghttp_ws_h2_pump(ad), GHTTP_OK);
  }
  void on_event(const GHTTP_H2Event & ev) {
    if (ev.type == GHTTP_H2_EVENT_HEADERS && role == GHTTP_H2_SERVER && !ad) {
      const GHTTP_Request * q = ghttp_h2_conn_request(h2);
      seen_scheme = ev.scheme ? ev.scheme : "-";
      seen_authority = ev.authority ? ev.authority : "-";
      seen_target = ghttp_request_target(q);
      GHTTP_Response * resp;
      ASSERT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
      GHTTP_WsServerResult sr;
      ASSERT_EQ(ghttp_ws_server_handshake_h2(q, &sopt, resp, &sr), GHTTP_OK);
      stream = ev.stream_id;
      ASSERT_EQ(ghttp_h2_conn_send_response(h2, stream, resp, !sr.accepted), GHTTP_OK);
      ghttp_response_destroy(resp);
      if (sr.accepted) {
        accepted = true;
        attach(&sr.negotiated, GHTTP_WS_SERVER);
        ghttp_ws_h2_input(ad, &ev);
      } else {
        refused = sr.status;
      }
    } else if (ev.type == GHTTP_H2_EVENT_HEADERS && role == GHTTP_H2_CLIENT && !ad
        && ev.stream_id == stream && !ev.interim) {
      GHTTP_WsClientResult cr;
      ASSERT_EQ(ghttp_ws_client_handshake_finish_h2(hs, ghttp_h2_conn_response(h2), &cr), GHTTP_OK);
      if (cr.accepted && ev.tunnel) {
        accepted = true;
        attach(&cr.negotiated, GHTTP_WS_CLIENT);
        ghttp_ws_h2_input(ad, &ev);
      } else {
        refused = ghttp_response_status(ghttp_h2_conn_response(h2));
        ghttp_h2_conn_reset_stream(h2, stream, GHTTP_H2_CANCEL);
      }
    } else if (ad) {
      EXPECT_EQ(ghttp_ws_h2_input(ad, &ev), GHTTP_OK);
    }
  }
  /** Feed bytes in pieces of @p piece (0: whole). */
  void feed(const std::string & bytes, size_t piece = 0) {
    size_t step = piece ? piece : bytes.size();
    for (size_t at = 0; at < bytes.size() || (at == 0 && bytes.empty()); at += step) {
      std::string chunk = bytes.substr(at, step);
      size_t off = 0;
      GHTTP_H2Event ev;
      do {
        size_t used = 0;
        GHTTP_Result r = ghttp_h2_conn_feed(h2, chunk.data() + off, chunk.size() - off, &used, &ev);
        if (r != GHTTP_OK) { h2_result = r; return; }
        off += used;
        if (ev.type != GHTTP_H2_EVENT_NEED_MORE) {
          h2events.push_back(std::to_string(ev.type));
          on_event(ev);
          if (!no_pump) ws_events();
        }
      } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
      if (bytes.empty()) break;
    }
  }
  GHTTP_WsH2Status status() {
    GHTTP_WsH2Status s;
    EXPECT_EQ(ghttp_ws_h2_status(ad, &s), GHTTP_OK);
    return s;
  }
};

void run(End & a, End & b, size_t piece = 0, int rounds = 500) {
  for (int i = 0; i < rounds; i++) {
    if (a.ad) a.ws_events();
    if (b.ad) b.ws_events();
    std::string x = a.take();
    std::string y = b.take();
    if (x.empty() && y.empty()) return;
    if (!x.empty()) b.feed(x, piece);
    if (!y.empty()) a.feed(y, piece);
  }
}

GHTTP_H2Limits srv_limits() {
  GHTTP_H2Limits l = limits();
  l.enable_connect_protocol = 1;
  return l;
}

/** Open a WebSocket over a fresh pair. */
struct Pair {
  GHTTP_H2Limits sl = srv_limits();
  GHTTP_H2Limits cl = limits();
  End c, s;
  explicit Pair(bool deflate = false, size_t piece = 0, const GHTTP_H2Limits * slim = nullptr,
      const GHTTP_H2Limits * clim = nullptr)
      : c(GHTTP_H2_CLIENT, clim ? clim : &cl, deflate),
        s(GHTTP_H2_SERVER, slim ? slim : &sl, deflate) {
    run(c, s, piece);  // SETTINGS
    EXPECT_TRUE(ghttp_h2_conn_can_send_extended_connect(c.h2));
    c.open();
    run(c, s, piece);
  }
};

std::string sized(size_t n) { return ws_lorem(n, static_cast<uint32_t>(n) + 3); }

}  // namespace

TEST(WsH2EndToEnd, MessagesOfEverySizeClassPassBothWaysWithAndWithoutDeflate) {
  for (bool deflate : {false, true}) {
    Pair p(deflate);
    ASSERT_TRUE(p.c.accepted && p.s.accepted) << deflate;
    ASSERT_NE(p.c.ad, nullptr);
    ASSERT_NE(p.s.ad, nullptr);
    EXPECT_EQ(ghttp_ws_conn_deflate_active(p.c.ws), deflate);
    EXPECT_EQ(ghttp_ws_conn_deflate_active(p.s.ws), deflate);
    std::vector<WsEv> expect_at_server, expect_at_client;
    for (size_t n : {size_t(0), size_t(1), size_t(125), size_t(126), size_t(1000), size_t(65535),
             size_t(65536), size_t(300000)}) {
      std::string m = sized(n);
      GHTTP_WsMessageType t = n % 2 ? GHTTP_WS_MESSAGE_BINARY : GHTTP_WS_MESSAGE_TEXT;
      if (t == GHTTP_WS_MESSAGE_TEXT) m = ws_lorem(n, 5);  // printable ASCII
      ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, t, m.data(), m.size()), GHTTP_OK) << n;
      ASSERT_EQ(ghttp_ws_conn_send_message(p.s.ws, t, m.data(), m.size()), GHTTP_OK) << n;
      WsEv e = ev(t == GHTTP_WS_MESSAGE_TEXT ? GHTTP_WS_EVENT_TEXT : GHTTP_WS_EVENT_BINARY, m);
      expect_at_server.push_back(e);
      expect_at_client.push_back(e);
      ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
      ASSERT_EQ(ghttp_ws_h2_pump(p.s.ad), GHTTP_OK);
      run(p.c, p.s);
    }
    auto strip = [](std::vector<WsEv> v) {
      for (auto & e : v) { e.fragments = 0; e.compressed = false; }
      return v;
    };
    auto cg = strip(p.c.got), sg = strip(p.s.got);
    ASSERT_EQ(sg.size(), expect_at_server.size()) << deflate;
    ASSERT_EQ(cg.size(), expect_at_client.size()) << deflate;
    for (size_t i = 0; i < sg.size(); i++) {
      EXPECT_TRUE(sg[i] == expect_at_server[i]) << "server " << i << " deflate=" << deflate;
      EXPECT_TRUE(cg[i] == expect_at_client[i]) << "client " << i << " deflate=" << deflate;
    }
  }
}

TEST(WsH2EndToEnd, AnyCutOfTheByteStreamGivesTheSameMessages) {
  for (size_t piece : {size_t(1), size_t(3), size_t(7), size_t(64)}) {
    Pair p(true, piece);
    ASSERT_TRUE(p.c.accepted && p.s.accepted) << piece;
    std::string m = ws_lorem(2000, 9);
    ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_conn_send_ping(p.c.ws, "p", 1), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
    run(p.c, p.s, piece);
    ASSERT_EQ(p.s.got.size(), 2u) << piece;
    EXPECT_EQ(p.s.got[0].data, m);
    EXPECT_EQ(p.s.got[1].type, GHTTP_WS_EVENT_PING);
    ASSERT_EQ(p.c.got.size(), 1u);
    EXPECT_EQ(p.c.got[0].type, GHTTP_WS_EVENT_PONG);
  }
}

TEST(WsH2EndToEnd, TheClosingHandshakeEndsBothSidesCleanlyAndTheStreamsAreGone) {
  for (bool client_first : {true, false}) {
    Pair p;
    ASSERT_TRUE(p.c.accepted && p.s.accepted);
    End & first = client_first ? p.c : p.s;
    ASSERT_EQ(ghttp_ws_conn_close(first.ws, 1000, "bye", 3), GHTTP_OK);
    ASSERT_EQ(ghttp_ws_h2_pump(first.ad), GHTTP_OK);
    run(p.c, p.s);
    EXPECT_EQ(p.c.status().state, GHTTP_WS_H2_CLOSED) << client_first;
    EXPECT_EQ(p.s.status().state, GHTTP_WS_H2_CLOSED) << client_first;
    EXPECT_EQ(ghttp_ws_conn_finish(p.c.ws), GHTTP_OK);
    EXPECT_EQ(ghttp_ws_conn_finish(p.s.ws), GHTTP_OK);
    EXPECT_TRUE(p.c.status().local_ended && p.s.status().local_ended);
    EXPECT_FALSE(ghttp_h2_conn_stream_is_active(p.c.h2, p.c.stream));
    EXPECT_FALSE(ghttp_h2_conn_stream_is_active(p.s.h2, p.s.stream));
    EXPECT_EQ(p.s.h2_result, GHTTP_OK);
    EXPECT_EQ(p.c.h2_result, GHTTP_OK);
    bool close_seen_c = false, close_seen_s = false;
    for (auto & e : p.c.got) close_seen_c |= e.type == GHTTP_WS_EVENT_CLOSE && e.code == 1000;
    for (auto & e : p.s.got) close_seen_s |= e.type == GHTTP_WS_EVENT_CLOSE && e.code == 1000;
    EXPECT_TRUE(client_first ? close_seen_s : close_seen_c);
  }
}

TEST(WsH2EndToEnd, AnEndStreamBeforeTheCloseIsAnAbnormalClosure1006) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  // The client simply ends its side of the stream.
  size_t acc;
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.h2, p.c.stream, nullptr, 0, 1, &acc), GHTTP_OK);
  run(p.c, p.s);
  GHTTP_WsH2Status st = p.s.status();
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
  EXPECT_TRUE(st.remote_ended);
  EXPECT_TRUE(st.local_ended) << "the server ends its side too, the stream is not left half-open";
  EXPECT_NE(ghttp_ws_conn_finish(p.s.ws), GHTTP_OK);
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(p.s.h2, p.s.stream));
}

TEST(WsH2EndToEnd, AResetMidMessageIsAbnormalWithTheCodeReported) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  std::string m = ws_lorem(200, 4);
  std::string frame = text(m, true);
  size_t acc;
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), 100), GHTTP_OK);
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.h2, p.c.stream, "\x81\x80", 2, 0, &acc), GHTTP_OK);  // half a header
  ASSERT_EQ(ghttp_h2_conn_reset_stream(p.c.h2, p.c.stream, GHTTP_H2_CANCEL), GHTTP_OK);
  run(p.c, p.s);
  GHTTP_WsH2Status st = p.s.status();
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
  EXPECT_TRUE(st.reset);
  EXPECT_EQ(st.reset_code, static_cast<uint32_t>(GHTTP_H2_CANCEL));
  EXPECT_EQ(p.s.h2_result, GHTTP_OK) << "a stream matter, the connection lives";
}

TEST(WsH2EndToEnd, ACodecViolationFailsTheWebSocketWithItsCodeAndEndsTheStream) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  // An unmasked client frame, written straight into the stream.
  std::string bad = text("hello", false);
  size_t acc;
  ASSERT_EQ(ghttp_h2_conn_send_data(p.c.h2, p.c.stream, bad.data(), bad.size(), 0, &acc), GHTTP_OK);
  run(p.c, p.s);
  GHTTP_WsH2Status st = p.s.status();
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1002);
  EXPECT_EQ(p.s.ws_result, GHTTP_ERR_CORRUPT);
  EXPECT_TRUE(st.local_ended);
  bool close1002 = false;
  for (auto & e : p.c.got) close1002 |= e.type == GHTTP_WS_EVENT_CLOSE && e.code == 1002;
  EXPECT_TRUE(close1002) << "the Close the codec owed was delivered";
}

TEST(WsH2EndToEnd, TheWritersHoldsBackAtASmallWindowAndEverythingArrives) {
  GHTTP_H2Limits sl = srv_limits();
  sl.initial_window_size = 200;
  GHTTP_H2Limits cl = limits();
  cl.initial_window_size = 200;
  Pair p(false, 0, &sl, &cl);
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  std::string m = ws_lorem(5000, 2);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  EXPECT_GT(ghttp_ws_conn_output_size(p.c.ws), 0u) << "held back by the window";
  run(p.c, p.s);
  ASSERT_EQ(p.s.got.size(), 1u);
  EXPECT_EQ(p.s.got[0].data, m);
  EXPECT_EQ(ghttp_ws_conn_output_size(p.c.ws), 0u);
}

TEST(WsH2EndToEnd, TheRfc8441Section4And5ExamplesAreBuiltAndReadByBothRoles) {
  static const char * const server_protos[] = {"chat"};
  static const char * const client_protos[] = {"chat", "superchat"};
  GHTTP_H2Limits sl = srv_limits();
  GHTTP_H2Limits cl = limits();
  End c(GHTTP_H2_CLIENT, &cl), s(GHTTP_H2_SERVER, &sl);
  c.copt.host = "server.example.com";
  c.copt.target = "/chat";
  c.copt.origin = "http://www.example.com";
  c.copt.subprotocols = client_protos;
  c.copt.subprotocol_count = 2;
  s.sopt.subprotocols = server_protos;
  s.sopt.subprotocol_count = 1;
  run(c, s);
  c.open();
  // The request as the server read it: the section 4 example.
  run(c, s);
  ASSERT_TRUE(c.accepted && s.accepted);
  const GHTTP_Request * q = ghttp_h2_conn_request(s.h2);
  EXPECT_STREQ(ghttp_request_method(q), "CONNECT");
  EXPECT_STREQ(ghttp_request_protocol(q), "websocket");
  EXPECT_STREQ(ghttp_request_target(q), "/chat");
  EXPECT_EQ(fields_text(ghttp_request_headers_const(q)),
      " [host: server.example.com] [sec-websocket-version: 13] [origin: http://www.example.com]"
      " [sec-websocket-protocol: chat, superchat]");
  // The response as the client read it: the section 5 example.
  const GHTTP_Response * r = ghttp_h2_conn_response(c.h2);
  EXPECT_EQ(ghttp_response_status(r), 200);
  EXPECT_EQ(fields_text(ghttp_response_headers_const(r)), " [sec-websocket-protocol: chat]");
  GHTTP_WsClientResult unused;
  (void)unused;
}

TEST(WsH2EndToEnd, AServerThatRefusesAnswersAndEndsTheStream) {
  GHTTP_H2Limits sl = srv_limits();
  End srv(GHTTP_H2_SERVER, &sl);
  End cli(GHTTP_H2_CLIENT);
  run(cli, srv);
  cli.prepare();  // only for its handshake state; the request below is crafted
  GHTTP_Request * q = h2_request("CONNECT", "websocket", {{"host", "h"}, {"sec-websocket-version", "8"}});
  ASSERT_EQ(ghttp_h2_conn_send_request(cli.h2, q, "https", 0, &cli.stream), GHTTP_OK);
  ghttp_request_destroy(q);
  run(cli, srv);
  EXPECT_EQ(srv.refused, 426);
  EXPECT_EQ(srv.ad, nullptr);
  EXPECT_FALSE(ghttp_h2_conn_stream_is_active(srv.h2, cli.stream)) << "ended with the refusal";
  EXPECT_EQ(cli.refused, 426);
  EXPECT_EQ(cli.ad, nullptr);
  EXPECT_EQ(cli.h2_result, GHTTP_OK);
  EXPECT_EQ(srv.h2_result, GHTTP_OK);
}

TEST(WsH2EndToEnd, EveryAllocationFailingInTurnIsOomOrTheSameAnswerAndNeverALeak) {
  auto once = [](const GHTTP_Allocator * a, GHTTP_Result * out) {
    // Only the adapter and the handshake take the allocator under test; the
    // h2 and WebSocket connections use theirs.
    GHTTP_H2Limits sl = srv_limits();
    GHTTP_H2Conn * h2 = nullptr;
    *out = ghttp_h2_conn_create(a, GHTTP_H2_SERVER, &sl, &h2);
    if (*out != GHTTP_OK) return std::string("create");
    GHTTP_WsConn * ws = nullptr;
    std::string log;
    GHTTP_Request * q = nullptr;
    GHTTP_Response * resp = nullptr;
    GHTTP_WsH2 * ad = nullptr;
    Block b;
    HList l = {{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "https"},
        {":path", "/"}, {":authority", "h"}, {"sec-websocket-version", "13"},
        {"sec-websocket-extensions", "permessage-deflate"}};
    std::string in = client_open() + settings_ack() + headers(1, b(l));
    in += data(1, text("hi", true));
    size_t off = 0;
    GHTTP_WsServerOptions o;
    ghttp_ws_server_options_default(&o);
    o.enable_deflate = 1;
    for (;;) {
      size_t used = 0;
      GHTTP_H2Event ev;
      GHTTP_Result r = ghttp_h2_conn_feed(h2, in.data() + off, in.size() - off, &used, &ev);
      off += used;
      if (r != GHTTP_OK) { *out = r; break; }
      if (ev.type == GHTTP_H2_EVENT_NEED_MORE) break;
      if (ev.type == GHTTP_H2_EVENT_HEADERS) {
        q = const_cast<GHTTP_Request *>(ghttp_h2_conn_request(h2));
        r = ghttp_response_create(a, &resp);
        GHTTP_WsServerResult sr;
        if (r == GHTTP_OK) r = ghttp_ws_server_handshake_h2(q, &o, resp, &sr);
        if (r == GHTTP_OK) r = ghttp_h2_conn_send_response(h2, 1, resp, 0);
        if (r == GHTTP_OK) r = ghttp_ws_conn_create(a, GHTTP_WS_SERVER, nullptr, &sr.negotiated, &ws);
        if (r == GHTTP_OK) r = ghttp_ws_h2_create(a, h2, 1, ws, &ad);
        if (r != GHTTP_OK) { *out = r; break; }
        log += "H;";
      } else if (ev.type == GHTTP_H2_EVENT_DATA && ad) {
        r = ghttp_ws_h2_input(ad, &ev);
        if (r != GHTTP_OK) { *out = r; break; }
        GHTTP_WsEvent we;
        do {
          r = ghttp_ws_h2_next(ad, &we);
          if (r != GHTTP_OK) { *out = r; break; }
          if (we.type != GHTTP_WS_EVENT_NEED_MORE)
            log += std::string(reinterpret_cast<const char *>(we.data), we.data_len) + ";";
        } while (we.type != GHTTP_WS_EVENT_NEED_MORE);
        if (r != GHTTP_OK) break;
      }
    }
    ghttp_ws_h2_destroy(ad);
    ghttp_ws_conn_destroy(ws);
    ghttp_response_destroy(resp);
    ghttp_h2_conn_destroy(h2);
    return log;
  };
  GHTTP_Result r0;
  std::string expected = once(nullptr, &r0);
  ASSERT_EQ(r0, GHTTP_OK);
  ASSERT_EQ(expected, "H;hi;");
  FailingAllocator counter(static_cast<size_t>(-1));
  GHTTP_Result rc;
  ASSERT_EQ(once(counter.get(), &rc), expected);
  size_t total = counter.requests();
  size_t oom = 0;
  for (size_t runlen : {size_t(1), size_t(0), size_t(2)}) {
    for (size_t k = 0; k <= total + 1; k++) {
      FailingAllocator fa(k, runlen);
      GHTTP_Result r;
      std::string got = once(fa.get(), &r);
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


// ---------------------------------------------------------------------------
// The adapter's API, the cases it must refuse, and how it learns the stream or
// the connection is gone
// ---------------------------------------------------------------------------

namespace {

GHTTP_H2Event data_event(uint32_t stream, const std::string & d, bool end = false) {
  // The event points at the bytes: keep them for the life of the test run.
  static std::list<std::string> keep;
  keep.push_back(d);
  GHTTP_H2Event e;
  memset(&e, 0, sizeof(e));
  e.size = sizeof(e);
  e.type = GHTTP_H2_EVENT_DATA;
  e.stream_id = stream;
  e.data = reinterpret_cast<const uint8_t *>(keep.back().data());
  e.data_len = d.size();
  e.end_stream = end;
  return e;
}

GHTTP_H2Event plain_event(GHTTP_H2EventType t, uint32_t stream, uint32_t code = 0, uint32_t last = 0) {
  GHTTP_H2Event e;
  memset(&e, 0, sizeof(e));
  e.size = sizeof(e);
  e.type = t;
  e.stream_id = stream;
  e.error_code = code;
  e.last_stream_id = last;
  return e;
}

}  // namespace

TEST(WsH2Adapter, CreateRefusesWhatIsNotAnActiveTunnelOfTheRightRoleWithItsHeadersSent) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  GHTTP_WsH2 * a = nullptr;
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, nullptr, 1, p.c.ws, &a), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.c.h2, 1, nullptr, &a), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.c.h2, 1, p.c.ws, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.c.h2, 0, p.c.ws, &a), GHTTP_ERR_INVALID) << "stream 0";
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.c.h2, 99, p.c.ws, &a), GHTTP_ERR_INVALID) << "no such stream";
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.c.h2, p.c.stream, p.s.ws, &a), GHTTP_ERR_INVALID)
      << "a server WebSocket on a client connection";
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.s.h2, p.s.stream, p.c.ws, &a), GHTTP_ERR_INVALID)
      << "a client WebSocket on a server connection";
  EXPECT_EQ(a, nullptr);
  // A stream that is not a tunnel: an ordinary GET.
  GHTTP_Request * q = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &q), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_target(q, "/plain"), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(ghttp_request_headers(q), "host", "h"), GHTTP_OK);
  uint32_t id = 0;
  ASSERT_EQ(ghttp_h2_conn_send_request(p.c.h2, q, "https", 0, &id), GHTTP_OK);
  ghttp_request_destroy(q);
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, p.c.h2, id, p.c.ws, &a), GHTTP_ERR_INVALID) << "not a tunnel";
}

TEST(WsH2Adapter, ACreateBeforeTheServerSentItsResponseIsRefused) {
  GHTTP_H2Limits sl = srv_limits();
  End c(GHTTP_H2_CLIENT), s(GHTTP_H2_SERVER, &sl);
  run(c, s);
  c.open();
  // The server has read the request but its handshake handler is not run yet:
  // feed by hand, without the harness answering.
  std::string bytes = c.take();
  size_t off = 0;
  GHTTP_H2Event ev;
  do {
    size_t used = 0;
    ASSERT_EQ(ghttp_h2_conn_feed(s.h2, bytes.data() + off, bytes.size() - off, &used, &ev), GHTTP_OK);
    off += used;
  } while (ev.type != GHTTP_H2_EVENT_HEADERS && off < bytes.size());
  ASSERT_EQ(ev.type, GHTTP_H2_EVENT_HEADERS);
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  GHTTP_WsConn * ws = nullptr;
  ASSERT_EQ(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, nullptr, &n, &ws), GHTTP_OK);
  GHTTP_WsH2 * a = nullptr;
  EXPECT_EQ(ghttp_ws_h2_create(nullptr, s.h2, ev.stream_id, ws, &a), GHTTP_ERR_INVALID)
      << "no DATA may go before the response";
  ghttp_ws_conn_destroy(ws);
}

TEST(WsH2Adapter, ASecondDataEventBeforeNextIsRefusedAndTheFirstIsKept) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  std::string f = text("one", true);
  GHTTP_H2Event e1 = data_event(p.s.stream, f);
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &e1), GHTTP_OK);
  GHTTP_H2Event e2 = data_event(p.s.stream, text("two", true));
  EXPECT_EQ(ghttp_ws_h2_input(p.s.ad, &e2), GHTTP_ERR_INVALID);
  GHTTP_WsEvent we;
  ASSERT_EQ(ghttp_ws_h2_next(p.s.ad, &we), GHTTP_OK);
  ASSERT_EQ(we.type, GHTTP_WS_EVENT_TEXT);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(we.data), we.data_len), "one");
  ASSERT_EQ(ghttp_ws_h2_next(p.s.ad, &we), GHTTP_OK);
  EXPECT_EQ(we.type, GHTTP_WS_EVENT_NEED_MORE);
  EXPECT_EQ(ghttp_ws_h2_input(p.s.ad, &e2), GHTTP_OK) << "once it has been read to the end";
}

TEST(WsH2Adapter, TheDataIsCopiedSoItMayBeReadAfterTheEventsBufferIsGone) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  std::string f = text("copied", true);
  GHTTP_H2Event e = data_event(p.s.stream, f);
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &e), GHTTP_OK);
  f.assign(f.size(), '\0');  // what the h2 connection's buffer becomes after the next feed
  GHTTP_WsEvent we;
  ASSERT_EQ(ghttp_ws_h2_next(p.s.ad, &we), GHTTP_OK);
  ASSERT_EQ(we.type, GHTTP_WS_EVENT_TEXT);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(we.data), we.data_len), "copied");
}

TEST(WsH2Adapter, NextClearsTheEventWhenTheCodecFails) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  GHTTP_H2Event e = data_event(p.s.stream, text("x", false));  // unmasked at a server
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &e), GHTTP_OK);
  GHTTP_WsEvent we;
  memset(&we, 0xaa, sizeof(we));
  EXPECT_EQ(ghttp_ws_h2_next(p.s.ad, &we), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(we.type, GHTTP_WS_EVENT_NEED_MORE);
  EXPECT_EQ(we.data, nullptr);
  EXPECT_EQ(we.data_len, 0u);
  EXPECT_EQ(we.size, sizeof(we));
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1002);
}

TEST(WsH2Adapter, AStreamTheServerDidNotProcessEndsTheWebSocketAbnormally) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  GHTTP_H2Event e = plain_event(GHTTP_H2_EVENT_STREAM_UNPROCESSED, p.c.stream, GHTTP_H2_REFUSED_STREAM);
  ASSERT_EQ(ghttp_ws_h2_input(p.c.ad, &e), GHTTP_OK);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
  EXPECT_TRUE(st.reset);
  EXPECT_EQ(st.reset_code, static_cast<uint32_t>(GHTTP_H2_REFUSED_STREAM));
}

TEST(WsH2Adapter, AGoawayBelowTheClientsStreamIsTheSameAndAboveItIsNot) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  GHTTP_H2Event above = plain_event(GHTTP_H2_EVENT_GOAWAY, 0, 0, p.c.stream);
  ASSERT_EQ(ghttp_ws_h2_input(p.c.ad, &above), GHTTP_OK);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_OPEN) << "the stream was processed";
  GHTTP_H2Event below = plain_event(GHTTP_H2_EVENT_GOAWAY, 0, 0, p.c.stream - 1);
  ASSERT_EQ(ghttp_ws_h2_input(p.c.ad, &below), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
  // A server is told nothing by a GOAWAY about a stream the client opened.
  GHTTP_H2Event at_server = plain_event(GHTTP_H2_EVENT_GOAWAY, 0, 0, 0);
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &at_server), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_OPEN);
}

TEST(WsH2Adapter, AConnectionErrorTheCallerReportsEndsTheWebSocketAndStopsTheOutput) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  EXPECT_EQ(ghttp_ws_h2_connection_failed(p.c.ad, GHTTP_OK), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_h2_connection_failed(nullptr, GHTTP_ERR_CORRUPT), GHTTP_ERR_INVALID);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_OPEN) << "before it is told, it cannot know";
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, "late", 4), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_connection_failed(p.c.ad, GHTTP_ERR_CORRUPT), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
  EXPECT_TRUE(st.connection_failed);
  EXPECT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  EXPECT_TRUE(p.c.take().empty()) << "nothing is sent on a failed connection";
  GHTTP_H2Event d = data_event(p.c.stream, text("x", false));
  EXPECT_EQ(ghttp_ws_h2_input(p.c.ad, &d), GHTTP_OK) << "dropped";
  GHTTP_WsEvent we;
  ASSERT_EQ(ghttp_ws_h2_next(p.c.ad, &we), GHTTP_OK);
  EXPECT_EQ(we.type, GHTTP_WS_EVENT_NEED_MORE);
}

TEST(WsH2Adapter, AResetAfterTheClosingHandshakeCompletedLeavesItClosed) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  ASSERT_EQ(ghttp_ws_conn_close(p.c.ws, 1000, "bye", 3), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  run(p.c, p.s);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  ASSERT_EQ(st.state, GHTTP_WS_H2_CLOSED);
  GHTTP_H2Event rs = plain_event(GHTTP_H2_EVENT_STREAM_RESET, p.s.stream, GHTTP_H2_CANCEL);
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &rs), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_input(p.c.ad, &rs), GHTTP_OK);
  for (End * e : {&p.s, &p.c}) {
    ASSERT_EQ(ghttp_ws_h2_status(e->ad, &st), GHTTP_OK);
    EXPECT_EQ(st.state, GHTTP_WS_H2_CLOSED);
    EXPECT_EQ(st.code, 0);
  }
  ASSERT_EQ(ghttp_ws_h2_connection_failed(p.s.ad, GHTTP_ERR_IO), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_CLOSED) << "nor does the connection dying afterwards";
}

TEST(WsH2Adapter, AnEndStreamWhileClosingWithNoReplyIsAbnormal) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  ASSERT_EQ(ghttp_ws_conn_close(p.s.ws, 1000, "bye", 3), GHTTP_OK);  // the server's Close; nobody answers
  GHTTP_H2Event e = data_event(p.s.stream, "", true);
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &e), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_state(p.s.ws), GHTTP_WS_STATE_CLOSING);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
}

TEST(WsH2Adapter, AStreamTheApplicationEndedItselfIsNotAnError) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  ASSERT_EQ(ghttp_h2_conn_reset_stream(p.c.h2, p.c.stream, GHTTP_H2_CANCEL), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, "x", 1), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  // The other way: the application ends its side with END_STREAM and keeps pumping.
  Pair q;
  ASSERT_TRUE(q.c.accepted && q.s.accepted);
  size_t acc = 0;
  ASSERT_EQ(ghttp_h2_conn_send_data(q.c.h2, q.c.stream, nullptr, 0, 1, &acc), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_conn_send_message(q.c.ws, GHTTP_WS_MESSAGE_TEXT, "x", 1), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_h2_pump(q.c.ad), GHTTP_OK) << "the send is refused as INVALID, which is not the caller's problem";
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(q.c.ad, &st), GHTTP_OK);
  EXPECT_TRUE(st.local_ended);
  EXPECT_EQ(ghttp_ws_h2_pump(q.c.ad), GHTTP_OK);
}

TEST(WsH2Adapter, AWindowUpdateAloneReleasesHeldOutputWithoutAnExplicitPump) {
  GHTTP_H2Limits sl = srv_limits();
  sl.initial_window_size = 200;
  GHTTP_H2Limits cl = limits();
  cl.initial_window_size = 200;
  Pair p(false, 0, &sl, &cl);
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  p.c.no_pump = p.s.no_pump = true;
  std::string m = ws_lorem(5000, 2);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  size_t held = ghttp_ws_conn_output_size(p.c.ws);
  ASSERT_GT(held, 0u);
  // The server's WINDOW_UPDATEs, as bytes, through the h2 connection and the adapter's input alone.
  p.c.feed(window_update(0, 100000) + window_update(p.c.stream, 100000));
  EXPECT_LT(ghttp_ws_conn_output_size(p.c.ws), held) << "released by the event";
  EXPECT_EQ(ghttp_ws_conn_output_size(p.c.ws), 0u);
}

TEST(WsH2Adapter, ASettingsWindowGrowthAloneReleasesHeldOutputWithoutAnExplicitPump) {
  GHTTP_H2Limits sl = srv_limits();
  sl.initial_window_size = 200;
  Pair p(false, 0, &sl, nullptr);
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  p.c.no_pump = true;
  std::string m = ws_lorem(5000, 2);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  size_t held = ghttp_ws_conn_output_size(p.c.ws);
  ASSERT_GT(held, 0u);
  p.c.feed(settings({{GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE, 60000}}));
  EXPECT_LT(ghttp_ws_conn_output_size(p.c.ws), held);
  EXPECT_EQ(ghttp_ws_conn_output_size(p.c.ws), 0u);
}

TEST(WsH2Adapter, HeldOutputIsSentBeforeTheStreamIsEndedWhenThePeerHalfClosed) {
  GHTTP_H2Limits sl = srv_limits();
  sl.initial_window_size = 200;
  Pair p(false, 0, &sl, nullptr);
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  p.c.no_pump = true;
  std::string m = ws_lorem(5000, 2);
  ASSERT_EQ(ghttp_ws_conn_send_message(p.c.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()), GHTTP_OK);
  GHTTP_H2Event end = data_event(p.c.stream, "", true);  // the server's END_STREAM
  ASSERT_EQ(ghttp_ws_h2_input(p.c.ad, &end), GHTTP_OK);
  ASSERT_EQ(ghttp_ws_h2_pump(p.c.ad), GHTTP_OK);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_GT(ghttp_ws_conn_output_size(p.c.ws), 0u) << "held back by the window";
  EXPECT_FALSE(st.local_ended) << "the stream must not be ended over data still to be sent";
  p.c.feed(window_update(p.c.stream, 100000));
  ASSERT_EQ(ghttp_ws_h2_status(p.c.ad, &st), GHTTP_OK);
  EXPECT_EQ(ghttp_ws_conn_output_size(p.c.ws), 0u);
  EXPECT_TRUE(st.local_ended) << "ended once the data has gone";
  // On the wire: all of the message's frame, and only then the END_STREAM.
  size_t total = 0;
  bool ended_last = false;
  for (const OutFrame & f : parse_frames(p.c.take())) {
    if (f.type != GHTTP_H2_DATA || f.stream != p.c.stream) continue;
    EXPECT_FALSE(ended_last) << "DATA after END_STREAM";
    total += f.payload.size();
    if (f.flags & END_STREAM) ended_last = true;
  }
  EXPECT_GE(total, m.size());
  EXPECT_TRUE(ended_last);
}

TEST(WsH2Adapter, AnEndStreamThatCameWithDataTakesEffectOnlyWhenTheDataIsRead) {
  Pair p;
  ASSERT_TRUE(p.c.accepted && p.s.accepted);
  GHTTP_H2Event e = data_event(p.s.stream, text("last", true), true);
  ASSERT_EQ(ghttp_ws_h2_input(p.s.ad, &e), GHTTP_OK);
  GHTTP_WsH2Status st;
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  EXPECT_FALSE(st.remote_ended) << "the data has not been read";
  EXPECT_EQ(st.state, GHTTP_WS_H2_OPEN);
  GHTTP_WsEvent we;
  ASSERT_EQ(ghttp_ws_h2_next(p.s.ad, &we), GHTTP_OK);
  ASSERT_EQ(we.type, GHTTP_WS_EVENT_TEXT);
  ASSERT_EQ(ghttp_ws_h2_next(p.s.ad, &we), GHTTP_OK);
  EXPECT_EQ(we.type, GHTTP_WS_EVENT_NEED_MORE);
  ASSERT_EQ(ghttp_ws_h2_status(p.s.ad, &st), GHTTP_OK);
  EXPECT_TRUE(st.remote_ended);
  EXPECT_EQ(st.state, GHTTP_WS_H2_ABNORMAL);
  EXPECT_EQ(st.code, 1006);
}

// ---------------------------------------------------------------------------
// Handshake corners
// ---------------------------------------------------------------------------

TEST(WsH2Handshake, TheProtocolNameIsMatchedIgnoringCase) {
  GHTTP_Request * q = h2_request("CONNECT", "WebSocket");
  EXPECT_EQ(ghttp_ws_is_h2_request(q), 1);
  Served s(q);
  EXPECT_EQ(s.res.accepted, 1);
  ghttp_request_destroy(q);
  GHTTP_Request * other = h2_request("CONNECT", "websocket2");
  EXPECT_EQ(ghttp_ws_is_h2_request(other), 0);
  ghttp_request_destroy(other);
  EXPECT_EQ(ghttp_ws_is_h2_request(nullptr), 0);
}

TEST(WsH2Handshake, ANullRequestOrResponseIsInvalidAndNotACrash) {
  GHTTP_Response * resp;
  ASSERT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
  GHTTP_WsServerResult r;
  EXPECT_EQ(ghttp_ws_server_handshake_h2(nullptr, nullptr, resp, &r), GHTTP_ERR_INVALID);
  GHTTP_Request * q = h2_request();
  EXPECT_EQ(ghttp_ws_server_handshake_h2(q, nullptr, nullptr, &r), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_server_handshake_h2(q, nullptr, resp, nullptr), GHTTP_ERR_INVALID);
  ghttp_request_destroy(q);
  ghttp_response_destroy(resp);
}

TEST(WsH2ClientHandshake, AnAbsoluteFormTargetGivesSchemeAuthorityAndPath_Rfc8441_4) {
  GHTTP_H2Limits sl = srv_limits();
  End c(GHTTP_H2_CLIENT), s(GHTTP_H2_SERVER, &sl);
  c.copt.target = "https://server.example.com/chat";
  c.copt.host = "server.example.com";
  run(c, s);
  c.open();
  run(c, s);
  ASSERT_TRUE(c.accepted && s.accepted);
  EXPECT_EQ(s.seen_scheme, "https");
  EXPECT_EQ(s.seen_authority, "server.example.com");
  EXPECT_EQ(s.seen_target, "/chat");
}

TEST(WsH2ClientHandshake, AnAsteriskOrAuthorityFormTargetIsInvalidAndTheRequestIsUntouched) {
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "h";
  for (const char * target : {"*", "host:443", "", "http:/x"}) {
    o.target = target;
    GHTTP_Request * q;
    ASSERT_EQ(ghttp_request_create(nullptr, &q), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(q, "/marker"), GHTTP_OK);
    ASSERT_EQ(ghttp_headers_add(ghttp_request_headers(q), "x-marker", "1"), GHTTP_OK);
    GHTTP_WsClientHandshake * hs = nullptr;
    EXPECT_EQ(ghttp_ws_client_handshake_create_h2(nullptr, &o, q, &hs), GHTTP_ERR_INVALID) << target;
    EXPECT_EQ(hs, nullptr);
    EXPECT_STREQ(ghttp_request_target(q), "/marker") << target;
    EXPECT_STREQ(ghttp_request_method(q), "GET");
    EXPECT_EQ(ghttp_headers_count(ghttp_request_headers_const(q)), 1u);
    EXPECT_EQ(ghttp_request_protocol(q), nullptr);
    ghttp_request_destroy(q);
  }
}

TEST(WsH2ClientHandshake, AFailureLeavesTheRequestUntouchedOrFresh) {
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "h";
  const char * protos[] = {"chat", "superchat"};
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  o.enable_deflate = 1;
  FailingAllocator counter(static_cast<size_t>(-1));
  {
    GHTTP_Request * q;
    ASSERT_EQ(ghttp_request_create(nullptr, &q), GHTTP_OK);
    GHTTP_WsClientHandshake * hs = nullptr;
    ASSERT_EQ(ghttp_ws_client_handshake_create_h2(counter.get(), &o, q, &hs), GHTTP_OK);
    ghttp_ws_client_handshake_destroy(hs);
    ghttp_request_destroy(q);
  }
  size_t total = counter.requests();
  for (size_t k = 0; k <= total; k++) {
    FailingAllocator fa(k, 0);
    GHTTP_Request * q;
    ASSERT_EQ(ghttp_request_create(nullptr, &q), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(q, "/marker"), GHTTP_OK);
    GHTTP_WsClientHandshake * hs = nullptr;
    GHTTP_Result r = ghttp_ws_client_handshake_create_h2(fa.get(), &o, q, &hs);
    if (r != GHTTP_OK) {
      std::string t = ghttp_request_target(q);
      EXPECT_TRUE(t == "/marker" || (t == "/" && ghttp_headers_count(ghttp_request_headers_const(q)) == 0))
          << k << " " << t;
      EXPECT_STREQ(ghttp_request_method(q), t == "/" ? "GET" : ghttp_request_method(q));
      EXPECT_EQ(ghttp_request_protocol(q), nullptr) << k;
    }
    ghttp_ws_client_handshake_destroy(hs);
    ghttp_request_destroy(q);
    EXPECT_EQ(fa.live(), 0u) << k;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
