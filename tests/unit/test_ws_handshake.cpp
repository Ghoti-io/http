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
 * The WebSocket opening handshake: RFC 6455 sections 1.3, 4 and 9.1, with the
 * parameters of RFC 7692 section 7.
 */

#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"
#include "ws_helpers.h"

using namespace ghttptest;

namespace {

using Fields = std::vector<std::pair<std::string, std::string>>;

const char * RFC_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const char * RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/** The RFC 6455 section 1.3 request, with the fields a test wants changed or added. */
Fields rfc_fields() {
  return {{"Host", "server.example.com"}, {"Upgrade", "websocket"},
      {"Connection", "Upgrade"}, {"Sec-WebSocket-Key", RFC_KEY},
      {"Origin", "http://example.com"}, {"Sec-WebSocket-Version", "13"}};
}

Fields without(Fields f, const std::string & name) {
  Fields out;
  for (auto & e : f) {
    if (strcasecmp(e.first.c_str(), name.c_str()) != 0) out.push_back(e);
  }
  return out;
}

Fields with(Fields f, const std::string & name, const std::string & value) {
  f = without(f, name);
  f.push_back({name, value});
  return f;
}

Fields plus(Fields f, const std::string & name, const std::string & value) {
  f.push_back({name, value});
  return f;
}

struct Request {
  GHTTP_Request * r = nullptr;
  explicit Request(const Fields & f, const char * method = "GET", int minor = 1) {
    EXPECT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
    EXPECT_EQ(ghttp_request_set_method(r, method), GHTTP_OK);
    EXPECT_EQ(ghttp_request_set_target(r, "/chat"), GHTTP_OK);
    EXPECT_EQ(ghttp_request_set_version(r, minor), GHTTP_OK);
    for (auto & e : f) {
      EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(r), e.first.c_str(), e.second.c_str()), GHTTP_OK);
    }
  }
  ~Request() { ghttp_request_destroy(r); }
  Request(const Request &) = delete;
};

std::string field(const GHTTP_Headers * h, const char * name) {
  size_t i = ghttp_headers_find(h, name, 0);
  if (i == GHTTP_HEADERS_NPOS) return "<none>";
  GHTTP_Field f;
  ghttp_headers_at(h, i, &f);
  return std::string(f.value, f.value_len);
}

struct Served {
  GHTTP_WsServerResult result;
  GHTTP_Response * response = nullptr;
  GHTTP_Result rc = GHTTP_OK;
  Served(const Fields & f, const GHTTP_WsServerOptions * o = nullptr,
      const char * method = "GET", int minor = 1) {
    Request req(f, method, minor);
    EXPECT_EQ(ghttp_response_create(nullptr, &response), GHTTP_OK);
    rc = ghttp_ws_server_handshake(req.r, o, response, &result);
  }
  ~Served() { ghttp_response_destroy(response); }
  std::string header(const char * name) const {
    return field(ghttp_response_headers_const(response), name);
  }
  int status() const { return ghttp_response_status(response); }
};

GHTTP_WsServerOptions server_options() {
  GHTTP_WsServerOptions o;
  ghttp_ws_server_options_default(&o);
  return o;
}

} // namespace

// ---- The key and the accept value: section 4.2.2 ------------------------------

TEST(WsAccept, TheRfcExampleKeyGivesTheRfcExampleAccept) {
  char accept[GHTTP_WS_ACCEPT_LEN + 1];
  ASSERT_EQ(ghttp_ws_accept_key(RFC_KEY, strlen(RFC_KEY), accept), GHTTP_OK);
  EXPECT_STREQ(accept, RFC_ACCEPT);
}

TEST(WsAccept, AKeyIsExactlySixteenOctetsOfCanonicalBase64) {
  EXPECT_TRUE(ghttp_ws_key_is_valid(RFC_KEY, 24));
  EXPECT_TRUE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAAAAA==", 24));
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAAAAB==", 24));  // bits in the padding
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAAAAA=", 23));
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAAAAAAA", 24));  // 18 octets
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAA", 16));          // 12 octets
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAAAA===", 24));
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAA*AA==", 24));
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAA=AAAAAAAAA==", 24));  // padding mid-string
  EXPECT_FALSE(ghttp_ws_key_is_valid("AAAAAAAAAAAAAAAAAAAAAA-_", 24));  // URL alphabet
  EXPECT_FALSE(ghttp_ws_key_is_valid(nullptr, 24));
  char accept[GHTTP_WS_ACCEPT_LEN + 1];
  EXPECT_EQ(ghttp_ws_accept_key("nope", 4, accept), GHTTP_ERR_INVALID);
}

// ---- The server: section 4.2.1 ------------------------------------------------

TEST(WsServerHandshake, TheRfcExampleIsAcceptedWithTheRfcExampleAnswer) {
  GHTTP_WsServerOptions o = server_options();
  const char * protos[] = {"superchat", "chat"};
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  Fields f = plus(rfc_fields(), "Sec-WebSocket-Protocol", "chat, superchat");
  Served s(f, &o);
  ASSERT_EQ(s.rc, GHTTP_OK);
  EXPECT_TRUE(s.result.accepted);
  EXPECT_EQ(s.result.status, 101);
  EXPECT_EQ(s.status(), 101);
  EXPECT_STREQ(ghttp_response_reason(s.response), "Switching Protocols");
  EXPECT_EQ(s.header("Upgrade"), "websocket");
  EXPECT_EQ(s.header("Connection"), "Upgrade");
  EXPECT_EQ(s.header("Sec-WebSocket-Accept"), RFC_ACCEPT);
  // The server's own order decides, not the client's.
  EXPECT_EQ(s.header("Sec-WebSocket-Protocol"), "superchat");
  EXPECT_STREQ(s.result.negotiated.subprotocol, "superchat");
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "<none>");
  EXPECT_FALSE(s.result.negotiated.deflate);
}

TEST(WsServerHandshake, TheResponseIsWrittenAsTheRfcShowsIt) {
  Served s(rfc_fields());
  ASSERT_TRUE(s.result.accepted);
  GHTTP_Buffer * b = nullptr;
  ASSERT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
  ASSERT_EQ(ghttp_write_response_head(b, s.response), GHTTP_OK);
  std::string wire(static_cast<const char *>(ghttp_buffer_data(b)), ghttp_buffer_size(b));
  ghttp_buffer_destroy(b);
  EXPECT_EQ(wire,
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
}

TEST(WsServerHandshake, NoSubprotocolIsChosenWhenNoneIsOfferedOrNoneMatches) {
  GHTTP_WsServerOptions o = server_options();
  const char * protos[] = {"mqtt"};
  o.subprotocols = protos;
  o.subprotocol_count = 1;
  Served none(rfc_fields(), &o);
  EXPECT_TRUE(none.result.accepted);
  EXPECT_EQ(none.header("Sec-WebSocket-Protocol"), "<none>");
  Served other(plus(rfc_fields(), "Sec-WebSocket-Protocol", "chat"), &o);
  EXPECT_TRUE(other.result.accepted);
  EXPECT_EQ(other.header("Sec-WebSocket-Protocol"), "<none>");
  EXPECT_STREQ(other.result.negotiated.subprotocol, "");
  Served two_lines(plus(plus(rfc_fields(), "Sec-WebSocket-Protocol", "chat"),
                       "Sec-WebSocket-Protocol", "mqtt"), &o);
  EXPECT_EQ(two_lines.header("Sec-WebSocket-Protocol"), "mqtt");
}

TEST(WsServerHandshake, SubprotocolNamesAreCaseSensitive) {
  GHTTP_WsServerOptions o = server_options();
  const char * protos[] = {"chat"};
  o.subprotocols = protos;
  o.subprotocol_count = 1;
  Served s(plus(rfc_fields(), "Sec-WebSocket-Protocol", "Chat"), &o);
  EXPECT_TRUE(s.result.accepted);
  EXPECT_EQ(s.header("Sec-WebSocket-Protocol"), "<none>");
}

TEST(WsServerHandshake, ARepeatedOrMalformedSubprotocolListIsRefused) {
  Served dup(plus(rfc_fields(), "Sec-WebSocket-Protocol", "chat, chat"));
  EXPECT_FALSE(dup.result.accepted);
  EXPECT_EQ(dup.result.status, 400);
  Served bad(plus(rfc_fields(), "Sec-WebSocket-Protocol", "chat; q=1"));
  EXPECT_FALSE(bad.result.accepted);
  EXPECT_EQ(bad.result.status, 400);
  Served spaced(plus(rfc_fields(), "Sec-WebSocket-Protocol", "ch at"));
  EXPECT_FALSE(spaced.result.accepted);
}

TEST(WsServerHandshake, EachWayAHandshakeCanBeWrongIsRefusedWithItsStatus) {
  struct Case {
    const char * name;
    Fields fields;
    const char * method;
    int minor;
    int status;
  };
  std::vector<Case> cases = {
      {"POST", rfc_fields(), "POST", 1, 405},
      {"HTTP/1.0", rfc_fields(), "GET", 0, 400},
      {"no Host", without(rfc_fields(), "Host"), "GET", 1, 400},
      {"two Hosts", plus(rfc_fields(), "Host", "other.example.com"), "GET", 1, 400},
      {"two Origins", plus(rfc_fields(), "Origin", "http://evil.example"), "GET", 1, 400},
      {"no Upgrade", without(rfc_fields(), "Upgrade"), "GET", 1, 400},
      {"Upgrade names another protocol", with(rfc_fields(), "Upgrade", "h2c"), "GET", 1, 400},
      {"no Connection", without(rfc_fields(), "Connection"), "GET", 1, 400},
      {"Connection without upgrade", with(rfc_fields(), "Connection", "keep-alive"), "GET", 1, 400},
      {"no key", without(rfc_fields(), "Sec-WebSocket-Key"), "GET", 1, 400},
      {"two keys", plus(rfc_fields(), "Sec-WebSocket-Key", RFC_KEY), "GET", 1, 400},
      {"short key", with(rfc_fields(), "Sec-WebSocket-Key", "dGhlIHNhbXBsZQ=="), "GET", 1, 400},
      {"key not base64", with(rfc_fields(), "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZ!=="), "GET", 1, 400},
      {"no version", without(rfc_fields(), "Sec-WebSocket-Version"), "GET", 1, 400},
      {"two versions", plus(rfc_fields(), "Sec-WebSocket-Version", "13"), "GET", 1, 400},
      {"version 8", with(rfc_fields(), "Sec-WebSocket-Version", "8"), "GET", 1, 426},
      {"version 14", with(rfc_fields(), "Sec-WebSocket-Version", "14"), "GET", 1, 426},
      {"version list", with(rfc_fields(), "Sec-WebSocket-Version", "13, 8"), "GET", 1, 426},
      {"version 013", with(rfc_fields(), "Sec-WebSocket-Version", "013"), "GET", 1, 426},
  };
  for (auto & c : cases) {
    Served s(c.fields, nullptr, c.method, c.minor);
    ASSERT_EQ(s.rc, GHTTP_OK) << c.name;
    EXPECT_FALSE(s.result.accepted) << c.name;
    EXPECT_EQ(s.result.status, c.status) << c.name;
    EXPECT_EQ(s.status(), c.status) << c.name;
    EXPECT_NE(std::string(s.result.reason), "") << c.name;
    // A refusal closes the connection and has no body.
    EXPECT_EQ(s.header("Connection"), "close") << c.name;
    EXPECT_EQ(s.header("Content-Length"), "0") << c.name;
    EXPECT_EQ(s.header("Sec-WebSocket-Accept"), "<none>") << c.name;
    if (c.status == 426) { EXPECT_EQ(s.header("Sec-WebSocket-Version"), "13") << c.name; }
    if (c.status == 405) { EXPECT_EQ(s.header("Allow"), "GET") << c.name; }
  }
}

TEST(WsServerHandshake, ListsAndCaseInFieldValuesAreRead) {
  Served a(with(with(rfc_fields(), "Upgrade", "WebSocket"), "Connection", "keep-alive, Upgrade"));
  EXPECT_TRUE(a.result.accepted);
  Served b(plus(with(rfc_fields(), "Connection", "keep-alive"), "Connection", "upgrade"));
  EXPECT_TRUE(b.result.accepted);
  Served c(with(rfc_fields(), "Upgrade", "foo, websocket"));
  EXPECT_TRUE(c.result.accepted);
  Served d(with(without(rfc_fields(), "Sec-WebSocket-Version"), "sec-websocket-version", " 13 "));
  EXPECT_TRUE(d.result.accepted);
}

TEST(WsServerHandshake, ARequestThatIsNotAnUpgradeIsRecognisedAsSuch) {
  Request ok(rfc_fields());
  EXPECT_TRUE(ghttp_ws_is_upgrade_request(ok.r));
  Request plain({{"Host", "h"}});
  EXPECT_FALSE(ghttp_ws_is_upgrade_request(plain.r));
  Request post(rfc_fields(), "POST");
  EXPECT_FALSE(ghttp_ws_is_upgrade_request(post.r));
  EXPECT_FALSE(ghttp_ws_is_upgrade_request(nullptr));
}

TEST(WsServerHandshake, AHandshakeOverTheSizeLimitIsRefusedWith431) {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  GHTTP_WsServerOptions o = server_options();
  o.limits = &l;
  // The measure is the names and values of every field; it is judged first.
  Fields f = rfc_fields();
  size_t base = 0;
  for (auto & e : f) base += e.first.size() + e.second.size();
  l.max_handshake_bytes = base;
  Served exact(f, &o);
  EXPECT_TRUE(exact.result.accepted);
  l.max_handshake_bytes = base - 1;
  Served over(f, &o);
  EXPECT_FALSE(over.result.accepted);
  EXPECT_EQ(over.result.status, 431);
}

TEST(WsServerHandshake, NullArgumentsAreInvalid) {
  Request req(rfc_fields());
  GHTTP_Response * resp = nullptr;
  ASSERT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
  GHTTP_WsServerResult r;
  EXPECT_EQ(ghttp_ws_server_handshake(nullptr, nullptr, resp, &r), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_server_handshake(req.r, nullptr, nullptr, &r), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_ws_server_handshake(req.r, nullptr, resp, nullptr), GHTTP_ERR_INVALID);
  ghttp_response_destroy(resp);
}

// ---- Extensions: RFC 6455 section 9.1 and RFC 7692 section 7 -------------------

TEST(WsExtensionNegotiation, ADeflateOfferIsAcceptedOnlyWhenEnabled) {
  Fields f = plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate");
  Served off(f);
  EXPECT_TRUE(off.result.accepted);
  EXPECT_FALSE(off.result.negotiated.deflate);
  EXPECT_EQ(off.header("Sec-WebSocket-Extensions"), "<none>");
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  Served on(f, &o);
  EXPECT_TRUE(on.result.accepted);
  EXPECT_TRUE(on.result.negotiated.deflate);
  EXPECT_EQ(on.header("Sec-WebSocket-Extensions"), "permessage-deflate");
}

TEST(WsExtensionNegotiation, ABrowsersOfferGetsTheLimitTheServerAsks) {
  // Chrome sends client_max_window_bits with no value.
  Fields f = plus(rfc_fields(), "Sec-WebSocket-Extensions",
      "permessage-deflate; client_max_window_bits");
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  Served plain(f, &o);
  EXPECT_EQ(plain.header("Sec-WebSocket-Extensions"), "permessage-deflate");
  o.deflate.client_max_window_bits = 12;
  o.deflate.server_no_context_takeover = 1;
  Served limited(f, &o);
  EXPECT_EQ(limited.header("Sec-WebSocket-Extensions"),
      "permessage-deflate; server_no_context_takeover; client_max_window_bits=12");
  EXPECT_EQ(limited.result.negotiated.deflate_params.client_max_window_bits, 12);
  EXPECT_TRUE(limited.result.negotiated.deflate_params.server_no_context_takeover);
}

TEST(WsExtensionNegotiation, TheServerMayNotNameClientMaxWindowBitsUnlessAsked) {
  Fields f = plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate");
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  o.deflate.client_max_window_bits = 10;
  Served s(f, &o);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "permessage-deflate");
  EXPECT_EQ(s.result.negotiated.deflate_params.client_max_window_bits, 0);
}

TEST(WsExtensionNegotiation, AnOfferWithABadParameterIsDeclinedAndALaterOneAccepted) {
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  Fields f = plus(rfc_fields(), "Sec-WebSocket-Extensions",
      "permessage-deflate; server_max_window_bits=7, permessage-deflate; server_max_window_bits=10");
  Served s(f, &o);
  EXPECT_TRUE(s.result.accepted);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "permessage-deflate; server_max_window_bits=10");
  // Every bad shape on its own: declined, and the handshake goes on without.
  for (const char * bad : {"permessage-deflate; foo", "permessage-deflate; server_no_context_takeover=1",
           "permessage-deflate; server_max_window_bits", "permessage-deflate; server_max_window_bits=16",
           "permessage-deflate; server_max_window_bits=08", "permessage-deflate; server_max_window_bits=+9",
           "permessage-deflate; client_max_window_bits=7", "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
           "permessage-deflate; server_max_window_bits=9; server_max_window_bits=9"}) {
    Served t(plus(rfc_fields(), "Sec-WebSocket-Extensions", bad), &o);
    EXPECT_TRUE(t.result.accepted) << bad;
    EXPECT_FALSE(t.result.negotiated.deflate) << bad;
    EXPECT_EQ(t.header("Sec-WebSocket-Extensions"), "<none>") << bad;
  }
}

TEST(WsExtensionNegotiation, OnlyOnePermessageDeflateIsAcceptedAndValuesMayBeQuoted) {
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions",
               "permessage-deflate; server_max_window_bits=\"9\", permessage-deflate"), &o);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "permessage-deflate; server_max_window_bits=9");
}

TEST(WsExtensionNegotiation, TheServersWindowAndTheClientsAskAreTheTighterOfTheTwo) {
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  o.deflate.server_max_window_bits = 12;
  Served a(plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate; server_max_window_bits=10"), &o);
  EXPECT_EQ(a.result.negotiated.deflate_params.server_max_window_bits, 10);
  Served b(plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate; server_max_window_bits=14"), &o);
  EXPECT_EQ(b.result.negotiated.deflate_params.server_max_window_bits, 12);
  Served c(plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate"), &o);
  EXPECT_EQ(c.result.negotiated.deflate_params.server_max_window_bits, 12);
  EXPECT_EQ(c.header("Sec-WebSocket-Extensions"), "permessage-deflate; server_max_window_bits=12");
}

TEST(WsExtensionNegotiation, AMalformedExtensionsFieldIsRefused) {
  for (const char * bad : {"permessage-deflate;", "permessage-deflate; =1", "permessage-deflate; a=\"b",
           "permessage-deflate x", "(foo)", "permessage-deflate; a=b=c", "permessage-deflate; a = b"}) {
    Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions", bad));
    EXPECT_FALSE(s.result.accepted) << bad;
    EXPECT_EQ(s.result.status, 400) << bad;
  }
}

TEST(WsExtensionNegotiation, ListsAndCaseAreReadAcrossFieldLines) {
  GHTTP_WsServerOptions o = server_options();
  o.enable_deflate = 1;
  Served s(plus(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-unknown; a=1"),
               "sec-websocket-extensions", " , PERMESSAGE-DEFLATE ;  Client_No_Context_Takeover"), &o);
  EXPECT_TRUE(s.result.negotiated.deflate);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "permessage-deflate; client_no_context_takeover");
}

TEST(WsExtensionNegotiation, MoreOffersOrParametersThanTheLimitsAreRefused) {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  GHTTP_WsServerOptions o = server_options();
  o.limits = &l;
  l.max_extension_offers = 2;
  Served ok(plus(rfc_fields(), "Sec-WebSocket-Extensions", "a, b"), &o);
  EXPECT_TRUE(ok.result.accepted);
  Served many(plus(rfc_fields(), "Sec-WebSocket-Extensions", "a, b, c"), &o);
  EXPECT_FALSE(many.result.accepted);
  EXPECT_EQ(many.result.status, 400);
  l.max_extension_params = 2;
  Served params_ok(plus(rfc_fields(), "Sec-WebSocket-Extensions", "a; x; y"), &o);
  EXPECT_TRUE(params_ok.result.accepted);
  Served params(plus(rfc_fields(), "Sec-WebSocket-Extensions", "a; x; y; z"), &o);
  EXPECT_FALSE(params.result.accepted);
  EXPECT_EQ(params.result.status, 400);
}

namespace {

struct HookLog {
  std::vector<std::string> seen;
  bool accept = true;
  uint8_t rsv = 0;
  std::string reply = "x-foo; level=2";
  GHTTP_Result rc = GHTTP_OK;
};

GHTTP_Result hook(void * ctx, const GHTTP_WsExtensionOffer * offer, GHTTP_WsExtensionReply * reply) {
  HookLog * log = static_cast<HookLog *>(ctx);
  std::string s(offer->name, offer->name_len);
  for (size_t i = 0; i < offer->param_count; i++) {
    s += ";" + std::string(offer->params[i].name, offer->params[i].name_len);
    if (offer->params[i].has_value) s += "=" + std::string(offer->params[i].value, offer->params[i].value_len);
  }
  s += offer->is_response ? " [response]" : " [offer]";
  log->seen.push_back(s);
  reply->accept = log->accept;
  reply->rsv = log->rsv;
  strncpy(reply->text, log->reply.c_str(), sizeof(reply->text) - 1);
  return log->rc;
}

} // namespace

TEST(WsExtensionNegotiation, AnUnknownExtensionGoesToTheHookAndItsReplyIsSent) {
  HookLog log;
  log.rsv = GHTTP_WS_RSV2;
  GHTTP_WsServerOptions o = server_options();
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-foo; level=\"2\"; z"), &o);
  ASSERT_TRUE(s.result.accepted);
  EXPECT_EQ(log.seen, (std::vector<std::string>{"x-foo;level=2;z [offer]"}));
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "x-foo; level=2");
  EXPECT_EQ(s.result.negotiated.extension_rsv, GHTTP_WS_RSV2);
}

TEST(WsExtensionNegotiation, AHookMayDeclineAndMayFailTheHandshake) {
  HookLog log;
  log.accept = false;
  GHTTP_WsServerOptions o = server_options();
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Served declined(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-foo"), &o);
  EXPECT_TRUE(declined.result.accepted);
  EXPECT_EQ(declined.header("Sec-WebSocket-Extensions"), "<none>");
  log.rc = GHTTP_ERR_INTERNAL;
  Served failed(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-foo"), &o);
  EXPECT_EQ(failed.rc, GHTTP_ERR_INTERNAL);
}

TEST(WsExtensionNegotiation, TwoExtensionsMayNotClaimTheSameReservedBit) {
  HookLog log;
  log.rsv = GHTTP_WS_RSV3;
  GHTTP_WsServerOptions o = server_options();
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-a, x-b"), &o);
  EXPECT_EQ(log.seen.size(), 2u);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "x-foo; level=2");  // only the first
}

TEST(WsExtensionNegotiation, DeflateNeverReachesTheHookWhetherEnabledOrNot) {
  HookLog log;
  GHTTP_WsServerOptions o = server_options();
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Served off(plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate"), &o);
  EXPECT_TRUE(log.seen.empty());
  o.enable_deflate = 1;
  // A second offer, after the first is taken or declined, is skipped too.
  Served on(plus(rfc_fields(), "Sec-WebSocket-Extensions",
               "permessage-deflate, permessage-deflate; foo, PERMESSAGE-DEFLATE"), &o);
  EXPECT_TRUE(on.result.negotiated.deflate);
  EXPECT_TRUE(log.seen.empty());
  Served bad(plus(rfc_fields(), "Sec-WebSocket-Extensions", "permessage-deflate; foo, permessage-deflate"), &o);
  EXPECT_TRUE(bad.result.negotiated.deflate);
  EXPECT_TRUE(log.seen.empty());
}

TEST(WsExtensionNegotiation, AHookReplyThatIsNotOneExtensionIsAnErrorAndNeverReachesTheHeader) {
  for (const char * text : {"x-foo\r\nSet-Cookie: a=b", "x-foo, x-bar", ",x-foo", "permessage-deflate", "x-foo;", "x foo",
           "x-foo; a=\"b\r\n\"", "x-foo; a=b=c", ";x"}) {
    HookLog log;
    log.reply = text;
    GHTTP_WsServerOptions o = server_options();
    o.extension_fn = hook;
    o.extension_ctx = &log;
    Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-foo"), &o);
    EXPECT_EQ(s.rc, GHTTP_ERR_INVALID) << text;
  }
  // A reply that is one is sent as written.
  HookLog good;
  good.reply = "x-foo; level=\"2\"; z";
  GHTTP_WsServerOptions o = server_options();
  o.extension_fn = hook;
  o.extension_ctx = &good;
  Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-foo"), &o);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "x-foo; level=\"2\"; z");
}

TEST(WsExtensionNegotiation, AnExtensionOfferedTwiceIsChosenOnce) {
  HookLog log;
  GHTTP_WsServerOptions o = server_options();
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Served s(plus(rfc_fields(), "Sec-WebSocket-Extensions", "x-foo; a=1, X-Foo; a=2"), &o);
  EXPECT_EQ(s.header("Sec-WebSocket-Extensions"), "x-foo; level=2");
}

TEST(WsServerHandshake, TheOriginIsHandedOverParsedForTheCallersPolicy) {
  // The origin points into the request, which must outlive the use.
  auto origin_of = [](const Fields & f, bool * has) {
    Request req(f);
    GHTTP_Response * resp = nullptr;
    EXPECT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
    GHTTP_WsServerResult r;
    EXPECT_EQ(ghttp_ws_server_handshake(req.r, nullptr, resp, &r), GHTTP_OK);
    EXPECT_TRUE(r.accepted);
    *has = r.has_origin;
    std::string o = r.has_origin ? std::string(r.origin, r.origin_len) : std::string();
    if (!r.has_origin) {
      EXPECT_EQ(r.origin_len, 0u);
    }
    ghttp_response_destroy(resp);
    return o;
  };
  bool has = false;
  EXPECT_EQ(origin_of(rfc_fields(), &has), "http://example.com");
  EXPECT_TRUE(has);
  EXPECT_EQ(origin_of(with(rfc_fields(), "Origin", "  http://a.example  "), &has), "http://a.example");
  EXPECT_TRUE(has);
  EXPECT_EQ(origin_of(without(rfc_fields(), "Origin"), &has), "");
  EXPECT_FALSE(has);
}

TEST(WsServerHandshake, OptionsThatCannotWorkAreInvalid) {
  Request req(rfc_fields());
  GHTTP_Response * resp = nullptr;
  ASSERT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
  GHTTP_WsServerResult r;
  auto call = [&](const GHTTP_WsServerOptions & o) { return ghttp_ws_server_handshake(req.r, &o, resp, &r); };
  GHTTP_WsServerOptions o = server_options();
  o.subprotocol_count = 2;  // with no array
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  const char * with_null[] = {"chat", nullptr};
  o.subprotocols = with_null;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  const char * with_empty[] = {"chat", ""};
  o.subprotocols = with_empty;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  const char * with_space[] = {"chat", "a b"};
  o.subprotocols = with_space;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  o = server_options();
  o.deflate.server_max_window_bits = 7;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  o = server_options();
  o.deflate.client_max_window_bits = 16;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  l.max_handshake_bytes = 0;
  o = server_options();
  o.limits = &l;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  ghttp_ws_limits_default(&l);
  l.max_frame_payload = l.max_message_bytes + 1;
  EXPECT_EQ(call(o), GHTTP_ERR_INVALID);
  ghttp_response_destroy(resp);
}

// ---- The parameters on their own -------------------------------------------------

namespace {

std::vector<GHTTP_WsParam> params(std::initializer_list<std::pair<const char *, const char *>> l) {
  std::vector<GHTTP_WsParam> out;
  for (auto & e : l) {
    GHTTP_WsParam p;
    p.name = e.first;
    p.name_len = strlen(e.first);
    p.value = e.second;
    p.value_len = e.second ? strlen(e.second) : 0;
    p.has_value = e.second != nullptr;
    out.push_back(p);
  }
  return out;
}

} // namespace

TEST(WsDeflateParams, ServerNegotiationCombinesTheOfferWithThePolicy) {
  GHTTP_WsDeflateParams policy, agreed;
  ghttp_ws_deflate_params_default(&policy);
  int accepted;
  auto p = params({{"client_no_context_takeover", nullptr}, {"server_max_window_bits", "11"},
      {"client_max_window_bits", nullptr}});
  ASSERT_EQ(ghttp_ws_deflate_server_negotiate(p.data(), p.size(), &policy, &agreed, &accepted), GHTTP_OK);
  EXPECT_TRUE(accepted);
  EXPECT_TRUE(agreed.client_no_context_takeover);
  EXPECT_FALSE(agreed.server_no_context_takeover);
  EXPECT_EQ(agreed.server_max_window_bits, 11);
  EXPECT_EQ(agreed.client_max_window_bits, 0);
  policy.server_no_context_takeover = 1;
  policy.client_max_window_bits = 9;
  ASSERT_EQ(ghttp_ws_deflate_server_negotiate(p.data(), p.size(), &policy, &agreed, &accepted), GHTTP_OK);
  EXPECT_TRUE(agreed.server_no_context_takeover);
  EXPECT_EQ(agreed.client_max_window_bits, 9);
  // With no offer there is nothing to take from and nothing to refuse.
  ASSERT_EQ(ghttp_ws_deflate_server_negotiate(nullptr, 0, nullptr, &agreed, &accepted), GHTTP_OK);
  EXPECT_TRUE(accepted);
  EXPECT_EQ(agreed.server_max_window_bits, 0);
}

TEST(WsDeflateParams, ClientVerificationHoldsTheServerToTheOffer) {
  GHTTP_WsDeflateParams offered, agreed;
  ghttp_ws_deflate_params_default(&offered);
  int ok;
  // Nothing offered, nothing but the permitted answered.
  auto none = params({});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(none.data(), 0, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_TRUE(ok);
  auto snct = params({{"server_no_context_takeover", nullptr}});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(snct.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_TRUE(ok);  // a server may ask for it unprompted
  EXPECT_TRUE(agreed.server_no_context_takeover);
  auto cmwb = params({{"client_max_window_bits", "10"}});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(cmwb.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_FALSE(ok);  // not offered
  offered.offer_client_max_window_bits = 1;
  ASSERT_EQ(ghttp_ws_deflate_client_verify(cmwb.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_TRUE(ok);
  EXPECT_EQ(agreed.client_max_window_bits, 10);
  auto novalue = params({{"client_max_window_bits", nullptr}});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(novalue.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_FALSE(ok);  // only an offer may leave the value out
  // An offered server limit must be honoured, and may be tightened.
  offered.server_max_window_bits = 12;
  ASSERT_EQ(ghttp_ws_deflate_client_verify(none.data(), 0, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_FALSE(ok);
  auto smwb11 = params({{"server_max_window_bits", "11"}});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(smwb11.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_TRUE(ok);
  auto smwb13 = params({{"server_max_window_bits", "13"}});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(smwb13.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_FALSE(ok);
  offered.server_max_window_bits = 0;
  offered.server_no_context_takeover = 1;
  ASSERT_EQ(ghttp_ws_deflate_client_verify(none.data(), 0, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_FALSE(ok);
  auto unknown = params({{"foo", nullptr}});
  ASSERT_EQ(ghttp_ws_deflate_client_verify(unknown.data(), 1, &offered, &agreed, &ok), GHTTP_OK);
  EXPECT_FALSE(ok);
}

TEST(WsDeflateParams, TheTextOfAnOfferAndOfAResponseIsWhatTheRfcShows) {
  GHTTP_WsDeflateParams p;
  ghttp_ws_deflate_params_default(&p);
  char text[GHTTP_WS_DEFLATE_TEXT_MAX];
  size_t n;
  ASSERT_EQ(ghttp_ws_deflate_format(&p, 0, text, sizeof(text), &n), GHTTP_OK);
  EXPECT_STREQ(text, "permessage-deflate");
  EXPECT_EQ(n, strlen(text));
  p.offer_client_max_window_bits = 1;
  p.client_no_context_takeover = 1;
  p.server_no_context_takeover = 1;
  p.server_max_window_bits = 10;
  ASSERT_EQ(ghttp_ws_deflate_format(&p, 0, text, sizeof(text), nullptr), GHTTP_OK);
  EXPECT_STREQ(text, "permessage-deflate; client_no_context_takeover; server_no_context_takeover; server_max_window_bits=10; client_max_window_bits");
  p.client_max_window_bits = 15;
  ASSERT_EQ(ghttp_ws_deflate_format(&p, 1, text, sizeof(text), nullptr), GHTTP_OK);
  EXPECT_STREQ(text, "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=15");
  p.server_max_window_bits = 7;
  EXPECT_EQ(ghttp_ws_deflate_format(&p, 1, text, sizeof(text), nullptr), GHTTP_ERR_INVALID);
  p.server_max_window_bits = 8;
  char small[8];
  EXPECT_EQ(ghttp_ws_deflate_format(&p, 1, small, sizeof(small), nullptr), GHTTP_ERR_INVALID);
}

// ---- The client: sections 4.1 and 4.2.2 ----------------------------------------

namespace {

struct Client {
  GHTTP_Request * request = nullptr;
  GHTTP_WsClientHandshake * hs = nullptr;
  GHTTP_Result rc = GHTTP_OK;
  Client(GHTTP_WsClientOptions o, const GHTTP_Allocator * a = nullptr) {
    // The request is the caller's and has its own allocator: only the
    // handshake state is under test.
    EXPECT_EQ(ghttp_request_create(nullptr, &request), GHTTP_OK);
    rc = ghttp_ws_client_handshake_create(a, &o, request, &hs);
  }
  ~Client() {
    ghttp_ws_client_handshake_destroy(hs);
    ghttp_request_destroy(request);
  }
  std::string wire() const {
    GHTTP_Buffer * b = nullptr;
    EXPECT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
    EXPECT_EQ(ghttp_write_request_head(b, request), GHTTP_OK);
    std::string s(static_cast<const char *>(ghttp_buffer_data(b)), ghttp_buffer_size(b));
    ghttp_buffer_destroy(b);
    return s;
  }
};

const uint8_t NONCE[16] = {'t', 'h', 'e', ' ', 's', 'a', 'm', 'p', 'l', 'e', ' ', 'n', 'o', 'n', 'c', 'e'};

GHTTP_WsClientOptions client_options() {
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  o.host = "server.example.com";
  o.target = "/chat";
  o.nonce = NONCE;
  return o;
}

/** A response, as a server would send it. */
struct Resp {
  GHTTP_Response * r = nullptr;
  explicit Resp(const Fields & f, int status = 101) {
    EXPECT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
    EXPECT_EQ(ghttp_response_set_status(r, status, "x"), GHTTP_OK);
    for (auto & e : f) {
      EXPECT_EQ(ghttp_headers_add(ghttp_response_headers(r), e.first.c_str(), e.second.c_str()), GHTTP_OK);
    }
  }
  ~Resp() { ghttp_response_destroy(r); }
};

Fields good_response() {
  return {{"Upgrade", "websocket"}, {"Connection", "Upgrade"}, {"Sec-WebSocket-Accept", RFC_ACCEPT}};
}

GHTTP_WsClientResult finish(const Client & c, const Fields & f, int status = 101) {
  Resp r(f, status);
  GHTTP_WsClientResult out;
  EXPECT_EQ(ghttp_ws_client_handshake_finish(c.hs, r.r, &out), GHTTP_OK);
  return out;
}

} // namespace

TEST(WsClientHandshake, TheRequestIsTheRfcExampleWhenTheNonceIsTheRfcOne) {
  GHTTP_WsClientOptions o = client_options();
  const char * protos[] = {"chat", "superchat"};
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  o.origin = "http://example.com";
  Client c(o);
  ASSERT_EQ(c.rc, GHTTP_OK);
  EXPECT_EQ(c.wire(),
      "GET /chat HTTP/1.1\r\n"
      "Host: server.example.com\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "Origin: http://example.com\r\n"
      "Sec-WebSocket-Protocol: chat, superchat\r\n\r\n");
}

TEST(WsClientHandshake, WithoutANonceTheKeyIsFreshEveryTime) {
  GHTTP_WsClientOptions o = client_options();
  o.nonce = nullptr;
  Client a(o), b(o);
  ASSERT_EQ(a.rc, GHTTP_OK);
  std::string ka = field(ghttp_request_headers_const(a.request), "Sec-WebSocket-Key");
  std::string kb = field(ghttp_request_headers_const(b.request), "Sec-WebSocket-Key");
  EXPECT_TRUE(ghttp_ws_key_is_valid(ka.data(), ka.size()));
  EXPECT_TRUE(ghttp_ws_key_is_valid(kb.data(), kb.size()));
  EXPECT_NE(ka, kb);
}

TEST(WsClientHandshake, TheRequestOffersExtensionsAsAskedAndAHostIsRequired) {
  GHTTP_WsClientOptions o = client_options();
  o.enable_deflate = 1;
  o.deflate.offer_client_max_window_bits = 1;
  o.deflate.server_max_window_bits = 11;
  const char * ext[] = {"x-foo; a=1"};
  o.extensions = ext;
  o.extension_count = 1;
  Client c(o);
  ASSERT_EQ(c.rc, GHTTP_OK);
  EXPECT_EQ(field(ghttp_request_headers_const(c.request), "Sec-WebSocket-Extensions"),
      "permessage-deflate; server_max_window_bits=11; client_max_window_bits, x-foo; a=1");
  GHTTP_WsClientOptions nohost = client_options();
  nohost.host = nullptr;
  Client bad(nohost);
  EXPECT_EQ(bad.rc, GHTTP_ERR_INVALID);
  GHTTP_WsClientOptions badproto = client_options();
  const char * protos[] = {"not a token"};
  badproto.subprotocols = protos;
  badproto.subprotocol_count = 1;
  Client bad2(badproto);
  EXPECT_EQ(bad2.rc, GHTTP_ERR_INVALID);
}

TEST(WsClientHandshake, OptionsThatCannotWorkAreInvalid) {
  GHTTP_WsClientOptions o = client_options();
  const char * empty[] = {""};
  o.subprotocols = empty;
  o.subprotocol_count = 1;
  EXPECT_EQ(Client(o).rc, GHTTP_ERR_INVALID);
  const char * with_null[] = {nullptr};
  o.subprotocols = with_null;
  EXPECT_EQ(Client(o).rc, GHTTP_ERR_INVALID);
  o = client_options();
  o.deflate.client_max_window_bits = 7;
  EXPECT_EQ(Client(o).rc, GHTTP_ERR_INVALID);
  o = client_options();
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  l.max_extension_params = 0;
  o.limits = &l;
  EXPECT_EQ(Client(o).rc, GHTTP_ERR_INVALID);
}

TEST(WsClientHandshake, AServerNamingTheSameExtensionTwiceIsRefused) {
  HookLog log;
  GHTTP_WsClientOptions o = client_options();
  const char * ext[] = {"x-foo"};
  o.extensions = ext;
  o.extension_count = 1;
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Client c(o);
  EXPECT_TRUE(finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "x-foo")).accepted);
  GHTTP_WsClientResult r = finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "x-foo; a=1, X-Foo; a=2"));
  EXPECT_FALSE(r.accepted);
  EXPECT_STREQ(r.reason, "an extension was chosen twice");
}

TEST(WsClientHandshake, TheRfcResponseIsAcceptedAndNothingIsNegotiated) {
  Client c(client_options());
  GHTTP_WsClientResult r = finish(c, good_response());
  EXPECT_TRUE(r.accepted);
  EXPECT_STREQ(r.reason, "");
  EXPECT_FALSE(r.negotiated.deflate);
  EXPECT_STREQ(r.negotiated.subprotocol, "");
}

TEST(WsClientHandshake, EachWayAResponseCanBeWrongIsRefused) {
  Client c(client_options());
  struct Case { const char * name; Fields f; int status; };
  std::vector<Case> cases = {
      {"status 200", good_response(), 200},
      {"status 400", good_response(), 400},
      {"no Upgrade", without(good_response(), "Upgrade"), 101},
      {"Upgrade other", with(good_response(), "Upgrade", "h2c"), 101},
      {"no Connection", without(good_response(), "Connection"), 101},
      {"no accept", without(good_response(), "Sec-WebSocket-Accept"), 101},
      {"wrong accept", with(good_response(), "Sec-WebSocket-Accept", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="), 101},
      {"accept of another key", with(good_response(), "Sec-WebSocket-Accept", "HSmrc0sMlYUkAGmm5OPpG2HaGWk="), 101},
      {"two accepts", plus(good_response(), "Sec-WebSocket-Accept", RFC_ACCEPT), 101},
      {"subprotocol not offered", plus(good_response(), "Sec-WebSocket-Protocol", "chat"), 101},
      {"extension not offered", plus(good_response(), "Sec-WebSocket-Extensions", "permessage-deflate"), 101},
      {"extension malformed", plus(good_response(), "Sec-WebSocket-Extensions", "x;"), 101},
  };
  for (auto & k : cases) {
    GHTTP_WsClientResult r = finish(c, k.f, k.status);
    EXPECT_FALSE(r.accepted) << k.name;
    EXPECT_NE(std::string(r.reason), "") << k.name;
  }
}

TEST(WsClientHandshake, TheSubprotocolMustBeOneOfferedAndOnlyOne) {
  GHTTP_WsClientOptions o = client_options();
  const char * protos[] = {"chat", "superchat"};
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  Client c(o);
  GHTTP_WsClientResult ok = finish(c, plus(good_response(), "Sec-WebSocket-Protocol", "superchat"));
  EXPECT_TRUE(ok.accepted);
  EXPECT_STREQ(ok.negotiated.subprotocol, "superchat");
  EXPECT_FALSE(finish(c, plus(good_response(), "Sec-WebSocket-Protocol", "mqtt")).accepted);
  EXPECT_FALSE(finish(c, plus(good_response(), "Sec-WebSocket-Protocol", "chat, superchat")).accepted);
  EXPECT_FALSE(finish(c, plus(plus(good_response(), "Sec-WebSocket-Protocol", "chat"),
                   "Sec-WebSocket-Protocol", "chat")).accepted);
  EXPECT_TRUE(finish(c, good_response()).accepted);  // none chosen: allowed
}

TEST(WsClientHandshake, DeflateIsAgreedWhenTheResponseKeepsToTheOffer) {
  GHTTP_WsClientOptions o = client_options();
  o.enable_deflate = 1;
  o.deflate.offer_client_max_window_bits = 1;
  Client c(o);
  GHTTP_WsClientResult r = finish(c, plus(good_response(), "Sec-WebSocket-Extensions",
      "permessage-deflate; server_no_context_takeover; client_max_window_bits=12"));
  ASSERT_TRUE(r.accepted);
  EXPECT_TRUE(r.negotiated.deflate);
  EXPECT_TRUE(r.negotiated.deflate_params.server_no_context_takeover);
  EXPECT_EQ(r.negotiated.deflate_params.client_max_window_bits, 12);
  EXPECT_FALSE(finish(c, plus(good_response(), "Sec-WebSocket-Extensions",
                   "permessage-deflate; foo")).accepted);
  EXPECT_FALSE(finish(c, plus(good_response(), "Sec-WebSocket-Extensions",
                   "permessage-deflate, permessage-deflate")).accepted);
  EXPECT_TRUE(finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "permessage-deflate")).negotiated.deflate);
}

TEST(WsClientHandshake, AnOtherExtensionNeedsToHaveBeenOfferedAndTheHooksApproval) {
  HookLog log;
  log.rsv = GHTTP_WS_RSV3;
  GHTTP_WsClientOptions o = client_options();
  const char * ext[] = {"x-foo; a=1"};
  o.extensions = ext;
  o.extension_count = 1;
  o.extension_fn = hook;
  o.extension_ctx = &log;
  Client c(o);
  GHTTP_WsClientResult r = finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "X-Foo; a=1"));
  ASSERT_TRUE(r.accepted);
  EXPECT_EQ(r.negotiated.extension_rsv, GHTTP_WS_RSV3);
  EXPECT_EQ(log.seen, (std::vector<std::string>{"X-Foo;a=1 [response]"}));
  EXPECT_FALSE(finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "x-bar")).accepted);
  log.accept = false;
  EXPECT_FALSE(finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "x-foo")).accepted);
}

TEST(WsClientHandshake, ARefusedHandshakeLeavesNothingNegotiated) {
  GHTTP_WsClientOptions o = client_options();
  o.enable_deflate = 1;
  Client c(o);
  GHTTP_WsClientResult r = finish(c, plus(good_response(), "Sec-WebSocket-Extensions", "permessage-deflate; foo"));
  EXPECT_FALSE(r.accepted);
  EXPECT_FALSE(r.negotiated.deflate);
}

TEST(WsClientHandshake, AllocationFailureAtEachPointIsOomAndLeaksNothing) {
  GHTTP_WsClientOptions o = client_options();
  const char * protos[] = {"chat", "superchat"};
  o.subprotocols = protos;
  o.subprotocol_count = 2;
  const char * ext[] = {"x-foo"};
  o.extensions = ext;
  o.extension_count = 1;
  o.enable_deflate = 1;
  FailingAllocator counter(static_cast<size_t>(-1));
  { Client c(o, counter.get()); ASSERT_EQ(c.rc, GHTTP_OK); }
  EXPECT_EQ(counter.live(), 0u);
  size_t total = counter.requests();
  ASSERT_GT(total, 4u);
  size_t oom = 0;
  for (size_t run : {size_t(1), size_t(0)}) {
    for (size_t k = 0; k <= total; k++) {
      FailingAllocator fa(k, run);
      {
        Client c(o, fa.get());
        if (fa.failed()) {
          if (c.rc == GHTTP_ERR_OOM) oom++;
        } else {
          EXPECT_EQ(c.rc, GHTTP_OK) << k;
        }
        fa.stop_failing();
      }
      EXPECT_EQ(fa.live(), 0u) << k << " run " << run;
    }
  }
  EXPECT_GT(oom, 0u);
}

TEST(WsHandshake, AClientAndAServerAgreeOnSubprotocolAndExtensionsThroughTheirConnections) {
  GHTTP_WsClientOptions co = client_options();
  co.nonce = nullptr;
  const char * cprotos[] = {"chat", "superchat"};
  co.subprotocols = cprotos;
  co.subprotocol_count = 2;
  co.enable_deflate = 1;
  co.deflate.offer_client_max_window_bits = 1;
  Client c(co);
  ASSERT_EQ(c.rc, GHTTP_OK);
  GHTTP_WsServerOptions so = server_options();
  const char * sprotos[] = {"superchat"};
  so.subprotocols = sprotos;
  so.subprotocol_count = 1;
  so.enable_deflate = 1;
  so.deflate.client_max_window_bits = 12;
  so.deflate.server_no_context_takeover = 1;
  GHTTP_Response * resp = nullptr;
  ASSERT_EQ(ghttp_response_create(nullptr, &resp), GHTTP_OK);
  GHTTP_WsServerResult sr;
  ASSERT_EQ(ghttp_ws_server_handshake(c.request, &so, resp, &sr), GHTTP_OK);
  ASSERT_TRUE(sr.accepted);
  GHTTP_WsClientResult cr;
  ASSERT_EQ(ghttp_ws_client_handshake_finish(c.hs, resp, &cr), GHTTP_OK);
  ghttp_response_destroy(resp);
  ASSERT_TRUE(cr.accepted) << cr.reason;
  EXPECT_STREQ(cr.negotiated.subprotocol, "superchat");
  EXPECT_STREQ(sr.negotiated.subprotocol, "superchat");
  EXPECT_TRUE(cr.negotiated.deflate);
  EXPECT_EQ(cr.negotiated.deflate_params.client_max_window_bits, 12);
  EXPECT_TRUE(cr.negotiated.deflate_params.server_no_context_takeover);
  EXPECT_EQ(sr.negotiated.deflate_params.client_max_window_bits, 12);
  // The connections made from what was agreed carry messages both ways.
  WsPair pair(&cr.negotiated);
  ASSERT_EQ(ghttp_ws_conn_send_message(pair.client.get(), GHTTP_WS_MESSAGE_TEXT, "hello", 5), GHTTP_OK);
  pair.pump();
  ASSERT_EQ(pair.server_events.size(), 1u);
  EXPECT_EQ(pair.server_events[0].data, "hello");
  EXPECT_TRUE(pair.server_events[0].compressed);
}

TEST(WsHandshake, ClientDefaultsAreWhatTheHeaderSays) {
  GHTTP_WsClientOptions o;
  ghttp_ws_client_options_default(&o);
  EXPECT_EQ(o.size, sizeof(o));
  EXPECT_EQ(o.enable_deflate, 0);
  GHTTP_WsServerOptions s;
  ghttp_ws_server_options_default(&s);
  EXPECT_EQ(s.size, sizeof(s));
  EXPECT_EQ(s.enable_deflate, 0);
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  EXPECT_FALSE(n.deflate);
  EXPECT_STREQ(n.subprotocol, "");
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
