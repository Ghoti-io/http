/**
 * @file
 *
 * libFuzzer harness for the WebSocket handshake: the request validator and
 * response builder, the client's response check, the extension field parser
 * and the permessage-deflate negotiation, driven by arbitrary field text.
 *
 * Byte 0 picks the server policy (enable deflate, its demands), byte 1 the
 * client's offer. The rest is "Name: value" lines, each a field of the request
 * and, as a second pass, of the response a client checks.
 *
 * The invariants: nothing crashes or leaks; a refusal has a status and a
 * reason and an acceptance the 101 with an accept value that matches the key; a
 * server and a client that make a structured offer and answer agree on what
 * was negotiated (the property the two negotiations are written to share).
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>

#include "fuzz_ws_common.h"
#include "../../src/http/ws_internal.h"

namespace {

void add_lines(GHTTP_Headers * h, const std::string & text) {
  size_t pos = 0;
  int count = 0;
  while (pos < text.size() && count < 24) {
    size_t eol = text.find('\n', pos);
    if (eol == std::string::npos) {
      eol = text.size();
    }
    std::string line = text.substr(pos, eol - pos);
    pos = eol + 1;
    size_t colon = line.find(':');
    if (colon == std::string::npos || colon == 0) {
      continue;
    }
    std::string name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);
    size_t b = value.find_first_not_of(" \t");
    value = b == std::string::npos ? "" : value.substr(b);
    // The header API refuses what a parser would; what it takes is what a handshake sees.
    if (ghttp_headers_add(h, name.c_str(), value.c_str()) == GHTTP_OK) {
      count++;
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  uint8_t policy = data[0];
  uint8_t offer = data[1];
  std::string text(reinterpret_cast<const char *>(data + 2), size - 2);

  // 1. The server on arbitrary fields, with the RFC's Upgrade fields added so that it gets past the first checks.
  GHTTP_Request * rq = nullptr;
  REQUIRE(ghttp_request_create(nullptr, &rq) == GHTTP_OK, "request");
  if (policy & 0x80) {
    ghttp_headers_add(ghttp_request_headers(rq), "Upgrade", "websocket");
    ghttp_headers_add(ghttp_request_headers(rq), "Connection", "Upgrade");
    ghttp_headers_add(ghttp_request_headers(rq), "Sec-WebSocket-Version", "13");
    ghttp_headers_add(ghttp_request_headers(rq), "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
  }
  add_lines(ghttp_request_headers(rq), text);
  GHTTP_WsServerOptions so;
  ghttp_ws_server_options_default(&so);
  so.enable_deflate = (policy & 1) != 0;
  so.deflate.server_no_context_takeover = (policy >> 1) & 1;
  so.deflate.client_no_context_takeover = (policy >> 2) & 1;
  so.deflate.server_max_window_bits = (policy & 8) ? static_cast<uint8_t>(8 + (policy >> 4) % 8) : 0;
  so.deflate.client_max_window_bits = (policy & 0x40) ? static_cast<uint8_t>(8 + (policy >> 4) % 8) : 0;
  const char * protos[] = {"chat", "superchat"};
  so.subprotocols = protos;
  so.subprotocol_count = 2;
  GHTTP_WsLimits limits;
  ghttp_ws_limits_default(&limits);
  if (offer & 0x80) {
    limits.max_extension_offers = 2;
    limits.max_extension_params = 2;
    limits.max_handshake_bytes = 200;
  }
  so.limits = &limits;
  GHTTP_Response * rs = nullptr;
  REQUIRE(ghttp_response_create(nullptr, &rs) == GHTTP_OK, "response");
  GHTTP_WsServerResult sr;
  GHTTP_Result r = ghttp_ws_server_handshake(rq, &so, rs, &sr);
  REQUIRE(r == GHTTP_OK, "the handshake returned something but OK with no hook");
  REQUIRE(sr.size == sizeof(sr), "result size");
  if (sr.accepted) {
    REQUIRE(sr.status == 101 && ghttp_response_status(rs) == 101, "accepted but not 101");
    size_t i = ghttp_headers_find(ghttp_request_headers_const(rq), "Sec-WebSocket-Key", 0);
    REQUIRE(i != GHTTP_HEADERS_NPOS, "accepted without a key");
    GHTTP_Field kf;
    ghttp_headers_at(ghttp_request_headers_const(rq), i, &kf);
    char accept[GHTTP_WS_ACCEPT_LEN + 1];
    REQUIRE(ghttp_ws_accept_key(kf.value, kf.value_len, accept) == GHTTP_OK, "accepted with a key that is not valid");
    size_t a = ghttp_headers_find(ghttp_response_headers_const(rs), "Sec-WebSocket-Accept", 0);
    REQUIRE(a != GHTTP_HEADERS_NPOS, "no accept value");
    GHTTP_Field af;
    ghttp_headers_at(ghttp_response_headers_const(rs), a, &af);
    REQUIRE(af.value_len == GHTTP_WS_ACCEPT_LEN && memcmp(af.value, accept, af.value_len) == 0, "the accept value is not the key's");
    if (sr.negotiated.deflate) {
      REQUIRE(so.enable_deflate, "deflate negotiated though not enabled");
      REQUIRE(ghttp_headers_find(ghttp_response_headers_const(rs), "Sec-WebSocket-Extensions", 0) != GHTTP_HEADERS_NPOS,
          "deflate negotiated and not said");
    }
  } else {
    REQUIRE(sr.status == 400 || sr.status == 405 || sr.status == 426 || sr.status == 431, "a refusal with a status the codec does not use");
    REQUIRE(sr.reason != nullptr && *sr.reason != '\0', "a refusal without a reason");
    REQUIRE(ghttp_response_status(rs) == sr.status, "response status and result differ");
  }

  // 2. The client's check of arbitrary response fields against its own offer.
  GHTTP_WsClientOptions co;
  ghttp_ws_client_options_default(&co);
  co.host = "h";
  co.enable_deflate = (offer & 1) != 0;
  co.deflate.client_no_context_takeover = (offer >> 1) & 1;
  co.deflate.server_no_context_takeover = (offer >> 2) & 1;
  co.deflate.offer_client_max_window_bits = (offer >> 3) & 1;
  co.deflate.server_max_window_bits = (offer & 0x10) ? static_cast<uint8_t>(8 + (offer >> 5) % 8) : 0;
  co.subprotocols = protos;
  co.subprotocol_count = 2;
  GHTTP_Request * crq = nullptr;
  REQUIRE(ghttp_request_create(nullptr, &crq) == GHTTP_OK, "request");
  GHTTP_WsClientHandshake * hs = nullptr;
  uint8_t nonce[16] = {'t', 'h', 'e', ' ', 's', 'a', 'm', 'p', 'l', 'e', ' ', 'n', 'o', 'n', 'c', 'e'};
  co.nonce = nonce;
  REQUIRE(ghttp_ws_client_handshake_create(nullptr, &co, crq, &hs) == GHTTP_OK, "client request");
  GHTTP_Response * resp = nullptr;
  REQUIRE(ghttp_response_create(nullptr, &resp) == GHTTP_OK, "response");
  ghttp_response_set_status(resp, (offer & 0x40) ? 200 : 101, "x");
  ghttp_headers_add(ghttp_response_headers(resp), "Upgrade", "websocket");
  ghttp_headers_add(ghttp_response_headers(resp), "Connection", "Upgrade");
  if (policy & 0x20) {
    ghttp_headers_add(ghttp_response_headers(resp), "Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  }
  add_lines(ghttp_response_headers(resp), text);
  GHTTP_WsClientResult cr;
  REQUIRE(ghttp_ws_client_handshake_finish(hs, resp, &cr) == GHTTP_OK, "finish");
  if (cr.accepted) {
    REQUIRE(ghttp_response_status(resp) == 101, "accepted a response that is not 101");
    if (cr.negotiated.deflate) {
      REQUIRE(co.enable_deflate, "deflate agreed though not offered");
    }
    if (cr.negotiated.subprotocol[0]) {
      REQUIRE(strcmp(cr.negotiated.subprotocol, "chat") == 0 || strcmp(cr.negotiated.subprotocol, "superchat") == 0,
          "a subprotocol that was not offered was accepted");
    }
  } else {
    REQUIRE(cr.reason != nullptr && *cr.reason != '\0', "a refusal without a reason");
  }

  // 3. The property: a structured offer, answered by the server, verifies at the client and both agree.
  {
    GHTTP_WsDeflateParams offered;
    ghttp_ws_deflate_params_default(&offered);
    offered.client_no_context_takeover = (offer >> 1) & 1;
    offered.server_no_context_takeover = (offer >> 2) & 1;
    offered.offer_client_max_window_bits = (offer >> 3) & 1;
    offered.server_max_window_bits = (offer & 0x10) ? static_cast<uint8_t>(8 + (offer >> 5) % 8) : 0;
    offered.client_max_window_bits = (policy & 0x20) ? static_cast<uint8_t>(8 + (offer >> 5) % 8) : 0;
    char otext[GHTTP_WS_DEFLATE_TEXT_MAX];
    REQUIRE(ghttp_ws_deflate_format(&offered, 0, otext, sizeof(otext), nullptr) == GHTTP_OK, "format an offer");
    GHTTP_WsExtItem item;
    const char * cur = otext;
    REQUIRE(ghttp_ws_ext_next(&cur, otext + strlen(otext), 16, &item) == GHTTP_WS_EXT_ITEM, "an offer the codec wrote does not parse");
    GHTTP_WsDeflateParams policy_params = so.deflate;
    GHTTP_WsDeflateParams agreed_server;
    int accepted = 0;
    REQUIRE(ghttp_ws_deflate_server_negotiate(item.params, item.nparams, &policy_params, &agreed_server, &accepted) == GHTTP_OK, "negotiate");
    REQUIRE(accepted, "a structured offer was declined");
    char rtext[GHTTP_WS_DEFLATE_TEXT_MAX];
    REQUIRE(ghttp_ws_deflate_format(&agreed_server, 1, rtext, sizeof(rtext), nullptr) == GHTTP_OK, "format a response");
    GHTTP_WsExtItem ritem;
    const char * rcur = rtext;
    REQUIRE(ghttp_ws_ext_next(&rcur, rtext + strlen(rtext), 16, &ritem) == GHTTP_WS_EXT_ITEM, "a response the codec wrote does not parse");
    GHTTP_WsDeflateParams agreed_client;
    int ok = 0;
    REQUIRE(ghttp_ws_deflate_client_verify(ritem.params, ritem.nparams, &offered, &agreed_client, &ok) == GHTTP_OK, "verify");
    REQUIRE(ok, "a client refused the answer to its own offer");
    REQUIRE(agreed_client.server_no_context_takeover == agreed_server.server_no_context_takeover
            && agreed_client.server_max_window_bits == agreed_server.server_max_window_bits,
        "the two ends disagree on what the server does");
    REQUIRE((agreed_client.client_no_context_takeover != 0) == (agreed_server.client_no_context_takeover != 0 || offered.client_no_context_takeover != 0),
        "the two ends disagree on what the client does");
  }

  ghttp_ws_client_handshake_destroy(hs);
  ghttp_request_destroy(crq);
  ghttp_response_destroy(resp);
  ghttp_response_destroy(rs);
  ghttp_request_destroy(rq);
  return 0;
}
