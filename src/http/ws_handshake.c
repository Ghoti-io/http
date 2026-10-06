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
 * The WebSocket opening handshake: key and accept values, subprotocol and
 * extension negotiation, the server's validation and response and the
 * client's request and check.
 *
 * Reference: RFC 6455 sections 1.3, 4 and 9.1; RFC 7692 for the
 * permessage-deflate parameters.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/ws_handshake.h>
#include "http_internal.h"
#include "ws_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/sha1.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Base64 and the key
// ---------------------------------------------------------------------------

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void ghttp_ws_base64_encode(const uint8_t * in, size_t n, char * out) {
  size_t o = 0;
  size_t i = 0;
  for (; i + 3 <= n; i += 3) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = B64[v & 63];
  }
  if (n - i == 1) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  } else if (n - i == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = '=';
  }
}

static int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

size_t ghttp_ws_base64_decode(
    const char * in, size_t len, uint8_t * out, size_t cap) {
  if (len % 4 != 0) {
    return (size_t)-1;
  }
  size_t o = 0;
  for (size_t i = 0; i < len; i += 4) {
    int a = b64_value(in[i]);
    int b = b64_value(in[i + 1]);
    bool last = i + 4 == len;
    bool pad2 = last && in[i + 2] == '=' && in[i + 3] == '=';
    bool pad1 = last && !pad2 && in[i + 3] == '=';
    int c = pad2 ? 0 : b64_value(in[i + 2]);
    int d = (pad2 || pad1) ? 0 : b64_value(in[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) {
      return (size_t)-1;
    }
    // The bits the padding leaves unused must be clear, so that each string
    // has one spelling.
    if ((pad2 && (b & 15) != 0) || (pad1 && (c & 3) != 0)) {
      return (size_t)-1;
    }
    size_t take = pad2 ? 1 : (pad1 ? 2 : 3);
    if (o + take > cap) {
      return (size_t)-1;
    }
    uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
    out[o++] = (uint8_t)(v >> 16);
    if (take > 1) {
      out[o++] = (uint8_t)(v >> 8);
    }
    if (take > 2) {
      out[o++] = (uint8_t)v;
    }
  }
  return o;
}

int ghttp_ws_key_is_valid(const char * key, size_t len) {
  if (!key || len != GHTTP_WS_KEY_LEN) {
    return 0;
  }
  uint8_t raw[18];
  return ghttp_ws_base64_decode(key, len, raw, sizeof(raw)) == 16;
}

GHTTP_Result ghttp_ws_accept_key(
    const char * key, size_t len, char accept[GHTTP_WS_ACCEPT_LEN + 1]) {
  if (!accept || !ghttp_ws_key_is_valid(key, len)) {
    return GHTTP_ERR_INVALID;
  }
  uint8_t in[GHTTP_WS_KEY_LEN + sizeof(GHTTP_WS_GUID) - 1];
  memcpy(in, key, len);
  memcpy(in + len, GHTTP_WS_GUID, sizeof(GHTTP_WS_GUID) - 1);
  unsigned char digest[GSEC_SHA1_DIGEST_LEN];
  if (gsec_sha1(in, sizeof(in), digest) != GSEC_OK) {
    return GHTTP_ERR_INTERNAL;
  }
  ghttp_ws_base64_encode(digest, sizeof(digest), accept);
  accept[GHTTP_WS_ACCEPT_LEN] = '\0';
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Extension and list syntax
// ---------------------------------------------------------------------------

static bool is_ows(char c) {
  return c == ' ' || c == '\t';
}

GHTTP_WsExtStatus ghttp_ws_ext_next(const char ** cursor, const char * end,
    size_t max_params, GHTTP_WsExtItem * item) {
  const char * p = *cursor;
  // Empty list elements are skipped (RFC 9110 section 5.6.1.2).
  while (p < end && (is_ows(*p) || *p == ',')) {
    p++;
  }
  if (p == end) {
    *cursor = p;
    return GHTTP_WS_EXT_END;
  }
  if (max_params > GHTTP_WS_HARD_MAX_PARAMS) {
    max_params = GHTTP_WS_HARD_MAX_PARAMS;
  }
  const char * name = p;
  while (p < end && ghttp_is_tchar((unsigned char)*p)) {
    p++;
  }
  if (p == name) {
    return GHTTP_WS_EXT_SYNTAX;
  }
  item->name = name;
  item->name_len = (size_t)(p - name);
  item->nparams = 0;
  for (;;) {
    while (p < end && is_ows(*p)) {
      p++;
    }
    if (p == end) {
      break;
    }
    if (*p == ',') {
      p++;
      break;
    }
    if (*p != ';') {
      return GHTTP_WS_EXT_SYNTAX;
    }
    p++;
    while (p < end && is_ows(*p)) {
      p++;
    }
    const char * pn = p;
    while (p < end && ghttp_is_tchar((unsigned char)*p)) {
      p++;
    }
    if (p == pn) {
      return GHTTP_WS_EXT_SYNTAX;
    }
    GHTTP_WsParam param;
    param.name = pn;
    param.name_len = (size_t)(p - pn);
    param.value = NULL;
    param.value_len = 0;
    param.has_value = 0;
    if (p < end && *p == '=') {
      p++;
      param.has_value = 1;
      if (p < end && *p == '"') {
        p++;
        const char * v = p;
        while (p < end && *p != '"') {
          unsigned char c = (unsigned char)*p;
          if ((c < 0x20 && c != '\t') || c == 0x7f) {
            return GHTTP_WS_EXT_SYNTAX;
          }
          if (c == '\\') {
            p++;
            if (p == end) {
              return GHTTP_WS_EXT_SYNTAX;
            }
          }
          p++;
        }
        if (p == end) {
          return GHTTP_WS_EXT_SYNTAX;
        }
        param.value = v;
        param.value_len = (size_t)(p - v);
        p++;
      } else {
        const char * v = p;
        while (p < end && ghttp_is_tchar((unsigned char)*p)) {
          p++;
        }
        if (p == v) {
          return GHTTP_WS_EXT_SYNTAX;
        }
        param.value = v;
        param.value_len = (size_t)(p - v);
      }
    }
    if (item->nparams >= max_params) {
      return GHTTP_WS_EXT_TOO_MANY;
    }
    item->params[item->nparams++] = param;
  }
  *cursor = p;
  return GHTTP_WS_EXT_ITEM;
}

/** Octets of every field's name and value: the measure of max_handshake_bytes. */
static size_t headers_size(const GHTTP_Headers * h) {
  size_t total = 0;
  size_t n = ghttp_headers_count(h);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    if (ghttp_headers_at(h, i, &f) == GHTTP_OK) {
      total += f.name_len + f.value_len;
    }
  }
  return total;
}

/** How many fields have this name. */
static size_t count_fields(const GHTTP_Headers * h, const char * name) {
  size_t n = 0;
  size_t i = 0;
  while ((i = ghttp_headers_find(h, name, i)) != GHTTP_HEADERS_NPOS) {
    n++;
    i++;
  }
  return n;
}

/** The value of the only field with this name; false if there are none or several. */
static bool single_field(const GHTTP_Headers * h, const char * name,
    const char ** value, size_t * len) {
  size_t i = ghttp_headers_find(h, name, 0);
  if (i == GHTTP_HEADERS_NPOS || count_fields(h, name) != 1) {
    return false;
  }
  GHTTP_Field f;
  if (ghttp_headers_at(h, i, &f) != GHTTP_OK) {
    return false;
  }
  *value = f.value;
  *len = f.value_len;
  return true;
}

/**
 * Read a field that is a list of tokens (Sec-WebSocket-Protocol), calling
 * @p fn for each. false if an element is not a token.
 */
typedef bool (*TokenFn)(void * ctx, const char * token, size_t len);

static bool each_token(const GHTTP_Headers * h, const char * name, TokenFn fn,
    void * ctx) {
  size_t i = 0;
  while ((i = ghttp_headers_find(h, name, i)) != GHTTP_HEADERS_NPOS) {
    GHTTP_Field f;
    if (ghttp_headers_at(h, i, &f) != GHTTP_OK) {
      return false;
    }
    const char * p = f.value;
    const char * end = f.value + f.value_len;
    while (p < end) {
      while (p < end && (is_ows(*p) || *p == ',')) {
        p++;
      }
      if (p == end) {
        break;
      }
      const char * t = p;
      while (p < end && ghttp_is_tchar((unsigned char)*p)) {
        p++;
      }
      if (p == t) {
        return false;
      }
      size_t tn = (size_t)(p - t);
      while (p < end && is_ows(*p)) {
        p++;
      }
      if (p < end && *p != ',') {
        return false;
      }
      if (!fn(ctx, t, tn)) {
        return false;
      }
    }
    i++;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

void ghttp_ws_negotiated_default(GHTTP_WsNegotiated * n) {
  if (!n) {
    return;
  }
  memset(n, 0, sizeof(*n));
  n->size = sizeof(*n);
  ghttp_ws_deflate_params_default(&n->deflate_params);
}

void ghttp_ws_server_options_default(GHTTP_WsServerOptions * o) {
  if (!o) {
    return;
  }
  memset(o, 0, sizeof(*o));
  o->size = sizeof(*o);
  ghttp_ws_deflate_params_default(&o->deflate);
}

void ghttp_ws_client_options_default(GHTTP_WsClientOptions * o) {
  if (!o) {
    return;
  }
  memset(o, 0, sizeof(*o));
  o->size = sizeof(*o);
  ghttp_ws_deflate_params_default(&o->deflate);
}

int ghttp_ws_is_upgrade_request(const GHTTP_Request * request) {
  if (!request) {
    return 0;
  }
  const GHTTP_Headers * h = ghttp_request_headers_const(request);
  return strcmp(ghttp_request_method(request), "GET") == 0
      && ghttp_headers_list_has(h, "upgrade", "websocket")
      && ghttp_headers_list_has(h, "connection", "upgrade");
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

static GHTTP_Result refuse(GHTTP_Response * response, GHTTP_WsServerResult * result,
    int status, const char * phrase, const char * reason) {
  GHTTP_Result r = ghttp_response_set_status(response, status, phrase);
  if (r == GHTTP_OK) {
    r = ghttp_response_set_version(response, 1);
  }
  GHTTP_Headers * h = ghttp_response_headers(response);
  ghttp_headers_clear(h);
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Connection", "close");
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Content-Length", "0");
  }
  if (r == GHTTP_OK && status == 426) {
    r = ghttp_headers_add(h, "Sec-WebSocket-Version", "13");
  }
  if (r == GHTTP_OK && status == 405) {
    r = ghttp_headers_add(h, "Allow", "GET");
  }
  if (r != GHTTP_OK) {
    return r;
  }
  result->accepted = 0;
  result->status = status;
  result->reason = reason;
  return GHTTP_OK;
}

typedef struct Offered {
  const char * names[64];
  size_t lens[64];
  size_t count;
  bool bad;       // a duplicate or an overflow
} Offered;

static bool collect_token(void * ctx, const char * t, size_t n) {
  Offered * o = ctx;
  for (size_t i = 0; i < o->count; i++) {
    if (o->lens[i] == n && memcmp(o->names[i], t, n) == 0) {
      o->bad = true;
      return false;  // RFC 6455 section 4.1: the list has no duplicates
    }
  }
  if (o->count >= sizeof(o->names) / sizeof(o->names[0])) {
    o->bad = true;
    return false;
  }
  o->names[o->count] = t;
  o->lens[o->count] = n;
  o->count++;
  return true;
}

/** Append @p text to @p out as one more element of a comma-separated list. */
static bool list_append(char * out, size_t cap, size_t * len, const char * text) {
  size_t n = strlen(text);
  size_t sep = *len ? 2 : 0;
  if (*len + sep + n + 1 > cap) {
    return false;
  }
  if (sep) {
    memcpy(out + *len, ", ", 2);
  }
  memcpy(out + *len + sep, text, n + 1);
  *len += sep + n;
  return true;
}

GHTTP_Result ghttp_ws_server_handshake(const GHTTP_Request * request,
    const GHTTP_WsServerOptions * options, GHTTP_Response * response,
    GHTTP_WsServerResult * result) {
  if (!request || !response || !result) {
    return GHTTP_ERR_INVALID;
  }
  memset(result, 0, sizeof(*result));
  result->size = sizeof(*result);
  result->reason = "";
  ghttp_ws_negotiated_default(&result->negotiated);
  GHTTP_WsServerOptions defaults;
  if (!options) {
    ghttp_ws_server_options_default(&defaults);
    options = &defaults;
  }
  GHTTP_WsLimits resolved;
  if (ghttp_ws_limits_resolve(options->limits, &resolved) != GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  const GHTTP_WsLimits * limits = &resolved;
  const GHTTP_Headers * h = ghttp_request_headers_const(request);

  if (headers_size(h) > limits->max_handshake_bytes) {
    return refuse(response, result, 431, "Request Header Fields Too Large",
        "the handshake is larger than the limit");
  }
  if (strcmp(ghttp_request_method(request), "GET") != 0) {
    return refuse(response, result, 405, "Method Not Allowed",
        "the method is not GET");
  }
  if (ghttp_request_version(request) != 1) {
    return refuse(response, result, 400, "Bad Request",
        "HTTP/1.1 or later is required");
  }
  if (!ghttp_headers_list_has(h, "upgrade", "websocket")) {
    return refuse(response, result, 400, "Bad Request",
        "no Upgrade: websocket");
  }
  if (!ghttp_headers_list_has(h, "connection", "upgrade")) {
    return refuse(response, result, 400, "Bad Request",
        "no Connection: Upgrade");
  }
  const char * v;
  size_t vn;
  if (!single_field(h, "sec-websocket-version", &v, &vn)) {
    return refuse(response, result, 400, "Bad Request",
        "Sec-WebSocket-Version is missing or repeated");
  }
  ghttp_trim_ows(&v, &vn);
  if (!(vn == 2 && memcmp(v, "13", 2) == 0)) {
    return refuse(response, result, 426, "Upgrade Required",
        "the version is not 13");
  }
  const char * key;
  size_t key_len;
  if (!single_field(h, "sec-websocket-key", &key, &key_len)
      || !ghttp_ws_key_is_valid(key, key_len)) {
    return refuse(response, result, 400, "Bad Request",
        "Sec-WebSocket-Key is missing, repeated or not sixteen octets of base64");
  }

  // Subprotocol: the first the server serves, in its own order, that the
  // client offered.
  Offered offered;
  memset(&offered, 0, sizeof(offered));
  if (!each_token(h, "sec-websocket-protocol", collect_token, &offered)) {
    return refuse(response, result, 400, "Bad Request",
        "Sec-WebSocket-Protocol is malformed, repeats a protocol or lists too many");
  }
  const char * chosen = NULL;
  for (size_t i = 0; i < options->subprotocol_count && !chosen; i++) {
    const char * want = options->subprotocols[i];
    size_t wn = want ? strlen(want) : 0;
    for (size_t k = 0; k < offered.count; k++) {
      if (offered.lens[k] == wn && memcmp(offered.names[k], want, wn) == 0) {
        chosen = want;
        break;
      }
    }
  }
  if (chosen && strlen(chosen) > GHTTP_WS_MAX_SUBPROTOCOL) {
    return GHTTP_ERR_INVALID;
  }

  // Extensions, in the client's order of preference.
  char ext_text[1024];
  size_t ext_len = 0;
  ext_text[0] = '\0';
  size_t offers = 0;
  size_t i = 0;
  while ((i = ghttp_headers_find(h, "sec-websocket-extensions", i)) != GHTTP_HEADERS_NPOS) {
    GHTTP_Field f;
    if (ghttp_headers_at(h, i, &f) != GHTTP_OK) {
      return GHTTP_ERR_INTERNAL;
    }
    i++;
    const char * cur = f.value;
    const char * end = f.value + f.value_len;
    for (;;) {
      GHTTP_WsExtItem item;
      GHTTP_WsExtStatus st = ghttp_ws_ext_next(&cur, end, limits->max_extension_params, &item);
      if (st == GHTTP_WS_EXT_END) {
        break;
      }
      if (st == GHTTP_WS_EXT_SYNTAX) {
        return refuse(response, result, 400, "Bad Request",
            "Sec-WebSocket-Extensions is malformed");
      }
      if (st == GHTTP_WS_EXT_TOO_MANY) {
        return refuse(response, result, 400, "Bad Request",
            "an extension offer has more parameters than the limit");
      }
      if (++offers > limits->max_extension_offers || offers > GHTTP_WS_HARD_MAX_OFFERS) {
        return refuse(response, result, 400, "Bad Request",
            "more extension offers than the limit");
      }
      if (options->enable_deflate && !result->negotiated.deflate
          && ghttp_ieq(item.name, item.name_len, GHTTP_WS_PERMESSAGE_DEFLATE)) {
        GHTTP_WsDeflateParams agreed;
        int accepted = 0;
        GHTTP_Result r = ghttp_ws_deflate_server_negotiate(item.params,
            item.nparams, &options->deflate, &agreed, &accepted);
        if (r != GHTTP_OK) {
          return r;
        }
        if (accepted) {
          char text[GHTTP_WS_DEFLATE_TEXT_MAX];
          r = ghttp_ws_deflate_format(&agreed, 1, text, sizeof(text), NULL);
          if (r != GHTTP_OK) {
            return r;
          }
          if (list_append(ext_text, sizeof(ext_text), &ext_len, text)) {
            result->negotiated.deflate = 1;
            result->negotiated.deflate_params = agreed;
          }
        }
        continue;
      }
      if (!options->extension_fn) {
        continue;  // an extension this server does not know is not accepted
      }
      GHTTP_WsExtensionOffer offer;
      memset(&offer, 0, sizeof(offer));
      offer.size = sizeof(offer);
      offer.name = item.name;
      offer.name_len = item.name_len;
      offer.params = item.params;
      offer.param_count = item.nparams;
      GHTTP_WsExtensionReply reply;
      memset(&reply, 0, sizeof(reply));
      reply.size = sizeof(reply);
      GHTTP_Result r = options->extension_fn(options->extension_ctx, &offer, &reply);
      if (r != GHTTP_OK) {
        return r;
      }
      reply.text[sizeof(reply.text) - 1] = '\0';
      uint8_t rsv = (uint8_t)(reply.rsv & (GHTTP_WS_RSV2 | GHTTP_WS_RSV3));
      // Two extensions may not use the same bit (RFC 6455 section 5.2).
      if (reply.accept && reply.text[0] != '\0'
          && (rsv & result->negotiated.extension_rsv) == 0
          && list_append(ext_text, sizeof(ext_text), &ext_len, reply.text)) {
        result->negotiated.extension_rsv |= rsv;
      }
    }
  }

  char accept[GHTTP_WS_ACCEPT_LEN + 1];
  GHTTP_Result r = ghttp_ws_accept_key(key, key_len, accept);
  if (r != GHTTP_OK) {
    return r;
  }
  r = ghttp_response_set_status(response, 101, "Switching Protocols");
  if (r == GHTTP_OK) {
    r = ghttp_response_set_version(response, 1);
  }
  GHTTP_Headers * rh = ghttp_response_headers(response);
  ghttp_headers_clear(rh);
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(rh, "Upgrade", "websocket");
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(rh, "Connection", "Upgrade");
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(rh, "Sec-WebSocket-Accept", accept);
  }
  if (r == GHTTP_OK && chosen) {
    r = ghttp_headers_add(rh, "Sec-WebSocket-Protocol", chosen);
  }
  if (r == GHTTP_OK && ext_len > 0) {
    r = ghttp_headers_add(rh, "Sec-WebSocket-Extensions", ext_text);
  }
  if (r != GHTTP_OK) {
    return r;
  }
  if (chosen) {
    memcpy(result->negotiated.subprotocol, chosen, strlen(chosen) + 1);
  }
  result->accepted = 1;
  result->status = 101;
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct GHTTP_WsClientHandshake {
  const GHTTP_Allocator * allocator;
  GHTTP_WsLimits limits;
  char accept[GHTTP_WS_ACCEPT_LEN + 1];
  bool offered_deflate;
  GHTTP_WsDeflateParams offered;
  char ** protocols;
  size_t nprotocols;
  char ** extensions;       // names of the other extensions offered
  size_t nextensions;
  GHTTP_WsExtensionFn extension_fn;
  void * extension_ctx;
};

void ghttp_ws_client_handshake_destroy(GHTTP_WsClientHandshake * hs) {
  if (!hs) {
    return;
  }
  for (size_t i = 0; i < hs->nprotocols; i++) {
    gcu_allocator_free(hs->allocator, hs->protocols[i]);
  }
  for (size_t i = 0; i < hs->nextensions; i++) {
    gcu_allocator_free(hs->allocator, hs->extensions[i]);
  }
  gcu_allocator_free(hs->allocator, hs->protocols);
  gcu_allocator_free(hs->allocator, hs->extensions);
  gcu_allocator_free(hs->allocator, hs);
}

/** The length of the name at the start of an extension as it is to be written, or 0 if it has none. */
static size_t extension_name_len(const char * text) {
  size_t n = 0;
  while (ghttp_is_tchar((unsigned char)text[n])) {
    n++;
  }
  return n;
}

GHTTP_Result ghttp_ws_client_handshake_create(const GHTTP_Allocator * allocator,
    const GHTTP_WsClientOptions * options, GHTTP_Request * request,
    GHTTP_WsClientHandshake ** out) {
  if (!options || !request || !out || !options->host) {
    return GHTTP_ERR_INVALID;
  }
  if ((options->subprotocol_count && !options->subprotocols)
      || (options->extension_count && !options->extensions)) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  for (size_t i = 0; i < options->subprotocol_count; i++) {
    const char * p = options->subprotocols[i];
    if (!p || !ghttp_is_token(p, strlen(p)) || strlen(p) > GHTTP_WS_MAX_SUBPROTOCOL) {
      return GHTTP_ERR_INVALID;
    }
  }
  for (size_t i = 0; i < options->extension_count; i++) {
    const char * e = options->extensions[i];
    if (!e || extension_name_len(e) == 0) {
      return GHTTP_ERR_INVALID;
    }
  }
  GHTTP_WsClientHandshake * hs = gcu_allocator_calloc(allocator, 1, sizeof(*hs));
  if (!hs) {
    return GHTTP_ERR_OOM;
  }
  hs->allocator = allocator;
  if (ghttp_ws_limits_resolve(options->limits, &hs->limits) != GHTTP_OK) {
    gcu_allocator_free(allocator, hs);
    return GHTTP_ERR_INVALID;
  }
  hs->offered_deflate = options->enable_deflate != 0;
  hs->offered = options->deflate;
  hs->extension_fn = options->extension_fn;
  hs->extension_ctx = options->extension_ctx;
  GHTTP_Result r = GHTTP_OK;

  uint8_t nonce[16];
  if (options->nonce) {
    memcpy(nonce, options->nonce, sizeof(nonce));
  } else if (gsec_random_bytes(nonce, sizeof(nonce), NULL) != GSEC_OK) {
    r = GHTTP_ERR_IO;
  }
  char key[GHTTP_WS_KEY_LEN + 1];
  if (r == GHTTP_OK) {
    ghttp_ws_base64_encode(nonce, sizeof(nonce), key);
    key[GHTTP_WS_KEY_LEN] = '\0';
    r = ghttp_ws_accept_key(key, GHTTP_WS_KEY_LEN, hs->accept);
  }

  // What the response is checked against: copies, because the options are the
  // caller's and may not outlive the call.
  if (r == GHTTP_OK && options->subprotocol_count) {
    hs->protocols = gcu_allocator_calloc(allocator, options->subprotocol_count, sizeof(char *));
    if (!hs->protocols) {
      r = GHTTP_ERR_OOM;
    }
    for (size_t i = 0; r == GHTTP_OK && i < options->subprotocol_count; i++) {
      hs->protocols[i] = ghttp_strndup(allocator, options->subprotocols[i],
          strlen(options->subprotocols[i]));
      if (!hs->protocols[i]) {
        r = GHTTP_ERR_OOM;
      } else {
        hs->nprotocols++;
      }
    }
  }
  if (r == GHTTP_OK && options->extension_count) {
    hs->extensions = gcu_allocator_calloc(allocator, options->extension_count, sizeof(char *));
    if (!hs->extensions) {
      r = GHTTP_ERR_OOM;
    }
    for (size_t i = 0; r == GHTTP_OK && i < options->extension_count; i++) {
      hs->extensions[i] = ghttp_strndup(allocator, options->extensions[i],
          extension_name_len(options->extensions[i]));
      if (!hs->extensions[i]) {
        r = GHTTP_ERR_OOM;
      } else {
        hs->nextensions++;
      }
    }
  }

  // The request.
  GHTTP_Headers * h = ghttp_request_headers(request);
  if (r == GHTTP_OK) {
    r = ghttp_request_set_method(request, "GET");
  }
  if (r == GHTTP_OK) {
    r = ghttp_request_set_target(request, options->target ? options->target : "/");
  }
  if (r == GHTTP_OK) {
    r = ghttp_request_set_version(request, 1);
  }
  ghttp_headers_clear(h);
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Host", options->host);
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Upgrade", "websocket");
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Connection", "Upgrade");
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Sec-WebSocket-Key", key);
  }
  if (r == GHTTP_OK) {
    r = ghttp_headers_add(h, "Sec-WebSocket-Version", "13");
  }
  if (r == GHTTP_OK && options->origin) {
    r = ghttp_headers_add(h, "Origin", options->origin);
  }
  if (r == GHTTP_OK && options->subprotocol_count) {
    size_t total = 0;
    for (size_t i = 0; i < options->subprotocol_count; i++) {
      total += strlen(options->subprotocols[i]) + 2;
    }
    char * list = gcu_allocator_malloc(allocator, total + 1);
    if (!list) {
      r = GHTTP_ERR_OOM;
    } else {
      size_t len = 0;
      list[0] = '\0';
      for (size_t i = 0; i < options->subprotocol_count; i++) {
        (void)list_append(list, total + 1, &len, options->subprotocols[i]);
      }
      r = ghttp_headers_add(h, "Sec-WebSocket-Protocol", list);
      gcu_allocator_free(allocator, list);
    }
  }
  if (r == GHTTP_OK && (options->enable_deflate || options->extension_count)) {
    size_t total = GHTTP_WS_DEFLATE_TEXT_MAX + 3;
    for (size_t i = 0; i < options->extension_count; i++) {
      total += strlen(options->extensions[i]) + 2;
    }
    char * list = gcu_allocator_malloc(allocator, total + 1);
    if (!list) {
      r = GHTTP_ERR_OOM;
    } else {
      size_t len = 0;
      list[0] = '\0';
      if (options->enable_deflate) {
        char text[GHTTP_WS_DEFLATE_TEXT_MAX];
        r = ghttp_ws_deflate_format(&options->deflate, 0, text, sizeof(text), NULL);
        if (r == GHTTP_OK) {
          (void)list_append(list, total + 1, &len, text);
        }
      }
      for (size_t i = 0; r == GHTTP_OK && i < options->extension_count; i++) {
        (void)list_append(list, total + 1, &len, options->extensions[i]);
      }
      if (r == GHTTP_OK) {
        r = ghttp_headers_add(h, "Sec-WebSocket-Extensions", list);
      }
      gcu_allocator_free(allocator, list);
    }
  }
  if (r == GHTTP_OK && headers_size(h) > hs->limits.max_handshake_bytes) {
    r = GHTTP_ERR_LIMIT;
  }
  if (r != GHTTP_OK) {
    ghttp_ws_client_handshake_destroy(hs);
    return r;
  }
  *out = hs;
  return GHTTP_OK;
}

static GHTTP_Result reject(GHTTP_WsClientResult * result, const char * reason) {
  result->accepted = 0;
  result->reason = reason;
  ghttp_ws_negotiated_default(&result->negotiated);
  return GHTTP_OK;
}

typedef struct ProtoCheck {
  size_t seen;
  const char * match;
  size_t match_len;
} ProtoCheck;

static bool check_protocol(void * ctx, const char * t, size_t n) {
  ProtoCheck * c = ctx;
  c->seen++;
  c->match = t;
  c->match_len = n;
  return true;
}

GHTTP_Result ghttp_ws_client_handshake_finish(const GHTTP_WsClientHandshake * hs,
    const GHTTP_Response * response, GHTTP_WsClientResult * result) {
  if (!hs || !response || !result) {
    return GHTTP_ERR_INVALID;
  }
  memset(result, 0, sizeof(*result));
  result->size = sizeof(*result);
  result->reason = "";
  ghttp_ws_negotiated_default(&result->negotiated);
  const GHTTP_Headers * h = ghttp_response_headers_const(response);

  if (ghttp_response_status(response) != 101) {
    return reject(result, "the status is not 101");
  }
  if (headers_size(h) > hs->limits.max_handshake_bytes) {
    return reject(result, "the handshake is larger than the limit");
  }
  if (!ghttp_headers_list_has(h, "upgrade", "websocket")) {
    return reject(result, "no Upgrade: websocket");
  }
  if (!ghttp_headers_list_has(h, "connection", "upgrade")) {
    return reject(result, "no Connection: Upgrade");
  }
  const char * acc;
  size_t acc_len;
  if (!single_field(h, "sec-websocket-accept", &acc, &acc_len)) {
    return reject(result, "Sec-WebSocket-Accept is missing or repeated");
  }
  ghttp_trim_ows(&acc, &acc_len);
  if (acc_len != GHTTP_WS_ACCEPT_LEN || memcmp(acc, hs->accept, acc_len) != 0) {
    return reject(result, "Sec-WebSocket-Accept is not the value for the key sent");
  }

  // Subprotocol: none, or exactly one that was offered.
  ProtoCheck pc = {0, NULL, 0};
  if (!each_token(h, "sec-websocket-protocol", check_protocol, &pc) || pc.seen > 1) {
    return reject(result, "Sec-WebSocket-Protocol is malformed or names more than one protocol");
  }
  if (pc.seen == 1) {
    bool found = false;
    for (size_t i = 0; i < hs->nprotocols; i++) {
      if (strlen(hs->protocols[i]) == pc.match_len
          && memcmp(hs->protocols[i], pc.match, pc.match_len) == 0) {
        found = true;
      }
    }
    if (!found) {
      return reject(result, "the subprotocol was not offered");
    }
    memcpy(result->negotiated.subprotocol, pc.match, pc.match_len);
    result->negotiated.subprotocol[pc.match_len] = '\0';
  }

  // Extensions: only ones that were offered, with parameters the offer allows.
  size_t i = 0;
  size_t chosen = 0;
  while ((i = ghttp_headers_find(h, "sec-websocket-extensions", i)) != GHTTP_HEADERS_NPOS) {
    GHTTP_Field f;
    if (ghttp_headers_at(h, i, &f) != GHTTP_OK) {
      return GHTTP_ERR_INTERNAL;
    }
    i++;
    const char * cur = f.value;
    const char * end = f.value + f.value_len;
    for (;;) {
      GHTTP_WsExtItem item;
      GHTTP_WsExtStatus st = ghttp_ws_ext_next(&cur, end, hs->limits.max_extension_params, &item);
      if (st == GHTTP_WS_EXT_END) {
        break;
      }
      if (st != GHTTP_WS_EXT_ITEM) {
        return reject(result, "Sec-WebSocket-Extensions is malformed");
      }
      if (++chosen > hs->limits.max_extension_offers || chosen > GHTTP_WS_HARD_MAX_OFFERS) {
        return reject(result, "more extensions than the limit");
      }
      if (hs->offered_deflate
          && ghttp_ieq(item.name, item.name_len, GHTTP_WS_PERMESSAGE_DEFLATE)) {
        if (result->negotiated.deflate) {
          return reject(result, "permessage-deflate was chosen twice");
        }
        GHTTP_WsDeflateParams agreed;
        int ok = 0;
        GHTTP_Result r = ghttp_ws_deflate_client_verify(item.params, item.nparams,
            &hs->offered, &agreed, &ok);
        if (r != GHTTP_OK) {
          return r;
        }
        if (!ok) {
          return reject(result, "the permessage-deflate parameters are not ones the offer allows");
        }
        result->negotiated.deflate = 1;
        result->negotiated.deflate_params = agreed;
        continue;
      }
      bool offered = false;
      for (size_t k = 0; k < hs->nextensions; k++) {
        if (ghttp_ieq(item.name, item.name_len, hs->extensions[k])) {
          offered = true;
        }
      }
      if (!offered || !hs->extension_fn) {
        return reject(result, "an extension was chosen that was not offered");
      }
      GHTTP_WsExtensionOffer offer;
      memset(&offer, 0, sizeof(offer));
      offer.size = sizeof(offer);
      offer.name = item.name;
      offer.name_len = item.name_len;
      offer.params = item.params;
      offer.param_count = item.nparams;
      offer.is_response = 1;
      GHTTP_WsExtensionReply reply;
      memset(&reply, 0, sizeof(reply));
      reply.size = sizeof(reply);
      GHTTP_Result r = hs->extension_fn(hs->extension_ctx, &offer, &reply);
      if (r != GHTTP_OK) {
        return r;
      }
      uint8_t rsv = (uint8_t)(reply.rsv & (GHTTP_WS_RSV2 | GHTTP_WS_RSV3));
      if (!reply.accept || (rsv & result->negotiated.extension_rsv) != 0) {
        return reject(result, "an extension's parameters were not acceptable");
      }
      result->negotiated.extension_rsv |= rsv;
    }
  }
  result->accepted = 1;
  return GHTTP_OK;
}
