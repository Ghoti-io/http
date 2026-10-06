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
 * HTTP/2 messages: pseudo-header fields, field validity and the mapping to the
 * version-neutral message types.
 *
 * Reference: RFC 9113 section 8 (and 7.6.1 of RFC 9110 for the
 * connection-specific fields).
 */

#include <ghoti.io/http/macros.h>
#include "h2_internal.h"
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

static bool is_lower_tchar(unsigned char c) {
  return ghttp_is_tchar(c) && !(c >= 'A' && c <= 'Z');
}

/** Section 8.2.1: no NUL, LF or CR, and no SP or HTAB at either end. */
static bool value_ok(const char * v, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (v[i] == '\0' || v[i] == '\n' || v[i] == '\r') {
      return false;
    }
  }
  if (n > 0 && (v[0] == ' ' || v[0] == '\t' || v[n - 1] == ' '
                   || v[n - 1] == '\t')) {
    return false;
  }
  return true;
}

/** Section 8.2.2 and RFC 9110 7.6.1. */
static bool is_connection_specific(const char * name, size_t n) {
  return ghttp_ieq(name, n, "connection") || ghttp_ieq(name, n, "proxy-connection")
      || ghttp_ieq(name, n, "keep-alive")
      || ghttp_ieq(name, n, "transfer-encoding") || ghttp_ieq(name, n, "upgrade");
}

static bool te_ok(const char * v, size_t n) {
  return n == 8 && ghttp_ieq(v, n, "trailers");
}

typedef enum { K_REQUEST, K_RESPONSE, K_TRAILERS } Kind;

typedef struct Pseudo {
  const char * method;
  size_t method_len;
  const char * scheme;
  size_t scheme_len;
  const char * authority;
  size_t authority_len;
  const char * path;
  size_t path_len;
  const char * status;
  size_t status_len;
  unsigned seen;  // bit per pseudo-header
} Pseudo;

enum { P_METHOD = 1, P_SCHEME = 2, P_AUTHORITY = 4, P_PATH = 8, P_STATUS = 16 };

/**
 * Walk the list once, applying every per-field rule, and collect the pseudo-
 * header fields. Malformed -> GHTTP_ERR_CORRUPT.
 */
static GHTTP_Result scan(const GHTTP_Headers * list, Kind kind, Pseudo * ps,
    size_t * regular_count) {
  memset(ps, 0, sizeof(*ps));
  bool seen_regular = false;
  size_t n = ghttp_headers_count(list);
  *regular_count = 0;
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    if (ghttp_headers_at(list, i, &f) != GHTTP_OK) {
      return GHTTP_ERR_INTERNAL;
    }
    if (f.name_len == 0 || !value_ok(f.value, f.value_len)) {
      return GHTTP_ERR_CORRUPT;
    }
    if (f.name[0] == ':') {
      if (seen_regular || kind == K_TRAILERS) {
        return GHTTP_ERR_CORRUPT;  // after a regular field; or in trailers
      }
      const char * nm = f.name + 1;
      size_t nl = f.name_len - 1;
      for (size_t k = 0; k < nl; k++) {
        if (!is_lower_tchar((unsigned char)nm[k])) {
          return GHTTP_ERR_CORRUPT;
        }
      }
      unsigned bit = 0;
      const char ** pp = NULL;
      size_t * pl = NULL;
      if (kind == K_REQUEST) {
        if (nl == 6 && memcmp(nm, "method", 6) == 0) {
          bit = P_METHOD; pp = &ps->method; pl = &ps->method_len;
        } else if (nl == 6 && memcmp(nm, "scheme", 6) == 0) {
          bit = P_SCHEME; pp = &ps->scheme; pl = &ps->scheme_len;
        } else if (nl == 9 && memcmp(nm, "authority", 9) == 0) {
          bit = P_AUTHORITY; pp = &ps->authority; pl = &ps->authority_len;
        } else if (nl == 4 && memcmp(nm, "path", 4) == 0) {
          bit = P_PATH; pp = &ps->path; pl = &ps->path_len;
        }
      } else if (nl == 6 && memcmp(nm, "status", 6) == 0) {
        bit = P_STATUS; pp = &ps->status; pl = &ps->status_len;
      }
      if (bit == 0 || (ps->seen & bit)) {
        return GHTTP_ERR_CORRUPT;  // undefined here, or repeated
      }
      ps->seen |= bit;
      *pp = f.value;
      *pl = f.value_len;
      continue;
    }
    seen_regular = true;
    (*regular_count)++;
    for (size_t k = 0; k < f.name_len; k++) {
      if (!is_lower_tchar((unsigned char)f.name[k])) {
        return GHTTP_ERR_CORRUPT;  // upper case, colon, space, control, 0x80+
      }
    }
    if (is_connection_specific(f.name, f.name_len)) {
      return GHTTP_ERR_CORRUPT;
    }
    if (ghttp_ieq(f.name, f.name_len, "te") && !te_ok(f.value, f.value_len)) {
      return GHTTP_ERR_CORRUPT;
    }
  }
  return GHTTP_OK;
}

/** Copy the regular fields, joining a split Cookie (section 8.2.3). */
static GHTTP_Result copy_regular(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Headers * out, bool prepend_host,
    const char * host, size_t host_len) {
  GHTTP_Result r = GHTTP_OK;
  if (prepend_host) {
    r = ghttp_headers_add_raw(out, "host", 4, host, host_len);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  size_t n = ghttp_headers_count(list);
  size_t first_cookie = GHTTP_HEADERS_NPOS;
  size_t cookies = 0;
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    ghttp_headers_at(list, i, &f);
    if (f.name[0] == ':') {
      continue;
    }
    if (f.name_len == 6 && memcmp(f.name, "cookie", 6) == 0) {
      cookies++;
      if (first_cookie == GHTTP_HEADERS_NPOS) {
        first_cookie = i;
      }
    }
  }
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    ghttp_headers_at(list, i, &f);
    if (f.name[0] == ':') {
      continue;
    }
    if (cookies > 1 && f.name_len == 6 && memcmp(f.name, "cookie", 6) == 0) {
      if (i != first_cookie) {
        continue;
      }
      // One field: "a=b; c=d" in the position of the first.
      GHTTP_Buffer * tmp;
      r = ghttp_buffer_create(alloc, &tmp);
      if (r != GHTTP_OK) {
        return r;
      }
      bool first = true;
      for (size_t j = i; j < n && r == GHTTP_OK; j++) {
        GHTTP_Field g;
        ghttp_headers_at(list, j, &g);
        if (g.name_len == 6 && memcmp(g.name, "cookie", 6) == 0) {
          if (!first) {
            r = ghttp_buffer_append(tmp, "; ", 2);
          }
          if (r == GHTTP_OK) {
            r = ghttp_buffer_append(tmp, g.value, g.value_len);
          }
          first = false;
        }
      }
      if (r == GHTTP_OK) {
        r = ghttp_headers_add_raw(
            out, "cookie", 6, ghttp_buffer_data(tmp), ghttp_buffer_size(tmp));
      }
      ghttp_buffer_destroy(tmp);
      if (r != GHTTP_OK) {
        return r;
      }
      continue;
    }
    r = ghttp_headers_add_raw(out, f.name, f.name_len, f.value, f.value_len);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  return GHTTP_OK;
}

static bool has_host(const GHTTP_Headers * list) {
  return ghttp_headers_find(list, "host", 0) != GHTTP_HEADERS_NPOS;
}

static void length_info(const GHTTP_Headers * h, GHTTP_H2MsgInfo * info,
    GHTTP_Result * r) {
  GHTTP_HeaderFraming fr;
  uint64_t len = 0;
  GHTTP_Result k = ghttp_framing_from_headers(h, 1, &fr, &len);
  if (k != GHTTP_OK) {
    *r = GHTTP_ERR_CORRUPT;  // a bad or conflicting Content-Length
    return;
  }
  info->has_length = fr == GHTTP_HF_LENGTH;
  info->length = len;
}

GHTTP_Result ghttp_h2msg_read_request(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Request * req, GHTTP_H2MsgInfo * info) {
  Pseudo ps;
  size_t regular;
  memset(info, 0, sizeof(*info));
  GHTTP_Result r = scan(list, K_REQUEST, &ps, &regular);
  if (r != GHTTP_OK) {
    return r;
  }
  if (!(ps.seen & P_METHOD) || !ghttp_is_token(ps.method, ps.method_len)) {
    return GHTTP_ERR_CORRUPT;
  }
  info->connect = ps.method_len == 7 && memcmp(ps.method, "CONNECT", 7) == 0;
  const char * target;
  size_t target_len;
  if (info->connect) {
    // Section 8.5: :scheme and :path omitted, :authority present.
    if ((ps.seen & (P_SCHEME | P_PATH)) || !(ps.seen & P_AUTHORITY)) {
      return GHTTP_ERR_CORRUPT;
    }
    target = ps.authority;
    target_len = ps.authority_len;
  } else {
    if ((ps.seen & (P_SCHEME | P_PATH)) != (P_SCHEME | P_PATH)) {
      return GHTTP_ERR_CORRUPT;
    }
    target = ps.path;
    target_len = ps.path_len;
  }
  if (!ghttp_is_target_text(target, target_len)) {
    return GHTTP_ERR_CORRUPT;  // empty, or a space or control character
  }
  if (!info->connect) {
    bool asterisk = target_len == 1 && target[0] == '*';
    bool is_options = ps.method_len == 7 && memcmp(ps.method, "OPTIONS", 7) == 0;
    if (!(target[0] == '/' || (asterisk && is_options))) {
      return GHTTP_ERR_CORRUPT;
    }
    if (ps.scheme_len == 0 || !ghttp_is_target_text(ps.scheme, ps.scheme_len)) {
      return GHTTP_ERR_CORRUPT;
    }
  }
  if (ps.seen & P_AUTHORITY) {
    if (!ghttp_is_target_text(ps.authority, ps.authority_len)) {
      return GHTTP_ERR_CORRUPT;
    }
    // No userinfo for http and https (section 8.3.1).
    bool web = (ps.seen & P_SCHEME)
        && ((ps.scheme_len == 4 && memcmp(ps.scheme, "http", 4) == 0)
            || (ps.scheme_len == 5 && memcmp(ps.scheme, "https", 5) == 0));
    if (web && memchr(ps.authority, '@', ps.authority_len)) {
      return GHTTP_ERR_CORRUPT;
    }
  }
  // The request line; the version is the semantic one (the message has none).
  r = ghttp_request_assign(req, ps.method, ps.method_len, target, target_len, 1);
  if (r != GHTTP_OK) {
    return r;
  }
  GHTTP_Headers * out = ghttp_request_headers(req);
  ghttp_headers_clear(out);
  bool host = (ps.seen & P_AUTHORITY) && !has_host(list);
  r = copy_regular(alloc, list, out, host, ps.authority, ps.authority_len);
  if (r != GHTTP_OK) {
    return r;
  }
  info->scheme = (ps.seen & P_SCHEME) ? ps.scheme : NULL;
  info->authority = (ps.seen & P_AUTHORITY) ? ps.authority : NULL;
  length_info(out, info, &r);
  return r;
}

GHTTP_Result ghttp_h2msg_read_response(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Response * resp, GHTTP_H2MsgInfo * info) {
  Pseudo ps;
  size_t regular;
  memset(info, 0, sizeof(*info));
  GHTTP_Result r = scan(list, K_RESPONSE, &ps, &regular);
  if (r != GHTTP_OK) {
    return r;
  }
  if (!(ps.seen & P_STATUS) || ps.status_len != 3) {
    return GHTTP_ERR_CORRUPT;
  }
  int status = 0;
  for (size_t i = 0; i < 3; i++) {
    if (ps.status[i] < '0' || ps.status[i] > '9') {
      return GHTTP_ERR_CORRUPT;
    }
    status = status * 10 + (ps.status[i] - '0');
  }
  if (status < 100 || status > 599 || status == 101) {
    return GHTTP_ERR_CORRUPT;  // section 8.6: 101 does not exist in HTTP/2
  }
  r = ghttp_response_assign(resp, status, "", 0, 1);
  if (r != GHTTP_OK) {
    return r;
  }
  GHTTP_Headers * out = ghttp_response_headers(resp);
  ghttp_headers_clear(out);
  r = copy_regular(alloc, list, out, false, NULL, 0);
  if (r != GHTTP_OK) {
    return r;
  }
  info->status = status;
  length_info(out, info, &r);
  return r;
}

GHTTP_Result ghttp_h2msg_read_trailers(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Headers * out) {
  Pseudo ps;
  size_t regular;
  GHTTP_Result r = scan(list, K_TRAILERS, &ps, &regular);
  if (r != GHTTP_OK) {
    return r;
  }
  ghttp_headers_clear(out);
  r = copy_regular(alloc, list, out, false, NULL, 0);
  if (r != GHTTP_OK) {
    return r;
  }
  return ghttp_trailers_validate(out) == GHTTP_OK ? GHTTP_OK : GHTTP_ERR_CORRUPT;
}

// ---------------------------------------------------------------------------
// Building what is sent
// ---------------------------------------------------------------------------

size_t ghttp_h2msg_list_size(const GHTTP_Headers * list) {
  size_t total = 0;
  size_t n = ghttp_headers_count(list);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    ghttp_headers_at(list, i, &f);
    total += f.name_len + f.value_len + 32;
  }
  return total;
}

bool ghttp_h2msg_status_has_no_content(int status) {
  return (status >= 100 && status < 200) || status == 204 || status == 304;
}

/** Add a field with a lower-cased name; GHTTP_ERR_INVALID for one HTTP/2 forbids. */
static GHTTP_Result add_lowered(const GHTTP_Allocator * alloc,
    GHTTP_Headers * list, const GHTTP_Field * f) {
  if (is_connection_specific(f->name, f->name_len)) {
    return GHTTP_ERR_INVALID;
  }
  if (ghttp_ieq(f->name, f->name_len, "te") && !te_ok(f->value, f->value_len)) {
    return GHTTP_ERR_INVALID;
  }
  char stack[96];
  char * name = stack;
  char * heap = NULL;
  if (f->name_len > sizeof(stack)) {
    heap = gcu_allocator_malloc(alloc, f->name_len);
    if (!heap) {
      return GHTTP_ERR_OOM;
    }
    name = heap;
  }
  for (size_t i = 0; i < f->name_len; i++) {
    char c = f->name[i];
    name[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
  }
  GHTTP_Result r =
      ghttp_headers_add_raw(list, name, f->name_len, f->value, f->value_len);
  gcu_allocator_free(alloc, heap);
  return r;
}

static GHTTP_Result add_pseudo(GHTTP_Headers * list, const char * name,
    const char * value, size_t value_len) {
  return ghttp_headers_add_raw(list, name, strlen(name), value, value_len);
}

GHTTP_Result ghttp_h2msg_build_request(const GHTTP_Allocator * alloc,
    const GHTTP_Request * request, const char * scheme, GHTTP_Headers * list,
    bool * connect) {
  if (!request || !list) {
    return GHTTP_ERR_INVALID;
  }
  const char * method = ghttp_request_method(request);
  const char * target = ghttp_request_target(request);
  GHTTP_TargetForm form;
  if (ghttp_request_target_form(request, &form) != GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  const GHTTP_Headers * h = ghttp_request_headers_const(request);
  bool is_connect = strcmp(method, "CONNECT") == 0;
  *connect = is_connect;
  ghttp_headers_clear(list);

  const char * authority = NULL;
  size_t authority_len = 0;
  const char * path = NULL;
  size_t path_len = 0;
  const char * sch = scheme ? scheme : "https";
  size_t sch_len = strlen(sch);
  size_t tlen = strlen(target);
  size_t host_idx = ghttp_headers_find(h, "host", 0);
  GHTTP_Field hf = {0};
  if (host_idx != GHTTP_HEADERS_NPOS) {
    ghttp_headers_at(h, host_idx, &hf);
  }
  switch (form) {
    case GHTTP_TARGET_ORIGIN:
      if (is_connect) {
        return GHTTP_ERR_INVALID;
      }
      path = target;
      path_len = tlen;
      break;
    case GHTTP_TARGET_ASTERISK:
      path = "*";
      path_len = 1;
      break;
    case GHTTP_TARGET_AUTHORITY:
      authority = target;
      authority_len = tlen;
      break;
    case GHTTP_TARGET_ABSOLUTE: {
      const char * sep = strstr(target, "://");
      if (!sep) {
        return GHTTP_ERR_INVALID;
      }
      sch = target;
      sch_len = (size_t)(sep - target);
      authority = sep + 3;
      const char * e = authority;
      while (*e && *e != '/' && *e != '?') {
        e++;
      }
      authority_len = (size_t)(e - authority);
      if (*e == '/') {
        path = e;
        path_len = strlen(e);
      } else {
        // "http://host" or "http://host?q": the path is "/" (section 8.3.1).
        static const char root[] = "/";
        if (*e == '?') {
          // Build "/?q" in the list itself below.
          path = NULL;
        } else {
          path = root;
          path_len = 1;
        }
      }
      if (authority_len == 0) {
        return GHTTP_ERR_INVALID;
      }
      if (is_connect) {
        return GHTTP_ERR_INVALID;
      }
      if (!path) {
        // "/" plus the query.
        size_t ql = strlen(e);
        char * q = gcu_allocator_malloc(alloc, ql + 1);
        if (!q) {
          return GHTTP_ERR_OOM;
        }
        q[0] = '/';
        memcpy(q + 1, e, ql);
        GHTTP_Result r0 = add_pseudo(list, ":method", method, strlen(method));
        if (r0 == GHTTP_OK) {
          r0 = add_pseudo(list, ":scheme", sch, sch_len);
        }
        if (r0 == GHTTP_OK) {
          r0 = add_pseudo(list, ":authority", authority, authority_len);
        }
        if (r0 == GHTTP_OK) {
          r0 = add_pseudo(list, ":path", q, ql + 1);
        }
        gcu_allocator_free(alloc, q);
        if (r0 != GHTTP_OK) {
          return r0;
        }
        goto fields;
      }
      break;
    }
  }
  if (!authority && host_idx != GHTTP_HEADERS_NPOS) {
    authority = hf.value;
    authority_len = hf.value_len;
  }
  GHTTP_Result r = add_pseudo(list, ":method", method, strlen(method));
  if (r == GHTTP_OK && !is_connect) {
    r = add_pseudo(list, ":scheme", sch, sch_len);
  }
  if (r == GHTTP_OK && authority) {
    r = add_pseudo(list, ":authority", authority, authority_len);
  }
  if (r == GHTTP_OK && !is_connect) {
    r = add_pseudo(list, ":path", path, path_len);
  }
  if (r != GHTTP_OK) {
    return r;
  }
fields:;
  size_t n = ghttp_headers_count(h);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    ghttp_headers_at(h, i, &f);
    if (i == host_idx) {
      continue;  // carried by :authority
    }
    GHTTP_Result r2 = add_lowered(alloc, list, &f);
    if (r2 != GHTTP_OK) {
      return r2;
    }
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2msg_build_response(const GHTTP_Allocator * alloc,
    const GHTTP_Response * response, GHTTP_Headers * list, int * status) {
  if (!response || !list) {
    return GHTTP_ERR_INVALID;
  }
  int code = ghttp_response_status(response);
  if (code < 100 || code > 599 || code == 101) {
    return GHTTP_ERR_INVALID;
  }
  *status = code;
  ghttp_headers_clear(list);
  char digits[3] = {(char)('0' + code / 100), (char)('0' + code / 10 % 10),
      (char)('0' + code % 10)};
  GHTTP_Result r = add_pseudo(list, ":status", digits, 3);
  const GHTTP_Headers * h = ghttp_response_headers_const(response);
  size_t n = ghttp_headers_count(h);
  for (size_t i = 0; r == GHTTP_OK && i < n; i++) {
    GHTTP_Field f;
    ghttp_headers_at(h, i, &f);
    r = add_lowered(alloc, list, &f);
  }
  return r;
}

GHTTP_Result ghttp_h2msg_build_trailers(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * trailers, GHTTP_Headers * list) {
  if (!trailers || !list) {
    return GHTTP_ERR_INVALID;
  }
  if (ghttp_trailers_validate(trailers) != GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  ghttp_headers_clear(list);
  size_t n = ghttp_headers_count(trailers);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    ghttp_headers_at(trailers, i, &f);
    GHTTP_Result r = add_lowered(alloc, list, &f);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  return GHTTP_OK;
}
