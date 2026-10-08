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
 * Character classes, growth, framing analysis and head validation, shared by
 * the parser and the writer.
 *
 * Reference: RFC 9110 section 5 (fields), RFC 9112 sections 3, 6.1 and 6.3.
 */

#include <ghoti.io/http/macros.h>
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

bool ghttp_is_tchar(unsigned char c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9')) {
    return true;
  }
  switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|':
    case '~':
      return true;
    default:
      return false;
  }
}

bool ghttp_is_token(const char * s, size_t n) {
  if (n == 0) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    if (!ghttp_is_tchar((unsigned char)s[i])) {
      return false;
    }
  }
  return true;
}

bool ghttp_is_protocol_name(const char * s, size_t n) {
  // RFC 9110 section 7.8: protocol = protocol-name ["/" protocol-version], each a token.
  const char * slash = n ? memchr(s, '/', n) : NULL;
  if (!slash) {
    return ghttp_is_token(s, n);
  }
  size_t first = (size_t)(slash - s);
  return ghttp_is_token(s, first) && ghttp_is_token(slash + 1, n - first - 1);
}

bool ghttp_is_field_text(const char * s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == ' ' || c == '\t' || (c >= 0x21 && c != 0x7f)) {
      continue;
    }
    return false;
  }
  return true;
}

bool ghttp_is_target_text(const char * s, size_t n) {
  if (n == 0) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x21 || c > 0x7e) {
      return false;
    }
  }
  return true;
}

void ghttp_trim_ows(const char ** s, size_t * n) {
  const char * p = *s;
  size_t len = *n;
  while (len > 0 && (*p == ' ' || *p == '\t')) {
    p++;
    len--;
  }
  while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
    len--;
  }
  *s = p;
  *n = len;
}

static unsigned char lower_ascii(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + ('a' - 'A')) : c;
}

bool ghttp_ieq(const char * s, size_t n, const char * lower_literal) {
  size_t i = 0;
  for (; i < n; i++) {
    if (lower_literal[i] == '\0'
        || lower_ascii((unsigned char)s[i])
            != (unsigned char)lower_literal[i]) {
      return false;
    }
  }
  return lower_literal[i] == '\0';
}

GHTTP_Result ghttp_reserve(const GHTTP_Allocator * allocator, void ** buf,
    size_t * cap, size_t need, size_t elem, size_t initial) {
  if (need <= *cap) {
    return GHTTP_OK;
  }
  size_t grown = *cap ? *cap : initial;
  while (grown < need) {
    if (grown > SIZE_MAX / 2) {
      grown = need;
      break;
    }
    grown *= 2;
  }
  if (elem != 0 && grown > SIZE_MAX / elem) {
    return GHTTP_ERR_OOM;
  }
  void * p = gcu_allocator_realloc(allocator, *buf, grown * elem);
  if (!p) {
    return GHTTP_ERR_OOM;
  }
  *buf = p;
  *cap = grown;
  return GHTTP_OK;
}

char * ghttp_strndup(
    const GHTTP_Allocator * allocator, const char * s, size_t n) {
  if (n == SIZE_MAX) {
    return NULL;
  }
  char * out = gcu_allocator_malloc(allocator, n + 1);
  if (!out) {
    return NULL;
  }
  if (n) {
    memcpy(out, s, n);
  }
  out[n] = '\0';
  return out;
}

// ---------------------------------------------------------------------------
// Framing (RFC 9112 section 6.1 and 6.3)
// ---------------------------------------------------------------------------

// Reads a Content-Length element: digits only, no sign, no whitespace inside.
// Sets *overflow instead of failing when the value does not fit in 64 bits,
// so that the caller can still see a Transfer-Encoding beside it: a message
// with both is a smuggling shape and is reported as one.
static bool parse_length(
    const char * s, size_t n, uint64_t * value, bool * overflow) {
  if (n == 0) {
    return false;
  }
  uint64_t v = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') {
      return false;
    }
    unsigned d = (unsigned)(s[i] - '0');
    if (v > (UINT64_MAX - d) / 10) {
      *overflow = true;
      v = 0;
      // Keep scanning: a later non-digit is still corruption.
      for (size_t j = i + 1; j < n; j++) {
        if (s[j] < '0' || s[j] > '9') {
          return false;
        }
      }
      *value = 0;
      return true;
    }
    v = v * 10 + d;
  }
  *value = v;
  return true;
}

GHTTP_Result ghttp_framing_from_headers(const GHTTP_Headers * headers,
    int minor, GHTTP_HeaderFraming * framing, uint64_t * length) {
  bool have_cl = false;
  bool overflow = false;
  uint64_t cl = 0;
  bool have_te = false;
  size_t te_elements = 0;
  size_t chunked_count = 0;
  bool last_is_chunked = false;

  size_t count = ghttp_headers_count(headers);
  for (size_t i = 0; i < count; i++) {
    GHTTP_Field f;
    if (ghttp_headers_at(headers, i, &f) != GHTTP_OK) {
      return GHTTP_ERR_INTERNAL;
    }
    bool is_cl = ghttp_ieq(f.name, f.name_len, "content-length");
    bool is_te = !is_cl && ghttp_ieq(f.name, f.name_len, "transfer-encoding");
    if (!is_cl && !is_te) {
      continue;
    }
    if (is_te) {
      have_te = true;
    }
    const char * p = f.value;
    size_t left = f.value_len;
    for (;;) {
      const char * comma = left ? memchr(p, ',', left) : NULL;
      size_t el = comma ? (size_t)(comma - p) : left;
      const char * es = p;
      size_t en = el;
      ghttp_trim_ows(&es, &en);
      if (is_cl) {
        // A Content-Length list has no empty elements: "5,,5" is not "5".
        uint64_t v = 0;
        if (!parse_length(es, en, &v, &overflow)) {
          return GHTTP_ERR_CORRUPT;
        }
        if (!overflow) {
          if (have_cl && v != cl) {
            return GHTTP_ERR_CORRUPT;
          }
          cl = v;
        }
        have_cl = true;
      } else if (en > 0) {
        // Empty elements of a list are ignored (RFC 9110 section 5.6.1.2).
        if (!ghttp_is_token(es, en)) {
          return GHTTP_ERR_CORRUPT;
        }
        if (last_is_chunked) {
          return GHTTP_ERR_CORRUPT; // chunked is not the final coding
        }
        te_elements++;
        if (ghttp_ieq(es, en, "chunked")) {
          chunked_count++;
          last_is_chunked = true;
        }
      }
      if (!comma) {
        break;
      }
      p = comma + 1;
      left -= el + 1;
    }
  }

  if (have_te && have_cl) {
    return GHTTP_ERR_CORRUPT;
  }
  if (have_te) {
    if (minor == 0 || te_elements == 0 || chunked_count != 1
        || !last_is_chunked) {
      return GHTTP_ERR_CORRUPT;
    }
    *framing = GHTTP_HF_CHUNKED;
    *length = 0;
    return GHTTP_OK;
  }
  if (have_cl) {
    if (overflow) {
      return GHTTP_ERR_LIMIT;
    }
    *framing = GHTTP_HF_LENGTH;
    *length = cl;
    return GHTTP_OK;
  }
  *framing = GHTTP_HF_NONE;
  *length = 0;
  return GHTTP_OK;
}

bool ghttp_headers_list_has(const GHTTP_Headers * headers, const char * name,
    const char * lower_token) {
  size_t i = 0;
  while ((i = ghttp_headers_find(headers, name, i)) != GHTTP_HEADERS_NPOS) {
    GHTTP_Field f;
    if (ghttp_headers_at(headers, i, &f) != GHTTP_OK) {
      return false;
    }
    const char * p = f.value;
    size_t left = f.value_len;
    for (;;) {
      const char * comma = left ? memchr(p, ',', left) : NULL;
      size_t el = comma ? (size_t)(comma - p) : left;
      const char * es = p;
      size_t en = el;
      ghttp_trim_ows(&es, &en);
      if (ghttp_ieq(es, en, lower_token)) {
        return true;
      }
      if (!comma) {
        break;
      }
      p = comma + 1;
      left -= el + 1;
    }
    i++;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Request target (RFC 9112 section 3.2)
// ---------------------------------------------------------------------------

static bool has_scheme_separator(const char * t) {
  if (!((t[0] >= 'a' && t[0] <= 'z') || (t[0] >= 'A' && t[0] <= 'Z'))) {
    return false;
  }
  size_t i = 1;
  while ((t[i] >= 'a' && t[i] <= 'z') || (t[i] >= 'A' && t[i] <= 'Z')
      || (t[i] >= '0' && t[i] <= '9') || t[i] == '+' || t[i] == '-'
      || t[i] == '.') {
    i++;
  }
  return t[i] == ':' && t[i + 1] == '/' && t[i + 2] == '/';
}

static bool is_authority(const char * t) {
  size_t n = strlen(t);
  if (n == 0) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    if (t[i] == '/' || t[i] == '?' || t[i] == '#' || t[i] == '@') {
      return false;
    }
  }
  // host ":" port; the port is the digits after the last colon.
  size_t colon = n;
  while (colon > 0 && t[colon - 1] != ':') {
    colon--;
  }
  if (colon == 0 || colon == n || colon == 1) {
    return false;
  }
  for (size_t i = colon; i < n; i++) {
    if (t[i] < '0' || t[i] > '9') {
      return false;
    }
  }
  return true;
}

GHTTP_Result ghttp_target_classify(
    const char * method, const char * target, GHTTP_TargetForm * form) {
  size_t n = strlen(target);
  if (!ghttp_is_target_text(target, n)) {
    return GHTTP_ERR_CORRUPT;
  }
  if (strcmp(method, "CONNECT") == 0) {
    if (!is_authority(target)) {
      return GHTTP_ERR_CORRUPT;
    }
    *form = GHTTP_TARGET_AUTHORITY;
    return GHTTP_OK;
  }
  if (strcmp(target, "*") == 0) {
    if (strcmp(method, "OPTIONS") != 0) {
      return GHTTP_ERR_CORRUPT;
    }
    *form = GHTTP_TARGET_ASTERISK;
    return GHTTP_OK;
  }
  if (target[0] == '/') {
    *form = GHTTP_TARGET_ORIGIN;
    return GHTTP_OK;
  }
  if (has_scheme_separator(target)) {
    *form = GHTTP_TARGET_ABSOLUTE;
    return GHTTP_OK;
  }
  return GHTTP_ERR_CORRUPT;
}

// ---------------------------------------------------------------------------
// Head validation
// ---------------------------------------------------------------------------

GHTTP_Result ghttp_request_validate(const GHTTP_Request * request) {
  const char * method = ghttp_request_method(request);
  if (!ghttp_is_token(method, strlen(method))) {
    return GHTTP_ERR_CORRUPT;
  }
  if (ghttp_request_protocol(request)) {
    return GHTTP_ERR_CORRUPT;  // a :protocol exists only in HTTP/2 (RFC 8441)
  }
  GHTTP_TargetForm form;
  GHTTP_Result r = ghttp_target_classify(
      method, ghttp_request_target(request), &form);
  if (r != GHTTP_OK) {
    return r;
  }
  int minor = ghttp_request_version(request);
  if (minor != 0 && minor != 1) {
    return GHTTP_ERR_CORRUPT;
  }
  const GHTTP_Headers * h = ghttp_request_headers_const(request);
  if (minor == 1) {
    // RFC 9112 section 3.2: a server MUST refuse an HTTP/1.1 request with no
    // Host or with more than one. Two Hosts is how two parties are made to
    // disagree about which origin a request was for.
    size_t first = ghttp_headers_find(h, "host", 0);
    if (first == GHTTP_HEADERS_NPOS
        || ghttp_headers_find(h, "host", first + 1) != GHTTP_HEADERS_NPOS) {
      return GHTTP_ERR_CORRUPT;
    }
  }
  GHTTP_HeaderFraming framing;
  uint64_t length;
  return ghttp_framing_from_headers(h, minor, &framing, &length);
}

GHTTP_Result ghttp_response_validate(const GHTTP_Response * response) {
  int status = ghttp_response_status(response);
  if (status < 100 || status > 999) {
    return GHTTP_ERR_CORRUPT;
  }
  int minor = ghttp_response_version(response);
  if (minor != 0 && minor != 1) {
    return GHTTP_ERR_CORRUPT;
  }
  const char * reason = ghttp_response_reason(response);
  if (!ghttp_is_field_text(reason, strlen(reason))) {
    return GHTTP_ERR_CORRUPT;
  }
  GHTTP_HeaderFraming framing;
  uint64_t length;
  return ghttp_framing_from_headers(
      ghttp_response_headers_const(response), minor, &framing, &length);
}

GHTTP_Result ghttp_trailers_validate(const GHTTP_Headers * trailers) {
  if (ghttp_headers_find(trailers, "content-length", 0) != GHTTP_HEADERS_NPOS
      || ghttp_headers_find(trailers, "transfer-encoding", 0)
          != GHTTP_HEADERS_NPOS) {
    return GHTTP_ERR_CORRUPT;
  }
  return GHTTP_OK;
}
