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
 * The writer: heads, chunks and the terminator.
 *
 * Every head is checked by the same predicates the parser applies
 * (ghttp_request_validate and friends) before a byte is written, and a failure
 * part way through - an allocation - puts the buffer back where it was.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/writer.h>
#include "http_internal.h"
#include <string.h>

static GHTTP_Result put(GHTTP_Buffer * b, const char * s) {
  return ghttp_buffer_append(b, s, strlen(s));
}

static GHTTP_Result put_fields(GHTTP_Buffer * b, const GHTTP_Headers * h) {
  size_t count = ghttp_headers_count(h);
  for (size_t i = 0; i < count; i++) {
    GHTTP_Field f;
    GHTTP_Result r = ghttp_headers_at(h, i, &f);
    if (r != GHTTP_OK) {
      return r;
    }
    if ((r = ghttp_buffer_append(b, f.name, f.name_len)) != GHTTP_OK
        || (r = put(b, f.value_len ? ": " : ":")) != GHTTP_OK
        || (r = ghttp_buffer_append(b, f.value, f.value_len)) != GHTTP_OK
        || (r = put(b, "\r\n")) != GHTTP_OK) {
      return r;
    }
  }
  return GHTTP_OK;
}

// A refused head is the caller's fault, whatever the parser would have called
// it: GHTTP_ERR_INVALID, never CORRUPT or LIMIT, which describe input.
static GHTTP_Result as_argument_error(GHTTP_Result r) {
  return (r == GHTTP_OK || r == GHTTP_ERR_OOM) ? r : GHTTP_ERR_INVALID;
}

GHTTP_Result ghttp_write_request_head(
    GHTTP_Buffer * buffer, const GHTTP_Request * request) {
  if (!buffer || !request) {
    return GHTTP_ERR_INVALID;
  }
  GHTTP_Result r = as_argument_error(ghttp_request_validate(request));
  if (r != GHTTP_OK) {
    return r;
  }
  size_t mark = ghttp_buffer_size(buffer);
  if ((r = put(buffer, ghttp_request_method(request))) != GHTTP_OK
      || (r = put(buffer, " ")) != GHTTP_OK
      || (r = put(buffer, ghttp_request_target(request))) != GHTTP_OK
      || (r = put(buffer,
              ghttp_request_version(request) == 1 ? " HTTP/1.1\r\n"
                                                  : " HTTP/1.0\r\n"))
          != GHTTP_OK
      || (r = put_fields(buffer, ghttp_request_headers_const(request)))
          != GHTTP_OK
      || (r = put(buffer, "\r\n")) != GHTTP_OK) {
    ghttp_buffer_truncate(buffer, mark);
  }
  return r;
}

GHTTP_Result ghttp_write_response_head(
    GHTTP_Buffer * buffer, const GHTTP_Response * response) {
  if (!buffer || !response) {
    return GHTTP_ERR_INVALID;
  }
  GHTTP_Result r = as_argument_error(ghttp_response_validate(response));
  if (r != GHTTP_OK) {
    return r;
  }
  int status = ghttp_response_status(response);
  char code[8];
  code[0] = (char)('0' + status / 100);
  code[1] = (char)('0' + (status / 10) % 10);
  code[2] = (char)('0' + status % 10);
  code[3] = ' ';
  code[4] = '\0';
  size_t mark = ghttp_buffer_size(buffer);
  if ((r = put(buffer,
           ghttp_response_version(response) == 1 ? "HTTP/1.1 " : "HTTP/1.0 "))
          != GHTTP_OK
      || (r = put(buffer, code)) != GHTTP_OK
      || (r = put(buffer, ghttp_response_reason(response))) != GHTTP_OK
      || (r = put(buffer, "\r\n")) != GHTTP_OK
      || (r = put_fields(buffer, ghttp_response_headers_const(response)))
          != GHTTP_OK
      || (r = put(buffer, "\r\n")) != GHTTP_OK) {
    ghttp_buffer_truncate(buffer, mark);
  }
  return r;
}

GHTTP_Result ghttp_write_chunk(
    GHTTP_Buffer * buffer, const void * data, size_t len) {
  if (!buffer || !data || len == 0) {
    return GHTTP_ERR_INVALID;
  }
  char hex[2 * sizeof(size_t) + 3];
  size_t pos = sizeof(hex);
  hex[--pos] = '\0';
  hex[--pos] = '\n';
  hex[--pos] = '\r';
  size_t v = len;
  do {
    hex[--pos] = "0123456789abcdef"[v & 0xf];
    v >>= 4;
  } while (v);
  size_t mark = ghttp_buffer_size(buffer);
  GHTTP_Result r;
  if ((r = put(buffer, hex + pos)) != GHTTP_OK
      || (r = ghttp_buffer_append(buffer, data, len)) != GHTTP_OK
      || (r = put(buffer, "\r\n")) != GHTTP_OK) {
    ghttp_buffer_truncate(buffer, mark);
  }
  return r;
}

GHTTP_Result ghttp_write_chunked_end(
    GHTTP_Buffer * buffer, const GHTTP_Headers * trailers) {
  if (!buffer) {
    return GHTTP_ERR_INVALID;
  }
  if (trailers && ghttp_trailers_validate(trailers) != GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(buffer);
  GHTTP_Result r;
  if ((r = put(buffer, "0\r\n")) != GHTTP_OK
      || (trailers && (r = put_fields(buffer, trailers)) != GHTTP_OK)
      || (r = put(buffer, "\r\n")) != GHTTP_OK) {
    ghttp_buffer_truncate(buffer, mark);
  }
  return r;
}
