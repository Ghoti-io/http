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
 * Declarations shared by the implementation files and never installed.
 *
 * What counts as a legal token, field value or target, how a header list
 * frames a body, and when a head is acceptable are each decided once here
 * and used by the parser and the writer alike, so the writer's head checks
 * (characters, framing headers, Host, target form) cannot drift from the
 * parser's. The writer does not apply limits or check body framing.
 */

#ifndef GHOTI_IO_GHTTP_SRC_HTTP_HTTP_INTERNAL_H
#define GHOTI_IO_GHTTP_SRC_HTTP_HTTP_INTERNAL_H

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/buffer.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** What the headers alone say about the body's length. */
typedef enum {
  GHTTP_HF_NONE,    ///< Neither Content-Length nor Transfer-Encoding.
  GHTTP_HF_LENGTH,  ///< Content-Length.
  GHTTP_HF_CHUNKED  ///< Transfer-Encoding ending in chunked.
} GHTTP_HeaderFraming;

/** A token character, RFC 9110 section 5.6.2. */
bool ghttp_is_tchar(unsigned char c);
/** A non-empty run of token characters. */
bool ghttp_is_token(const char * s, size_t n);
/** Visible characters, space, tab and bytes of 0x80 and above: no control. */
bool ghttp_is_field_text(const char * s, size_t n);
/** A non-empty run of visible ASCII: no space and no control. */
bool ghttp_is_target_text(const char * s, size_t n);
/** Strip leading and trailing space and tab. */
void ghttp_trim_ows(const char ** s, size_t * n);
/** Compare, ignoring ASCII case, with a lower-case NUL-terminated literal. */
bool ghttp_ieq(const char * s, size_t n, const char * lower_literal);

/**
 * Grow *buf to hold at least @p need elements of @p elem bytes, doubling.
 * Overflow of the byte count is GHTTP_ERR_OOM, as is a refused allocation;
 * *buf and *cap are unchanged on failure.
 */
GHTTP_Result ghttp_reserve(const GHTTP_Allocator * allocator, void ** buf,
    size_t * cap, size_t need, size_t elem, size_t initial);

/** Copy @p n bytes and a NUL; NULL on a refused allocation. */
char * ghttp_strndup(const GHTTP_Allocator * allocator, const char * s, size_t n);

/** Append a field without checking it; the callers have. */
GHTTP_Result ghttp_headers_add_raw(GHTTP_Headers * headers, const char * name,
    size_t name_len, const char * value, size_t value_len);

/** Replace the whole request line; unchanged on failure. */
GHTTP_Result ghttp_request_assign(GHTTP_Request * request, const char * method,
    size_t method_len, const char * target, size_t target_len, int minor);

/** Replace the status line; unchanged on failure. */
GHTTP_Result ghttp_response_assign(GHTTP_Response * response, int status,
    const char * reason, size_t reason_len, int minor);

/** Drop the byte count to @p size, undoing appends after a failure. */
void ghttp_buffer_truncate(GHTTP_Buffer * buffer, size_t size);

/** Remove @p n bytes starting at @p off (as many as there are), closing the gap. */
void ghttp_buffer_erase(GHTTP_Buffer * buffer, size_t off, size_t n);

/** Remove the first @p n bytes (all of them if n is larger). */
void ghttp_buffer_consume(GHTTP_Buffer * buffer, size_t n);

/**
 * What the headers say about the body: GHTTP_ERR_CORRUPT for a
 * Content-Length with a bad or differing value, a Transfer-Encoding whose
 * last coding is not chunked or that names chunked twice, both fields
 * together, or a Transfer-Encoding at all in an HTTP/1.0 message;
 * GHTTP_ERR_LIMIT for a Content-Length beyond 64 bits.
 */
GHTTP_Result ghttp_framing_from_headers(const GHTTP_Headers * headers,
    int minor, GHTTP_HeaderFraming * framing, uint64_t * length);

/** Whether a comma-separated field holds @p lower_token, ignoring case. */
bool ghttp_headers_list_has(
    const GHTTP_Headers * headers, const char * name, const char * lower_token);

/** Classify a request target for a method; GHTTP_ERR_CORRUPT if it is none. */
GHTTP_Result ghttp_target_classify(const char * method, const char * target,
    GHTTP_TargetForm * form);

/**
 * Whether a request head is one the parser accepts: a token method, a target
 * of a form its method allows, HTTP/1.0 or 1.1, exactly one Host in a 1.1
 * request, unambiguous framing.
 */
GHTTP_Result ghttp_request_validate(const GHTTP_Request * request);

/** The same for a response: status 100 to 999 and unambiguous framing. */
GHTTP_Result ghttp_response_validate(const GHTTP_Response * response);

/** Trailers may not carry framing: no Content-Length, no Transfer-Encoding. */
GHTTP_Result ghttp_trailers_validate(const GHTTP_Headers * trailers);

#endif // GHOTI_IO_GHTTP_SRC_HTTP_HTTP_INTERNAL_H
