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
 * What the HTTP/2 connection (h2conn.c) and the message layer (h2msg.c) share.
 *
 * The message layer is where RFC 9113 section 8 lives: pseudo-header fields,
 * field validity, connection-specific fields, and the mapping between a
 * decoded header list and the version-neutral GHTTP_Request, GHTTP_Response and
 * GHTTP_Headers. It knows nothing about frames or streams, so that a later
 * HTTP/3 connection (whose message rules are the same ones) can use it.
 */

#ifndef GHOTI_IO_GHTTP_SRC_HTTP_H2_INTERNAL_H
#define GHOTI_IO_GHTTP_SRC_HTTP_H2_INTERNAL_H

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** What reading a header section learned beyond the message it filled in. */
typedef struct GHTTP_H2MsgInfo {
  const char * scheme;     ///< The :scheme, into the list; NULL if absent.
  const char * authority;  ///< The :authority, likewise.
  bool connect;            ///< A CONNECT request.
  bool has_length;         ///< A Content-Length was present and valid.
  uint64_t length;
  int status;              ///< A response's :status.
} GHTTP_H2MsgInfo;

/**
 * Check a decoded request header list against RFC 9113 sections 8.2 and 8.3.1
 * and 8.5, and fill @p req and its headers. GHTTP_ERR_CORRUPT means the
 * request is malformed (section 8.1.1: a stream error); GHTTP_ERR_OOM.
 * @p req is cleared first. The list is not changed.
 */
GHTTP_Result ghttp_h2msg_read_request(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Request * req, GHTTP_H2MsgInfo * info);

/** The same for a response (sections 8.2 and 8.3.2). 101 is malformed. */
GHTTP_Result ghttp_h2msg_read_response(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Response * resp, GHTTP_H2MsgInfo * info);

/** The same for a trailer section: no pseudo-header fields, no framing fields. @p out is cleared first. */
GHTTP_Result ghttp_h2msg_read_trailers(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * list, GHTTP_Headers * out);

/**
 * Build the header list to send for a request: pseudo-header fields first,
 * then the fields in lower case. GHTTP_ERR_INVALID for what cannot be sent.
 * @p list is cleared first.
 */
GHTTP_Result ghttp_h2msg_build_request(const GHTTP_Allocator * alloc,
    const GHTTP_Request * request, const char * scheme, GHTTP_Headers * list,
    bool * connect);

GHTTP_Result ghttp_h2msg_build_response(const GHTTP_Allocator * alloc,
    const GHTTP_Response * response, GHTTP_Headers * list, int * status);

GHTTP_Result ghttp_h2msg_build_trailers(const GHTTP_Allocator * alloc,
    const GHTTP_Headers * trailers, GHTTP_Headers * list);

/** The measure of RFC 9113 section 6.5.2: name + value + 32 per field. */
size_t ghttp_h2msg_list_size(const GHTTP_Headers * list);

/** A response with this status has no content (RFC 9110 section 6.4.1): 1xx, 204, 304. */
bool ghttp_h2msg_status_has_no_content(int status);

#endif // GHOTI_IO_GHTTP_SRC_HTTP_H2_INTERNAL_H
