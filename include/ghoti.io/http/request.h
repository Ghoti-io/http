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
 * An HTTP request head: method, target, version and header fields.
 *
 * The same object is what a caller builds to hand to the writer and what the
 * parser hands back, so a message written and parsed again can be compared
 * field for field.
 */

#ifndef GHOTI_IO_GHTTP_REQUEST_H
#define GHOTI_IO_GHTTP_REQUEST_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief A request head. Opaque. */
typedef struct GHTTP_Request GHTTP_Request;

/**
 * @brief The four forms of request target (RFC 9112 section 3.2).
 *
 * The target itself is kept verbatim. The form is the only interpretation
 * this library makes; percent-decoding, normalisation and routing belong to
 * the caller.
 */
typedef enum {
  GHTTP_TARGET_ORIGIN,    ///< "/path?query"
  GHTTP_TARGET_ABSOLUTE,  ///< "scheme://authority/path?query"
  GHTTP_TARGET_AUTHORITY, ///< "host:port", the target of CONNECT
  GHTTP_TARGET_ASTERISK   ///< "*", the target of server-wide OPTIONS
} GHTTP_TargetForm;

/**
 * @brief Create a request, initially "GET" and "/" at HTTP/1.1 with no fields.
 *
 * @param allocator The allocator to use, or NULL for the default.
 * @param[out] out Receives the request, written only on success.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL @p out, GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_request_create(
    const GHTTP_Allocator * allocator, GHTTP_Request ** out);

/** @brief Free a request. NULL is ignored. */
GHTTP_API void ghttp_request_destroy(GHTTP_Request * request);

/**
 * @brief Set the method, copying it.
 *
 * @return GHTTP_OK; GHTTP_ERR_INVALID for NULL or anything that is not a
 *   token; GHTTP_ERR_OOM. The request is unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_request_set_method(
    GHTTP_Request * request, const char * method);

/**
 * @brief Set the request target, copying it verbatim.
 *
 * A target is accepted if it is not empty and holds only visible ASCII
 * characters. Whether it is a valid target for the method (a CONNECT target
 * is an authority, "*" belongs to OPTIONS) is checked when the head is
 * written, because the method may be set after it.
 *
 * @return GHTTP_OK, GHTTP_ERR_INVALID, GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_request_set_target(
    GHTTP_Request * request, const char * target);

/**
 * @brief Set the HTTP minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
 *
 * @return GHTTP_OK, or GHTTP_ERR_INVALID for any other value.
 */
GHTTP_API GHTTP_Result ghttp_request_set_version(
    GHTTP_Request * request, int minor);

/** @brief The method, NUL-terminated, owned by the request. */
GHTTP_API const char * ghttp_request_method(const GHTTP_Request * request);

/** @brief The target as given, NUL-terminated, owned by the request. */
GHTTP_API const char * ghttp_request_target(const GHTTP_Request * request);

/** @brief The HTTP minor version, 0 or 1. */
GHTTP_API int ghttp_request_version(const GHTTP_Request * request);

/**
 * @brief The request's header fields, to read or to add to.
 *
 * Owned by the request and valid until it is destroyed.
 */
GHTTP_API GHTTP_Headers * ghttp_request_headers(GHTTP_Request * request);

/** @brief The same list, read-only. */
GHTTP_API const GHTTP_Headers * ghttp_request_headers_const(
    const GHTTP_Request * request);

/**
 * @brief Classify the target for the request's method.
 *
 * @param request The request.
 * @param[out] out Receives the form, written only on success.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument or a target that
 *   is not one of the four forms for this method.
 */
GHTTP_API GHTTP_Result ghttp_request_target_form(
    const GHTTP_Request * request, GHTTP_TargetForm * out);

/**
 * @brief Split an origin-form target at its first question mark.
 *
 * The pieces are views into the target and are not decoded. The query
 * excludes the question mark; a target without one has a NULL query of
 * length zero.
 *
 * @param request The request.
 * @param[out] path Receives the start of the path; may be NULL.
 * @param[out] path_len Receives its length; may be NULL.
 * @param[out] query Receives the start of the query or NULL; may be NULL.
 * @param[out] query_len Receives its length; may be NULL.
 * @return GHTTP_OK, or GHTTP_ERR_INVALID if the target is not origin-form.
 */
GHTTP_API GHTTP_Result ghttp_request_target_split(const GHTTP_Request * request,
    const char ** path, size_t * path_len, const char ** query,
    size_t * query_len);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_REQUEST_H
