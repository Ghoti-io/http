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
 * An HTTP response head: version, status, reason phrase and header fields.
 */

#ifndef GHOTI_IO_GHTTP_RESPONSE_H
#define GHOTI_IO_GHTTP_RESPONSE_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief A response head. Opaque. */
typedef struct GHTTP_Response GHTTP_Response;

/**
 * @brief Create a response, initially "200 OK" at HTTP/1.1 with no fields.
 *
 * @param allocator The allocator to use, or NULL for the default.
 * @param[out] out Receives the response, written only on success.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL @p out, GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_response_create(
    const GHTTP_Allocator * allocator, GHTTP_Response ** out);

/** @brief Free a response. NULL is ignored. */
GHTTP_API void ghttp_response_destroy(GHTTP_Response * response);

/**
 * @brief Set the status code and reason phrase, copying the phrase.
 *
 * @param response The response.
 * @param status A three-digit code, 100 to 999.
 * @param reason The reason phrase, which may be empty; NULL means empty.
 *   Control characters other than a tab are refused.
 * @return GHTTP_OK, GHTTP_ERR_INVALID, GHTTP_ERR_OOM. Unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_response_set_status(
    GHTTP_Response * response, int status, const char * reason);

/**
 * @brief Set the HTTP minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
 *
 * @return GHTTP_OK, or GHTTP_ERR_INVALID for any other value.
 */
GHTTP_API GHTTP_Result ghttp_response_set_version(
    GHTTP_Response * response, int minor);

/** @brief The status code. */
GHTTP_API int ghttp_response_status(const GHTTP_Response * response);

/** @brief The reason phrase, NUL-terminated, owned by the response. */
GHTTP_API const char * ghttp_response_reason(const GHTTP_Response * response);

/** @brief The HTTP minor version, 0 or 1. */
GHTTP_API int ghttp_response_version(const GHTTP_Response * response);

/** @brief The response's header fields, to read or to add to. */
GHTTP_API GHTTP_Headers * ghttp_response_headers(GHTTP_Response * response);

/** @brief The same list, read-only. */
GHTTP_API const GHTTP_Headers * ghttp_response_headers_const(
    const GHTTP_Response * response);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_RESPONSE_H
