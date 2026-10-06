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
 * The HTTP/1.1 writer: a head, chunks and a terminator as bytes.
 *
 * The writer refuses what the parser would refuse. A head whose method,
 * target, status, reason or fields the parser would reject, or whose framing
 * headers the parser would call ambiguous (both Content-Length and
 * Transfer-Encoding, differing Content-Lengths, a Transfer-Encoding that does
 * not end in chunked), fails with GHTTP_ERR_INVALID and writes nothing. It
 * does not add framing headers: the caller sets Content-Length or
 * Transfer-Encoding as it sees fit, and then appends the body with
 * @ref ghttp_buffer_append or @ref ghttp_write_chunk.
 */

#ifndef GHOTI_IO_GHTTP_WRITER_H
#define GHOTI_IO_GHTTP_WRITER_H

#include <ghoti.io/http/buffer.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Append a request head, ending with the empty line.
 *
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument or a head the
 *   parser would refuse (an HTTP/1.1 request needs exactly one Host field, a
 *   CONNECT target is an authority, "*" belongs to OPTIONS, and so on);
 *   GHTTP_ERR_OOM. The buffer is unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_write_request_head(
    GHTTP_Buffer * buffer, const GHTTP_Request * request);

/**
 * @brief Append a response head, ending with the empty line.
 *
 * @return GHTTP_OK, GHTTP_ERR_INVALID, GHTTP_ERR_OOM. The buffer is
 *   unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_write_response_head(
    GHTTP_Buffer * buffer, const GHTTP_Response * response);

/**
 * @brief Append one chunk of a chunked body.
 *
 * @param buffer The buffer.
 * @param data The chunk's bytes.
 * @param len How many; zero is GHTTP_ERR_INVALID, because a zero-size chunk
 *   would end the body - use @ref ghttp_write_chunked_end for that.
 * @return GHTTP_OK, GHTTP_ERR_INVALID, GHTTP_ERR_OOM. Unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_write_chunk(
    GHTTP_Buffer * buffer, const void * data, size_t len);

/**
 * @brief Append the last chunk, any trailer fields and the empty line.
 *
 * @param buffer The buffer.
 * @param trailers Trailer fields, or NULL for none. A Content-Length or
 *   Transfer-Encoding trailer is GHTTP_ERR_INVALID, as the parser refuses it.
 * @return GHTTP_OK, GHTTP_ERR_INVALID, GHTTP_ERR_OOM. Unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_write_chunked_end(
    GHTTP_Buffer * buffer, const GHTTP_Headers * trailers);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_WRITER_H
