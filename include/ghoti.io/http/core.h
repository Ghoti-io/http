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
 * Core types, result codes, and limits for the Ghoti.io HTTP library.
 *
 * The library is a codec for HTTP/1.1 messages as specified by RFC 9112
 * (message syntax and framing) over RFC 9110 (semantics): bytes in, bytes
 * out. It never reads a socket, opens a file, reads a clock or starts a
 * thread.
 */

#ifndef GHOTI_IO_GHTTP_CORE_H
#define GHOTI_IO_GHTTP_CORE_H

#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result code for HTTP library operations.
 *
 * The suite's fixed vocabulary (CONVENTIONS.md section 5). `ERR_CORRUPT` is
 * a message that RFC 9112 forbids or that this library refuses rather than
 * guesses at (a smuggling shape, a bare LF, a malformed size line).
 * `ERR_UNSUPPORTED` is a well-formed message this library does not handle
 * (an HTTP version other than 1.0 and 1.1). `ERR_LIMIT` is a
 * @ref GHTTP_Limits field exceeded; the library never truncates instead.
 * `ERR_INVALID` is a wrong argument, including a value the writer would have
 * to emit as something the parser refuses. `ERR_FORMAT` is in the vocabulary
 * and never returned: a byte stream that is not HTTP at all is `ERR_CORRUPT`.
 * `ERR_IO` is returned only by the WebSocket codec, when the operating
 * system's random generator fails to supply a key (ws_handshake.h,
 * ws_conn.h); nothing here reads a file or a socket.
 */
typedef enum {
  GHTTP_OK = 0,          ///< Operation succeeded.
  GHTTP_ERR_IO,          ///< The OS random generator failed (WebSocket keys); no other I/O is done here.
  GHTTP_ERR_FORMAT,      ///< Not this format; never returned, see above.
  GHTTP_ERR_UNSUPPORTED, ///< Well-formed, but a feature not implemented.
  GHTTP_ERR_LIMIT,       ///< A GHTTP_Limits field was exceeded.
  GHTTP_ERR_CORRUPT,     ///< The bytes are wrong, or forbidden by RFC 9112.
  GHTTP_ERR_OOM,         ///< The allocator returned NULL.
  GHTTP_ERR_INVALID,     ///< Invalid argument.
  GHTTP_ERR_INTERNAL,    ///< Internal library error; a bug.
  GHTTP_RESULT_COUNT
} GHTTP_Result;

/**
 * @brief Convert a result code to a human-readable string.
 *
 * The returned string is statically allocated and must not be freed.
 *
 * @param result The result code.
 * @return A description of the result code, never NULL.
 */
GHTTP_API const char * ghttp_result_string(GHTTP_Result result);

/**
 * @brief Caps on every quantity a peer can make unbounded.
 *
 * Every field is a hard cap and a field set to zero allows none of its
 * quantity, so there is no "unlimited" and no value that means "default":
 * @ref ghttp_limits_default fills in the defaults and a caller that wants
 * more says so. Exceeding a cap is `GHTTP_ERR_LIMIT` at the same input byte
 * however the input is split; the parser never truncates.
 */
typedef struct GHTTP_Limits {
  /** Start line plus header lines plus the final empty line, in bytes. */
  size_t max_head_bytes;
  /**
   * One line, excluding its CRLF: the start line, a header line, a trailer
   * line, a chunk-size line with its extensions.
   */
  size_t max_line_length;
  /** Header fields in a message head (not counting the start line). */
  size_t max_header_count;
  /** Trailer section, in bytes, including its final empty line. */
  size_t max_trailer_bytes;
  /** Trailer fields. */
  size_t max_trailer_count;
  /** Body bytes in one message after any chunked framing is removed. */
  uint64_t max_body_bytes;
  /** The size one chunk declares. */
  uint64_t max_chunk_size;
} GHTTP_Limits;

/** Default for GHTTP_Limits::max_head_bytes. */
#define GHTTP_DEFAULT_MAX_HEAD_BYTES 65536u
/** Default for GHTTP_Limits::max_line_length. */
#define GHTTP_DEFAULT_MAX_LINE_LENGTH 8192u
/** Default for GHTTP_Limits::max_header_count. */
#define GHTTP_DEFAULT_MAX_HEADER_COUNT 100u
/** Default for GHTTP_Limits::max_trailer_bytes. */
#define GHTTP_DEFAULT_MAX_TRAILER_BYTES 8192u
/** Default for GHTTP_Limits::max_trailer_count. */
#define GHTTP_DEFAULT_MAX_TRAILER_COUNT 32u
/** Default for GHTTP_Limits::max_body_bytes: 16 MiB. */
#define GHTTP_DEFAULT_MAX_BODY_BYTES ((uint64_t)16 << 20)
/** Default for GHTTP_Limits::max_chunk_size: 16 MiB. */
#define GHTTP_DEFAULT_MAX_CHUNK_SIZE ((uint64_t)16 << 20)

/**
 * @brief Set every field of a caller-owned limits struct to its default.
 *
 * @param limits The struct to fill; NULL is ignored.
 */
GHTTP_API void ghttp_limits_default(GHTTP_Limits * limits);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_CORE_H
