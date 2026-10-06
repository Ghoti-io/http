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
 * An ordered list of header fields, owned by the list.
 *
 * Used for a message's header section and for a chunked body's trailers. Names
 * keep the case they were given in; lookup ignores case. Order and duplicates
 * are kept, because a list of the same field name is a different message from
 * one comma-joined value (RFC 9110 section 5.3).
 */

#ifndef GHOTI_IO_GHTTP_HEADERS_H
#define GHOTI_IO_GHTTP_HEADERS_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief One header field as a view into a @ref GHTTP_Headers.
 *
 * Both strings are NUL-terminated copies owned by the list, with the length
 * alongside. The view is valid until the list is next modified or destroyed.
 */
typedef struct GHTTP_Field {
  const char * name;  ///< Field name, a token.
  size_t name_len;    ///< Length of the name, excluding the NUL.
  const char * value; ///< Field value, with surrounding whitespace removed.
  size_t value_len;   ///< Length of the value, excluding the NUL.
} GHTTP_Field;

/** @brief An ordered list of header fields. Opaque. */
typedef struct GHTTP_Headers GHTTP_Headers;

/** @brief What @ref ghttp_headers_find returns when there is no match. */
#define GHTTP_HEADERS_NPOS ((size_t)-1)

/**
 * @brief Create an empty list.
 *
 * @param allocator The allocator to use, or NULL for the default. It must
 *   outlive the list.
 * @param[out] out Receives the list, written only on success.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL @p out, GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_headers_create(
    const GHTTP_Allocator * allocator, GHTTP_Headers ** out);

/** @brief Free a list. NULL is ignored. */
GHTTP_API void ghttp_headers_destroy(GHTTP_Headers * headers);

/** @brief Remove every field, keeping the list's storage. */
GHTTP_API void ghttp_headers_clear(GHTTP_Headers * headers);

/**
 * @brief Append a field, copying both strings.
 *
 * The name must be a token (RFC 9110 section 5.6.2). The value may hold
 * visible characters, spaces, tabs and bytes of 0x80 and above, and is
 * stored without leading and trailing space or tab. A carriage return, a line
 * feed, a NUL or any other control character is refused, because a writer
 * that emitted one would let a caller smuggle a second field or a second
 * message through a value.
 *
 * @param headers The list.
 * @param name The field name, NUL-terminated.
 * @param value The field value, NUL-terminated.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL argument or a name or value
 *   that is not allowed, GHTTP_ERR_OOM. The list is unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_headers_add(
    GHTTP_Headers * headers, const char * name, const char * value);

/** @brief The number of fields. */
GHTTP_API size_t ghttp_headers_count(const GHTTP_Headers * headers);

/**
 * @brief Read the field at an index.
 *
 * @param headers The list.
 * @param index Position, from zero, in arrival order.
 * @param[out] out Receives the view, written only on success.
 * @return GHTTP_OK, or GHTTP_ERR_INVALID for a NULL argument or an index at
 *   or beyond the count.
 */
GHTTP_API GHTTP_Result ghttp_headers_at(
    const GHTTP_Headers * headers, size_t index, GHTTP_Field * out);

/**
 * @brief Find the first field at or after an index whose name matches.
 *
 * The comparison ignores ASCII case. To walk every field of one name, pass
 * the previous index plus one as @p from.
 *
 * @param headers The list.
 * @param name The field name, NUL-terminated.
 * @param from The first position to consider.
 * @return The index, or GHTTP_HEADERS_NPOS.
 */
GHTTP_API size_t ghttp_headers_find(
    const GHTTP_Headers * headers, const char * name, size_t from);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_HEADERS_H
