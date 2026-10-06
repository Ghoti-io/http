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
 * A growable byte buffer that the writer appends to.
 */

#ifndef GHOTI_IO_GHTTP_BUFFER_H
#define GHOTI_IO_GHTTP_BUFFER_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief A growable byte buffer. Opaque. */
typedef struct GHTTP_Buffer GHTTP_Buffer;

/**
 * @brief Create an empty buffer.
 *
 * @param allocator The allocator to use, or NULL for the default.
 * @param[out] out Receives the buffer, written only on success.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL @p out, GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_buffer_create(
    const GHTTP_Allocator * allocator, GHTTP_Buffer ** out);

/** @brief Free a buffer. NULL is ignored. */
GHTTP_API void ghttp_buffer_destroy(GHTTP_Buffer * buffer);

/** @brief Drop the contents, keeping the storage. */
GHTTP_API void ghttp_buffer_clear(GHTTP_Buffer * buffer);

/**
 * @brief The bytes written so far.
 *
 * Valid until the buffer is next modified. Not NUL-terminated.
 */
GHTTP_API const void * ghttp_buffer_data(const GHTTP_Buffer * buffer);

/** @brief The number of bytes written so far. */
GHTTP_API size_t ghttp_buffer_size(const GHTTP_Buffer * buffer);

/**
 * @brief Append bytes, for a message body the caller frames itself.
 *
 * @param buffer The buffer.
 * @param data The bytes; may be NULL when @p len is zero.
 * @param len How many.
 * @return GHTTP_OK, GHTTP_ERR_INVALID, GHTTP_ERR_OOM. Unchanged on failure.
 */
GHTTP_API GHTTP_Result ghttp_buffer_append(
    GHTTP_Buffer * buffer, const void * data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_BUFFER_H
