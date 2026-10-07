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
 * The growable output buffer.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/buffer.h>
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

struct GHTTP_Buffer {
  const GHTTP_Allocator * allocator;
  unsigned char * data;
  size_t len;
  size_t cap;
};

GHTTP_Result ghttp_buffer_create(
    const GHTTP_Allocator * allocator, GHTTP_Buffer ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_Buffer * b = gcu_allocator_calloc(allocator, 1, sizeof(*b));
  if (!b) {
    return GHTTP_ERR_OOM;
  }
  b->allocator = allocator;
  *out = b;
  return GHTTP_OK;
}

void ghttp_buffer_destroy(GHTTP_Buffer * buffer) {
  if (!buffer) {
    return;
  }
  gcu_allocator_free(buffer->allocator, buffer->data);
  gcu_allocator_free(buffer->allocator, buffer);
}

void ghttp_buffer_clear(GHTTP_Buffer * buffer) {
  if (buffer) {
    buffer->len = 0;
  }
}

const void * ghttp_buffer_data(const GHTTP_Buffer * buffer) {
  return buffer ? buffer->data : NULL;
}

size_t ghttp_buffer_size(const GHTTP_Buffer * buffer) {
  return buffer ? buffer->len : 0;
}

GHTTP_Result ghttp_buffer_append(
    GHTTP_Buffer * buffer, const void * data, size_t len) {
  if (!buffer || (!data && len > 0)) {
    return GHTTP_ERR_INVALID;
  }
  if (len == 0) {
    return GHTTP_OK;
  }
  if (len > SIZE_MAX - buffer->len) {
    return GHTTP_ERR_OOM;
  }
  void * p = buffer->data;
  GHTTP_Result r =
      ghttp_reserve(buffer->allocator, &p, &buffer->cap, buffer->len + len, 1, 256);
  buffer->data = p;
  if (r != GHTTP_OK) {
    return r;
  }
  memcpy(buffer->data + buffer->len, data, len);
  buffer->len += len;
  return GHTTP_OK;
}

void ghttp_buffer_truncate(GHTTP_Buffer * buffer, size_t size) {
  if (buffer && size <= buffer->len) {
    buffer->len = size;
  }
}

void ghttp_buffer_consume(GHTTP_Buffer * buffer, size_t n) {
  if (!buffer || n == 0) {
    return;
  }
  if (n >= buffer->len) {
    buffer->len = 0;
    return;
  }
  memmove(buffer->data, buffer->data + n, buffer->len - n);
  buffer->len -= n;
}

void ghttp_buffer_erase(GHTTP_Buffer * buffer, size_t off, size_t n) {
  if (!buffer || off >= buffer->len || n == 0) {
    return;
  }
  if (n > buffer->len - off) {
    n = buffer->len - off;
  }
  memmove(buffer->data + off, buffer->data + off + n, buffer->len - off - n);
  buffer->len -= n;
}
