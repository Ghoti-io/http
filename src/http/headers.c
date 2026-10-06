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
 * The header field list.
 *
 * The text of every field lives in one NUL-separated blob and the fields are
 * offsets into it, not pointers, because the blob moves when it grows.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/headers.h>
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

typedef struct FieldRef {
  size_t name_off;
  size_t name_len;
  size_t value_off;
  size_t value_len;
} FieldRef;

struct GHTTP_Headers {
  const GHTTP_Allocator * allocator;
  char * blob;
  size_t blob_len;
  size_t blob_cap;
  FieldRef * refs;
  size_t count;
  size_t cap;
};

GHTTP_Result ghttp_headers_create(
    const GHTTP_Allocator * allocator, GHTTP_Headers ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_Headers * h = gcu_allocator_calloc(allocator, 1, sizeof(*h));
  if (!h) {
    return GHTTP_ERR_OOM;
  }
  h->allocator = allocator;
  *out = h;
  return GHTTP_OK;
}

void ghttp_headers_destroy(GHTTP_Headers * headers) {
  if (!headers) {
    return;
  }
  const GHTTP_Allocator * a = headers->allocator;
  gcu_allocator_free(a, headers->blob);
  gcu_allocator_free(a, headers->refs);
  gcu_allocator_free(a, headers);
}

void ghttp_headers_clear(GHTTP_Headers * headers) {
  if (headers) {
    headers->blob_len = 0;
    headers->count = 0;
  }
}

GHTTP_Result ghttp_headers_add_raw(GHTTP_Headers * h, const char * name,
    size_t name_len, const char * value, size_t value_len) {
  if (name_len > SIZE_MAX / 4 || value_len > SIZE_MAX / 4) {
    return GHTTP_ERR_OOM;
  }
  size_t add = name_len + value_len + 2;
  if (add > SIZE_MAX - h->blob_len) {
    return GHTTP_ERR_OOM;
  }
  // Both reserves first, so that a refusal on the second leaves the list as
  // it was: growing capacity changes nothing a reader can see.
  void * blob = h->blob;
  GHTTP_Result r = ghttp_reserve(
      h->allocator, &blob, &h->blob_cap, h->blob_len + add, 1, 256);
  h->blob = blob;
  if (r != GHTTP_OK) {
    return r;
  }
  void * refs = h->refs;
  r = ghttp_reserve(
      h->allocator, &refs, &h->cap, h->count + 1, sizeof(FieldRef), 8);
  h->refs = refs;
  if (r != GHTTP_OK) {
    return r;
  }
  FieldRef * ref = &h->refs[h->count];
  ref->name_off = h->blob_len;
  ref->name_len = name_len;
  memcpy(h->blob + h->blob_len, name, name_len);
  h->blob[h->blob_len + name_len] = '\0';
  ref->value_off = h->blob_len + name_len + 1;
  ref->value_len = value_len;
  memcpy(h->blob + ref->value_off, value, value_len);
  h->blob[ref->value_off + value_len] = '\0';
  h->blob_len += add;
  h->count++;
  return GHTTP_OK;
}

GHTTP_Result ghttp_headers_add(
    GHTTP_Headers * headers, const char * name, const char * value) {
  if (!headers || !name || !value) {
    return GHTTP_ERR_INVALID;
  }
  size_t nlen = strlen(name);
  size_t vlen = strlen(value);
  const char * v = value;
  ghttp_trim_ows(&v, &vlen);
  if (!ghttp_is_token(name, nlen) || !ghttp_is_field_text(v, vlen)) {
    return GHTTP_ERR_INVALID;
  }
  return ghttp_headers_add_raw(headers, name, nlen, v, vlen);
}

size_t ghttp_headers_count(const GHTTP_Headers * headers) {
  return headers ? headers->count : 0;
}

GHTTP_Result ghttp_headers_at(
    const GHTTP_Headers * headers, size_t index, GHTTP_Field * out) {
  if (!headers || !out || index >= headers->count) {
    return GHTTP_ERR_INVALID;
  }
  const FieldRef * ref = &headers->refs[index];
  out->name = headers->blob + ref->name_off;
  out->name_len = ref->name_len;
  out->value = headers->blob + ref->value_off;
  out->value_len = ref->value_len;
  return GHTTP_OK;
}

size_t ghttp_headers_find(
    const GHTTP_Headers * headers, const char * name, size_t from) {
  if (!headers || !name) {
    return GHTTP_HEADERS_NPOS;
  }
  for (size_t i = from; i < headers->count; i++) {
    const FieldRef * ref = &headers->refs[i];
    size_t n = strlen(name);
    if (n != ref->name_len) {
      continue;
    }
    const char * have = headers->blob + ref->name_off;
    size_t k = 0;
    for (; k < n; k++) {
      unsigned char a = (unsigned char)have[k];
      unsigned char b = (unsigned char)name[k];
      if (a >= 'A' && a <= 'Z') {
        a = (unsigned char)(a + ('a' - 'A'));
      }
      if (b >= 'A' && b <= 'Z') {
        b = (unsigned char)(b + ('a' - 'A'));
      }
      if (a != b) {
        break;
      }
    }
    if (k == n) {
      return i;
    }
  }
  return GHTTP_HEADERS_NPOS;
}
