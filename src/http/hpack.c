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
 * HPACK: the dynamic table, the decoder and the encoder.
 *
 * Reference: RFC 7541. The decoder is a function of one whole block; nothing in
 * it depends on how the block reached the caller.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/hpack.h>
#include "hpack_internal.h"
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

// ---------------------------------------------------------------------------
// The dynamic table (RFC 7541 section 2.3.2, 4). Oldest entry first in the
// ring; HPACK index 62 is the newest.
// ---------------------------------------------------------------------------

typedef struct Entry {
  char * name;
  size_t name_len;
  char * value;
  size_t value_len;
} Entry;

typedef struct Table {
  const GHTTP_Allocator * allocator;
  Entry * ring;
  size_t cap;    // a power of two, or zero
  size_t start;  // ring index of the oldest entry
  size_t count;
  size_t size;   // section 4.1: sum of name + value + 32
  size_t max;
} Table;

#define ENTRY_OVERHEAD 32u

static Entry * table_at(const Table * t, size_t newest_first) {
  return &t->ring[(t->start + t->count - 1 - newest_first) & (t->cap - 1)];
}

static void entry_free(const GHTTP_Allocator * a, Entry * e) {
  gcu_allocator_free(a, e->name);
  gcu_allocator_free(a, e->value);
  e->name = NULL;
  e->value = NULL;
}

static void table_evict_one(Table * t) {
  Entry * e = &t->ring[t->start];
  t->size -= e->name_len + e->value_len + ENTRY_OVERHEAD;
  entry_free(t->allocator, e);
  t->start = (t->start + 1) & (t->cap - 1);
  t->count--;
}

static void table_shrink_to(Table * t, size_t limit) {
  while (t->count > 0 && t->size > limit) {
    table_evict_one(t);
  }
}

static void table_free(Table * t) {
  while (t->count > 0) {
    table_evict_one(t);
  }
  gcu_allocator_free(t->allocator, t->ring);
  t->ring = NULL;
  t->cap = 0;
}

/** Set the maximum and evict to fit (section 4.3). */
static void table_set_max(Table * t, size_t max) {
  t->max = max;
  table_shrink_to(t, max);
}

static GHTTP_Result table_grow(Table * t) {
  size_t ncap = t->cap ? t->cap * 2 : 16;
  Entry * n = gcu_allocator_calloc(t->allocator, ncap, sizeof(Entry));
  if (!n) {
    return GHTTP_ERR_OOM;
  }
  for (size_t i = 0; i < t->count; i++) {
    n[i] = t->ring[(t->start + i) & (t->cap - 1)];
  }
  gcu_allocator_free(t->allocator, t->ring);
  t->ring = n;
  t->cap = ncap;
  t->start = 0;
  return GHTTP_OK;
}

/**
 * Add an entry (section 4.4). The strings are copied before anything is
 * evicted, because the arguments may point into the entry that eviction frees
 * (a literal whose name is an index into this table).
 */
static GHTTP_Result table_add(Table * t, const char * name, size_t name_len,
    const char * value, size_t value_len) {
  size_t esize = name_len + value_len + ENTRY_OVERHEAD;
  if (esize > t->max) {
    // Too big for the table: the table is emptied and nothing is added.
    table_shrink_to(t, 0);
    return GHTTP_OK;
  }
  char * n = ghttp_strndup(t->allocator, name, name_len);
  char * v = ghttp_strndup(t->allocator, value, value_len);
  if (!n || !v) {
    gcu_allocator_free(t->allocator, n);
    gcu_allocator_free(t->allocator, v);
    return GHTTP_ERR_OOM;
  }
  table_shrink_to(t, t->max - esize);
  if (t->count == t->cap) {
    GHTTP_Result r = table_grow(t);
    if (r != GHTTP_OK) {
      gcu_allocator_free(t->allocator, n);
      gcu_allocator_free(t->allocator, v);
      return r;
    }
  }
  Entry * e = &t->ring[(t->start + t->count) & (t->cap - 1)];
  e->name = n;
  e->name_len = name_len;
  e->value = v;
  e->value_len = value_len;
  t->count++;
  t->size += esize;
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

void ghttp_hpack_limits_default(GHTTP_HpackLimits * limits) {
  if (!limits) {
    return;
  }
  memset(limits, 0, sizeof(*limits));
  limits->size = sizeof(*limits);
  limits->max_table_size = GHTTP_HPACK_DEFAULT_MAX_TABLE_SIZE;
  limits->max_header_list_bytes = GHTTP_HPACK_DEFAULT_MAX_HEADER_LIST_BYTES;
  limits->max_field_bytes = GHTTP_HPACK_DEFAULT_MAX_FIELD_BYTES;
  limits->max_header_count = GHTTP_HPACK_DEFAULT_MAX_HEADER_COUNT;
}

static void limits_copy(GHTTP_HpackLimits * dst, const GHTTP_HpackLimits * src) {
  if (!src) {
    ghttp_hpack_limits_default(dst);
    return;
  }
  // A caller built against an older, shorter struct: the members it does not
  // have take their defaults.
  ghttp_hpack_limits_default(dst);
  size_t n = src->size < sizeof(*dst) && src->size > 0 ? src->size : sizeof(*dst);
  memcpy(dst, src, n);
  dst->size = sizeof(*dst);
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

struct GHTTP_HpackDecoder {
  const GHTTP_Allocator * allocator;
  GHTTP_HpackLimits limits;
  Table table;
  size_t cap;          // the largest size update the peer may name
  bool must_update;    // the cap was lowered below the table's maximum
  GHTTP_Result failed;
  uint8_t * scratch[2];
  size_t scratch_cap[2];
};

GHTTP_Result ghttp_hpack_decoder_create(const GHTTP_Allocator * allocator,
    const GHTTP_HpackLimits * limits, size_t table_size,
    GHTTP_HpackDecoder ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_HpackDecoder * d = gcu_allocator_calloc(allocator, 1, sizeof(*d));
  if (!d) {
    return GHTTP_ERR_OOM;
  }
  d->allocator = allocator;
  limits_copy(&d->limits, limits);
  // The peer's encoder may use the protocol default until it sees (and
  // acknowledges) a smaller advertised size, so that is the least this table
  // can be allowed to grow to.
  size_t ceiling = d->limits.max_table_size > GHTTP_HPACK_DEFAULT_TABLE_SIZE
      ? d->limits.max_table_size : GHTTP_HPACK_DEFAULT_TABLE_SIZE;
  if (table_size > ceiling) {
    table_size = ceiling;
  }
  d->table.allocator = allocator;
  d->table.max = table_size;
  d->cap = ceiling;
  *out = d;
  return GHTTP_OK;
}

void ghttp_hpack_decoder_destroy(GHTTP_HpackDecoder * d) {
  if (!d) {
    return;
  }
  table_free(&d->table);
  gcu_allocator_free(d->allocator, d->scratch[0]);
  gcu_allocator_free(d->allocator, d->scratch[1]);
  gcu_allocator_free(d->allocator, d);
}

GHTTP_Result ghttp_hpack_decoder_set_max_table_size(
    GHTTP_HpackDecoder * d, size_t size) {
  if (!d || size > d->limits.max_table_size) {
    return GHTTP_ERR_INVALID;
  }
  d->cap = size;
  if (size < d->table.max) {
    d->must_update = true;
  }
  return GHTTP_OK;
}

size_t ghttp_hpack_decoder_table_size(const GHTTP_HpackDecoder * d) {
  return d ? d->table.size : 0;
}

size_t ghttp_hpack_decoder_table_max(const GHTTP_HpackDecoder * d) {
  return d ? d->table.max : 0;
}

size_t ghttp_hpack_decoder_table_count(const GHTTP_HpackDecoder * d) {
  return d ? d->table.count : 0;
}

static GHTTP_Result entry_out(const Table * t, size_t index, GHTTP_Field * out) {
  if (!out || index >= t->count) {
    return GHTTP_ERR_INVALID;
  }
  const Entry * e = table_at(t, index);
  out->name = e->name;
  out->name_len = e->name_len;
  out->value = e->value;
  out->value_len = e->value_len;
  return GHTTP_OK;
}

GHTTP_Result ghttp_hpack_decoder_table_entry(
    const GHTTP_HpackDecoder * d, size_t index, GHTTP_Field * out) {
  return d ? entry_out(&d->table, index, out) : GHTTP_ERR_INVALID;
}

int ghttp_hpack_decoder_failed(const GHTTP_HpackDecoder * d) {
  return d && d->failed != GHTTP_OK;
}

/** The (name, value) at HPACK index @p idx; CORRUPT when there is none. */
static GHTTP_Result index_lookup(const Table * t, uint32_t idx,
    const char ** name, size_t * nlen, const char ** value, size_t * vlen) {
  if (idx == 0) {
    return GHTTP_ERR_CORRUPT;
  }
  if (idx <= GHTTP_HPACK_STATIC_COUNT) {
    const GHTTP_HpackStaticEntry * s = &ghttp_hpack_static_table[idx];
    *name = s->name;
    *nlen = s->name_len;
    if (value) {
      *value = s->value;
      *vlen = s->value_len;
    }
    return GHTTP_OK;
  }
  size_t k = (size_t)idx - GHTTP_HPACK_STATIC_COUNT - 1;
  if (k >= t->count) {
    return GHTTP_ERR_CORRUPT;
  }
  const Entry * e = table_at(t, k);
  *name = e->name;
  *nlen = e->name_len;
  if (value) {
    *value = e->value;
    *vlen = e->value_len;
  }
  return GHTTP_OK;
}

/**
 * One string literal (section 5.2). The result points into the block when it
 * is plain and into scratch slot @p slot when it was Huffman-coded.
 */
static GHTTP_Result read_string(GHTTP_HpackDecoder * d, const uint8_t ** pp,
    const uint8_t * end, int slot, const char ** out, size_t * out_len) {
  const uint8_t * p = *pp;
  if (p >= end) {
    return GHTTP_ERR_CORRUPT;
  }
  bool huff = (*p & 0x80) != 0;
  uint32_t len;
  size_t used;
  GHTTP_Result r = ghttp_int_decode(p, (size_t)(end - p), 7, &len, &used);
  if (r != GHTTP_OK) {
    return r;
  }
  p += used;
  if (len > (size_t)(end - p)) {
    return GHTTP_ERR_CORRUPT;  // the string runs past the block
  }
  if (!huff) {
    if (len > d->limits.max_field_bytes) {
      return GHTTP_ERR_LIMIT;
    }
    *out = (const char *)p;
    *out_len = len;
  } else {
    // No Huffman code is shorter than 5 bits, so len octets give at most
    // len * 8 / 5 symbols; the cap on the output is that or the limit.
    size_t cap = (size_t)len * 8 / 5;
    if (cap > d->limits.max_field_bytes) {
      cap = d->limits.max_field_bytes;
    }
    void * buf = d->scratch[slot];
    r = ghttp_reserve(d->allocator, &buf, &d->scratch_cap[slot], cap + 1, 1, 64);
    d->scratch[slot] = buf;
    if (r != GHTTP_OK) {
      return r;
    }
    size_t n;
    r = ghttp_huff_decode(p, len, d->scratch[slot], cap, &n);
    if (r != GHTTP_OK) {
      return r;
    }
    *out = (const char *)d->scratch[slot];
    *out_len = n;
  }
  *pp = p + len;
  return GHTTP_OK;
}

static GHTTP_Result decode_block(GHTTP_HpackDecoder * d, const uint8_t * p,
    const uint8_t * end, GHTTP_Headers * out) {
  size_t count = 0;
  size_t list_bytes = 0;
  bool seen_update = false;
  bool seen_field = false;
  while (p < end) {
    uint8_t b = *p;
    const char * name;
    size_t nlen;
    const char * value;
    size_t vlen;
    bool add = false;
    uint32_t v;
    size_t used;
    GHTTP_Result r;

    if (b & 0x80) {  // 6.1 indexed field
      r = ghttp_int_decode(p, (size_t)(end - p), 7, &v, &used);
      if (r != GHTTP_OK) {
        return r;
      }
      p += used;
      r = index_lookup(&d->table, v, &name, &nlen, &value, &vlen);
      if (r != GHTTP_OK) {
        return r;
      }
    } else if ((b & 0xe0) == 0x20) {  // 6.3 dynamic table size update
      if (seen_field) {
        return GHTTP_ERR_CORRUPT;  // only at the start of a block
      }
      r = ghttp_int_decode(p, (size_t)(end - p), 5, &v, &used);
      if (r != GHTTP_OK) {
        return r;
      }
      p += used;
      if (v > d->cap) {
        return GHTTP_ERR_CORRUPT;
      }
      table_set_max(&d->table, v);
      seen_update = true;
      d->must_update = false;
      continue;
    } else {  // 6.2 literal field
      unsigned prefix;
      if ((b & 0xc0) == 0x40) {
        prefix = 6;
        add = true;
      } else {
        prefix = 4;  // without indexing (0000) or never indexed (0001)
      }
      r = ghttp_int_decode(p, (size_t)(end - p), prefix, &v, &used);
      if (r != GHTTP_OK) {
        return r;
      }
      p += used;
      if (v > 0) {
        r = index_lookup(&d->table, v, &name, &nlen, NULL, NULL);
        if (r != GHTTP_OK) {
          return r;
        }
      } else {
        r = read_string(d, &p, end, 0, &name, &nlen);
        if (r != GHTTP_OK) {
          return r;
        }
      }
      r = read_string(d, &p, end, 1, &value, &vlen);
      if (r != GHTTP_OK) {
        return r;
      }
    }

    if (!seen_field) {
      seen_field = true;
      if (d->must_update && !seen_update) {
        // The cap was lowered, so this block had to open with an update.
        return GHTTP_ERR_CORRUPT;
      }
    }
    if (count >= d->limits.max_header_count) {
      return GHTTP_ERR_LIMIT;
    }
    size_t cost = nlen + vlen + ENTRY_OVERHEAD;
    if (cost > d->limits.max_header_list_bytes
        || list_bytes > d->limits.max_header_list_bytes - cost) {
      return GHTTP_ERR_LIMIT;
    }
    count++;
    list_bytes += cost;
    r = ghttp_headers_add_raw(out, name, nlen, value, vlen);
    if (r != GHTTP_OK) {
      return r;
    }
    if (add) {
      r = table_add(&d->table, name, nlen, value, vlen);
      if (r != GHTTP_OK) {
        return r;
      }
    }
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_hpack_decode(GHTTP_HpackDecoder * d, const void * block,
    size_t len, GHTTP_Headers * out) {
  if (!d || !out || (!block && len > 0)) {
    return GHTTP_ERR_INVALID;
  }
  if (d->failed != GHTTP_OK) {
    return d->failed;
  }
  // An empty block may arrive as NULL; pointer arithmetic on it is not defined.
  static const uint8_t none[1] = {0};
  const uint8_t * p = block ? (const uint8_t *)block : none;
  GHTTP_Result r = decode_block(d, p, p + len, out);
  if (r != GHTTP_OK) {
    d->failed = r;
  }
  return r;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

struct GHTTP_HpackEncoder {
  const GHTTP_Allocator * allocator;
  GHTTP_HpackLimits limits;
  Table table;
  bool pending;
  size_t pending_min;
  size_t pending_final;
  GHTTP_Result failed;
  uint8_t * scratch;
  size_t scratch_cap;
};

GHTTP_Result ghttp_hpack_encoder_create(const GHTTP_Allocator * allocator,
    const GHTTP_HpackLimits * limits, size_t table_size,
    GHTTP_HpackEncoder ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_HpackEncoder * e = gcu_allocator_calloc(allocator, 1, sizeof(*e));
  if (!e) {
    return GHTTP_ERR_OOM;
  }
  e->allocator = allocator;
  limits_copy(&e->limits, limits);
  e->table.allocator = allocator;
  e->table.max = table_size;
  if (table_size > e->limits.max_table_size) {
    // The peer's table is larger than this encoder will use: say so in the
    // first block, so that the two agree on when entries are evicted.
    e->pending = true;
    e->pending_min = e->limits.max_table_size;
    e->pending_final = e->limits.max_table_size;
    e->table.max = e->limits.max_table_size;
  }
  *out = e;
  return GHTTP_OK;
}

void ghttp_hpack_encoder_destroy(GHTTP_HpackEncoder * e) {
  if (!e) {
    return;
  }
  table_free(&e->table);
  gcu_allocator_free(e->allocator, e->scratch);
  gcu_allocator_free(e->allocator, e);
}

GHTTP_Result ghttp_hpack_encoder_set_peer_table_size(
    GHTTP_HpackEncoder * e, size_t size) {
  if (!e) {
    return GHTTP_ERR_INVALID;
  }
  if (size > e->limits.max_table_size) {
    size = e->limits.max_table_size;
  }
  if (size == e->table.max && !e->pending) {
    return GHTTP_OK;
  }
  if (!e->pending) {
    e->pending = true;
    e->pending_min = e->table.max;
  }
  if (size < e->pending_min) {
    e->pending_min = size;
  }
  e->pending_final = size;
  table_set_max(&e->table, size);
  return GHTTP_OK;
}

size_t ghttp_hpack_encoder_table_size(const GHTTP_HpackEncoder * e) {
  return e ? e->table.size : 0;
}

size_t ghttp_hpack_encoder_table_max(const GHTTP_HpackEncoder * e) {
  return e ? e->table.max : 0;
}

size_t ghttp_hpack_encoder_table_count(const GHTTP_HpackEncoder * e) {
  return e ? e->table.count : 0;
}

GHTTP_Result ghttp_hpack_encoder_table_entry(
    const GHTTP_HpackEncoder * e, size_t index, GHTTP_Field * out) {
  return e ? entry_out(&e->table, index, out) : GHTTP_ERR_INVALID;
}

static GHTTP_Result put_int(GHTTP_Buffer * out, unsigned prefix, uint8_t flags,
    uint64_t value) {
  uint8_t tmp[GHTTP_INT_MAX_ENCODED];
  size_t n = ghttp_int_encode(tmp, prefix, flags, value);
  return ghttp_buffer_append(out, tmp, n);
}

static GHTTP_Result put_string(GHTTP_HpackEncoder * e, const char * s, size_t n,
    GHTTP_HpackHuffman mode, GHTTP_Buffer * out) {
  const uint8_t * in = (const uint8_t *)s;
  bool huff = false;
  size_t hlen = 0;
  if (mode != GHTTP_HPACK_HUFFMAN_NEVER) {
    hlen = ghttp_huff_encoded_len(in, n);
    huff = mode == GHTTP_HPACK_HUFFMAN_ALWAYS || hlen <= n;
  }
  if (!huff) {
    GHTTP_Result r = put_int(out, 7, 0x00, n);
    return r != GHTTP_OK ? r : ghttp_buffer_append(out, s, n);
  }
  GHTTP_Result r = put_int(out, 7, 0x80, hlen);
  if (r != GHTTP_OK) {
    return r;
  }
  void * buf = e->scratch;
  r = ghttp_reserve(e->allocator, &buf, &e->scratch_cap, hlen + 1, 1, 64);
  e->scratch = buf;
  if (r != GHTTP_OK) {
    return r;
  }
  ghttp_huff_encode(in, n, e->scratch);
  return ghttp_buffer_append(out, e->scratch, hlen);
}

static bool name_is(const char * name, size_t n, const char * lit) {
  return ghttp_ieq(name, n, lit);
}

static bool is_sensitive(const char * name, size_t n) {
  return name_is(name, n, "authorization")
      || name_is(name, n, "proxy-authorization") || name_is(name, n, "cookie")
      || name_is(name, n, "set-cookie");
}

/** Find an exact match (@p want_value) or a name match; 0 when none. */
static uint32_t find_index(const Table * t, const char * name, size_t nlen,
    const char * value, size_t vlen, bool want_value) {
  for (uint32_t i = 1; i <= GHTTP_HPACK_STATIC_COUNT; i++) {
    const GHTTP_HpackStaticEntry * s = &ghttp_hpack_static_table[i];
    if (s->name_len == nlen && memcmp(s->name, name, nlen) == 0
        && (!want_value
            || (s->value_len == vlen && memcmp(s->value, value, vlen) == 0))) {
      return i;
    }
  }
  for (size_t k = 0; k < t->count; k++) {
    const Entry * e = table_at(t, k);
    if (e->name_len == nlen && memcmp(e->name, name, nlen) == 0
        && (!want_value
            || (e->value_len == vlen && memcmp(e->value, value, vlen) == 0))) {
      return (uint32_t)(GHTTP_HPACK_STATIC_COUNT + 1 + k);
    }
  }
  return 0;
}

static GHTTP_Result emit_pending_update(
    GHTTP_HpackEncoder * e, GHTTP_Buffer * out) {
  if (!e->pending) {
    return GHTTP_OK;
  }
  GHTTP_Result r = GHTTP_OK;
  if (e->pending_min < e->pending_final) {
    r = put_int(out, 5, 0x20, e->pending_min);
  }
  if (r == GHTTP_OK) {
    r = put_int(out, 5, 0x20, e->pending_final);
  }
  if (r == GHTTP_OK) {
    e->pending = false;
  }
  return r;
}

GHTTP_Result ghttp_hpack_encode_field(GHTTP_HpackEncoder * e, const char * name,
    size_t nlen, const char * value, size_t vlen, GHTTP_HpackIndexing indexing,
    GHTTP_HpackHuffman huffman, GHTTP_Buffer * out) {
  if (!e || !out || (!name && nlen > 0) || (!value && vlen > 0)) {
    return GHTTP_ERR_INVALID;
  }
  if (e->failed != GHTTP_OK) {
    return e->failed;
  }
  size_t mark = ghttp_buffer_size(out);
  GHTTP_Result r = emit_pending_update(e, out);
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(out, mark);
    return r;  // nothing changed: the update is still pending
  }

  if (indexing == GHTTP_HPACK_INDEX_AUTO || indexing == GHTTP_HPACK_INDEX_SAFE) {
    uint32_t idx = find_index(&e->table, name, nlen, value, vlen, true);
    if (idx != 0) {
      // An exact match is one index and no table change.
      r = put_int(out, 7, 0x80, idx);
      if (r != GHTTP_OK) {
        ghttp_buffer_truncate(out, mark);
        e->failed = r;  // the pending update (if any) was written
      }
      return r;
    }
    indexing = indexing == GHTTP_HPACK_INDEX_SAFE && is_sensitive(name, nlen)
        ? GHTTP_HPACK_INDEX_NEVER : GHTTP_HPACK_INDEX_INCREMENTAL;
  }

  uint32_t nidx = find_index(&e->table, name, nlen, NULL, 0, false);
  uint8_t flags;
  unsigned prefix;
  switch (indexing) {
    case GHTTP_HPACK_INDEX_NONE:
      flags = 0x00;
      prefix = 4;
      break;
    case GHTTP_HPACK_INDEX_NEVER:
      flags = 0x10;
      prefix = 4;
      break;
    default:
      flags = 0x40;
      prefix = 6;
      break;
  }
  r = put_int(out, prefix, flags, nidx);
  if (r == GHTTP_OK && nidx == 0) {
    r = put_string(e, name, nlen, huffman, out);
  }
  if (r == GHTTP_OK) {
    r = put_string(e, value, vlen, huffman, out);
  }
  if (r == GHTTP_OK && flags == 0x40) {
    r = table_add(&e->table, name, nlen, value, vlen);
  }
  if (r != GHTTP_OK) {
    goto fail;
  }
  return GHTTP_OK;

fail:
  // The block is half written and the table may have moved: the peer's
  // decoder and this encoder can no longer agree.
  ghttp_buffer_truncate(out, mark);
  e->failed = r;
  return r;
}

GHTTP_Result ghttp_hpack_encode(
    GHTTP_HpackEncoder * e, const GHTTP_Headers * headers, GHTTP_Buffer * out) {
  if (!e || !headers || !out) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(out);
  size_t n = ghttp_headers_count(headers);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    GHTTP_Result r = ghttp_headers_at(headers, i, &f);
    if (r == GHTTP_OK) {
      r = ghttp_hpack_encode_field(e, f.name, f.name_len, f.value, f.value_len,
          GHTTP_HPACK_INDEX_SAFE, GHTTP_HPACK_HUFFMAN_AUTO, out);
    }
    if (r != GHTTP_OK) {
      ghttp_buffer_truncate(out, mark);
      if (i > 0 && e->failed == GHTTP_OK) {
        // Earlier fields of this list are in the table (and the pending
        // size update has been spent on the block just thrown away): the
        // peer's decoder and this encoder can no longer agree.
        e->failed = r;
      }
      return r;
    }
  }
  return GHTTP_OK;
}
