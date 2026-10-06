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
 * Prefix-coded integers and the static Huffman code.
 *
 * Reference: RFC 7541 sections 5.1 and 5.2 and Appendix B.
 */

#include <ghoti.io/http/macros.h>
#include <stdbool.h>
#include "coding_internal.h"

size_t ghttp_huff_encoded_len(const uint8_t * in, size_t n) {
  uint64_t bits = 0;
  for (size_t i = 0; i < n; i++) {
    bits += ghttp_huff_len[in[i]];
  }
  return (size_t)((bits + 7) / 8);
}

void ghttp_huff_encode(const uint8_t * in, size_t n, uint8_t * out) {
  uint64_t acc = 0;   // bits not yet written, right aligned
  unsigned have = 0;  // how many
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned len = ghttp_huff_len[in[i]];
    acc = (acc << len) | ghttp_huff_code[in[i]];
    have += len;
    while (have >= 8) {
      have -= 8;
      out[o++] = (uint8_t)(acc >> have);
    }
    acc &= ((uint64_t)1 << have) - 1;
  }
  if (have > 0) {
    // Pad with the most significant bits of EOS: all ones.
    out[o++] = (uint8_t)((acc << (8 - have)) | (0xffu >> have));
  }
}

GHTTP_Result ghttp_huff_decode(const uint8_t * in, size_t n, uint8_t * out,
    size_t cap, size_t * out_len) {
  size_t o = 0;
  int node = 0;
  unsigned pending = 0;  // bits consumed since the last symbol
  bool all_ones = true;  // and whether every one of them was 1
  for (size_t i = 0; i < n; i++) {
    for (int b = 7; b >= 0; b--) {
      unsigned bit = (in[i] >> b) & 1u;
      int next = ghttp_huff_tree[node][bit];
      pending++;
      all_ones = all_ones && bit == 1;
      if (next > 0) {
        node = next;
        continue;
      }
      int sym = -1 - next;
      if (sym == 256) {
        return GHTTP_ERR_CORRUPT;  // EOS inside a string
      }
      if (o >= cap) {
        return GHTTP_ERR_LIMIT;
      }
      out[o++] = (uint8_t)sym;
      node = 0;
      pending = 0;
      all_ones = true;
    }
  }
  // What is left must be a strict prefix of EOS (all ones) of at most 7 bits.
  if (pending > 7 || (pending > 0 && !all_ones)) {
    return GHTTP_ERR_CORRUPT;
  }
  *out_len = o;
  return GHTTP_OK;
}

size_t ghttp_int_encode(
    uint8_t * out, unsigned prefix_bits, uint8_t flags, uint64_t value) {
  uint64_t max = ((uint64_t)1 << prefix_bits) - 1;
  size_t o = 0;
  if (value < max) {
    out[o++] = (uint8_t)(flags | value);
    return o;
  }
  out[o++] = (uint8_t)(flags | max);
  value -= max;
  while (value >= 128) {
    out[o++] = (uint8_t)((value & 127) | 128);
    value >>= 7;
  }
  out[o++] = (uint8_t)value;
  return o;
}

GHTTP_Result ghttp_int_decode(const uint8_t * in, size_t n, unsigned prefix_bits,
    uint32_t * value, size_t * used) {
  if (n == 0) {
    return GHTTP_ERR_CORRUPT;
  }
  uint64_t max = ((uint64_t)1 << prefix_bits) - 1;
  uint64_t v = in[0] & max;
  size_t i = 1;
  if (v == max) {
    unsigned shift = 0;
    for (;;) {
      if (i >= n || shift > 28) {
        // Out of input, or a sixth continuation octet.
        return GHTTP_ERR_CORRUPT;
      }
      uint8_t b = in[i++];
      v += (uint64_t)(b & 127) << shift;
      shift += 7;
      if (v > 0x7fffffffu) {
        return GHTTP_ERR_CORRUPT;
      }
      if (!(b & 128)) {
        break;
      }
    }
  }
  *value = (uint32_t)v;
  *used = i;
  return GHTTP_OK;
}
