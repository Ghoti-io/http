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
 * The two codings that HPACK (RFC 7541) and QPACK share: the prefix-coded
 * integer (RFC 7541 section 5.1) and the static Huffman code (section 5.2,
 * Appendix B). Kept apart from the HPACK tables and the HTTP/2 code so that a
 * later QPACK implementation (RFC 9204) can use them unchanged.
 */

#ifndef GHOTI_IO_GHTTP_SRC_HTTP_CODING_INTERNAL_H
#define GHOTI_IO_GHTTP_SRC_HTTP_CODING_INTERNAL_H

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/core.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Generated (hpack_tables.c): code and length per symbol, LSB aligned. */
extern const uint32_t ghttp_huff_code[257];
extern const uint8_t ghttp_huff_len[257];
/** Generated: [node][bit] -> positive node index, or -1 - symbol. */
extern const int16_t ghttp_huff_tree[][2];
extern const size_t ghttp_huff_tree_nodes;

/** The most bytes a prefix-coded integer this module writes can take. */
#define GHTTP_INT_MAX_ENCODED 11

/** The bytes the Huffman code needs for @p n octets, padding included. */
size_t ghttp_huff_encoded_len(const uint8_t * in, size_t n);

/** Encode into @p out, which holds ghttp_huff_encoded_len(in, n) bytes. */
void ghttp_huff_encode(const uint8_t * in, size_t n, uint8_t * out);

/**
 * Decode @p n bytes into @p out (capacity @p cap).
 *
 * GHTTP_ERR_CORRUPT for the EOS symbol inside the string, padding longer than
 * seven bits or not made of the EOS code's high bits, and GHTTP_ERR_LIMIT for
 * output longer than @p cap (checked as it is produced, so the cost of a hostile
 * string is bounded by @p cap and not by its expansion).
 */
GHTTP_Result ghttp_huff_decode(const uint8_t * in, size_t n, uint8_t * out,
    size_t cap, size_t * out_len);

/**
 * Write @p value with an N-bit prefix; the high bits of the first byte are
 * @p flags (already shifted). Returns the bytes written, at most
 * GHTTP_INT_MAX_ENCODED.
 */
size_t ghttp_int_encode(
    uint8_t * out, unsigned prefix_bits, uint8_t flags, uint64_t value);

/**
 * Read an N-bit-prefix integer from @p in. GHTTP_ERR_CORRUPT when the input
 * ends inside it, when it needs more than five continuation octets or when
 * the value exceeds 2^31 - 1 (RFC 7541 section 5.1 leaves the bound to the
 * implementation; zero-padded runs are what it prevents).
 */
GHTTP_Result ghttp_int_decode(const uint8_t * in, size_t n, unsigned prefix_bits,
    uint32_t * value, size_t * used);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_SRC_HTTP_CODING_INTERNAL_H
