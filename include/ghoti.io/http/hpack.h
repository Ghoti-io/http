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
 * @file hpack.h
 *
 * HPACK, header compression for HTTP/2: RFC 7541.
 *
 * A decoder and an encoder, each holding the dynamic table that RFC 7541
 * section 2.3.2 makes a piece of connection state. Bytes in, header list out,
 * and the reverse; no I/O.
 *
 * The decoder takes a whole header block (HTTP/2 joins HEADERS and
 * CONTINUATION fragments before decoding, and the compression state is shared
 * by every stream, so a block half-decoded is state nobody can recover). Any
 * error leaves the decoder failed for good: it returns the same error to every
 * later call, which is what RFC 9113 section 4.3 asks of a connection.
 *
 * Decoded fields are appended to a GHTTP_Headers with names and values exactly
 * as they were coded: HPACK conveys any octets, and the field-validity rules of
 * RFC 9113 section 8.2.1 belong to the HTTP/2 layer, not here. Pseudo-header
 * fields (":method") come out as fields whose name begins with a colon.
 *
 * A decoder and an encoder are each used from one thread at a time.
 */

#ifndef GHOTI_IO_GHTTP_HPACK_H
#define GHOTI_IO_GHTTP_HPACK_H

#include <ghoti.io/http/buffer.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The dynamic table size RFC 7541 assumes before anything is negotiated. */
#define GHTTP_HPACK_DEFAULT_TABLE_SIZE 4096u

/**
 * Every unbounded quantity in HPACK decoding. Each is a hard cap; zero allows
 * none. Initialise with ghttp_hpack_limits_default().
 */
typedef struct GHTTP_HpackLimits {
  size_t size;  ///< sizeof(GHTTP_HpackLimits); set by _default().
  /**
   * The largest dynamic table the decoder will hold, and the largest size an
   * encoder's table-size update may name. This is what an HTTP/2 endpoint
   * advertises as SETTINGS_HEADER_TABLE_SIZE.
   */
  size_t max_table_size;
  /**
   * The decoded header list: the sum over fields of name + value + 32 octets,
   * the measure of RFC 9113 section 6.5.2 (SETTINGS_MAX_HEADER_LIST_SIZE).
   */
  size_t max_header_list_bytes;
  /** One decoded name or value, after Huffman expansion. */
  size_t max_field_bytes;
  /** Fields in one header block. */
  size_t max_header_count;
  uint64_t reserved[4];  ///< Zero; for later versions.
} GHTTP_HpackLimits;

#define GHTTP_HPACK_DEFAULT_MAX_TABLE_SIZE 4096u
#define GHTTP_HPACK_DEFAULT_MAX_HEADER_LIST_BYTES 65536u
#define GHTTP_HPACK_DEFAULT_MAX_FIELD_BYTES 16384u
#define GHTTP_HPACK_DEFAULT_MAX_HEADER_COUNT 100u

/** Fill @p limits with the defaults. */
GHTTP_API void ghttp_hpack_limits_default(GHTTP_HpackLimits * limits);

/** How the encoder is to represent one field (RFC 7541 section 6.2). */
typedef enum GHTTP_HpackIndexing {
  /**
   * An exact match in a table is sent as an index; otherwise a literal with
   * incremental indexing. This is what RFC 7541 Appendix C does.
   */
  GHTTP_HPACK_INDEX_AUTO,
  /**
   * As GHTTP_HPACK_INDEX_AUTO, except that fields whose names carry
   * credentials (authorization, proxy-authorization, cookie, set-cookie) are
   * sent never indexed (section 7.1.3), so that guessing one cannot be tested
   * against the compressed size. What ghttp_hpack_encode() and HTTP/2 use.
   */
  GHTTP_HPACK_INDEX_SAFE,
  /** Literal with incremental indexing, even when the field is in a table. */
  GHTTP_HPACK_INDEX_INCREMENTAL,
  /** Literal without indexing: the table is left alone. */
  GHTTP_HPACK_INDEX_NONE,
  /** Literal never indexed: an intermediary must not index it either. */
  GHTTP_HPACK_INDEX_NEVER
} GHTTP_HpackIndexing;

/** Whether the encoder Huffman-codes a string. */
typedef enum GHTTP_HpackHuffman {
  GHTTP_HPACK_HUFFMAN_AUTO,   ///< Unless it is longer (RFC 7541 Appendix C.6.2 codes "307", where it is no shorter).
  GHTTP_HPACK_HUFFMAN_NEVER,  ///< Always the plain octets.
  GHTTP_HPACK_HUFFMAN_ALWAYS  ///< Always Huffman.
} GHTTP_HpackHuffman;

typedef struct GHTTP_HpackDecoder GHTTP_HpackDecoder;
typedef struct GHTTP_HpackEncoder GHTTP_HpackEncoder;

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/**
 * Create a decoder.
 *
 * @param allocator NULL for the default.
 * @param limits NULL for the defaults.
 * @param table_size The dynamic table maximum the peer's encoder starts with:
 *   GHTTP_HPACK_DEFAULT_TABLE_SIZE for HTTP/2, whatever this endpoint
 *   advertises, until the peer acknowledges (see
 *   ghttp_hpack_decoder_set_max_table_size). It is capped at the larger of the
 *   limits' max_table_size and that default, which is the most a peer is
 *   entitled to before it has seen a smaller advertisement.
 */
GHTTP_API GHTTP_Result ghttp_hpack_decoder_create(
    const GHTTP_Allocator * allocator, const GHTTP_HpackLimits * limits,
    size_t table_size, GHTTP_HpackDecoder ** out);

GHTTP_API void ghttp_hpack_decoder_destroy(GHTTP_HpackDecoder * decoder);

/**
 * Set the largest table size the peer's encoder may use. Call it when the peer
 * ACKNOWLEDGES the SETTINGS_HEADER_TABLE_SIZE this endpoint advertised: until
 * then the peer is entitled to the old size, and the decoder's cap is the
 * larger of the old and the limits' max_table_size. @p size may not exceed the
 * limits' max_table_size (GHTTP_ERR_INVALID). Lowering it below the table's
 * current maximum obliges the peer's next header block to open with a dynamic
 * table size update (RFC 7541 section 4.2); the decoder refuses one that does
 * not.
 */
GHTTP_API GHTTP_Result ghttp_hpack_decoder_set_max_table_size(
    GHTTP_HpackDecoder * decoder, size_t size);

/**
 * Decode one whole header block, appending its fields to @p out.
 *
 * @return GHTTP_OK; GHTTP_ERR_CORRUPT for a COMPRESSION_ERROR (a bad index, an
 *   overlong or truncated integer or string, bad Huffman padding or the EOS
 *   symbol, a table size update that is misplaced or above the cap);
 *   GHTTP_ERR_LIMIT when a limit would be exceeded; GHTTP_ERR_OOM. On any
 *   error the decoder is failed for good and @p out holds an unspecified
 *   prefix of the list.
 */
GHTTP_API GHTTP_Result ghttp_hpack_decode(GHTTP_HpackDecoder * decoder,
    const void * block, size_t len, GHTTP_Headers * out);

/** The dynamic table's size now, in the units of RFC 7541 section 4.1. */
GHTTP_API size_t ghttp_hpack_decoder_table_size(const GHTTP_HpackDecoder * decoder);

/** The dynamic table's current maximum size. */
GHTTP_API size_t ghttp_hpack_decoder_table_max(const GHTTP_HpackDecoder * decoder);

/** Entries in the dynamic table. */
GHTTP_API size_t ghttp_hpack_decoder_table_count(
    const GHTTP_HpackDecoder * decoder);

/**
 * Entry @p index of the dynamic table, 0 being the newest (HPACK index 62).
 * The strings are NUL-terminated and valid until the next decode.
 */
GHTTP_API GHTTP_Result ghttp_hpack_decoder_table_entry(
    const GHTTP_HpackDecoder * decoder, size_t index, GHTTP_Field * out);

/** Whether an earlier decode failed. */
GHTTP_API int ghttp_hpack_decoder_failed(const GHTTP_HpackDecoder * decoder);

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/**
 * Create an encoder.
 *
 * @param table_size The dynamic table size the peer's decoder is assumed to
 *   have now: GHTTP_HPACK_DEFAULT_TABLE_SIZE until its SETTINGS say
 *   otherwise. No table size update is sent for it, unless it is larger than
 *   the limits' max_table_size, which is the most this encoder will use: the
 *   first block then opens with an update down to that.
 * @param limits->max_table_size caps what this encoder uses, whatever the peer
 *   allows (see ghttp_hpack_encoder_set_peer_table_size).
 */
GHTTP_API GHTTP_Result ghttp_hpack_encoder_create(
    const GHTTP_Allocator * allocator, const GHTTP_HpackLimits * limits,
    size_t table_size, GHTTP_HpackEncoder ** out);

GHTTP_API void ghttp_hpack_encoder_destroy(GHTTP_HpackEncoder * encoder);

/**
 * The peer announced SETTINGS_HEADER_TABLE_SIZE = @p size. The encoder uses
 * the smaller of that and its own cap, and opens the next header block with
 * the dynamic table size update(s) RFC 7541 section 4.2 requires (the
 * smallest size since the last block, then the final one).
 */
GHTTP_API GHTTP_Result ghttp_hpack_encoder_set_peer_table_size(
    GHTTP_HpackEncoder * encoder, size_t size);

/**
 * Encode one field and append it to @p out, preceded by any pending table size
 * update. Fields of one block are encoded by consecutive calls; the block ends
 * when the caller says so, HPACK having no terminator.
 *
 * @return GHTTP_OK, GHTTP_ERR_INVALID (a name or value that cannot be coded:
 *   none today, the argument checks only), GHTTP_ERR_OOM. On OOM the table may
 *   have changed and the encoder is failed for good.
 */
GHTTP_API GHTTP_Result ghttp_hpack_encode_field(GHTTP_HpackEncoder * encoder,
    const char * name, size_t name_len, const char * value, size_t value_len,
    GHTTP_HpackIndexing indexing, GHTTP_HpackHuffman huffman,
    GHTTP_Buffer * out);

/**
 * Encode a whole header list with GHTTP_HPACK_INDEX_SAFE and
 * GHTTP_HPACK_HUFFMAN_AUTO. Appends to @p out; on failure @p out is restored
 * to its size on entry.
 */
GHTTP_API GHTTP_Result ghttp_hpack_encode(GHTTP_HpackEncoder * encoder,
    const GHTTP_Headers * headers, GHTTP_Buffer * out);

GHTTP_API size_t ghttp_hpack_encoder_table_size(const GHTTP_HpackEncoder * encoder);
GHTTP_API size_t ghttp_hpack_encoder_table_max(const GHTTP_HpackEncoder * encoder);
GHTTP_API size_t ghttp_hpack_encoder_table_count(
    const GHTTP_HpackEncoder * encoder);
GHTTP_API GHTTP_Result ghttp_hpack_encoder_table_entry(
    const GHTTP_HpackEncoder * encoder, size_t index, GHTTP_Field * out);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_HPACK_H
