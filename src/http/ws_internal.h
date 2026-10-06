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
 * What the WebSocket handshake (ws_handshake.c), the permessage-deflate
 * negotiation and codec (ws_deflate.c) and the connection (ws_conn.c) share.
 * Never installed.
 */

#ifndef GHOTI_IO_GHTTP_SRC_HTTP_WS_INTERNAL_H
#define GHOTI_IO_GHTTP_SRC_HTTP_WS_INTERNAL_H

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/buffer.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/ws_deflate.h>
#include <ghoti.io/http/ws_frame.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The most parameters one extension offer is read with, whatever the limit says. */
#define GHTTP_WS_HARD_MAX_PARAMS 16u
/** The most extension offers a handshake is read with, whatever the limit says. */
#define GHTTP_WS_HARD_MAX_OFFERS 32u

/**
 * The limits a caller gave, or the defaults for NULL, into @p out: a struct
 * from a caller built against an older header is read as far as its own @c size
 * goes and the rest is the defaults. GHTTP_ERR_INVALID for a size of 0.
 */
GHTTP_Result ghttp_ws_limits_resolve(const GHTTP_WsLimits * in, GHTTP_WsLimits * out);

/** Base64 (RFC 4648) of @p n octets into @p out, which holds 4 * ((n + 2) / 3) characters; no NUL. */
void ghttp_ws_base64_encode(const uint8_t * in, size_t n, char * out);

/**
 * Strict base64 decode: only the 64 characters, padding exactly as needed, and
 * the unused bits of the last character clear. Returns the octets written, or
 * (size_t)-1 for anything else. @p cap must be at least 3 * (len / 4).
 */
size_t ghttp_ws_base64_decode(
    const char * in, size_t len, uint8_t * out, size_t cap);

/** One extension offer read from a `Sec-WebSocket-Extensions` field. */
typedef struct GHTTP_WsExtItem {
  const char * name;
  size_t name_len;
  GHTTP_WsParam params[GHTTP_WS_HARD_MAX_PARAMS];
  size_t nparams;
} GHTTP_WsExtItem;

typedef enum {
  GHTTP_WS_EXT_ITEM,      ///< An offer was read.
  GHTTP_WS_EXT_END,       ///< The list is finished.
  GHTTP_WS_EXT_SYNTAX,    ///< The field does not match the grammar of RFC 6455 section 9.1.
  GHTTP_WS_EXT_TOO_MANY   ///< An offer has more parameters than @p max_params.
} GHTTP_WsExtStatus;

/**
 * Read the next extension from the list that starts at @p *cursor and ends at
 * @p end, advancing the cursor. Empty list elements are skipped. Quoted-string
 * values are returned without the quotes and are not unescaped.
 */
GHTTP_WsExtStatus ghttp_ws_ext_next(const char ** cursor, const char * end,
    size_t max_params, GHTTP_WsExtItem * item);

/**
 * The permessage-deflate state of one connection: a compressor for what this
 * end sends and a decompressor for what it receives, each created when first
 * used. Bounded inflate: see ghttp_ws_inflate_update().
 */
typedef struct GHTTP_WsDeflate GHTTP_WsDeflate;

/**
 * @param enc_window_bits The window the compressor uses, 8 to 15, 0 for 15.
 * @param enc_reset The compressor forgets its history after each message.
 * @param dec_reset The decompressor does too.
 * @param max_message The most one message may inflate to.
 * @param max_ratio The most output per input octet of one message.
 */
GHTTP_Result ghttp_ws_deflate_open(const GHTTP_Allocator * allocator,
    unsigned enc_window_bits, bool enc_reset, bool dec_reset,
    uint64_t max_message, uint64_t max_ratio, GHTTP_WsDeflate ** out);

void ghttp_ws_deflate_close(GHTTP_WsDeflate * d);

/**
 * Compress the next piece of a message and append what the compressor
 * produced to @p out. With @p fin the message is ended: flushed to a byte
 * boundary, and the trailing 0x00 0x00 0xff 0xff of RFC 7692 section 7.2.1 is
 * removed. The history is then forgotten if @c enc_reset.
 *
 * Errors: GHTTP_ERR_OOM; GHTTP_ERR_INTERNAL if the compressor misbehaves. After
 * either the compressor must not be used again.
 */
GHTTP_Result ghttp_ws_deflate_compress(GHTTP_WsDeflate * d, const void * in,
    size_t n, bool fin, GHTTP_Buffer * out);

/** Start a received message: its counts are zero. */
void ghttp_ws_inflate_begin(GHTTP_WsDeflate * d);

/**
 * Decompress the next piece of the current message and append the output to
 * @p out, never more than one octet past the message limit or the ratio's
 * allowance, and never appending that octet.
 *
 * @return GHTTP_OK; GHTTP_ERR_LIMIT when the output would pass either (the
 *   close code is 1009); GHTTP_ERR_CORRUPT for data that is not deflate, or
 *   anything after a final block; GHTTP_ERR_OOM.
 */
GHTTP_Result ghttp_ws_inflate_update(
    GHTTP_WsDeflate * d, const void * in, size_t n, GHTTP_Buffer * out);

/**
 * End the message: supply the removed trailer and drain the decompressor. If
 * the message ended in a final block the decompressor starts afresh, which
 * ends any context takeover (documentation/permessage-deflate.md).
 */
GHTTP_Result ghttp_ws_inflate_end(GHTTP_WsDeflate * d, GHTTP_Buffer * out);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_SRC_HTTP_WS_INTERNAL_H
