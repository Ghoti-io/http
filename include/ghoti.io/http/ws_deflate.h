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
 * @file ws_deflate.h
 *
 * The permessage-deflate extension of RFC 7692: its parameters, and the
 * negotiation of them from the `Sec-WebSocket-Extensions` field.
 *
 * Only the negotiation is public. The compressor and decompressor that the
 * connection runs with the agreed parameters are internal to ws_conn.h, which
 * takes the agreed parameters in a ::GHTTP_WsNegotiated.
 *
 * ### What is agreed
 *
 * Four parameters (RFC 7692 section 7.1):
 *
 *  - `server_no_context_takeover` and `client_no_context_takeover`: the named
 *    side starts every message with an empty LZ77 window.
 *  - `server_max_window_bits` and `client_max_window_bits`: 8 to 15, the
 *    base-two logarithm of the window the named side compresses with.
 *
 * Whoever decompresses accepts any window up to 15 bits; the window the peer
 * compresses with is the peer's to keep (documentation/permessage-deflate.md).
 */

#ifndef GHOTI_IO_GHTTP_WS_DEFLATE_H
#define GHOTI_IO_GHTTP_WS_DEFLATE_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The extension's registered name. */
#define GHTTP_WS_PERMESSAGE_DEFLATE "permessage-deflate"

/** The longest `permessage-deflate` text this library writes, with room to spare. */
#define GHTTP_WS_DEFLATE_TEXT_MAX 160u

/** One extension parameter as it appeared in the field: views into the caller's bytes. */
typedef struct GHTTP_WsParam {
  const char * name;   ///< The parameter name, a token.
  size_t name_len;
  const char * value;  ///< The value with any quotes removed; NULL when @c has_value is 0.
  size_t value_len;
  int has_value;       ///< Whether "=" and a value followed the name.
} GHTTP_WsParam;

/**
 * The parameters of permessage-deflate: what is agreed, what an endpoint
 * offers, or what a server will insist on, according to where it is used.
 */
typedef struct GHTTP_WsDeflateParams {
  size_t size;  ///< sizeof(GHTTP_WsDeflateParams); set by _default().
  /** The server starts each message with an empty window. */
  int server_no_context_takeover;
  /** The client starts each message with an empty window. */
  int client_no_context_takeover;
  /** 8 to 15, or 0 for "not limited" (15, and nothing is said on the wire). */
  uint8_t server_max_window_bits;
  /** 8 to 15, or 0 for "not limited". */
  uint8_t client_max_window_bits;
  /**
   * Offers only: name `client_max_window_bits` without a value, saying the
   * client would accept the server limiting it (browsers do).
   */
  int offer_client_max_window_bits;
  uint64_t reserved[2];
} GHTTP_WsDeflateParams;

/** Nothing demanded, nothing limited, no offer of a window limit: the plainest agreement. */
GHTTP_API void ghttp_ws_deflate_params_default(GHTTP_WsDeflateParams * params);

/**
 * Decide a client's offer (RFC 7692 section 7).
 *
 * @param params The offer's parameters, in order.
 * @param count How many.
 * @param policy What this server insists on: its no-context-takeover flags
 *   are applied whatever the client asked, and its window limits cap the
 *   client's; NULL for none.
 * @param[out] agreed The parameters the server will respond with, and use.
 *   Written when @p accepted.
 * @param[out] accepted 1 to accept this offer; 0 to decline it, because a
 *   parameter is unknown, repeated or has an invalid value (the server MUST
 *   decline such an offer; a later offer may still be accepted).
 * @return GHTTP_OK, or GHTTP_ERR_INVALID for a NULL argument.
 */
GHTTP_API GHTTP_Result ghttp_ws_deflate_server_negotiate(
    const GHTTP_WsParam * params, size_t count,
    const GHTTP_WsDeflateParams * policy, GHTTP_WsDeflateParams * agreed,
    int * accepted);

/**
 * Check a server's response against what the client offered.
 *
 * @param params The response's parameters.
 * @param count How many.
 * @param offered What the client offered.
 * @param[out] agreed What was agreed. Written when @p ok.
 * @param[out] ok 1 if the response is acceptable; 0 if the client must fail
 *   the connection: an unknown or repeated parameter, an invalid value,
 *   `client_max_window_bits` where none was offered, a window larger than
 *   offered, or an offered `server_no_context_takeover` or
 *   `server_max_window_bits` the response does not honour.
 * @return GHTTP_OK, or GHTTP_ERR_INVALID.
 */
GHTTP_API GHTTP_Result ghttp_ws_deflate_client_verify(
    const GHTTP_WsParam * params, size_t count,
    const GHTTP_WsDeflateParams * offered, GHTTP_WsDeflateParams * agreed,
    int * ok);

/**
 * Write the extension as it goes in a field: the name and its parameters,
 * NUL-terminated.
 *
 * @param params The parameters to write.
 * @param is_response 0 to write an offer (a client; includes the valueless
 *   `client_max_window_bits` when asked), 1 to write a response (the
 *   no-context-takeover flags and window sizes that are set).
 * @param[out] out At least ::GHTTP_WS_DEFLATE_TEXT_MAX octets.
 * @param cap Its size.
 * @param[out] len The length without the NUL; may be NULL.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument, a window outside 8
 *   to 15 or too small a buffer.
 */
GHTTP_API GHTTP_Result ghttp_ws_deflate_format(
    const GHTTP_WsDeflateParams * params, int is_response, char * out,
    size_t cap, size_t * len);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_WS_DEFLATE_H
