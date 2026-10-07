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
 * @file ws_handshake.h
 *
 * The WebSocket opening handshake over HTTP/1.1: RFC 6455 section 4, with the
 * subprotocol of section 1.9 and the extension negotiation of section 9.
 *
 * Both functions work on the message objects the parser produces and the
 * writer takes, so the flow is
 *
 * @code
 * // server
 * GHTTP_WsServerResult r;
 * ghttp_ws_server_handshake(request, &options, response, &r);
 * ghttp_write_response_head(out, response);       // 101, or the refusal
 * if (r.accepted) {
 *   ghttp_ws_conn_create(NULL, GHTTP_WS_SERVER, NULL, &r.negotiated, &conn);
 *   // from here on the bytes after the request head go to
 *   // ghttp_ws_conn_feed(), and ghttp_ws_conn_output() goes to the socket
 * }
 * @endcode
 *
 * The handshake needs no state on the server; a client keeps a
 * ::GHTTP_WsClientHandshake from building its request to checking the
 * response, because the key it sent decides the accept value it must see.
 *
 * Nothing about the connection is specific to HTTP/1.1: it takes only the
 * agreed ::GHTTP_WsNegotiated, and the permessage-deflate negotiation
 * (ws_deflate.h) takes the parameters of an offer, so a handshake of another
 * kind (the Extended CONNECT of RFC 8441) builds the same things and reuses
 * both.
 *
 * Policy that is not the codec's: an Origin check (a server that serves
 * browsers must apply one, to refuse cross-site WebSocket hijacking; the
 * request is the caller's to inspect before it calls this) and authentication.
 */

#ifndef GHOTI_IO_GHTTP_WS_HANDSHAKE_H
#define GHOTI_IO_GHTTP_WS_HANDSHAKE_H

#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include <ghoti.io/http/ws_deflate.h>
#include <ghoti.io/http/ws_frame.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The GUID of RFC 6455 section 1.3 that the accept value is derived with. */
#define GHTTP_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
/** The only version of the protocol this codec speaks. */
#define GHTTP_WS_VERSION 13
/** The length of a Sec-WebSocket-Key: sixteen octets in base64. */
#define GHTTP_WS_KEY_LEN 24u
/** The length of a Sec-WebSocket-Accept: a SHA-1 in base64. */
#define GHTTP_WS_ACCEPT_LEN 28u
/** The longest subprotocol name the negotiated result holds. */
#define GHTTP_WS_MAX_SUBPROTOCOL 127u
/** The longest reply text an extension hook may give. */
#define GHTTP_WS_EXTENSION_TEXT_MAX 256u

/** The reserved bits an extension may claim for itself, as they sit in the first frame octet. */
enum {
  GHTTP_WS_RSV1 = 0x40,
  GHTTP_WS_RSV2 = 0x20,
  GHTTP_WS_RSV3 = 0x10
};

/** What a handshake agreed, which is everything the connection needs from it. */
typedef struct GHTTP_WsNegotiated {
  size_t size;  ///< sizeof(GHTTP_WsNegotiated); set by _default().
  /** permessage-deflate was agreed. */
  int deflate;
  /** The agreed parameters; meaningful when @c deflate. */
  GHTTP_WsDeflateParams deflate_params;
  /** The chosen subprotocol, NUL-terminated; "" for none. */
  char subprotocol[GHTTP_WS_MAX_SUBPROTOCOL + 1];
  /**
   * RSV2 and RSV3 as the extensions accepted through the hook claimed them
   * (::GHTTP_WS_RSV2, ::GHTTP_WS_RSV3). The connection lets such a bit through
   * and reports it; what it means is the extension's.
   */
  uint8_t extension_rsv;
  uint64_t reserved[2];
} GHTTP_WsNegotiated;

/** Nothing negotiated: no extension, no subprotocol. */
GHTTP_API void ghttp_ws_negotiated_default(GHTTP_WsNegotiated * negotiated);

/**
 * What an extension hook is asked about.
 *
 * @c is_response is 0 at a server (a client's offer) and 1 at a client (the
 * server's chosen extension). Pointers are valid during the call.
 */
typedef struct GHTTP_WsExtensionOffer {
  size_t size;
  const char * name;               ///< The extension name, a token.
  size_t name_len;
  const GHTTP_WsParam * params;    ///< Its parameters, in order.
  size_t param_count;
  int is_response;
} GHTTP_WsExtensionOffer;

/** What an extension hook answers. */
typedef struct GHTTP_WsExtensionReply {
  size_t size;
  /** 1 to accept the offer (server) or the response (client). */
  int accept;
  /**
   * Server: the extension as it is to appear in the response, name and
   * parameters, NUL-terminated (for example `x-foo; level=2`), checked as one
   * extension in the grammar of RFC 6455 section 9.1 and not permessage-deflate;
   * anything else makes the handshake return GHTTP_ERR_INVALID. Ignored at a
   * client.
   */
  char text[GHTTP_WS_EXTENSION_TEXT_MAX];
  /** The RSV2 and RSV3 bits the extension uses; others are ignored. */
  uint8_t rsv;
} GHTTP_WsExtensionReply;

/**
 * The seam for further extensions. Called for every offer (server) or every
 * chosen extension (client) other than permessage-deflate, which is never
 * offered to it (a second offer, or one while the
 * use is disabled, is skipped). Without a hook such an extension is ignored by
 * a server and a failure at a client.
 *
 * @return GHTTP_OK with @c reply->accept set or clear. Any other value ends the
 *   handshake with that result and no response is built.
 */
typedef GHTTP_Result (*GHTTP_WsExtensionFn)(void * ctx,
    const GHTTP_WsExtensionOffer * offer, GHTTP_WsExtensionReply * reply);

/** Whether @p key is a Sec-WebSocket-Key: exactly 24 base64 characters decoding to 16 octets. */
GHTTP_API int ghttp_ws_key_is_valid(const char * key, size_t len);

/**
 * The Sec-WebSocket-Accept for a key (RFC 6455 section 4.2.2): the base64 of
 * the SHA-1 of the key followed by the GUID.
 *
 * @param key The key as the client sent it, 24 characters.
 * @param len Its length.
 * @param[out] accept ::GHTTP_WS_ACCEPT_LEN characters and a NUL.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a key that is not valid.
 */
GHTTP_API GHTTP_Result ghttp_ws_accept_key(
    const char * key, size_t len, char accept[GHTTP_WS_ACCEPT_LEN + 1]);

/**
 * Whether a request asks for a WebSocket: GET with `Upgrade` naming
 * `websocket` and `Connection` naming `upgrade`. For a server that serves
 * other things on the same path, to decide whether to call
 * ghttp_ws_server_handshake().
 */
GHTTP_API int ghttp_ws_is_upgrade_request(const GHTTP_Request * request);

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/** What a server accepts. Initialise with ghttp_ws_server_options_default(). */
typedef struct GHTTP_WsServerOptions {
  size_t size;  ///< sizeof(GHTTP_WsServerOptions); set by _default().
  /** The subprotocols served, in order of preference; the first one the client offered is chosen. */
  const char * const * subprotocols;
  size_t subprotocol_count;
  /** Negotiate permessage-deflate if the client offers it. Default 0. */
  int enable_deflate;
  /** What the server insists on if it does; see ghttp_ws_deflate_server_negotiate(). */
  GHTTP_WsDeflateParams deflate;
  /** Called for the other extensions; NULL ignores them. */
  GHTTP_WsExtensionFn extension_fn;
  void * extension_ctx;
  /** The limits; NULL for the defaults. */
  const GHTTP_WsLimits * limits;
  uint64_t reserved[4];
} GHTTP_WsServerOptions;

/** No subprotocol, no extension, the default limits. */
GHTTP_API void ghttp_ws_server_options_default(GHTTP_WsServerOptions * options);

/** The outcome of a server handshake. */
typedef struct GHTTP_WsServerResult {
  size_t size;
  /** 1 if the request is a valid WebSocket handshake and the response is the 101. */
  int accepted;
  /** The status of the response: 101, or 400, 405, 426 or 431. */
  int status;
  /** Why it was refused, static text; "" if accepted. */
  const char * reason;
  /** What was agreed, when accepted. */
  GHTTP_WsNegotiated negotiated;
  /**
   * The request's `Origin` field, parsed for the caller's policy: 1 if there was
   * exactly one (a second is refused with 400), and then a view of its value,
   * valid as long as the request is. This library does not judge it. A server
   * whose clients are browsers MUST: a page on any site may open a WebSocket to
   * it with the user's cookies (cross-site WebSocket hijacking, RFC 6455 section
   * 10.2), and the Origin is the only thing that says which site. Check it
   * against the sites that may, and refuse the rest before using the connection.
   */
  int has_origin;
  const char * origin;
  size_t origin_len;
} GHTTP_WsServerResult;

/**
 * Validate a client's handshake (RFC 6455 section 4.2.1) and build the
 * response.
 *
 * A valid request gets 101 with `Upgrade`, `Connection`, `Sec-WebSocket-Accept`
 * and, if chosen, `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions`. A
 * request that is not one gets a refusal to send instead: 405 for a method
 * other than GET, 426 with `Sec-WebSocket-Version: 13` for another version,
 * 431 for a handshake over @c max_handshake_bytes, 400 for the rest (HTTP/1.0,
 * a missing or repeated Host (RFC 6455 section 4.2.1), Origin, Key or Version, a missing Upgrade or Connection, a key that is not
 * 16 octets of base64, malformed Protocol or Extensions fields). Each
 * refusal closes the connection and has no body.
 *
 * @param request The parsed request.
 * @param options The options, or NULL for ghttp_ws_server_options_default().
 * @param response A response object (ghttp_response_create()); its status and
 *   fields are replaced.
 * @param[out] result The outcome.
 * @return GHTTP_OK whether or not the request was accepted (see @p result);
 *   GHTTP_ERR_INVALID for a NULL argument; GHTTP_ERR_OOM; anything an
 *   extension hook returned.
 */
GHTTP_API GHTTP_Result ghttp_ws_server_handshake(const GHTTP_Request * request,
    const GHTTP_WsServerOptions * options, GHTTP_Response * response,
    GHTTP_WsServerResult * result);

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/** What a client sends. Initialise with ghttp_ws_client_options_default(). */
typedef struct GHTTP_WsClientOptions {
  size_t size;  ///< sizeof(GHTTP_WsClientOptions); set by _default().
  /** The Host field: required. */
  const char * host;
  /** The request target; "/" if NULL. */
  const char * target;
  /** The Origin field; omitted if NULL. */
  const char * origin;
  /** Subprotocols to offer, in order of preference. */
  const char * const * subprotocols;
  size_t subprotocol_count;
  /** Offer permessage-deflate. Default 0. */
  int enable_deflate;
  /** The parameters to offer. */
  GHTTP_WsDeflateParams deflate;
  /**
   * Other extensions to offer, each as it is to appear in the field (name and
   * parameters). The server's choice among them goes through the hook.
   */
  const char * const * extensions;
  size_t extension_count;
  /** Called for the extensions the server chose other than permessage-deflate. */
  GHTTP_WsExtensionFn extension_fn;
  void * extension_ctx;
  /**
   * Sixteen octets to base64 as the key, for a test that needs the request to
   * be reproducible. NULL draws them from the kernel generator, which is what
   * every real use wants.
   */
  const uint8_t * nonce;
  /** The limits; NULL for the defaults. */
  const GHTTP_WsLimits * limits;
  uint64_t reserved[4];
} GHTTP_WsClientOptions;

/** No host (it must be set), no extension, the default limits. */
GHTTP_API void ghttp_ws_client_options_default(GHTTP_WsClientOptions * options);

/** The state a client keeps between its request and the response. */
typedef struct GHTTP_WsClientHandshake GHTTP_WsClientHandshake;

/** The outcome of checking a response. */
typedef struct GHTTP_WsClientResult {
  size_t size;
  /** 1 if the response is a valid 101 for this request. */
  int accepted;
  /** Why it was refused, static text; "" if accepted. */
  const char * reason;
  /** What was agreed, when accepted. */
  GHTTP_WsNegotiated negotiated;
} GHTTP_WsClientResult;

/**
 * Build the client's request (RFC 6455 section 4.1) and remember what the
 * response must say.
 *
 * @param allocator The allocator for the handshake state, or NULL.
 * @param options The options; @c host is required.
 * @param request A request object (ghttp_request_create()); its method,
 *   target, version and fields are replaced.
 * @param[out] out The state; free with ghttp_ws_client_handshake_destroy().
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument, a missing host or a
 *   value that cannot be a field; GHTTP_ERR_LIMIT if the request would exceed
 *   @c max_handshake_bytes; GHTTP_ERR_IO if the kernel generator failed;
 *   GHTTP_ERR_OOM. @p request may have been changed on failure.
 */
GHTTP_API GHTTP_Result ghttp_ws_client_handshake_create(
    const GHTTP_Allocator * allocator, const GHTTP_WsClientOptions * options,
    GHTTP_Request * request, GHTTP_WsClientHandshake ** out);

/** Free the state. NULL is ignored. */
GHTTP_API void ghttp_ws_client_handshake_destroy(GHTTP_WsClientHandshake * handshake);

/**
 * Check the server's response (RFC 6455 section 4.2.2 and the client's side of
 * section 9.1): status 101, `Upgrade`, `Connection`, the exact accept value,
 * at most one subprotocol and one of those offered, and only extensions that
 * were offered, with parameters the offer allows.
 *
 * @param handshake The state from ghttp_ws_client_handshake_create().
 * @param response The parsed response.
 * @param[out] result The outcome. A refused response is not an error of this
 *   call: the client closes the connection.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument; or whatever an
 *   extension hook returned.
 */
GHTTP_API GHTTP_Result ghttp_ws_client_handshake_finish(
    const GHTTP_WsClientHandshake * handshake, const GHTTP_Response * response,
    GHTTP_WsClientResult * result);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_WS_HANDSHAKE_H
