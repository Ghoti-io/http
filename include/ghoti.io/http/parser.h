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
 * The incremental HTTP/1.1 parser (RFC 9112).
 *
 * The caller owns the I/O. It reads whatever bytes arrive, in pieces of any
 * size, and hands them to @ref ghttp_parser_feed; the parser reports one
 * event at a time. The events, and the head, headers, body bytes and trailers
 * behind them, are the same however the input is split. A parser reads one
 * direction of one connection: a request parser for the server side, a
 * response parser for the client side, one message after another.
 *
 * @code
 * size_t off = 0;
 * do {
 *   size_t used;
 *   GHTTP_Event ev;
 *   GHTTP_Result r = ghttp_parser_feed(p, buf + off, n - off, &used, &ev);
 *   if (r != GHTTP_OK) { ... close the connection ... }
 *   off += used;
 *   switch (ev) { ... }
 * } while (ev != GHTTP_EVENT_NEED_MORE);
 * @endcode
 *
 * Framing follows RFC 9112 section 6: Content-Length, chunked with trailers,
 * and, for a response, a body that runs to the end of the connection. Messages
 * with an ambiguous length are refused and never guessed at. Section "which
 * rules are enforced" of documentation/rfc9112.md lists what is and is not
 * checked.
 */

#ifndef GHOTI_IO_GHTTP_PARSER_H
#define GHOTI_IO_GHTTP_PARSER_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief An incremental parser. Opaque. */
typedef struct GHTTP_Parser GHTTP_Parser;

/** @brief Which direction a parser reads. */
typedef enum {
  GHTTP_PARSE_REQUEST,  ///< Requests: the server side of a connection.
  GHTTP_PARSE_RESPONSE  ///< Responses: the client side of a connection.
} GHTTP_ParserKind;

/** @brief What one call to @ref ghttp_parser_feed found. */
typedef enum {
  /** The input is used up and nothing is pending; supply more bytes. */
  GHTTP_EVENT_NEED_MORE = 0,
  /**
   * A message head is complete. Read it with @ref ghttp_parser_request or
   * @ref ghttp_parser_response, and the framing with
   * @ref ghttp_parser_framing.
   */
  GHTTP_EVENT_HEAD,
  /** Body bytes are available from @ref ghttp_parser_body. */
  GHTTP_EVENT_BODY,
  /**
   * The message is complete, trailers included (@ref ghttp_parser_trailers).
   * Whatever follows in the input is the next message.
   */
  GHTTP_EVENT_END
} GHTTP_Event;

/** @brief How the length of the current message body is determined. */
typedef enum {
  GHTTP_FRAMING_NONE,    ///< No body: a request without a length, HEAD, 1xx, 204, 304.
  GHTTP_FRAMING_LENGTH,  ///< Content-Length.
  GHTTP_FRAMING_CHUNKED, ///< Transfer-Encoding ending in chunked.
  GHTTP_FRAMING_CLOSE    ///< A response body that ends when the connection does.
} GHTTP_Framing;

/**
 * @brief What the current message asks for beyond HTTP/1.1 messaging.
 *
 * Only reported. The parser does not perform an upgrade or a tunnel.
 */
typedef enum {
  GHTTP_UPGRADE_NONE,    ///< An ordinary message.
  GHTTP_UPGRADE_CONNECT, ///< A CONNECT request, or a 2xx response to one.
  GHTTP_UPGRADE_UPGRADE  ///< A request offering Upgrade, or a 101 response.
} GHTTP_Upgrade;

/**
 * @brief Create a parser.
 *
 * @param kind Requests or responses.
 * @param limits The caps, copied; NULL means @ref ghttp_limits_default.
 * @param allocator The allocator to use, or NULL for the default. It must
 *   outlive the parser.
 * @param[out] out Receives the parser, written only on success.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL @p out or an unknown kind,
 *   GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_parser_create(GHTTP_ParserKind kind,
    const GHTTP_Limits * limits, const GHTTP_Allocator * allocator,
    GHTTP_Parser ** out);

/** @brief Free a parser and everything it holds. NULL is ignored. */
GHTTP_API void ghttp_parser_destroy(GHTTP_Parser * parser);

/**
 * @brief Tell a response parser which request the next response answers.
 *
 * A response to HEAD has no body whatever its headers say, and a 2xx response
 * to CONNECT is the start of a tunnel. The framing of a response is decided
 * when its head completes, so call this after the previous message's
 * @ref GHTTP_EVENT_END and before the next head's last byte is fed. The
 * method applies until a final (non-1xx) response ends and then is forgotten:
 * a parser that is never told treats every response as one to a GET.
 *
 * @param parser A response parser.
 * @param method The request method, NUL-terminated.
 * @return GHTTP_OK, GHTTP_ERR_INVALID for a NULL argument or a request parser.
 */
GHTTP_API GHTTP_Result ghttp_parser_expect_response_to(
    GHTTP_Parser * parser, const char * method);

/**
 * @brief Feed bytes and receive at most one event.
 *
 * The parser uses some prefix of the input and stops at the first event.
 * Keep calling with the unused remainder until @ref GHTTP_EVENT_NEED_MORE:
 * a head, some body bytes or the end of a message each ask for another call
 * even when the input is used up. Bytes after a message's end are left for
 * the next call, which begins the next message.
 *
 * Any error other than GHTTP_ERR_INVALID is permanent: the stream is not
 * recoverable, every later call returns the same error, and the connection
 * should be closed. After a response that starts a tunnel or an upgrade
 * (@ref ghttp_parser_upgrade at its head: a 101, or a 2xx to CONNECT) the
 * parser reads nothing more: this returns GHTTP_EVENT_NEED_MORE having used
 * nothing, and the bytes it did not use belong to the other protocol.
 *
 * @param parser The parser.
 * @param data The bytes; may be NULL when @p len is zero.
 * @param len How many.
 * @param[out] consumed Receives how many bytes were used.
 * @param[out] event Receives the event.
 * @return GHTTP_OK; GHTTP_ERR_CORRUPT for bytes RFC 9112 forbids or this
 *   library refuses to guess at; GHTTP_ERR_LIMIT for a cap exceeded;
 *   GHTTP_ERR_UNSUPPORTED for an HTTP version other than 1.0 and 1.1;
 *   GHTTP_ERR_OOM; GHTTP_ERR_INVALID for a NULL argument.
 */
GHTTP_API GHTTP_Result ghttp_parser_feed(GHTTP_Parser * parser,
    const void * data, size_t len, size_t * consumed, GHTTP_Event * event);

/**
 * @brief Tell the parser the peer closed its end of the stream.
 *
 * A response body with @ref GHTTP_FRAMING_CLOSE ends here: @p event is
 * @ref GHTTP_EVENT_END. Between messages the end of input is clean and
 * @p event is @ref GHTTP_EVENT_NEED_MORE. Anywhere else the message was cut
 * short and this returns GHTTP_ERR_CORRUPT: a truncated body is never
 * reported as a complete one.
 *
 * @param parser The parser.
 * @param[out] event Receives the event.
 * @return GHTTP_OK, GHTTP_ERR_CORRUPT, a stored earlier error,
 *   GHTTP_ERR_INVALID for a NULL argument.
 */
GHTTP_API GHTTP_Result ghttp_parser_finish(
    GHTTP_Parser * parser, GHTTP_Event * event);

/**
 * @brief The request head, after @ref GHTTP_EVENT_HEAD.
 *
 * Valid until the next head is parsed or the parser is destroyed. NULL for a
 * response parser or before the first head.
 */
GHTTP_API const GHTTP_Request * ghttp_parser_request(const GHTTP_Parser * parser);

/** @brief The response head; see @ref ghttp_parser_request. */
GHTTP_API const GHTTP_Response * ghttp_parser_response(
    const GHTTP_Parser * parser);

/**
 * @brief The body bytes of the last @ref GHTTP_EVENT_BODY.
 *
 * They point into the buffer given to the call that reported them, are
 * already free of chunk framing, and are valid until the next call.
 */
GHTTP_API void ghttp_parser_body(
    const GHTTP_Parser * parser, const void ** data, size_t * len);

/**
 * @brief The trailer fields, after @ref GHTTP_EVENT_END of a chunked body.
 *
 * Empty for any other message. Valid until the next message's head.
 */
GHTTP_API const GHTTP_Headers * ghttp_parser_trailers(
    const GHTTP_Parser * parser);

/** @brief How the current message's body is framed. */
GHTTP_API GHTTP_Framing ghttp_parser_framing(const GHTTP_Parser * parser);

/** @brief Whether the current message is a CONNECT or upgrade. */
GHTTP_API GHTTP_Upgrade ghttp_parser_upgrade(const GHTTP_Parser * parser);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_PARSER_H
