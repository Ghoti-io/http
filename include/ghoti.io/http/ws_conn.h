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
 * @file ws_conn.h
 *
 * A WebSocket connection: RFC 6455 sections 5 to 7 and the permessage-deflate
 * extension of RFC 7692, for a client or a server, as bytes in and bytes out.
 * No socket, TLS, clock, thread or event loop: the caller reads bytes from
 * wherever and gives them to ghttp_ws_conn_feed(), writes whatever
 * ghttp_ws_conn_output() holds to wherever, and supplies a clock reading
 * through ghttp_ws_conn_tick() if the per-interval limit is to renew.
 *
 * The connection starts after the opening handshake (ws_handshake.h) and does
 * not care what carried it: the bytes after an HTTP/1.1 request head, or the
 * DATA of an HTTP/2 stream.
 *
 * ### The loop
 *
 * @code
 * for (;;) {
 *   // 1. whatever is waiting to be sent
 *   size_t n; const uint8_t * out = ghttp_ws_conn_output(c, &n);
 *   if (n) { write_all(out, n); ghttp_ws_conn_output_consume(c, n); }
 *   // 2. what arrived
 *   size_t off = 0;
 *   do {
 *     size_t used; GHTTP_WsEvent ev;
 *     GHTTP_Result r = ghttp_ws_conn_feed(c, buf + off, got - off, &used, &ev);
 *     if (r != GHTTP_OK) { write the Close in the output, then close }
 *     off += used;
 *     switch (ev.type) { ... }
 *   } while (ev.type != GHTTP_WS_EVENT_NEED_MORE);
 * }
 * @endcode
 *
 * ### Messages
 *
 * A message is delivered whole, after reassembly from its fragments and, when
 * permessage-deflate was agreed, after decompression: one event per message,
 * the same however the input was cut. A text message has been checked to be
 * valid UTF-8 (a code point may span fragments and feeds), and the check runs
 * on the octets as they arrive, so an invalid message is refused at the
 * octet and not at its end. The size of a message is capped by
 * GHTTP_WsLimits::max_message_bytes after decompression. A message larger
 * than that cannot be received: this codec has no streaming delivery.
 *
 * ### Errors and closing
 *
 * A **connection error** is returned by ghttp_ws_conn_feed(): GHTTP_ERR_CORRUPT
 * for a protocol violation, GHTTP_ERR_LIMIT when a limit was reached,
 * GHTTP_ERR_OOM. The codec has already queued the Close frame carrying the
 * close code (RFC 6455 section 7.4; 1002 protocol error, 1007 invalid
 * payload data, 1008 policy violation, 1009 message too big, 1011
 * internal); ghttp_ws_conn_error() says which. The connection is failed
 * for good: it returns the same error to every later feed and sends nothing
 * more. The caller writes the output and closes the transport.
 *
 * Queueing that Close is best effort: with no memory to build it the error
 * is still returned and the output has no Close, which is no worse for a
 * caller that closes the transport on the error as it must.
 *
 * The close handshake (section 7.1): a Close from the peer is reported as
 * GHTTP_WS_EVENT_CLOSE and answered with a Close that has been queued; a
 * Close this endpoint starts with ghttp_ws_conn_close() waits for the peer's.
 * When both have gone the state is GHTTP_WS_STATE_CLOSED and the server closes
 * the transport (section 7.1.1). The peer's Close is the end of what it may say:
 * whatever follows it, in the same read or a later one, is **left unread**
 * (`consumed` stays 0, no event, no error), so a closure that completed stays
 * clean; a caller that wants to know sees that it was not all consumed.
 *
 * ### Pongs
 *
 * A Pong answers the most recent Ping (RFC 6455 section 5.5.3 allows it): when
 * a Ping arrives while the Pong for an earlier one has not yet begun to be
 * written, that Pong is replaced, so a peer that Pings faster than the output
 * is taken cannot fill the queue with Pongs. Every Ping is still reported. A
 * caller that takes the output after every event, as the loop above does, sees
 * one Pong per Ping.
 *
 * ### Extension seams
 *
 * Extensions other than permessage-deflate are negotiated through the hook of
 * ws_handshake.h; the reserved bits one claims are let through and reported
 * in GHTTP_WsEvent::rsv. A connection is used from one thread at a time.
 */

#ifndef GHOTI_IO_GHTTP_WS_CONN_H
#define GHOTI_IO_GHTTP_WS_CONN_H

#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/ws_frame.h>
#include <ghoti.io/http/ws_handshake.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which end this is. A client masks what it sends and refuses masked frames; a server the reverse. */
typedef enum GHTTP_WsRole {
  GHTTP_WS_CLIENT,
  GHTTP_WS_SERVER
} GHTTP_WsRole;

/** What kind of message is sent. */
typedef enum GHTTP_WsMessageType {
  GHTTP_WS_MESSAGE_TEXT = 1,
  GHTTP_WS_MESSAGE_BINARY = 2
} GHTTP_WsMessageType;

/** What a call to ghttp_ws_conn_feed() reports. */
typedef enum GHTTP_WsEventType {
  /** Nothing more can be reported until more bytes arrive. */
  GHTTP_WS_EVENT_NEED_MORE = 0,
  /** A text message: `data`, valid UTF-8, valid until the next feed. */
  GHTTP_WS_EVENT_TEXT,
  /** A binary message: `data`, valid until the next feed. */
  GHTTP_WS_EVENT_BINARY,
  /** A Ping arrived and its Pong is queued; `data` is its payload. */
  GHTTP_WS_EVENT_PING,
  /** A Pong arrived; `data` is its payload. */
  GHTTP_WS_EVENT_PONG,
  /**
   * The peer's Close: `code` (1005 if it carried none) and `data`, the reason.
   * If this endpoint had not sent a Close, the reply is queued.
   */
  GHTTP_WS_EVENT_CLOSE
} GHTTP_WsEventType;

/** What ghttp_ws_conn_feed() reports. Filled in whole on every call that returns GHTTP_OK. */
typedef struct GHTTP_WsEvent {
  size_t size;  ///< sizeof(GHTTP_WsEvent) as the library wrote it.
  GHTTP_WsEventType type;
  const uint8_t * data;  ///< The message, the payload or the close reason; valid until the next feed.
  size_t data_len;
  uint16_t code;         ///< CLOSE: the status code; 1005 when the frame had none.
  int compressed;        ///< TEXT, BINARY: the message arrived compressed.
  uint32_t fragments;    ///< TEXT, BINARY: the frames it arrived in.
  uint8_t rsv;           ///< TEXT, BINARY: the RSV2 and RSV3 bits of its first frame, as an extension claimed them.
  uint64_t reserved[4];
} GHTTP_WsEvent;

/** Where the closing handshake stands. */
typedef enum GHTTP_WsState {
  GHTTP_WS_STATE_OPEN,     ///< Neither side has sent a Close.
  GHTTP_WS_STATE_CLOSING,  ///< One Close has gone, in either direction, and the other has not.
  GHTTP_WS_STATE_CLOSED,   ///< Both have: the transport may be closed.
  GHTTP_WS_STATE_FAILED    ///< A connection error ended it; see ghttp_ws_conn_error().
} GHTTP_WsState;

/** A WebSocket connection. Opaque. */
typedef struct GHTTP_WsConn GHTTP_WsConn;

/** A source of random octets for masking keys. */
typedef GHTTP_Result (*GHTTP_WsRandomFn)(void * ctx, void * out, size_t n);

/**
 * Create a connection.
 *
 * @param allocator The allocator, or NULL for the default; the compressor
 *   uses it too.
 * @param role Which end.
 * @param limits The limits, or NULL for the defaults. Copied.
 * @param negotiated What the handshake agreed, or NULL for no extension.
 * @param[out] out The connection; free with ghttp_ws_conn_destroy().
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL @p out or limits that cannot
 *   work (a zero where the connection needs room); GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_ws_conn_create(const GHTTP_Allocator * allocator,
    GHTTP_WsRole role, const GHTTP_WsLimits * limits,
    const GHTTP_WsNegotiated * negotiated, GHTTP_WsConn ** out);

/** Free a connection. NULL is ignored. */
GHTTP_API void ghttp_ws_conn_destroy(GHTTP_WsConn * conn);

/**
 * Replace the source of masking keys, which is the kernel generator. A client
 * must use a source an attacker cannot predict (RFC 6455 section 10.3); this is
 * for a test that needs reproducible bytes.
 */
GHTTP_API void ghttp_ws_conn_set_random(
    GHTTP_WsConn * conn, GHTTP_WsRandomFn fn, void * ctx);

/**
 * Messages shorter than this are sent uncompressed when permessage-deflate is
 * agreed (ghttp_ws_conn_send_message() only). Default 0: compress them all.
 */
GHTTP_API void ghttp_ws_conn_set_compress_min(GHTTP_WsConn * conn, size_t bytes);

/**
 * Give the connection bytes from the peer; it uses a prefix of them and
 * reports at most one event.
 *
 * Call again with the rest until the event is GHTTP_WS_EVENT_NEED_MORE. The
 * events, and the output queued, are the same however the input is cut.
 *
 * @param conn The connection.
 * @param data The bytes from the peer; may be NULL if @p len is 0.
 * @param len How many.
 * @param[out] consumed Octets used. Written on every return.
 * @param[out] event What happened. Written on every return: zeroed (type
 *   GHTTP_WS_EVENT_NEED_MORE, size set) unless the call reported something.
 * @return GHTTP_OK, or the connection error (see the file comment). Once an
 *   error has been returned it is returned again and nothing is consumed.
 *   GHTTP_ERR_INVALID (a NULL argument) is the one return that is not sticky.
 */
GHTTP_API GHTTP_Result ghttp_ws_conn_feed(GHTTP_WsConn * conn, const void * data,
    size_t len, size_t * consumed, GHTTP_WsEvent * event);

/**
 * The input has ended. GHTTP_OK if the closing handshake completed;
 * GHTTP_ERR_CORRUPT otherwise: the transport was closed without it (close
 * code 1006, which is never sent). Queues nothing. It does not say whether the
 * connection was still open or had failed: both are abnormal ends; ask
 * ghttp_ws_conn_state() (GHTTP_WS_STATE_FAILED, or OPEN or CLOSING) and
 * ghttp_ws_conn_error() for which.
 */
GHTTP_API GHTTP_Result ghttp_ws_conn_finish(const GHTTP_WsConn * conn);

/** The connection error that ended it: its close code and a static reason; zero and "" if none. */
GHTTP_API GHTTP_Result ghttp_ws_conn_error(
    const GHTTP_WsConn * conn, uint16_t * code, const char ** reason);

/** Where the closing handshake stands. */
GHTTP_API GHTTP_WsState ghttp_ws_conn_state(const GHTTP_WsConn * conn);

/** Whether permessage-deflate is in use on this connection. */
GHTTP_API int ghttp_ws_conn_deflate_active(const GHTTP_WsConn * conn);

/** The clock: milliseconds from any fixed starting point. Renews the per-interval count. */
GHTTP_API void ghttp_ws_conn_tick(GHTTP_WsConn * conn, uint64_t now_ms);

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/** The bytes waiting to be sent, and how many. Valid until the next call that queues output. */
GHTTP_API const uint8_t * ghttp_ws_conn_output(const GHTTP_WsConn * conn, size_t * len);

/** The first @p n octets of the output were sent. */
GHTTP_API void ghttp_ws_conn_output_consume(GHTTP_WsConn * conn, size_t n);

/** Octets queued and not yet consumed. */
GHTTP_API size_t ghttp_ws_conn_output_size(const GHTTP_WsConn * conn);

// ---------------------------------------------------------------------------
// Sending. All of these queue output; none blocks.
// ---------------------------------------------------------------------------

/**
 * Send one message in one frame, compressed if permessage-deflate was agreed
 * and the message is at least the threshold of ghttp_ws_conn_set_compress_min().
 *
 * @param conn The connection.
 * @param type Text or binary.
 * @param data The message; may be NULL if @p len is 0.
 * @param len Its length, at most GHTTP_WsLimits::max_message_bytes.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a text message that is not UTF-8, a
 *   closing or failed connection, a fragmented message in progress or a NULL
 *   argument; GHTTP_ERR_LIMIT if the message or the queue would exceed its
 *   limit (nothing is queued); GHTTP_ERR_IO if the kernel generator failed;
 *   GHTTP_ERR_OOM, after which the connection is failed unless nothing had
 *   been done yet.
 */
GHTTP_API GHTTP_Result ghttp_ws_conn_send_message(GHTTP_WsConn * conn,
    GHTTP_WsMessageType type, const void * data, size_t len);

/**
 * Send part of a message as one frame. The first call of a message names its
 * type and the later ones must repeat it; the call with @p fin set ends the
 * message. Between fragments only control frames may be sent. A message sent
 * this way is compressed when permessage-deflate was agreed.
 *
 * Errors as ghttp_ws_conn_send_message().
 */
GHTTP_API GHTTP_Result ghttp_ws_conn_send_fragment(GHTTP_WsConn * conn,
    GHTTP_WsMessageType type, const void * data, size_t len, int fin);

/** Send a Ping with up to 125 octets of payload. The caller decides when; this codec has no keepalive. */
GHTTP_API GHTTP_Result ghttp_ws_conn_send_ping(
    GHTTP_WsConn * conn, const void * data, size_t len);

/** Send an unsolicited Pong, up to 125 octets. A Pong for a received Ping is queued by the codec itself. */
GHTTP_API GHTTP_Result ghttp_ws_conn_send_pong(
    GHTTP_WsConn * conn, const void * data, size_t len);

/**
 * Start the closing handshake (section 7.1.2). Once only.
 *
 * @param conn The connection.
 * @param code A code from ghttp_ws_close_code_is_valid(), or 0 to send a Close
 *   with no body (then @p reason must be empty).
 * @param reason UTF-8, at most 123 octets; may be NULL if @p reason_len is 0.
 * @param reason_len Its length.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a bad code, a reason that is too
 *   long or not UTF-8, or a connection that has sent a Close already or has
 *   failed; GHTTP_ERR_LIMIT; GHTTP_ERR_IO; GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_ws_conn_close(GHTTP_WsConn * conn, uint16_t code,
    const void * reason, size_t reason_len);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_WS_CONN_H
