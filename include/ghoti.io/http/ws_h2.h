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
 * @file ws_h2.h
 *
 * A WebSocket over an HTTP/2 stream: the adapter between a tunnel stream of
 * h2conn.h and a ::GHTTP_WsConn (RFC 8441). It moves bytes and the end of the
 * stream and nothing else: the DATA of the stream is what the WebSocket
 * connection is fed, and what the connection has queued is sent as DATA as the
 * windows allow. The connection itself is used unchanged, so the codec cannot
 * tell this carrier from an upgraded HTTP/1.1 connection - and an HTTP/3
 * carrier (RFC 9220) would use the same two functions.
 *
 * ### Opening
 *
 * @code
 * // server: the HEADERS event of a stream with ghttp_ws_is_h2_request()
 * GHTTP_WsServerResult r;
 * ghttp_ws_server_handshake_h2(ghttp_h2_conn_request(h2), &options, response, &r);
 * ghttp_h2_conn_send_response(h2, ev.stream_id, response, !r.accepted);
 * if (r.accepted) {
 *   ghttp_ws_conn_create(NULL, GHTTP_WS_SERVER, NULL, &r.negotiated, &ws);
 *   ghttp_ws_h2_create(NULL, h2, ev.stream_id, ws, &adapter);
 *   ghttp_ws_h2_input(adapter, &ev);      // the HEADERS event too (see below)
 * }
 * // client: ghttp_ws_client_handshake_create_h2(), ghttp_h2_conn_send_request()
 * // with the request, and, at the HEADERS event for the response,
 * // ghttp_ws_client_handshake_finish_h2(), ghttp_ws_conn_create() with the
 * // client role and the same ghttp_ws_h2_create().
 * @endcode
 *
 * ### The loop
 *
 * @code
 * // for every event the h2 connection reports, after ghttp_h2_conn_feed():
 * ghttp_ws_h2_input(adapter, &ev);              // ignores other streams
 * GHTTP_WsEvent we;
 * do {
 *   ghttp_ws_h2_next(adapter, &we);             // a message, a Ping, a Close...
 *   // use `we`, answer with ghttp_ws_conn_send_message() and the like
 * } while (we.type != GHTTP_WS_EVENT_NEED_MORE);
 * ghttp_ws_h2_pump(adapter);                    // queued WebSocket bytes -> DATA
 * // then write ghttp_h2_conn_output() to the transport, as always
 * @endcode
 *
 * The data of a DATA event is valid only until the next call to
 * ghttp_h2_conn_feed(), so ghttp_ws_h2_next() must be called until it reports
 * GHTTP_WS_EVENT_NEED_MORE before that.
 *
 * ### How the stream ends
 *
 * The closing handshake of RFC 6455 section 7 runs in the DATA. When it has
 * completed (both Closes have gone) and the queued bytes have been sent, the
 * adapter ends its side of the stream with END_STREAM; the peer's END_STREAM
 * after its Close is the normal end. END_STREAM from the peer **before** the
 * handshake has completed, or a RST_STREAM at any time, is an abnormal closure:
 * ghttp_ws_h2_status() says ::GHTTP_WS_H2_ABNORMAL with code 1006 (RFC 6455
 * section 7.1.5, a code that is never sent), and, for a reset, the code the peer
 * gave. A half-close that is not preceded by a Close is answered by ending the
 * adapter's side too, so the stream is not left half-open. A connection error
 * of the WebSocket codec (a protocol violation: the Close it queued carries its
 * code) ends the same way, with that code.
 *
 * Flow control is the h2 connection's: ghttp_ws_h2_pump() sends what the
 * stream's and the connection's windows allow and keeps the rest queued in
 * the WebSocket connection; call it again after a GHTTP_H2_EVENT_WINDOW_UPDATE
 * (ghttp_ws_h2_input() does so itself for one that concerns the stream or the
 * connection). Manual receive flow control (GHTTP_H2Limits::manual_flow_control)
 * stays the caller's.
 *
 * A connection is used from one thread at a time.
 */

#ifndef GHOTI_IO_GHTTP_WS_H2_H
#define GHOTI_IO_GHTTP_WS_H2_H

#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/h2conn.h>
#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/ws_conn.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The adapter for one stream. Opaque. */
typedef struct GHTTP_WsH2 GHTTP_WsH2;

/** How the stream's WebSocket stands. */
typedef enum GHTTP_WsH2State {
  GHTTP_WS_H2_OPEN,      ///< Not over.
  GHTTP_WS_H2_CLOSED,    ///< The closing handshake completed: a normal closure.
  GHTTP_WS_H2_ABNORMAL   ///< Ended without it, or failed; see GHTTP_WsH2Status::code.
} GHTTP_WsH2State;

/** What ghttp_ws_h2_status() reports. */
typedef struct GHTTP_WsH2Status {
  size_t size;  ///< sizeof(GHTTP_WsH2Status); set by the library.
  GHTTP_WsH2State state;
  /**
   * ABNORMAL: the close code for the application. 1006 when the stream ended
   * or was reset with no closing handshake; the code the codec failed with
   * (1002, 1007, 1009, ...) when it did. 0 otherwise.
   */
  uint16_t code;
  int remote_ended;     ///< The peer's END_STREAM has been seen and read.
  int local_ended;      ///< This end's END_STREAM has been sent.
  int reset;            ///< The stream was reset, by the peer or this endpoint.
  uint32_t reset_code;  ///< The RST_STREAM error code, when @c reset.
  uint64_t reserved[4];
} GHTTP_WsH2Status;

/**
 * Join a tunnel stream to a WebSocket connection. Neither is owned: destroy the
 * adapter first, then the connection and the stream's owner as usual. Create it
 * after the handshake's response has gone (a server) or been read (a client),
 * since DATA may not be sent before then.
 *
 * @param allocator The allocator, or NULL for the default.
 * @param h2 The HTTP/2 connection.
 * @param stream_id The stream: it must be active and in tunnel mode.
 * @param ws The WebSocket connection for this stream.
 * @param[out] out The adapter; free with ghttp_ws_h2_destroy().
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument or a stream that is not
 *   an active tunnel; GHTTP_ERR_OOM.
 */
GHTTP_API GHTTP_Result ghttp_ws_h2_create(const GHTTP_Allocator * allocator,
    GHTTP_H2Conn * h2, uint32_t stream_id, GHTTP_WsConn * ws, GHTTP_WsH2 ** out);

/** Free the adapter. NULL is ignored. */
GHTTP_API void ghttp_ws_h2_destroy(GHTTP_WsH2 * adapter);

/**
 * Take an event of the h2 connection. Events for other streams, and the kinds
 * that carry nothing for a tunnel, are ignored: pass them all. For this stream:
 * DATA is held for ghttp_ws_h2_next(); a HEADERS event with `end_stream` (the
 * peer opened the stream and ended it) and a DATA event with `end_stream` are
 * the peer's END_STREAM; STREAM_RESET, STREAM_ERROR and STREAM_UNPROCESSED end
 * the stream abnormally; WINDOW_UPDATE (this stream or the connection) pumps.
 *
 * @return GHTTP_OK; GHTTP_ERR_INVALID for a NULL argument or a DATA event
 *   while the data of the last one has not been read to the end; whatever
 *   ghttp_ws_h2_pump() returns for a WINDOW_UPDATE.
 */
GHTTP_API GHTTP_Result ghttp_ws_h2_input(GHTTP_WsH2 * adapter, const GHTTP_H2Event * event);

/**
 * Feed the held data to the WebSocket connection: the same contract as
 * ghttp_ws_conn_feed() with the same ::GHTTP_WsEvent, one event per call, and
 * GHTTP_WS_EVENT_NEED_MORE when the data is used up. A connection error is
 * returned (GHTTP_ERR_CORRUPT, GHTTP_ERR_LIMIT, GHTTP_ERR_OOM) and is sticky;
 * the Close the codec owes is queued, so call ghttp_ws_h2_pump() to send it.
 *
 * After the last of a stream's data has been read, the peer's END_STREAM (if it
 * came with that data) takes effect.
 */
GHTTP_API GHTTP_Result ghttp_ws_h2_next(GHTTP_WsH2 * adapter, GHTTP_WsEvent * event);

/**
 * Move what the WebSocket connection has queued into DATA frames, as far as the
 * windows and the h2 connection's output limit allow; end the stream with
 * END_STREAM when the WebSocket has closed, failed or been half-closed by the
 * peer and everything queued has gone. Does nothing once the stream is gone.
 *
 * @return GHTTP_OK (also when the windows held something back: it stays
 *   queued); a connection error of the h2 connection.
 */
GHTTP_API GHTTP_Result ghttp_ws_h2_pump(GHTTP_WsH2 * adapter);

/** How the stream's WebSocket stands. */
GHTTP_API GHTTP_Result ghttp_ws_h2_status(
    const GHTTP_WsH2 * adapter, GHTTP_WsH2Status * status);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_WS_H2_H
