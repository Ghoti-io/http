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
 * @file h2conn.h
 *
 * An HTTP/2 connection: RFC 9113, for a client or a server, as bytes in and
 * bytes out. No socket, TLS, ALPN, clock or event loop: the caller reads bytes
 * from wherever and gives them to ghttp_h2_conn_feed(), writes whatever
 * ghttp_h2_conn_output() holds to wherever, and supplies a clock reading
 * through ghttp_h2_conn_tick() if the per-interval limits are to renew.
 *
 * Only the prior-knowledge start (RFC 9113 section 3.3) exists: the client
 * connection preface "PRI * HTTP/2.0", then SETTINGS. The `Upgrade: h2c` path
 * was removed from the protocol and is not here.
 *
 * ### The loop
 *
 * @code
 * for (;;) {
 *   // 1. whatever is waiting to be sent
 *   size_t n; const uint8_t * out = ghttp_h2_conn_output(c, &n);
 *   if (n) { write_all(out, n); ghttp_h2_conn_output_consume(c, n); }
 *   // 2. what arrived
 *   size_t off = 0;
 *   do {
 *     size_t used; GHTTP_H2Event ev;
 *     GHTTP_Result r = ghttp_h2_conn_feed(c, buf + off, got - off, &used, &ev);
 *     if (r != GHTTP_OK) { write the GOAWAY in the output, then close }
 *     off += used;
 *     switch (ev.type) { ... }
 *   } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
 * }
 * @endcode
 *
 * ### Errors
 *
 * A **connection error** is returned by ghttp_h2_conn_feed(): GHTTP_ERR_CORRUPT
 * for a protocol violation, GHTTP_ERR_LIMIT when a limit was reached,
 * GHTTP_ERR_OOM. The codec has already queued the GOAWAY (RFC 9113 section
 * 5.4.1) carrying the error code; ghttp_h2_conn_error() says which. The
 * connection is failed for good: it returns the same error to every later feed
 * and sends nothing more. The caller writes the output and closes.
 *
 * A **stream error** is an event (GHTTP_H2_EVENT_STREAM_ERROR) and the connection
 * carries on; the RST_STREAM has been queued. A reset by the peer is
 * GHTTP_H2_EVENT_STREAM_RESET.
 *
 * ### Flow control
 *
 * The codec tracks every window. The send functions refuse to write past one
 * (ghttp_h2_conn_send_data() returns how much it took), and
 * ghttp_h2_conn_send_window() says how much would be taken now; a
 * GHTTP_H2_EVENT_WINDOW_UPDATE says that a window opened. For receiving, credit
 * is returned automatically as data is delivered, unless
 * GHTTP_H2Limits::manual_flow_control is set, in which case the caller returns
 * it with ghttp_h2_conn_consume() as it uses the data.
 *
 * ### Extension seams
 *
 * Unknown frame types and unknown SETTINGS are not dropped: they go to the
 * handler set with ghttp_h2_conn_set_extension_handler(). A stream has a
 * GHTTP_H2StreamMode, so that CONNECT (and, later, the WebSocket of RFC 8441)
 * can carry opaque data past message framing. Server push and the
 * RFC 7540 priority scheme are each refused by one function in h2conn.c
 * (@c h2_refuse_push and @c h2_handle_priority). Settings, limits and the event
 * carry a size so that they can grow. documentation/rfc9113.md lists each.
 *
 * A connection is used from one thread at a time.
 */

#ifndef GHOTI_IO_GHTTP_H2CONN_H
#define GHOTI_IO_GHTTP_H2CONN_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/h2frame.h>
#include <ghoti.io/http/headers.h>
#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum GHTTP_H2Role {
  GHTTP_H2_CLIENT,
  GHTTP_H2_SERVER
} GHTTP_H2Role;

/** A set of the six SETTINGS of RFC 9113 section 6.5.2. */
typedef struct GHTTP_H2Settings {
  size_t size;  ///< sizeof(GHTTP_H2Settings); set by _default().
  uint32_t header_table_size;       ///< Default 4096.
  uint32_t enable_push;             ///< 0 or 1; default 1 (always 0 here).
  uint32_t max_concurrent_streams;  ///< Default UINT32_MAX: no limit.
  uint32_t initial_window_size;     ///< Default 65535.
  uint32_t max_frame_size;          ///< Default 16384.
  uint32_t max_header_list_size;    ///< Default UINT32_MAX: no limit.
  uint64_t reserved[4];
} GHTTP_H2Settings;

/** The protocol's initial values (section 6.5.2). */
GHTTP_API void ghttp_h2_settings_default(GHTTP_H2Settings * settings);

/**
 * What this endpoint advertises and what it will tolerate. Every unbounded
 * quantity is here, and each is a hard cap. Initialise with
 * ghttp_h2_limits_default().
 *
 * The ones that count frames count them per interval: the interval is
 * @c interval_ms of the clock the caller supplies with ghttp_h2_conn_tick().
 * A caller that never ticks gets a count that never renews, so the limit
 * applies to the connection's whole life: unsafe for a long-lived connection,
 * safe in the sense that nothing is left unbounded.
 */
typedef struct GHTTP_H2Limits {
  size_t size;  ///< sizeof(GHTTP_H2Limits); set by _default().

  // Advertised in SETTINGS.
  /** SETTINGS_MAX_FRAME_SIZE: the largest frame payload accepted, 16384 to 2^24 - 1. */
  size_t max_frame_size;
  /** SETTINGS_MAX_HEADER_LIST_SIZE, and the cap on a decoded header list (name + value + 32 per field). */
  size_t max_header_list_bytes;
  /** SETTINGS_HEADER_TABLE_SIZE: the decoder's dynamic table cap. */
  size_t max_table_size;
  /** SETTINGS_MAX_CONCURRENT_STREAMS: streams the peer may have open. */
  uint32_t max_concurrent_streams;
  /** SETTINGS_INITIAL_WINDOW_SIZE: each stream's receive window. */
  uint32_t initial_window_size;
  /** The connection's receive window, raised to this by a WINDOW_UPDATE at the start. At least 65535. */
  uint32_t connection_window;

  // Not advertised.
  /** The largest table the encoder will use, whatever the peer allows. */
  size_t max_encoder_table_size;
  /** Encoded octets of one header block (HEADERS plus CONTINUATIONs). */
  size_t max_header_block_bytes;
  /** CONTINUATION frames in one header block. */
  uint32_t max_continuation_frames;
  /** Fields in one header block. */
  size_t max_header_count;
  /** One decoded field name or value. */
  size_t max_field_bytes;
  /** Octets of message content in one stream (not applied to a tunnel). */
  uint64_t max_body_bytes;
  /** Octets held at once: a partial frame, a header block being gathered, and queued output. */
  size_t max_buffered_bytes;
  /** Streams open at once, both directions together. */
  uint32_t max_streams;
  /** Closed streams remembered so that late frames on them can be told from errors. */
  uint32_t max_closed_streams;

  // Per interval.
  /** SETTINGS frames (ACKs included). */
  uint32_t max_settings_per_interval;
  /** PING frames (ACKs included). */
  uint32_t max_ping_per_interval;
  /** RST_STREAM frames: the rapid-reset limit (CVE-2023-44487). */
  uint32_t max_rst_per_interval;
  /** DATA frames with no data and no END_STREAM, in a row. */
  uint32_t max_empty_data_frames;
  /** Length of an interval. */
  uint32_t interval_ms;

  /** Non-zero: window credit is returned only by ghttp_h2_conn_consume(). */
  int manual_flow_control;
  uint64_t reserved[4];
} GHTTP_H2Limits;

#define GHTTP_H2_DEFAULT_MAX_HEADER_LIST_BYTES 65536u
#define GHTTP_H2_DEFAULT_MAX_TABLE_SIZE 4096u
#define GHTTP_H2_DEFAULT_MAX_CONCURRENT_STREAMS 100u
#define GHTTP_H2_DEFAULT_MAX_HEADER_BLOCK_BYTES 65536u
#define GHTTP_H2_DEFAULT_MAX_CONTINUATION_FRAMES 16u
#define GHTTP_H2_DEFAULT_MAX_HEADER_COUNT 100u
#define GHTTP_H2_DEFAULT_MAX_FIELD_BYTES 16384u
#define GHTTP_H2_DEFAULT_MAX_BODY_BYTES ((uint64_t)16 << 20)
#define GHTTP_H2_DEFAULT_MAX_BUFFERED_BYTES ((size_t)1 << 20)
#define GHTTP_H2_DEFAULT_MAX_STREAMS 256u
#define GHTTP_H2_DEFAULT_MAX_CLOSED_STREAMS 256u
#define GHTTP_H2_DEFAULT_MAX_SETTINGS_PER_INTERVAL 32u
#define GHTTP_H2_DEFAULT_MAX_PING_PER_INTERVAL 32u
#define GHTTP_H2_DEFAULT_MAX_RST_PER_INTERVAL 200u
#define GHTTP_H2_DEFAULT_MAX_EMPTY_DATA_FRAMES 32u
#define GHTTP_H2_DEFAULT_INTERVAL_MS 10000u

GHTTP_API void ghttp_h2_limits_default(GHTTP_H2Limits * limits);

/** How a stream's DATA relates to message framing. */
typedef enum GHTTP_H2StreamMode {
  /** An HTTP message: content-length is checked against the DATA received. */
  GHTTP_H2_STREAM_MESSAGE,
  /** Opaque data (a CONNECT tunnel): no message framing is applied. */
  GHTTP_H2_STREAM_TUNNEL
} GHTTP_H2StreamMode;

typedef enum GHTTP_H2EventType {
  /** Nothing more can be reported until more bytes arrive. */
  GHTTP_H2_EVENT_NEED_MORE = 0,
  /** The peer's SETTINGS were applied and acknowledged; see ghttp_h2_conn_peer_settings(). */
  GHTTP_H2_EVENT_SETTINGS,
  /** The peer acknowledged this endpoint's SETTINGS. */
  GHTTP_H2_EVENT_SETTINGS_ACK,
  /**
   * A header section decoded and validated. A server gets the request
   * (ghttp_h2_conn_request()), a client a response
   * (ghttp_h2_conn_response()); `interim` marks a 1xx. A new stream starts here.
   */
  GHTTP_H2_EVENT_HEADERS,
  /** Message content: `data`, valid until the next feed. */
  GHTTP_H2_EVENT_DATA,
  /** A trailer section (ghttp_h2_conn_trailers()); the stream's last frame from the peer. */
  GHTTP_H2_EVENT_TRAILERS,
  /** The peer sent RST_STREAM with `error_code`. The stream is closed. */
  GHTTP_H2_EVENT_STREAM_RESET,
  /** This endpoint found a stream error, sent RST_STREAM with `error_code`, and closed the stream. */
  GHTTP_H2_EVENT_STREAM_ERROR,
  /** The peer sent GOAWAY: `last_stream_id`, `error_code`, `data` (debug). */
  GHTTP_H2_EVENT_GOAWAY,
  /** A PING arrived and its ACK is queued; `data` is its 8 octets. */
  GHTTP_H2_EVENT_PING,
  /** A PING ACK arrived; `data` is its 8 octets. */
  GHTTP_H2_EVENT_PING_ACK,
  /** A send window opened by `increment` on `stream_id` (0: the connection). */
  GHTTP_H2_EVENT_WINDOW_UPDATE
} GHTTP_H2EventType;

/** What ghttp_h2_conn_feed() reports. Filled in whole on every call that returns GHTTP_OK. */
typedef struct GHTTP_H2Event {
  size_t size;  ///< sizeof(GHTTP_H2Event) as the library wrote it.
  GHTTP_H2EventType type;
  uint32_t stream_id;
  int end_stream;           ///< HEADERS, DATA: the peer's last frame on the stream.
  int interim;              ///< HEADERS: a 1xx response.
  uint32_t error_code;      ///< STREAM_RESET, STREAM_ERROR, GOAWAY.
  uint32_t last_stream_id;  ///< GOAWAY.
  uint32_t increment;       ///< WINDOW_UPDATE.
  const uint8_t * data;     ///< DATA, GOAWAY, PING, PING_ACK.
  size_t data_len;
  /** HEADERS at a server: the request's :scheme and :authority, NUL-terminated,
   *  or NULL when absent. Valid until the next feed. */
  const char * scheme;
  const char * authority;
  uint64_t reserved[4];
} GHTTP_H2Event;

typedef struct GHTTP_H2Conn GHTTP_H2Conn;

GHTTP_API GHTTP_Result ghttp_h2_conn_create(const GHTTP_Allocator * allocator,
    GHTTP_H2Role role, const GHTTP_H2Limits * limits, GHTTP_H2Conn ** out);

GHTTP_API void ghttp_h2_conn_destroy(GHTTP_H2Conn * conn);

/**
 * Give the connection bytes from the peer; it uses a prefix of them and
 * reports at most one event.
 *
 * Call again with the rest until the event is GHTTP_H2_EVENT_NEED_MORE. The
 * events, and the output queued, are the same however the input is cut.
 *
 * @param[out] consumed Octets used.
 * @param[out] event What happened. Written on GHTTP_OK only.
 * @return GHTTP_OK, or the connection error (see the file comment). Once an
 *   error has been returned, it is returned again and nothing is consumed.
 */
GHTTP_API GHTTP_Result ghttp_h2_conn_feed(GHTTP_H2Conn * conn, const void * data,
    size_t len, size_t * consumed, GHTTP_H2Event * event);

/**
 * The peer closed its side: was that at a frame boundary?
 *
 * Call it when the transport reports end of input. GHTTP_OK if the input ended
 * between frames and no header block was left open, GHTTP_ERR_CORRUPT if it
 * ended inside a frame, inside the connection preface or between a HEADERS
 * frame and the CONTINUATION that never came (the connection was cut, not
 * closed: there is nothing to send the peer, so no GOAWAY is queued), and the
 * connection's own error if it has failed. Nothing is changed.
 */
GHTTP_API GHTTP_Result ghttp_h2_conn_finish(const GHTTP_H2Conn * conn);

/** The request of the last GHTTP_H2_EVENT_HEADERS at a server. Valid until the next feed. */
GHTTP_API const GHTTP_Request * ghttp_h2_conn_request(const GHTTP_H2Conn * conn);

/** The response of the last GHTTP_H2_EVENT_HEADERS at a client (a 1xx included). */
GHTTP_API const GHTTP_Response * ghttp_h2_conn_response(const GHTTP_H2Conn * conn);

/** The trailers of the last GHTTP_H2_EVENT_TRAILERS. */
GHTTP_API const GHTTP_Headers * ghttp_h2_conn_trailers(const GHTTP_H2Conn * conn);

/** The connection error that ended it: its code and a static reason; zero and "" if none. */
GHTTP_API GHTTP_Result ghttp_h2_conn_error(
    const GHTTP_H2Conn * conn, uint32_t * code, const char ** reason);

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/** The bytes waiting to be sent, and how many. Valid until the next call that queues output. */
GHTTP_API const uint8_t * ghttp_h2_conn_output(const GHTTP_H2Conn * conn, size_t * len);

/** The first @p n octets of the output were sent. */
GHTTP_API void ghttp_h2_conn_output_consume(GHTTP_H2Conn * conn, size_t n);

/** Octets queued and not yet consumed. */
GHTTP_API size_t ghttp_h2_conn_output_size(const GHTTP_H2Conn * conn);

/** The clock: milliseconds from any fixed starting point. Renews the per-interval counts. */
GHTTP_API void ghttp_h2_conn_tick(GHTTP_H2Conn * conn, uint64_t now_ms);

// ---------------------------------------------------------------------------
// Sending. All of these queue output; none blocks.
// ---------------------------------------------------------------------------

/**
 * Open a stream with a request (a client). The method, target and fields come
 * from @p request: an origin-form or asterisk target is the :path, an
 * absolute-form target gives :scheme, :authority and :path, an authority-form
 * target (CONNECT) the :authority. A `host` field becomes :authority when the
 * target gave none. Field names are lower-cased; a field that HTTP/2 forbids
 * (RFC 9113 section 8.2.2) is GHTTP_ERR_INVALID, never silently dropped.
 *
 * @param scheme for the :scheme, unless the target names one or the method is
 *   CONNECT; NULL means "https".
 * @param[out] stream_id The new stream's identifier.
 * @return GHTTP_ERR_LIMIT when the peer's SETTINGS_MAX_CONCURRENT_STREAMS or
 *   MAX_HEADER_LIST_SIZE would be exceeded, or too much output is queued:
 *   nothing was sent, try again later. GHTTP_ERR_INVALID after GOAWAY.
 */
GHTTP_API GHTTP_Result ghttp_h2_conn_send_request(GHTTP_H2Conn * conn,
    const GHTTP_Request * request, const char * scheme, int end_stream,
    uint32_t * stream_id);

/** Send a response (a server): final, or interim (1xx other than 101, no end_stream). */
GHTTP_API GHTTP_Result ghttp_h2_conn_send_response(GHTTP_H2Conn * conn,
    uint32_t stream_id, const GHTTP_Response * response, int end_stream);

/** Send a trailer section, which ends the stream. */
GHTTP_API GHTTP_Result ghttp_h2_conn_send_trailers(
    GHTTP_H2Conn * conn, uint32_t stream_id, const GHTTP_Headers * trailers);

/**
 * Send message content. At most as much as the stream's and the
 * connection's windows allow, in frames no larger than the peer accepts;
 * @p accepted says how much was taken, and the rest is the caller's to offer
 * again after a GHTTP_H2_EVENT_WINDOW_UPDATE. @p end_stream takes effect only
 * if all of @p data was accepted. An empty final frame is always accepted.
 */
GHTTP_API GHTTP_Result ghttp_h2_conn_send_data(GHTTP_H2Conn * conn,
    uint32_t stream_id, const void * data, size_t len, int end_stream,
    size_t * accepted);

/** How many octets of DATA could be sent now on the stream: the smaller of its window and the connection's. */
GHTTP_API size_t ghttp_h2_conn_send_window(const GHTTP_H2Conn * conn, uint32_t stream_id);

/** Return @p n octets of receive credit (manual flow control). */
GHTTP_API GHTTP_Result ghttp_h2_conn_consume(
    GHTTP_H2Conn * conn, uint32_t stream_id, size_t n);

/** Reset a stream with RST_STREAM. */
GHTTP_API GHTTP_Result ghttp_h2_conn_reset_stream(
    GHTTP_H2Conn * conn, uint32_t stream_id, uint32_t error_code);

GHTTP_API GHTTP_Result ghttp_h2_conn_ping(GHTTP_H2Conn * conn, const uint8_t data[8]);

/**
 * Send GOAWAY with the highest peer-initiated stream accepted so far. Streams
 * the peer opens after it are refused. The connection stays usable for what is
 * in flight; the caller closes it when that is done.
 */
GHTTP_API GHTTP_Result ghttp_h2_conn_shutdown(GHTTP_H2Conn * conn,
    uint32_t error_code, const void * debug, size_t debug_len);

/** Send a frame of a type this document does not define (an extension). */
GHTTP_API GHTTP_Result ghttp_h2_conn_send_extension_frame(GHTTP_H2Conn * conn,
    uint8_t type, uint8_t flags, uint32_t stream_id, const void * payload,
    size_t len);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** The peer's settings as last applied. */
GHTTP_API void ghttp_h2_conn_peer_settings(
    const GHTTP_H2Conn * conn, GHTTP_H2Settings * out);

/** This endpoint's settings, as advertised. */
GHTTP_API void ghttp_h2_conn_local_settings(
    const GHTTP_H2Conn * conn, GHTTP_H2Settings * out);

/** Whether ghttp_h2_conn_send_request() would be accepted now. */
GHTTP_API int ghttp_h2_conn_can_open_stream(const GHTTP_H2Conn * conn);

/** Streams that are open or half-closed. */
GHTTP_API size_t ghttp_h2_conn_stream_count(const GHTTP_H2Conn * conn);

/** Whether the stream is open or half-closed (both directions: ended = closed). */
GHTTP_API int ghttp_h2_conn_stream_is_active(
    const GHTTP_H2Conn * conn, uint32_t stream_id);

/** The connection's send window, or the stream's receive window, for tests and diagnostics; negative is possible after a SETTINGS change. */
GHTTP_API int64_t ghttp_h2_conn_connection_send_window(const GHTTP_H2Conn * conn);
GHTTP_API int64_t ghttp_h2_conn_connection_recv_window(const GHTTP_H2Conn * conn);

/** A stream's windows; GHTTP_ERR_INVALID if it is not active. */
GHTTP_API GHTTP_Result ghttp_h2_conn_stream_windows(const GHTTP_H2Conn * conn,
    uint32_t stream_id, int64_t * send_window, int64_t * recv_window);

GHTTP_API GHTTP_Result ghttp_h2_conn_stream_mode(
    const GHTTP_H2Conn * conn, uint32_t stream_id, GHTTP_H2StreamMode * mode);

/** Change a stream's mode: the seam for extensions that carry non-message data. */
GHTTP_API GHTTP_Result ghttp_h2_conn_set_stream_mode(
    GHTTP_H2Conn * conn, uint32_t stream_id, GHTTP_H2StreamMode mode);

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

typedef enum GHTTP_H2ExtensionKind {
  GHTTP_H2_EXT_FRAME,   ///< A frame of an unknown type.
  GHTTP_H2_EXT_SETTING  ///< A setting with an unknown identifier.
} GHTTP_H2ExtensionKind;

typedef struct GHTTP_H2Extension {
  size_t size;
  GHTTP_H2ExtensionKind kind;
  GHTTP_H2FrameHeader frame;  ///< EXT_FRAME.
  const uint8_t * payload;    ///< EXT_FRAME; valid during the call only.
  size_t payload_len;
  uint16_t setting_id;        ///< EXT_SETTING.
  uint32_t setting_value;
} GHTTP_H2Extension;

typedef void (*GHTTP_H2ExtensionFn)(void * ctx, const GHTTP_H2Extension * ext);

/**
 * Where unknown frames and settings go (RFC 9113 section 5.5 says to ignore
 * them; the handler sees them first). NULL restores ignoring. The handler is
 * called from inside ghttp_h2_conn_feed() and must not call into the connection.
 */
GHTTP_API void ghttp_h2_conn_set_extension_handler(
    GHTTP_H2Conn * conn, GHTTP_H2ExtensionFn fn, void * ctx);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_H2CONN_H
