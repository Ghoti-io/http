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
 * The HTTP/2 connection: stream and connection state machines, SETTINGS, flow
 * control, GOAWAY and RST_STREAM generation, and the abuse limits.
 *
 * Reference: RFC 9113 sections 3.4, 4 to 6 and 8, and the 2023 rapid-reset and
 * CONTINUATION-flood advisories for the limits the RFC leaves open.
 *
 * Every decision is taken on a whole frame, never on how many bytes a call
 * happened to deliver, so the events and the output are the same however the
 * input is cut.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/h2conn.h>
#include <ghoti.io/http/hpack.h>
#include "h2_internal.h"
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

typedef enum { HOW_SENT_RST, HOW_RECV_RST, HOW_ENDED } ClosedHow;

typedef struct Closed {
  uint32_t id;
  uint8_t how;
} Closed;

typedef struct Stream {
  uint32_t id;
  bool local_ended;   // END_STREAM sent
  bool remote_ended;  // END_STREAM received
  uint8_t mode;
  bool got_headers;   // the peer's request, or final response, has arrived
  bool sent_headers;  // this side's final response (server); always true at a client
  bool is_head;       // a client's request was HEAD
  bool connect;
  bool has_length;
  uint64_t length;
  uint64_t received;
  int64_t send_window;
  int64_t recv_window;
  uint64_t recv_unreturned;  // received and consumed, credit not yet sent
  uint64_t recv_unconsumed;  // received and not yet consumed (manual flow control)
} Stream;

typedef enum { KIND_NEW, KIND_EXISTING, KIND_DISCARD } BlockKind;
typedef enum { SS_IDLE, SS_ACTIVE, SS_CLOSED } StreamClass;

struct GHTTP_H2Conn {
  const GHTTP_Allocator * allocator;
  GHTTP_H2Role role;
  GHTTP_H2Limits limits;

  // Failure (sticky).
  GHTTP_Result failed;
  uint32_t err_code;
  const char * err_reason;

  // Input.
  size_t preface_pos;      // server: preface octets matched
  bool settings_received;  // the peer's first frame has been seen
  GHTTP_Buffer * in;       // the frame being gathered: header, then payload
  bool have_header;
  GHTTP_H2FrameHeader hdr;
  bool hdr_stream_error;   // the header showed a stream error (payload still read)
  GHTTP_H2FrameError hdr_err;
  bool frame_done;         // the last frame's bytes are still lent to the caller

  // Header block being gathered.
  bool hb_active;
  BlockKind hb_kind;
  uint32_t hb_stream;
  bool hb_end_stream;
  uint32_t hb_frames;
  GHTTP_Buffer * hb;

  // Output.
  GHTTP_Buffer * out;
  GHTTP_Buffer * enc_buf;

  // Header compression and messages.
  GHTTP_HpackDecoder * dec;
  GHTTP_HpackEncoder * enc;
  GHTTP_Headers * list;       // the decoded list, until the next decode
  GHTTP_Headers * send_list;  // what is about to be encoded
  GHTTP_Request * req;
  GHTTP_Response * resp;
  GHTTP_Headers * trailers;
  GHTTP_H2MsgInfo info;

  // Streams.
  Stream * streams;
  size_t nstreams;
  size_t cap_streams;
  Closed * closed;
  size_t closed_head;
  size_t closed_count;
  uint32_t last_peer_id;   // the highest stream the peer opened
  uint32_t next_local_id;  // a client's next stream

  // Settings.
  GHTTP_H2Settings peer;
  GHTTP_H2Settings local;
  bool local_acked;
  uint32_t recv_initial;   // the initial receive window streams are given now

  // Windows (signed: a SETTINGS change can make a send window negative).
  int64_t send_window;
  int64_t recv_window;
  uint64_t recv_unreturned;

  // GOAWAY.
  bool goaway_sent;
  uint32_t goaway_sent_last;
  bool goaway_received;
  uint32_t goaway_received_last;

  // Abuse counters.
  bool clock_started;
  uint64_t interval_start;
  uint32_t n_settings;
  uint32_t n_ping;
  uint32_t n_rst;
  uint32_t n_empty_data;

  GHTTP_H2ExtensionFn ext_fn;
  void * ext_ctx;

  GHTTP_H2Event ev;
};

// ---------------------------------------------------------------------------
// Settings and limits
// ---------------------------------------------------------------------------

void ghttp_h2_settings_default(GHTTP_H2Settings * s) {
  if (!s) {
    return;
  }
  memset(s, 0, sizeof(*s));
  s->size = sizeof(*s);
  s->header_table_size = 4096;
  s->enable_push = 1;
  s->max_concurrent_streams = UINT32_MAX;
  s->initial_window_size = GHTTP_H2_DEFAULT_WINDOW;
  s->max_frame_size = GHTTP_H2_DEFAULT_MAX_FRAME_SIZE;
  s->max_header_list_size = UINT32_MAX;
}

void ghttp_h2_limits_default(GHTTP_H2Limits * l) {
  if (!l) {
    return;
  }
  memset(l, 0, sizeof(*l));
  l->size = sizeof(*l);
  l->max_frame_size = GHTTP_H2_DEFAULT_MAX_FRAME_SIZE;
  l->max_header_list_bytes = GHTTP_H2_DEFAULT_MAX_HEADER_LIST_BYTES;
  l->max_table_size = GHTTP_H2_DEFAULT_MAX_TABLE_SIZE;
  l->max_concurrent_streams = GHTTP_H2_DEFAULT_MAX_CONCURRENT_STREAMS;
  l->initial_window_size = GHTTP_H2_DEFAULT_WINDOW;
  l->connection_window = GHTTP_H2_DEFAULT_WINDOW;
  l->max_encoder_table_size = GHTTP_H2_DEFAULT_MAX_TABLE_SIZE;
  l->max_header_block_bytes = GHTTP_H2_DEFAULT_MAX_HEADER_BLOCK_BYTES;
  l->max_continuation_frames = GHTTP_H2_DEFAULT_MAX_CONTINUATION_FRAMES;
  l->max_header_count = GHTTP_H2_DEFAULT_MAX_HEADER_COUNT;
  l->max_field_bytes = GHTTP_H2_DEFAULT_MAX_FIELD_BYTES;
  l->max_body_bytes = GHTTP_H2_DEFAULT_MAX_BODY_BYTES;
  l->max_buffered_bytes = GHTTP_H2_DEFAULT_MAX_BUFFERED_BYTES;
  l->max_streams = GHTTP_H2_DEFAULT_MAX_STREAMS;
  l->max_closed_streams = GHTTP_H2_DEFAULT_MAX_CLOSED_STREAMS;
  l->max_settings_per_interval = GHTTP_H2_DEFAULT_MAX_SETTINGS_PER_INTERVAL;
  l->max_ping_per_interval = GHTTP_H2_DEFAULT_MAX_PING_PER_INTERVAL;
  l->max_rst_per_interval = GHTTP_H2_DEFAULT_MAX_RST_PER_INTERVAL;
  l->max_empty_data_frames = GHTTP_H2_DEFAULT_MAX_EMPTY_DATA_FRAMES;
  l->interval_ms = GHTTP_H2_DEFAULT_INTERVAL_MS;
}

// ---------------------------------------------------------------------------
// Failure
// ---------------------------------------------------------------------------

/** End the connection: record why, queue GOAWAY. Always returns @p r. */
static GHTTP_Result conn_fail(GHTTP_H2Conn * c, uint32_t code,
    const char * reason, GHTTP_Result r) {
  if (c->failed == GHTTP_OK) {
    c->failed = r;
    c->err_code = code;
    c->err_reason = reason;
    // Best effort: if even this cannot be allocated the connection is closed
    // without it.
    (void)ghttp_h2_write_goaway(
        c->out, c->last_peer_id, code, reason, strlen(reason));
    c->goaway_sent = true;
  }
  return c->failed;
}

static GHTTP_Result oom(GHTTP_H2Conn * c) {
  return conn_fail(c, GHTTP_H2_INTERNAL_ERROR, "out of memory", GHTTP_ERR_OOM);
}

static GHTTP_Result calm(GHTTP_H2Conn * c, const char * why) {
  return conn_fail(c, GHTTP_H2_ENHANCE_YOUR_CALM, why, GHTTP_ERR_LIMIT);
}

static GHTTP_Result proto(GHTTP_H2Conn * c, const char * why) {
  return conn_fail(c, GHTTP_H2_PROTOCOL_ERROR, why, GHTTP_ERR_CORRUPT);
}

/** Queued output has grown past the limit: the peer is not draining, or is
 *  provoking replies faster than they can be sent. */
static GHTTP_Result check_output(GHTTP_H2Conn * c) {
  if (ghttp_buffer_size(c->out) > c->limits.max_buffered_bytes) {
    return calm(c, "too much output queued");
  }
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

static bool peer_initiated(const GHTTP_H2Conn * c, uint32_t id) {
  return c->role == GHTTP_H2_SERVER ? (id & 1u) != 0 : (id & 1u) == 0;
}

static Stream * stream_find(GHTTP_H2Conn * c, uint32_t id) {
  for (size_t i = 0; i < c->nstreams; i++) {
    if (c->streams[i].id == id) {
      return &c->streams[i];
    }
  }
  return NULL;
}

static const Stream * stream_find_const(const GHTTP_H2Conn * c, uint32_t id) {
  return stream_find((GHTTP_H2Conn *)c, id);
}

static Closed * closed_find(GHTTP_H2Conn * c, uint32_t id) {
  for (size_t i = 0; i < c->closed_count; i++) {
    Closed * e = &c->closed[(c->closed_head + i) % c->limits.max_closed_streams];
    if (e->id == id) {
      return e;
    }
  }
  return NULL;
}

static void closed_add(GHTTP_H2Conn * c, uint32_t id, ClosedHow how) {
  size_t cap = c->limits.max_closed_streams;
  if (cap == 0) {
    return;
  }
  Closed * e = closed_find(c, id);
  if (e) {
    e->how = (uint8_t)how;
    return;
  }
  if (c->closed_count == cap) {
    c->closed_head = (c->closed_head + 1) % cap;  // forget the oldest
    c->closed_count--;
  }
  e = &c->closed[(c->closed_head + c->closed_count) % cap];
  e->id = id;
  e->how = (uint8_t)how;
  c->closed_count++;
}

static StreamClass classify(GHTTP_H2Conn * c, uint32_t id, Stream ** out) {
  Stream * s = stream_find(c, id);
  if (s) {
    if (out) {
      *out = s;
    }
    return SS_ACTIVE;
  }
  if (peer_initiated(c, id)) {
    // At a client the peer's (even) streams are pushes, never opened here.
    return id > c->last_peer_id ? SS_IDLE : SS_CLOSED;
  }
  if (c->role == GHTTP_H2_CLIENT) {
    return id < c->next_local_id ? SS_CLOSED : SS_IDLE;
  }
  return SS_IDLE;  // a server opens none
}

/** Room for one more stream record; the add cannot then fail. */
static GHTTP_Result streams_reserve(GHTTP_H2Conn * c) {
  if (c->nstreams < c->cap_streams) {
    return GHTTP_OK;
  }
  void * p = c->streams;
  GHTTP_Result r = ghttp_reserve(
      c->allocator, &p, &c->cap_streams, c->nstreams + 1, sizeof(Stream), 8);
  c->streams = p;
  return r;
}

static Stream * stream_add(GHTTP_H2Conn * c, uint32_t id) {
  Stream * s = &c->streams[c->nstreams++];
  memset(s, 0, sizeof(*s));
  s->id = id;
  s->mode = GHTTP_H2_STREAM_MESSAGE;
  s->send_window = c->peer.initial_window_size;
  s->recv_window = c->recv_initial;
  return s;
}

// Connection-level credit: window the peer may use again.
static GHTTP_Result credit_connection(GHTTP_H2Conn * c, uint64_t n) {
  c->recv_unreturned += n;
  uint64_t thr = c->limits.connection_window / 2;
  if (thr == 0) {
    thr = 1;
  }
  if (c->recv_unreturned >= thr && c->recv_unreturned > 0) {
    uint64_t inc = c->recv_unreturned;
    // Never beyond what the window can hold.
    if (inc > GHTTP_H2_MAX_WINDOW) {
      inc = GHTTP_H2_MAX_WINDOW;
    }
    GHTTP_Result r = ghttp_h2_write_window_update(c->out, 0, (uint32_t)inc);
    if (r != GHTTP_OK) {
      return oom(c);
    }
    c->recv_window += (int64_t)inc;
    c->recv_unreturned -= inc;
  }
  return GHTTP_OK;
}

static GHTTP_Result credit_stream(GHTTP_H2Conn * c, Stream * s, uint64_t n) {
  if (s->remote_ended) {
    return GHTTP_OK;  // the peer will send no more: no window to restore
  }
  s->recv_unreturned += n;
  uint64_t thr = c->recv_initial / 2;
  if (thr == 0) {
    thr = 1;
  }
  if (s->recv_unreturned >= thr) {
    uint64_t inc = s->recv_unreturned;
    if (inc > GHTTP_H2_MAX_WINDOW) {
      inc = GHTTP_H2_MAX_WINDOW;
    }
    GHTTP_Result r = ghttp_h2_write_window_update(c->out, s->id, (uint32_t)inc);
    if (r != GHTTP_OK) {
      return oom(c);
    }
    s->recv_window += (int64_t)inc;
    s->recv_unreturned -= inc;
  }
  return GHTTP_OK;
}

/** Drop a stream from the table and remember how it ended. */
static GHTTP_Result stream_remove(GHTTP_H2Conn * c, uint32_t id, ClosedHow how) {
  GHTTP_Result r = GHTTP_OK;
  for (size_t i = 0; i < c->nstreams; i++) {
    if (c->streams[i].id == id) {
      uint64_t unconsumed = c->streams[i].recv_unconsumed;
      c->streams[i] = c->streams[--c->nstreams];
      if (unconsumed > 0) {
        // Data the application will never consume must not leak window.
        r = credit_connection(c, unconsumed);
      }
      break;
    }
  }
  closed_add(c, id, how);
  return r;
}

static GHTTP_Result close_if_done(GHTTP_H2Conn * c, Stream * s) {
  if (s->local_ended && s->remote_ended) {
    return stream_remove(c, s->id, HOW_ENDED);
  }
  return GHTTP_OK;
}

/** A stream error: RST_STREAM, forget the stream, and report it. */
static GHTTP_Result stream_error(
    GHTTP_H2Conn * c, uint32_t id, uint32_t code, ClosedHow how) {
  if (ghttp_h2_write_rst_stream(c->out, id, code) != GHTTP_OK) {
    return oom(c);
  }
  GHTTP_Result r = stream_remove(c, id, how);
  if (r != GHTTP_OK) {
    return r;
  }
  c->ev.type = GHTTP_H2_EVENT_STREAM_ERROR;
  c->ev.stream_id = id;
  c->ev.error_code = code;
  return check_output(c);
}

// ---------------------------------------------------------------------------
// The two places where push and priorities are decided, one function each, so
// that supporting either is a local change (RFC 9113 sections 5.3.2, 8.4).
// ---------------------------------------------------------------------------

/** Server push is disabled (ENABLE_PUSH = 0): a PUSH_PROMISE is an error. */
static GHTTP_Result h2_refuse_push(GHTTP_H2Conn * c) {
  return proto(c, "PUSH_PROMISE received but push is not enabled");
}

/** The RFC 7540 priority scheme is deprecated: PRIORITY is accepted and ignored. */
static GHTTP_Result h2_handle_priority(
    GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  (void)c;
  (void)f;
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

static GHTTP_Result normalise_limits(GHTTP_H2Limits * dst, const GHTTP_H2Limits * src) {
  ghttp_h2_limits_default(dst);
  if (src) {
    size_t n = src->size > 0 && src->size < sizeof(*dst) ? src->size : sizeof(*dst);
    memcpy(dst, src, n);
    dst->size = sizeof(*dst);
  }
  if (dst->max_frame_size < GHTTP_H2_DEFAULT_MAX_FRAME_SIZE
      || dst->max_frame_size > GHTTP_H2_MAX_MAX_FRAME_SIZE
      || dst->initial_window_size > GHTTP_H2_MAX_WINDOW
      || dst->connection_window < GHTTP_H2_DEFAULT_WINDOW
      || dst->connection_window > GHTTP_H2_MAX_WINDOW
      || dst->max_header_list_bytes > UINT32_MAX
      || dst->max_table_size > UINT32_MAX) {
    return GHTTP_ERR_INVALID;
  }
  return GHTTP_OK;
}

void ghttp_h2_conn_destroy(GHTTP_H2Conn * c) {
  if (!c) {
    return;
  }
  const GHTTP_Allocator * a = c->allocator;
  ghttp_buffer_destroy(c->in);
  ghttp_buffer_destroy(c->hb);
  ghttp_buffer_destroy(c->out);
  ghttp_buffer_destroy(c->enc_buf);
  ghttp_hpack_decoder_destroy(c->dec);
  ghttp_hpack_encoder_destroy(c->enc);
  ghttp_headers_destroy(c->list);
  ghttp_headers_destroy(c->send_list);
  ghttp_headers_destroy(c->trailers);
  ghttp_request_destroy(c->req);
  ghttp_response_destroy(c->resp);
  gcu_allocator_free(a, c->streams);
  gcu_allocator_free(a, c->closed);
  gcu_allocator_free(a, c);
}

GHTTP_Result ghttp_h2_conn_create(const GHTTP_Allocator * allocator,
    GHTTP_H2Role role, const GHTTP_H2Limits * limits, GHTTP_H2Conn ** out) {
  if (!out || (role != GHTTP_H2_CLIENT && role != GHTTP_H2_SERVER)) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_H2Conn * c = gcu_allocator_calloc(allocator, 1, sizeof(*c));
  if (!c) {
    return GHTTP_ERR_OOM;
  }
  c->allocator = allocator;
  c->role = role;
  GHTTP_Result r = normalise_limits(&c->limits, limits);
  if (r != GHTTP_OK) {
    gcu_allocator_free(allocator, c);
    return r;
  }
  const GHTTP_H2Limits * l = &c->limits;

  GHTTP_HpackLimits hl;
  ghttp_hpack_limits_default(&hl);
  hl.max_table_size = l->max_table_size;
  hl.max_header_list_bytes = l->max_header_list_bytes;
  hl.max_field_bytes = l->max_field_bytes;
  hl.max_header_count = l->max_header_count;
  GHTTP_HpackLimits el = hl;
  el.max_table_size = l->max_encoder_table_size;

  if (l->max_closed_streams > 0) {
    c->closed = gcu_allocator_calloc(
        allocator, l->max_closed_streams, sizeof(Closed));
    if (!c->closed) {
      r = GHTTP_ERR_OOM;
    }
  }
  if (r == GHTTP_OK) r = ghttp_buffer_create(allocator, &c->in);
  if (r == GHTTP_OK) r = ghttp_buffer_create(allocator, &c->hb);
  if (r == GHTTP_OK) r = ghttp_buffer_create(allocator, &c->out);
  if (r == GHTTP_OK) r = ghttp_buffer_create(allocator, &c->enc_buf);
  if (r == GHTTP_OK) {
    r = ghttp_hpack_decoder_create(
        allocator, &hl, GHTTP_HPACK_DEFAULT_TABLE_SIZE, &c->dec);
  }
  if (r == GHTTP_OK) {
    r = ghttp_hpack_encoder_create(
        allocator, &el, GHTTP_HPACK_DEFAULT_TABLE_SIZE, &c->enc);
  }
  if (r == GHTTP_OK) r = ghttp_headers_create(allocator, &c->list);
  if (r == GHTTP_OK) r = ghttp_headers_create(allocator, &c->send_list);
  if (r == GHTTP_OK) r = ghttp_headers_create(allocator, &c->trailers);
  if (r == GHTTP_OK) r = ghttp_request_create(allocator, &c->req);
  if (r == GHTTP_OK) r = ghttp_response_create(allocator, &c->resp);
  if (r != GHTTP_OK) {
    ghttp_h2_conn_destroy(c);
    return r;
  }

  ghttp_h2_settings_default(&c->peer);
  ghttp_h2_settings_default(&c->local);
  c->local.header_table_size = (uint32_t)l->max_table_size;
  c->local.enable_push = 0;
  c->local.max_concurrent_streams = l->max_concurrent_streams;
  c->local.initial_window_size = l->initial_window_size;
  c->local.max_frame_size = (uint32_t)l->max_frame_size;
  c->local.max_header_list_size = (uint32_t)l->max_header_list_bytes;

  c->next_local_id = 1;
  c->send_window = GHTTP_H2_DEFAULT_WINDOW;
  c->recv_window = l->connection_window;
  // Until the peer acknowledges our SETTINGS it may still use the default.
  c->recv_initial = l->initial_window_size > GHTTP_H2_DEFAULT_WINDOW
      ? l->initial_window_size : GHTTP_H2_DEFAULT_WINDOW;

  // The connection preface (section 3.4): the client's magic, then SETTINGS.
  if (role == GHTTP_H2_CLIENT) {
    r = ghttp_buffer_append(c->out, GHTTP_H2_PREFACE, GHTTP_H2_PREFACE_SIZE);
  }
  uint16_t ids[6];
  uint32_t vals[6];
  size_t n = 0;
  if (r == GHTTP_OK) {
    if (c->local.header_table_size != 4096) {
      ids[n] = GHTTP_H2_SETTINGS_HEADER_TABLE_SIZE;
      vals[n++] = c->local.header_table_size;
    }
    if (role == GHTTP_H2_CLIENT) {
      ids[n] = GHTTP_H2_SETTINGS_ENABLE_PUSH;
      vals[n++] = 0;
    }
    ids[n] = GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS;
    vals[n++] = c->local.max_concurrent_streams;
    if (c->local.initial_window_size != GHTTP_H2_DEFAULT_WINDOW) {
      ids[n] = GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE;
      vals[n++] = c->local.initial_window_size;
    }
    if (c->local.max_frame_size != GHTTP_H2_DEFAULT_MAX_FRAME_SIZE) {
      ids[n] = GHTTP_H2_SETTINGS_MAX_FRAME_SIZE;
      vals[n++] = c->local.max_frame_size;
    }
    ids[n] = GHTTP_H2_SETTINGS_MAX_HEADER_LIST_SIZE;
    vals[n++] = c->local.max_header_list_size;
    r = ghttp_h2_write_settings(c->out, ids, vals, n, 0);
  }
  if (r == GHTTP_OK && l->connection_window > GHTTP_H2_DEFAULT_WINDOW) {
    r = ghttp_h2_write_window_update(
        c->out, 0, l->connection_window - GHTTP_H2_DEFAULT_WINDOW);
  }
  if (r != GHTTP_OK) {
    ghttp_h2_conn_destroy(c);
    return r == GHTTP_ERR_INVALID ? GHTTP_ERR_INTERNAL : r;
  }
  *out = c;
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Receiving: frame handlers. Each returns GHTTP_OK (possibly with c->ev set)
// or the connection error it has already recorded.
// ---------------------------------------------------------------------------

static GHTTP_Result complete_block(GHTTP_H2Conn * c);

static GHTTP_Result on_data(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  uint32_t id = f->header.stream_id;
  uint64_t len = f->header.length;

  // Section 6.9: every flow-controlled frame counts against the connection
  // window, whatever becomes of it.
  if ((int64_t)len > c->recv_window) {
    return conn_fail(c, GHTTP_H2_FLOW_CONTROL_ERROR,
        "DATA exceeds the connection window", GHTTP_ERR_CORRUPT);
  }
  c->recv_window -= (int64_t)len;

  Stream * s = NULL;
  switch (classify(c, id, &s)) {
    case SS_IDLE:
      return proto(c, "DATA on an idle stream");
    case SS_CLOSED: {
      Closed * e = closed_find(c, id);
      if (e && e->how == HOW_SENT_RST) {
        // Sent before the peer saw our RST_STREAM: minimal processing.
        return credit_connection(c, len);
      }
      if (!e) {
        return proto(c, "DATA on a stream that is not known to have been open");
      }
      return conn_fail(c, GHTTP_H2_STREAM_CLOSED, "DATA on a closed stream",
          GHTTP_ERR_CORRUPT);
    }
    case SS_ACTIVE:
      break;
  }

  if (s->remote_ended) {
    GHTTP_Result r = credit_connection(c, len);
    return r != GHTTP_OK ? r
        : stream_error(c, id, GHTTP_H2_STREAM_CLOSED, HOW_SENT_RST);
  }
  if (c->role == GHTTP_H2_CLIENT && !s->got_headers) {
    GHTTP_Result r = credit_connection(c, len);
    return r != GHTTP_OK ? r
        : stream_error(c, id, GHTTP_H2_PROTOCOL_ERROR, HOW_SENT_RST);
  }
  if ((int64_t)len > s->recv_window) {
    GHTTP_Result r = credit_connection(c, len);
    return r != GHTTP_OK ? r
        : stream_error(c, id, GHTTP_H2_FLOW_CONTROL_ERROR, HOW_SENT_RST);
  }
  s->recv_window -= (int64_t)len;

  size_t dlen = f->data_len;
  s->received += dlen;
  if (s->mode == GHTTP_H2_STREAM_MESSAGE) {
    bool bad = false;
    if (s->has_length) {
      bad = s->received > s->length
          || (f->end_stream && s->received != s->length);
    }
    if (bad) {
      GHTTP_Result r = credit_connection(c, len);
      return r != GHTTP_OK ? r
          : stream_error(c, id, GHTTP_H2_PROTOCOL_ERROR, HOW_SENT_RST);
    }
    if (s->received > c->limits.max_body_bytes) {
      GHTTP_Result r = credit_connection(c, len);
      return r != GHTTP_OK ? r
          : stream_error(c, id, GHTTP_H2_ENHANCE_YOUR_CALM, HOW_SENT_RST);
    }
  }

  // Padding is never seen by the application, so its credit goes back now.
  uint64_t pad = len - dlen;
  if (f->end_stream) {
    s->remote_ended = true;
  }
  GHTTP_Result r = GHTTP_OK;
  if (pad > 0) {
    r = credit_connection(c, pad);
    if (r == GHTTP_OK) {
      r = credit_stream(c, s, pad);
    }
  }
  if (r == GHTTP_OK) {
    if (c->limits.manual_flow_control) {
      s->recv_unconsumed += dlen;
    } else if (dlen > 0) {
      r = credit_connection(c, dlen);
      if (r == GHTTP_OK) {
        r = credit_stream(c, s, dlen);
      }
    }
  }
  if (r != GHTTP_OK) {
    return r;
  }
  c->ev.type = GHTTP_H2_EVENT_DATA;
  c->ev.stream_id = id;
  c->ev.end_stream = f->end_stream;
  c->ev.data = f->data;
  c->ev.data_len = dlen;
  r = close_if_done(c, s);
  return r != GHTTP_OK ? r : check_output(c);
}

static GHTTP_Result start_block(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  uint32_t id = f->header.stream_id;
  Stream * s = NULL;
  BlockKind kind;
  switch (classify(c, id, &s)) {
    case SS_IDLE:
      if (c->role == GHTTP_H2_CLIENT || !peer_initiated(c, id)) {
        return proto(c, "HEADERS on a stream the sender may not open");
      }
      c->last_peer_id = id;  // opening it closes every lower idle stream
      kind = KIND_NEW;
      break;
    case SS_CLOSED: {
      Closed * e = closed_find(c, id);
      if (e && e->how == HOW_SENT_RST) {
        kind = KIND_DISCARD;  // compression state still has to be updated
        break;
      }
      if (!e) {
        // Lower than a stream already opened and never seen open: section
        // 5.1.1, an unexpected stream identifier.
        return proto(c, "unexpected stream identifier");
      }
      return conn_fail(c, GHTTP_H2_STREAM_CLOSED, "HEADERS on a closed stream",
          GHTTP_ERR_CORRUPT);
    }
    default:
      kind = KIND_EXISTING;
      break;
  }
  // The priority fields of a HEADERS frame are parsed and ignored.
  ghttp_buffer_clear(c->hb);
  c->hb_active = true;
  c->hb_kind = kind;
  c->hb_stream = id;
  c->hb_end_stream = f->end_stream;
  c->hb_frames = 1;
  return GHTTP_OK;
}

static GHTTP_Result add_fragment(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  if (f->data_len > c->limits.max_header_block_bytes
      || ghttp_buffer_size(c->hb) > c->limits.max_header_block_bytes - f->data_len) {
    return calm(c, "header block too large");
  }
  if (ghttp_buffer_append(c->hb, f->data, f->data_len) != GHTTP_OK) {
    return oom(c);
  }
  return GHTTP_OK;
}

static GHTTP_Result on_headers(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  GHTTP_Result r = start_block(c, f);
  if (r != GHTTP_OK) {
    return r;
  }
  r = add_fragment(c, f);
  if (r != GHTTP_OK) {
    return r;
  }
  return f->end_headers ? complete_block(c) : GHTTP_OK;
}

static GHTTP_Result on_continuation(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  if (!c->hb_active) {
    return proto(c, "CONTINUATION without a header block to continue");
  }
  if (++c->hb_frames - 1 > c->limits.max_continuation_frames) {
    return calm(c, "too many CONTINUATION frames");
  }
  GHTTP_Result r = add_fragment(c, f);
  if (r != GHTTP_OK) {
    return r;
  }
  return f->end_headers ? complete_block(c) : GHTTP_OK;
}

static uint32_t count_peer_streams(const GHTTP_H2Conn * c) {
  uint32_t n = 0;
  for (size_t i = 0; i < c->nstreams; i++) {
    n += peer_initiated(c, c->streams[i].id) ? 1u : 0u;
  }
  return n;
}

/** A stream error caused by a malformed message. */
static GHTTP_Result malformed(GHTTP_H2Conn * c, uint32_t id) {
  return stream_error(c, id, GHTTP_H2_PROTOCOL_ERROR, HOW_SENT_RST);
}

static GHTTP_Result read_trailers_for(GHTTP_H2Conn * c, Stream * s) {
  uint32_t id = s->id;
  if (s->mode == GHTTP_H2_STREAM_TUNNEL || !c->hb_end_stream) {
    return malformed(c, id);  // section 8.1: trailers end the stream
  }
  GHTTP_Result r = ghttp_h2msg_read_trailers(c->allocator, c->list, c->trailers);
  if (r == GHTTP_ERR_OOM) {
    return oom(c);
  }
  if (r != GHTTP_OK || (s->has_length && s->received != s->length)) {
    return malformed(c, id);
  }
  s->remote_ended = true;
  c->ev.type = GHTTP_H2_EVENT_TRAILERS;
  c->ev.stream_id = id;
  c->ev.end_stream = 1;
  return close_if_done(c, s);
}

static GHTTP_Result complete_block(GHTTP_H2Conn * c) {
  c->hb_active = false;
  uint32_t id = c->hb_stream;
  ghttp_headers_clear(c->list);
  GHTTP_Result r = ghttp_hpack_decode(
      c->dec, ghttp_buffer_data(c->hb), ghttp_buffer_size(c->hb), c->list);
  ghttp_buffer_clear(c->hb);
  if (r == GHTTP_ERR_CORRUPT) {
    return conn_fail(c, GHTTP_H2_COMPRESSION_ERROR,
        "header block could not be decoded", GHTTP_ERR_CORRUPT);
  }
  if (r == GHTTP_ERR_LIMIT) {
    return calm(c, "decoded header list too large");
  }
  if (r != GHTTP_OK) {
    return r == GHTTP_ERR_OOM ? oom(c)
        : conn_fail(c, GHTTP_H2_INTERNAL_ERROR, "internal error", r);
  }

  if (c->hb_kind == KIND_DISCARD) {
    return GHTTP_OK;
  }

  if (c->hb_kind == KIND_NEW) {
    // A request opens a stream (a server).
    if ((c->goaway_sent && id > c->goaway_sent_last)
        || count_peer_streams(c) >= c->limits.max_concurrent_streams
        || c->nstreams >= c->limits.max_streams) {
      return stream_error(c, id, GHTTP_H2_REFUSED_STREAM, HOW_SENT_RST);
    }
    GHTTP_H2MsgInfo info;
    r = ghttp_h2msg_read_request(c->allocator, c->list, c->req, &info);
    if (r == GHTTP_ERR_OOM) {
      return oom(c);
    }
    if (r != GHTTP_OK
        || (c->hb_end_stream && info.has_length && info.length != 0
            && !info.connect)) {
      return malformed(c, id);
    }
    if (streams_reserve(c) != GHTTP_OK) {
      return oom(c);
    }
    Stream * s = stream_add(c, id);
    s->got_headers = true;
    s->connect = info.connect;
    s->mode = info.connect ? GHTTP_H2_STREAM_TUNNEL : GHTTP_H2_STREAM_MESSAGE;
    s->has_length = info.has_length && !info.connect;
    s->length = info.length;
    s->remote_ended = c->hb_end_stream;
    c->ev.type = GHTTP_H2_EVENT_HEADERS;
    c->ev.stream_id = id;
    c->ev.end_stream = c->hb_end_stream;
    c->ev.scheme = info.scheme;
    c->ev.authority = info.authority;
    return GHTTP_OK;
  }

  Stream * s = stream_find(c, id);
  if (!s) {
    return GHTTP_ERR_INTERNAL;
  }
  if (s->remote_ended) {
    return stream_error(c, id, GHTTP_H2_STREAM_CLOSED, HOW_SENT_RST);
  }
  if (c->role == GHTTP_H2_SERVER || s->got_headers) {
    return read_trailers_for(c, s);
  }

  // A client reads a response.
  GHTTP_H2MsgInfo info;
  r = ghttp_h2msg_read_response(c->allocator, c->list, c->resp, &info);
  if (r == GHTTP_ERR_OOM) {
    return oom(c);
  }
  if (r != GHTTP_OK) {
    return malformed(c, id);
  }
  if (info.status < 200) {
    if (c->hb_end_stream) {
      return malformed(c, id);  // section 8.1: an interim response ends nothing
    }
    c->ev.type = GHTTP_H2_EVENT_HEADERS;
    c->ev.stream_id = id;
    c->ev.interim = 1;
    return GHTTP_OK;
  }
  bool no_content = s->is_head || ghttp_h2msg_status_has_no_content(info.status);
  if (c->hb_end_stream && info.has_length && info.length != 0 && !no_content) {
    return malformed(c, id);
  }
  s->got_headers = true;
  s->has_length = info.has_length && !no_content;
  s->length = info.length;
  if (s->connect && info.status >= 200 && info.status < 300) {
    s->mode = GHTTP_H2_STREAM_TUNNEL;
    s->has_length = false;
  }
  s->remote_ended = c->hb_end_stream;
  c->ev.type = GHTTP_H2_EVENT_HEADERS;
  c->ev.stream_id = id;
  c->ev.end_stream = c->hb_end_stream;
  return close_if_done(c, s);
}

static GHTTP_Result on_rst(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  uint32_t id = f->header.stream_id;
  Stream * s = NULL;
  switch (classify(c, id, &s)) {
    case SS_IDLE:
      return proto(c, "RST_STREAM on an idle stream");
    case SS_CLOSED:
      return GHTTP_OK;  // allowed for a while after the stream ends
    case SS_ACTIVE:
      break;
  }
  GHTTP_Result r = stream_remove(c, id, HOW_RECV_RST);
  if (r != GHTTP_OK) {
    return r;
  }
  c->ev.type = GHTTP_H2_EVENT_STREAM_RESET;
  c->ev.stream_id = id;
  c->ev.error_code = f->error_code;
  return GHTTP_OK;
}

static GHTTP_Result on_window_update(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  uint32_t id = f->header.stream_id;
  if (id == 0) {
    if ((int64_t)f->increment > (int64_t)GHTTP_H2_MAX_WINDOW - c->send_window) {
      return conn_fail(c, GHTTP_H2_FLOW_CONTROL_ERROR,
          "WINDOW_UPDATE overflows the connection window", GHTTP_ERR_CORRUPT);
    }
    c->send_window += f->increment;
  } else {
    Stream * s = NULL;
    switch (classify(c, id, &s)) {
      case SS_IDLE:
        return proto(c, "WINDOW_UPDATE on an idle stream");
      case SS_CLOSED:
        return GHTTP_OK;
      case SS_ACTIVE:
        break;
    }
    if ((int64_t)f->increment > (int64_t)GHTTP_H2_MAX_WINDOW - s->send_window) {
      return stream_error(c, id, GHTTP_H2_FLOW_CONTROL_ERROR, HOW_SENT_RST);
    }
    s->send_window += f->increment;
  }
  c->ev.type = GHTTP_H2_EVENT_WINDOW_UPDATE;
  c->ev.stream_id = id;
  c->ev.increment = f->increment;
  return GHTTP_OK;
}

static void call_extension_setting(
    GHTTP_H2Conn * c, uint16_t id, uint32_t value) {
  if (c->ext_fn) {
    GHTTP_H2Extension x;
    memset(&x, 0, sizeof(x));
    x.size = sizeof(x);
    x.kind = GHTTP_H2_EXT_SETTING;
    x.setting_id = id;
    x.setting_value = value;
    c->ext_fn(c->ext_ctx, &x);
  }
}

static GHTTP_Result apply_peer_setting(
    GHTTP_H2Conn * c, uint16_t id, uint32_t v) {
  switch (id) {
    case GHTTP_H2_SETTINGS_HEADER_TABLE_SIZE: {
      c->peer.header_table_size = v;
      size_t use = v;
      if (use > c->limits.max_encoder_table_size) {
        use = c->limits.max_encoder_table_size;
      }
      if (ghttp_hpack_encoder_set_peer_table_size(c->enc, use) != GHTTP_OK) {
        return oom(c);
      }
      break;
    }
    case GHTTP_H2_SETTINGS_ENABLE_PUSH:
      if (v > 1) {
        return proto(c, "SETTINGS_ENABLE_PUSH is neither 0 nor 1");
      }
      if (v == 1 && c->role == GHTTP_H2_CLIENT) {
        return proto(c, "a server set SETTINGS_ENABLE_PUSH to 1");
      }
      c->peer.enable_push = v;
      break;
    case GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS:
      c->peer.max_concurrent_streams = v;
      break;
    case GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE: {
      if (v > GHTTP_H2_MAX_WINDOW) {
        return conn_fail(c, GHTTP_H2_FLOW_CONTROL_ERROR,
            "SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1", GHTTP_ERR_CORRUPT);
      }
      int64_t delta = (int64_t)v - (int64_t)c->peer.initial_window_size;
      for (size_t i = 0; i < c->nstreams; i++) {
        int64_t w = c->streams[i].send_window + delta;
        if (w > (int64_t)GHTTP_H2_MAX_WINDOW) {
          return conn_fail(c, GHTTP_H2_FLOW_CONTROL_ERROR,
              "SETTINGS_INITIAL_WINDOW_SIZE overflows a stream window",
              GHTTP_ERR_CORRUPT);
        }
      }
      for (size_t i = 0; i < c->nstreams; i++) {
        c->streams[i].send_window += delta;
      }
      c->peer.initial_window_size = v;
      break;
    }
    case GHTTP_H2_SETTINGS_MAX_FRAME_SIZE:
      if (v < GHTTP_H2_DEFAULT_MAX_FRAME_SIZE || v > GHTTP_H2_MAX_MAX_FRAME_SIZE) {
        return proto(c, "SETTINGS_MAX_FRAME_SIZE out of range");
      }
      c->peer.max_frame_size = v;
      break;
    case GHTTP_H2_SETTINGS_MAX_HEADER_LIST_SIZE:
      c->peer.max_header_list_size = v;
      break;
    default:
      call_extension_setting(c, id, v);  // section 5.5: otherwise ignored
      break;
  }
  return GHTTP_OK;
}

static GHTTP_Result on_settings(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  if (++c->n_settings > c->limits.max_settings_per_interval) {
    return calm(c, "too many SETTINGS frames");
  }
  if (f->ack) {
    if (!c->local_acked) {
      // Our SETTINGS take effect now (section 6.5.3).
      c->local_acked = true;
      int64_t delta = (int64_t)c->local.initial_window_size - (int64_t)c->recv_initial;
      for (size_t i = 0; i < c->nstreams; i++) {
        c->streams[i].recv_window += delta;
      }
      c->recv_initial = c->local.initial_window_size;
      if (ghttp_hpack_decoder_set_max_table_size(
              c->dec, c->local.header_table_size) != GHTTP_OK) {
        return GHTTP_ERR_INTERNAL;
      }
      c->ev.type = GHTTP_H2_EVENT_SETTINGS_ACK;
    }
    return GHTTP_OK;  // an ACK with nothing to acknowledge is ignored
  }
  for (size_t i = 0; i < f->settings_count; i++) {
    uint16_t id;
    uint32_t v;
    ghttp_h2_frame_setting_at(f, i, &id, &v);
    GHTTP_Result r = apply_peer_setting(c, id, v);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  if (ghttp_h2_write_settings(c->out, NULL, NULL, 0, 1) != GHTTP_OK) {
    return oom(c);
  }
  c->ev.type = GHTTP_H2_EVENT_SETTINGS;
  return check_output(c);
}

static GHTTP_Result on_ping(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  if (++c->n_ping > c->limits.max_ping_per_interval) {
    return calm(c, "too many PING frames");
  }
  if (f->ack) {
    c->ev.type = GHTTP_H2_EVENT_PING_ACK;
  } else {
    if (ghttp_h2_write_ping(c->out, f->ping, 1) != GHTTP_OK) {
      return oom(c);
    }
    c->ev.type = GHTTP_H2_EVENT_PING;
  }
  c->ev.data_len = 8;
  return check_output(c);
}

static GHTTP_Result on_goaway(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  c->goaway_received = true;
  c->goaway_received_last = f->last_stream_id;
  // Streams this endpoint opened beyond the last one processed will not be
  // answered (section 6.8): forget them.
  if (c->role == GHTTP_H2_CLIENT) {
    for (size_t i = 0; i < c->nstreams;) {
      if (c->streams[i].id > f->last_stream_id) {
        uint32_t id = c->streams[i].id;
        GHTTP_Result r = stream_remove(c, id, HOW_ENDED);
        if (r != GHTTP_OK) {
          return r;
        }
      } else {
        i++;
      }
    }
  }
  c->ev.type = GHTTP_H2_EVENT_GOAWAY;
  c->ev.error_code = f->error_code;
  c->ev.last_stream_id = f->last_stream_id;
  c->ev.data = f->data;
  c->ev.data_len = f->data_len;
  return GHTTP_OK;
}

static GHTTP_Result on_unknown(GHTTP_H2Conn * c, const GHTTP_H2Frame * f) {
  if (c->ext_fn) {
    GHTTP_H2Extension x;
    memset(&x, 0, sizeof(x));
    x.size = sizeof(x);
    x.kind = GHTTP_H2_EXT_FRAME;
    x.frame = f->header;
    x.payload = f->data;
    x.payload_len = f->data_len;
    c->ext_fn(c->ext_ctx, &x);
  }
  return GHTTP_OK;
}

/** A stream error the frame header already showed (a PRIORITY of the wrong size). */
static GHTTP_Result on_header_stream_error(GHTTP_H2Conn * c) {
  uint32_t id = c->hdr_err.stream_id;
  Stream * s = NULL;
  switch (classify(c, id, &s)) {
    case SS_IDLE:
      return conn_fail(c, c->hdr_err.code, "frame size error on an idle stream",
          GHTTP_ERR_CORRUPT);
    case SS_CLOSED:
      return GHTTP_OK;
    case SS_ACTIVE:
      break;
  }
  return stream_error(c, id, c->hdr_err.code, HOW_SENT_RST);
}

static GHTTP_Result process_frame(GHTTP_H2Conn * c) {
  const uint8_t * payload = (const uint8_t *)ghttp_buffer_data(c->in)
      + GHTTP_H2_FRAME_HEADER_SIZE;
  if (c->hdr_stream_error) {
    return on_header_stream_error(c);
  }
  GHTTP_H2Frame f;
  GHTTP_H2FrameError err;
  GHTTP_Result r = ghttp_h2_frame_parse(
      &c->hdr, payload, c->limits.max_frame_size, &f, &err);
  if (r != GHTTP_OK) {
    if (err.connection) {
      return conn_fail(c, err.code, "malformed frame", GHTTP_ERR_CORRUPT);
    }
    // A zero WINDOW_UPDATE increment: a stream error, unless idle.
    c->hdr_err = err;
    return on_header_stream_error(c);
  }

  // Frames that are not a DATA frame without data end the run of empty ones.
  bool empty_data = f.header.type == GHTTP_H2_DATA && f.data_len == 0
      && !f.end_stream;
  if (empty_data) {
    if (++c->n_empty_data > c->limits.max_empty_data_frames) {
      return calm(c, "too many empty DATA frames");
    }
  } else {
    c->n_empty_data = 0;
  }

  switch (f.header.type) {
    case GHTTP_H2_DATA:
      return on_data(c, &f);
    case GHTTP_H2_HEADERS:
      return on_headers(c, &f);
    case GHTTP_H2_PRIORITY:
      return h2_handle_priority(c, &f);
    case GHTTP_H2_RST_STREAM:
      if (++c->n_rst > c->limits.max_rst_per_interval) {
        return calm(c, "too many RST_STREAM frames");
      }
      return on_rst(c, &f);
    case GHTTP_H2_SETTINGS:
      return on_settings(c, &f);
    case GHTTP_H2_PUSH_PROMISE:
      return h2_refuse_push(c);
    case GHTTP_H2_PING:
      return on_ping(c, &f);
    case GHTTP_H2_GOAWAY:
      return on_goaway(c, &f);
    case GHTTP_H2_WINDOW_UPDATE:
      return on_window_update(c, &f);
    case GHTTP_H2_CONTINUATION:
      return on_continuation(c, &f);
    default:
      return on_unknown(c, &f);
  }
}

// ---------------------------------------------------------------------------
// Feeding
// ---------------------------------------------------------------------------

static GHTTP_Result take_header(GHTTP_H2Conn * c, const uint8_t * data,
    size_t len, size_t * used, bool * ready) {
  size_t have = ghttp_buffer_size(c->in);
  size_t take = GHTTP_H2_FRAME_HEADER_SIZE - have;
  if (take > len - *used) {
    take = len - *used;
  }
  if (ghttp_buffer_append(c->in, data + *used, take) != GHTTP_OK) {
    return oom(c);
  }
  *used += take;
  if (ghttp_buffer_size(c->in) < GHTTP_H2_FRAME_HEADER_SIZE) {
    *ready = false;
    return GHTTP_OK;
  }
  ghttp_h2_frame_header_parse(
      (const uint8_t *)ghttp_buffer_data(c->in), &c->hdr);

  // What the header alone shows to be wrong.
  GHTTP_H2FrameError err;
  c->hdr_stream_error = false;
  if (ghttp_h2_frame_header_check(&c->hdr, c->limits.max_frame_size, &err)
      != GHTTP_OK) {
    if (err.connection) {
      return conn_fail(c, err.code, "malformed frame header", GHTTP_ERR_CORRUPT);
    }
    c->hdr_stream_error = true;
    c->hdr_err = err;
  }
  // The first frame from the peer is its SETTINGS (section 3.4).
  if (!c->settings_received) {
    if (c->hdr.type != GHTTP_H2_SETTINGS
        || (c->hdr.flags & GHTTP_H2_FLAG_ACK)) {
      return proto(c, "the connection preface did not end with SETTINGS");
    }
    c->settings_received = true;
  }
  // A header block admits nothing but its CONTINUATIONs (section 6.10).
  if (c->hb_active
      && (c->hdr.type != GHTTP_H2_CONTINUATION
          || c->hdr.stream_id != c->hb_stream)) {
    return proto(c, "a frame interrupted a header block");
  }
  // Everything held at once.
  size_t held = ghttp_buffer_size(c->hb) + ghttp_buffer_size(c->out);
  if (c->hdr.length > c->limits.max_buffered_bytes
      || held > c->limits.max_buffered_bytes - c->hdr.length) {
    return calm(c, "too many octets buffered");
  }
  c->have_header = true;
  *ready = true;
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_feed(GHTTP_H2Conn * c, const void * data, size_t len,
    size_t * consumed, GHTTP_H2Event * event) {
  if (!c || !consumed || !event || (!data && len > 0)) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  const uint8_t * p = data;
  size_t used = 0;
  if (c->frame_done) {
    ghttp_buffer_clear(c->in);
    c->have_header = false;
    c->frame_done = false;
  }
  for (;;) {
    // A server reads the client's preface first, a byte at a time so that a
    // wrong byte is refused at the same place however the input is cut.
    if (c->role == GHTTP_H2_SERVER && c->preface_pos < GHTTP_H2_PREFACE_SIZE) {
      while (used < len && c->preface_pos < GHTTP_H2_PREFACE_SIZE) {
        if (p[used] != (uint8_t)GHTTP_H2_PREFACE[c->preface_pos]) {
          return proto(c, "invalid connection preface");
        }
        used++;
        c->preface_pos++;
      }
      if (c->preface_pos < GHTTP_H2_PREFACE_SIZE) {
        break;
      }
    }

    if (!c->have_header) {
      bool ready;
      GHTTP_Result r = take_header(c, p, len, &used, &ready);
      if (r != GHTTP_OK) {
        return r;
      }
      if (!ready) {
        break;
      }
    }
    size_t have = ghttp_buffer_size(c->in) - GHTTP_H2_FRAME_HEADER_SIZE;
    size_t need = c->hdr.length - have;
    size_t take = need < len - used ? need : len - used;
    if (take > 0 && ghttp_buffer_append(c->in, p + used, take) != GHTTP_OK) {
      return oom(c);
    }
    used += take;
    if (take < need) {
      break;
    }

    memset(&c->ev, 0, sizeof(c->ev));
    c->ev.size = sizeof(c->ev);
    c->ev.type = GHTTP_H2_EVENT_NEED_MORE;
    c->frame_done = true;
    GHTTP_Result r = process_frame(c);
    if (r == GHTTP_OK && c->failed != GHTTP_OK) {
      r = c->failed;  // a handler recorded a failure and still returned OK
    }
    if (r != GHTTP_OK) {
      return r;
    }
    if (c->ev.type != GHTTP_H2_EVENT_NEED_MORE) {
      if (c->ev.type == GHTTP_H2_EVENT_PING
          || c->ev.type == GHTTP_H2_EVENT_PING_ACK) {
        // The 8 octets live in the input buffer, which stays until the next feed.
        c->ev.data = (const uint8_t *)ghttp_buffer_data(c->in)
            + GHTTP_H2_FRAME_HEADER_SIZE;
      }
      *consumed = used;
      *event = c->ev;
      return GHTTP_OK;
    }
    ghttp_buffer_clear(c->in);
    c->have_header = false;
    c->frame_done = false;
  }
  memset(event, 0, sizeof(*event));
  event->size = sizeof(*event);
  event->type = GHTTP_H2_EVENT_NEED_MORE;
  *consumed = used;
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_finish(const GHTTP_H2Conn * c) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  bool in_preface = c->role == GHTTP_H2_SERVER && c->preface_pos > 0
      && c->preface_pos < GHTTP_H2_PREFACE_SIZE;
  // A frame whose last octet has arrived is complete (and its bytes are kept
  // only for the caller to read); anything else in the buffer is a stub.
  bool mid_frame = !c->frame_done && ghttp_buffer_size(c->in) > 0;
  return in_preface || mid_frame || c->hb_active ? GHTTP_ERR_CORRUPT : GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

const GHTTP_Request * ghttp_h2_conn_request(const GHTTP_H2Conn * c) {
  return c ? c->req : NULL;
}

const GHTTP_Response * ghttp_h2_conn_response(const GHTTP_H2Conn * c) {
  return c ? c->resp : NULL;
}

const GHTTP_Headers * ghttp_h2_conn_trailers(const GHTTP_H2Conn * c) {
  return c ? c->trailers : NULL;
}

GHTTP_Result ghttp_h2_conn_error(
    const GHTTP_H2Conn * c, uint32_t * code, const char ** reason) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  if (code) {
    *code = c->err_code;
  }
  if (reason) {
    *reason = c->err_reason ? c->err_reason : "";
  }
  return c->failed;
}

const uint8_t * ghttp_h2_conn_output(const GHTTP_H2Conn * c, size_t * len) {
  if (len) {
    *len = c ? ghttp_buffer_size(c->out) : 0;
  }
  return c ? ghttp_buffer_data(c->out) : NULL;
}

void ghttp_h2_conn_output_consume(GHTTP_H2Conn * c, size_t n) {
  if (c) {
    ghttp_buffer_consume(c->out, n);
  }
}

size_t ghttp_h2_conn_output_size(const GHTTP_H2Conn * c) {
  return c ? ghttp_buffer_size(c->out) : 0;
}

void ghttp_h2_conn_tick(GHTTP_H2Conn * c, uint64_t now_ms) {
  if (!c) {
    return;
  }
  if (!c->clock_started || now_ms < c->interval_start
      || now_ms - c->interval_start >= c->limits.interval_ms) {
    c->clock_started = true;
    c->interval_start = now_ms;
    c->n_settings = 0;
    c->n_ping = 0;
    c->n_rst = 0;
  }
}

void ghttp_h2_conn_peer_settings(const GHTTP_H2Conn * c, GHTTP_H2Settings * out) {
  if (c && out) {
    *out = c->peer;
  }
}

void ghttp_h2_conn_local_settings(const GHTTP_H2Conn * c, GHTTP_H2Settings * out) {
  if (c && out) {
    *out = c->local;
  }
}

static uint32_t count_local_streams(const GHTTP_H2Conn * c) {
  uint32_t n = 0;
  for (size_t i = 0; i < c->nstreams; i++) {
    n += peer_initiated(c, c->streams[i].id) ? 0u : 1u;
  }
  return n;
}

int ghttp_h2_conn_can_open_stream(const GHTTP_H2Conn * c) {
  return c && c->role == GHTTP_H2_CLIENT && c->failed == GHTTP_OK
      && !c->goaway_received && c->next_local_id <= GHTTP_H2_MAX_STREAM_ID
      && count_local_streams(c) < c->peer.max_concurrent_streams
      && c->nstreams < c->limits.max_streams
      && ghttp_buffer_size(c->out) <= c->limits.max_buffered_bytes;
}

size_t ghttp_h2_conn_stream_count(const GHTTP_H2Conn * c) {
  return c ? c->nstreams : 0;
}

int ghttp_h2_conn_stream_is_active(const GHTTP_H2Conn * c, uint32_t id) {
  return c && stream_find_const(c, id) != NULL;
}

int64_t ghttp_h2_conn_connection_send_window(const GHTTP_H2Conn * c) {
  return c ? c->send_window : 0;
}

int64_t ghttp_h2_conn_connection_recv_window(const GHTTP_H2Conn * c) {
  return c ? c->recv_window : 0;
}

GHTTP_Result ghttp_h2_conn_stream_windows(const GHTTP_H2Conn * c, uint32_t id,
    int64_t * send_window, int64_t * recv_window) {
  const Stream * s = c ? stream_find_const(c, id) : NULL;
  if (!s) {
    return GHTTP_ERR_INVALID;
  }
  if (send_window) {
    *send_window = s->send_window;
  }
  if (recv_window) {
    *recv_window = s->recv_window;
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_stream_mode(
    const GHTTP_H2Conn * c, uint32_t id, GHTTP_H2StreamMode * mode) {
  const Stream * s = c ? stream_find_const(c, id) : NULL;
  if (!s || !mode) {
    return GHTTP_ERR_INVALID;
  }
  *mode = (GHTTP_H2StreamMode)s->mode;
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_set_stream_mode(
    GHTTP_H2Conn * c, uint32_t id, GHTTP_H2StreamMode mode) {
  Stream * s = c ? stream_find(c, id) : NULL;
  if (!s || (mode != GHTTP_H2_STREAM_MESSAGE && mode != GHTTP_H2_STREAM_TUNNEL)) {
    return GHTTP_ERR_INVALID;
  }
  s->mode = (uint8_t)mode;
  return GHTTP_OK;
}

void ghttp_h2_conn_set_extension_handler(
    GHTTP_H2Conn * c, GHTTP_H2ExtensionFn fn, void * ctx) {
  if (c) {
    c->ext_fn = fn;
    c->ext_ctx = ctx;
  }
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/** Encode c->send_list and write it as a header block on @p id. */
static GHTTP_Result send_block(
    GHTTP_H2Conn * c, uint32_t id, int end_stream) {
  size_t size = ghttp_h2msg_list_size(c->send_list);
  if (size > c->peer.max_header_list_size) {
    return GHTTP_ERR_LIMIT;  // the peer said it would not take it
  }
  if (ghttp_buffer_size(c->out) > c->limits.max_buffered_bytes) {
    return GHTTP_ERR_LIMIT;
  }
  ghttp_buffer_clear(c->enc_buf);
  GHTTP_Result r = ghttp_hpack_encode(c->enc, c->send_list, c->enc_buf);
  if (r != GHTTP_OK) {
    // The encoder's table and the peer's decoder can no longer agree.
    return conn_fail(c, GHTTP_H2_INTERNAL_ERROR, "header encoding failed", r);
  }
  r = ghttp_h2_write_header_block(c->out, id, ghttp_buffer_data(c->enc_buf),
      ghttp_buffer_size(c->enc_buf), end_stream, c->peer.max_frame_size);
  if (r != GHTTP_OK) {
    return conn_fail(c, GHTTP_H2_INTERNAL_ERROR, "header write failed", r);
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_send_request(GHTTP_H2Conn * c,
    const GHTTP_Request * request, const char * scheme, int end_stream,
    uint32_t * stream_id) {
  if (!c || !request || !stream_id || c->role != GHTTP_H2_CLIENT) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  if (c->goaway_received || c->next_local_id > GHTTP_H2_MAX_STREAM_ID) {
    return GHTTP_ERR_INVALID;
  }
  if (count_local_streams(c) >= c->peer.max_concurrent_streams
      || c->nstreams >= c->limits.max_streams) {
    return GHTTP_ERR_LIMIT;
  }
  bool connect;
  GHTTP_Result r = ghttp_h2msg_build_request(
      c->allocator, request, scheme, c->send_list, &connect);
  if (r != GHTTP_OK) {
    return r;
  }
  if (streams_reserve(c) != GHTTP_OK) {
    return GHTTP_ERR_OOM;
  }
  uint32_t id = c->next_local_id;
  r = send_block(c, id, end_stream);
  if (r != GHTTP_OK) {
    return r;
  }
  c->next_local_id += 2;
  Stream * s = stream_add(c, id);
  s->sent_headers = true;
  s->is_head = strcmp(ghttp_request_method(request), "HEAD") == 0;
  s->connect = connect;
  s->local_ended = end_stream != 0;
  *stream_id = id;
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_send_response(GHTTP_H2Conn * c, uint32_t stream_id,
    const GHTTP_Response * response, int end_stream) {
  if (!c || !response || c->role != GHTTP_H2_SERVER) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  Stream * s = stream_find(c, stream_id);
  if (!s || s->local_ended || s->sent_headers) {
    return GHTTP_ERR_INVALID;
  }
  int status;
  GHTTP_Result r = ghttp_h2msg_build_response(
      c->allocator, response, c->send_list, &status);
  if (r != GHTTP_OK) {
    return r;
  }
  bool interim = status < 200;
  if (interim && end_stream) {
    return GHTTP_ERR_INVALID;
  }
  r = send_block(c, stream_id, end_stream);
  if (r != GHTTP_OK) {
    return r;
  }
  if (!interim) {
    s->sent_headers = true;
  }
  if (end_stream) {
    s->local_ended = true;
    return close_if_done(c, s);
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_send_trailers(
    GHTTP_H2Conn * c, uint32_t stream_id, const GHTTP_Headers * trailers) {
  if (!c || !trailers) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  Stream * s = stream_find(c, stream_id);
  if (!s || s->local_ended || !s->sent_headers
      || s->mode == GHTTP_H2_STREAM_TUNNEL) {
    return GHTTP_ERR_INVALID;
  }
  GHTTP_Result r = ghttp_h2msg_build_trailers(c->allocator, trailers, c->send_list);
  if (r != GHTTP_OK) {
    return r;
  }
  r = send_block(c, stream_id, 1);
  if (r != GHTTP_OK) {
    return r;
  }
  s->local_ended = true;
  return close_if_done(c, s);
}

static size_t window_for(const GHTTP_H2Conn * c, const Stream * s) {
  int64_t w = c->send_window < s->send_window ? c->send_window : s->send_window;
  return w > 0 ? (size_t)w : 0;
}

size_t ghttp_h2_conn_send_window(const GHTTP_H2Conn * c, uint32_t stream_id) {
  const Stream * s = c ? stream_find_const(c, stream_id) : NULL;
  return s ? window_for(c, s) : 0;
}

GHTTP_Result ghttp_h2_conn_send_data(GHTTP_H2Conn * c, uint32_t stream_id,
    const void * data, size_t len, int end_stream, size_t * accepted) {
  if (!c || (!data && len > 0) || !accepted) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  Stream * s = stream_find(c, stream_id);
  if (!s || s->local_ended || !s->sent_headers) {
    return GHTTP_ERR_INVALID;
  }
  size_t out_size = ghttp_buffer_size(c->out);
  size_t room = out_size < c->limits.max_buffered_bytes
      ? c->limits.max_buffered_bytes - out_size : 0;
  size_t take = len;
  size_t window = window_for(c, s);
  if (take > window) {
    take = window;
  }
  if (take > room) {
    take = room;
  }
  const uint8_t * p = data;
  size_t sent = 0;
  bool all = take == len;
  size_t max_frame = c->peer.max_frame_size;
  while (sent < take || (all && len == 0 && sent == 0 && end_stream)) {
    size_t n = take - sent < max_frame ? take - sent : max_frame;
    bool last = all && sent + n == take;
    GHTTP_Result r = ghttp_h2_write_data(
        c->out, stream_id, p + sent, n, last && end_stream, 0, 0);
    if (r != GHTTP_OK) {
      return conn_fail(c, GHTTP_H2_INTERNAL_ERROR, "DATA write failed", r);
    }
    sent += n;
    if (len == 0) {
      break;
    }
  }
  c->send_window -= (int64_t)take;
  s->send_window -= (int64_t)take;
  *accepted = take;
  if (all && end_stream) {
    s->local_ended = true;
    return close_if_done(c, s);
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_consume(
    GHTTP_H2Conn * c, uint32_t stream_id, size_t n) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  Stream * s = stream_find(c, stream_id);
  if (!s) {
    return GHTTP_OK;  // closed: its credit was returned when it went
  }
  if (n > s->recv_unconsumed) {
    return GHTTP_ERR_INVALID;
  }
  s->recv_unconsumed -= n;
  GHTTP_Result r = credit_connection(c, n);
  if (r == GHTTP_OK) {
    r = credit_stream(c, s, n);
  }
  return r;
}

GHTTP_Result ghttp_h2_conn_reset_stream(
    GHTTP_H2Conn * c, uint32_t stream_id, uint32_t error_code) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  Stream * s = stream_find(c, stream_id);
  if (!s) {
    return GHTTP_ERR_INVALID;
  }
  if (ghttp_h2_write_rst_stream(c->out, stream_id, error_code) != GHTTP_OK) {
    return oom(c);
  }
  return stream_remove(c, stream_id, HOW_SENT_RST);
}

GHTTP_Result ghttp_h2_conn_ping(GHTTP_H2Conn * c, const uint8_t data[8]) {
  if (!c || !data) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  if (ghttp_h2_write_ping(c->out, data, 0) != GHTTP_OK) {
    return oom(c);
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_shutdown(GHTTP_H2Conn * c, uint32_t error_code,
    const void * debug, size_t debug_len) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  GHTTP_Result r = ghttp_h2_write_goaway(
      c->out, c->last_peer_id, error_code, debug, debug_len);
  if (r == GHTTP_ERR_OOM) {
    return oom(c);
  }
  if (r != GHTTP_OK) {
    return r;
  }
  c->goaway_sent = true;
  c->goaway_sent_last = c->last_peer_id;
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_conn_send_extension_frame(GHTTP_H2Conn * c, uint8_t type,
    uint8_t flags, uint32_t stream_id, const void * payload, size_t len) {
  if (!c || type <= GHTTP_H2_CONTINUATION) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  GHTTP_Result r = ghttp_h2_write_frame(
      c->out, type, flags, stream_id, payload, len);
  return r == GHTTP_ERR_OOM ? oom(c) : r;
}
