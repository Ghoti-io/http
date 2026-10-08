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
 * The adapter that joins an HTTP/2 tunnel stream to a WebSocket connection
 * (RFC 8441). It holds no WebSocket state of its own: bytes go in, bytes come
 * out, and the end of the stream is mapped to the closing handshake's outcome.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/buffer.h>
#include <ghoti.io/http/ws_h2.h>
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <stdbool.h>
#include <string.h>

struct GHTTP_WsH2 {
  const GHTTP_Allocator * allocator;
  GHTTP_H2Conn * h2;
  uint32_t stream_id;
  GHTTP_WsConn * ws;
  GHTTP_Buffer * pending;   // DATA copied from an event, not yet given to the WebSocket
  bool pending_end;         // the peer's END_STREAM came with that DATA
  bool remote_ended;
  bool local_ended;
  bool reset;
  uint32_t reset_code;
  GHTTP_Result conn_failed; // the h2 connection's error, if the caller said so
};

GHTTP_Result ghttp_ws_h2_create(const GHTTP_Allocator * allocator,
    GHTTP_H2Conn * h2, uint32_t stream_id, GHTTP_WsConn * ws, GHTTP_WsH2 ** out) {
  if (!h2 || !ws || !out || stream_id == 0) {
    return GHTTP_ERR_INVALID;
  }
  GHTTP_H2StreamMode mode;
  GHTTP_WsRole role;
  if (!ghttp_h2_conn_stream_is_active(h2, stream_id)
      || ghttp_h2_conn_stream_mode(h2, stream_id, &mode) != GHTTP_OK
      || mode != GHTTP_H2_STREAM_TUNNEL
      || ghttp_ws_conn_role(ws, &role) != GHTTP_OK
      || (ghttp_h2_conn_role(h2) == GHTTP_H2_CLIENT) != (role == GHTTP_WS_CLIENT)
      || !ghttp_h2_conn_stream_headers_sent(h2, stream_id)) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_WsH2 * a = gcu_allocator_calloc(allocator, 1, sizeof(*a));
  if (!a) {
    return GHTTP_ERR_OOM;
  }
  a->allocator = allocator;
  a->h2 = h2;
  a->stream_id = stream_id;
  a->ws = ws;
  GHTTP_Result r = ghttp_buffer_create(allocator, &a->pending);
  if (r != GHTTP_OK) {
    gcu_allocator_free(allocator, a);
    return r;
  }
  *out = a;
  return GHTTP_OK;
}

void ghttp_ws_h2_destroy(GHTTP_WsH2 * a) {
  if (a) {
    ghttp_buffer_destroy(a->pending);
    gcu_allocator_free(a->allocator, a);
  }
}

static void stream_gone(GHTTP_WsH2 * a, uint32_t code) {
  a->reset = true;
  a->reset_code = code;
  ghttp_buffer_clear(a->pending);
  a->pending_end = false;
}

GHTTP_Result ghttp_ws_h2_input(GHTTP_WsH2 * a, const GHTTP_H2Event * ev) {
  if (!a || !ev) {
    return GHTTP_ERR_INVALID;
  }
  bool ours = ev->stream_id == a->stream_id;
  switch (ev->type) {
    case GHTTP_H2_EVENT_HEADERS:
      if (ours && ev->end_stream && !ev->interim) {
        a->remote_ended = true;
      }
      return GHTTP_OK;
    case GHTTP_H2_EVENT_DATA:
      if (!ours || a->reset || a->conn_failed != GHTTP_OK) {
        return GHTTP_OK;
      }
      if (ghttp_buffer_size(a->pending) > 0 || a->pending_end) {
        return GHTTP_ERR_INVALID;  // the last one has not been read to the end
      }
      if (ev->data_len > 0 && ghttp_buffer_append(a->pending, ev->data, ev->data_len) != GHTTP_OK) {
        return GHTTP_ERR_OOM;
      }
      if (ev->end_stream) {
        if (ev->data_len == 0) {
          a->remote_ended = true;
        } else {
          a->pending_end = true;
        }
      }
      return GHTTP_OK;
    case GHTTP_H2_EVENT_STREAM_RESET:
    case GHTTP_H2_EVENT_STREAM_ERROR:
    case GHTTP_H2_EVENT_STREAM_UNPROCESSED:
      if (ours) {
        stream_gone(a, ev->error_code);
      }
      return GHTTP_OK;
    case GHTTP_H2_EVENT_GOAWAY:
      // A client's stream above the peer's last_stream_id was not processed
      // (RFC 9113 section 6.8): as GHTTP_H2_EVENT_STREAM_UNPROCESSED says.
      if (ghttp_h2_conn_role(a->h2) == GHTTP_H2_CLIENT && a->stream_id > ev->last_stream_id) {
        stream_gone(a, GHTTP_H2_REFUSED_STREAM);
      }
      return GHTTP_OK;
    case GHTTP_H2_EVENT_WINDOW_UPDATE:
      if (ev->stream_id == 0 || ours) {
        return ghttp_ws_h2_pump(a);
      }
      return GHTTP_OK;
    case GHTTP_H2_EVENT_SETTINGS:
      // A larger SETTINGS_INITIAL_WINDOW_SIZE opens the window of every stream.
      return ghttp_ws_h2_pump(a);
    default:
      return GHTTP_OK;
  }
}

GHTTP_Result ghttp_ws_h2_next(GHTTP_WsH2 * a, GHTTP_WsEvent * event) {
  if (!a || !event) {
    return GHTTP_ERR_INVALID;
  }
  memset(event, 0, sizeof(*event));
  event->size = sizeof(*event);
  event->type = GHTTP_WS_EVENT_NEED_MORE;
  size_t have = ghttp_buffer_size(a->pending);
  if (have == 0) {
    if (a->pending_end) {
      a->pending_end = false;
      a->remote_ended = true;
    }
    return GHTTP_OK;
  }
  size_t used = 0;
  GHTTP_Result r = ghttp_ws_conn_feed(a->ws, ghttp_buffer_data(a->pending), have, &used, event);
  if (r != GHTTP_OK) {
    // The codec has failed and queued its Close; nothing more is read.
    ghttp_buffer_clear(a->pending);
    a->pending_end = false;
    memset(event, 0, sizeof(*event));
    event->size = sizeof(*event);
    event->type = GHTTP_WS_EVENT_NEED_MORE;
    return r;
  }
  // The event's data points into the WebSocket connection's own buffers, not at
  // the copy, so the copy may be consumed now.
  ghttp_buffer_consume(a->pending, used);
  if (ghttp_buffer_size(a->pending) == 0 && event->type == GHTTP_WS_EVENT_NEED_MORE
      && a->pending_end) {
    a->pending_end = false;
    a->remote_ended = true;
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_h2_pump(GHTTP_WsH2 * a) {
  if (!a) {
    return GHTTP_ERR_INVALID;
  }
  if (a->reset || a->local_ended || a->conn_failed != GHTTP_OK
      || !ghttp_h2_conn_stream_is_active(a->h2, a->stream_id)) {
    return GHTTP_OK;  // the stream is gone, or this end has finished with it
  }
  for (;;) {
    size_t n = 0;
    const uint8_t * out = ghttp_ws_conn_output(a->ws, &n);
    if (n == 0) {
      break;
    }
    size_t accepted = 0;
    GHTTP_Result r = ghttp_h2_conn_send_data(a->h2, a->stream_id, out, n, 0, &accepted);
    if (r == GHTTP_ERR_INVALID) {
      // The application ended or reset the stream itself: nothing can be sent
      // on it, now or later, and asking again would only be refused again.
      a->local_ended = true;
      return GHTTP_OK;
    }
    if (r != GHTTP_OK) {
      return r;
    }
    ghttp_ws_conn_output_consume(a->ws, accepted);
    if (accepted < n) {
      return GHTTP_OK;  // held back by a window or the output limit; it stays queued
    }
  }
  GHTTP_WsState st = ghttp_ws_conn_state(a->ws);
  if (st == GHTTP_WS_STATE_CLOSED || st == GHTTP_WS_STATE_FAILED || a->remote_ended) {
    size_t accepted = 0;
    GHTTP_Result r = ghttp_h2_conn_send_data(a->h2, a->stream_id, NULL, 0, 1, &accepted);
    if (r == GHTTP_ERR_INVALID) {
      a->local_ended = true;
      return GHTTP_OK;
    }
    if (r != GHTTP_OK) {
      return r;
    }
    a->local_ended = true;
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_h2_connection_failed(GHTTP_WsH2 * a, GHTTP_Result error) {
  if (!a || error == GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  a->conn_failed = error;
  ghttp_buffer_clear(a->pending);
  a->pending_end = false;
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_h2_status(const GHTTP_WsH2 * a, GHTTP_WsH2Status * s) {
  if (!a || !s) {
    return GHTTP_ERR_INVALID;
  }
  memset(s, 0, sizeof(*s));
  s->size = sizeof(*s);
  s->remote_ended = a->remote_ended;
  s->local_ended = a->local_ended;
  s->reset = a->reset;
  s->reset_code = a->reset ? a->reset_code : 0;
  s->connection_failed = a->conn_failed != GHTTP_OK;
  GHTTP_WsState st = ghttp_ws_conn_state(a->ws);
  if (st == GHTTP_WS_STATE_CLOSED) {
    // The closing handshake completed: whatever happens to the stream after it
    // (its reset, the connection dying) does not undo that.
    s->state = GHTTP_WS_H2_CLOSED;
  } else if (a->reset || a->conn_failed != GHTTP_OK) {
    s->state = GHTTP_WS_H2_ABNORMAL;
    s->code = 1006;
  } else if (st == GHTTP_WS_STATE_FAILED) {
    uint16_t code = 0;
    const char * why;
    (void)ghttp_ws_conn_error(a->ws, &code, &why);
    s->state = GHTTP_WS_H2_ABNORMAL;
    s->code = code ? code : 1006;
  } else if (a->remote_ended) {
    // Also while closing: one Close has gone and the peer ended the stream
    // without answering.
    s->state = GHTTP_WS_H2_ABNORMAL;
    s->code = 1006;
  } else {
    s->state = GHTTP_WS_H2_OPEN;
  }
  return GHTTP_OK;
}
