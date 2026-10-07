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
 * The WebSocket connection: framing, fragmentation and reassembly, control
 * frames, the closing handshake, UTF-8 validation, permessage-deflate and the
 * abuse limits, for either role.
 *
 * Reference: RFC 6455 sections 5 to 8 and 10.3, and RFC 7692 section 7.2.
 *
 * Every decision is taken on the octets the stream holds up to a point and
 * never on how many a call happened to deliver: a header is read an octet at a
 * time through the stateless parser, payload is processed in fixed pieces, and
 * a message becomes an event only at its last frame, so the events and the
 * output are the same however the input is cut.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/ws_conn.h>
#include "http_internal.h"
#include "ws_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/random.h>
#include <string.h>

/** Payload is unmasked and processed this much at a time. */
#define PIECE 512u

typedef enum { IN_HEADER, IN_PAYLOAD } InState;

struct GHTTP_WsConn {
  const GHTTP_Allocator * allocator;
  GHTTP_WsRole role;
  GHTTP_WsLimits limits;
  GHTTP_WsNegotiated neg;

  // Failure (sticky).
  GHTTP_Result failed;
  uint16_t err_code;
  const char * err_reason;

  // Input.
  InState in_state;
  uint8_t hdr[GHTTP_WS_MAX_HEADER_LEN];
  size_t hdr_have;
  GHTTP_WsFrameHeader fh;
  uint64_t payload_done;
  bool close_received;

  // The message being assembled.
  bool in_message;
  uint8_t msg_opcode;
  bool msg_compressed;
  uint8_t msg_rsv;
  uint32_t msg_frames;
  uint64_t msg_wire;     // compressed octets so far
  GHTTP_Buffer * msg;
  GHTTP_WsUtf8 utf8;
  bool lent;             // msg is lent to the caller by the last event

  // Compressed payload waits here until a whole PIECE of it has arrived, or
  // its frame ends, so that the decompressor is called on units of the stream
  // and not of the caller's reads (see on_payload()).
  uint8_t blk[PIECE];
  size_t blk_len;

  // The control frame being read.
  uint8_t ctl[GHTTP_WS_MAX_CONTROL_PAYLOAD];
  size_t ctl_len;

  // Per interval.
  uint32_t ctl_count;
  uint64_t interval_start;
  bool have_clock;

  // permessage-deflate, created when first needed.
  GHTTP_WsDeflate * defl;

  // Output.
  GHTTP_Buffer * out;
  GHTTP_Buffer * scratch;
  bool close_sent;
  bool send_open;                  // a fragmented message is being sent
  GHTTP_WsMessageType send_type;
  bool send_compressed;
  uint64_t send_total;
  GHTTP_WsUtf8 send_utf8;
  GHTTP_WsRandomFn rnd;
  void * rnd_ctx;
  size_t compress_min;
};

static const uint8_t EMPTY[1] = {0};

static GHTTP_Result default_random(void * ctx, void * out, size_t n) {
  (void)ctx;
  return gsec_random_bytes(out, n, NULL) == GSEC_OK ? GHTTP_OK : GHTTP_ERR_IO;
}

GHTTP_Result ghttp_ws_conn_create(const GHTTP_Allocator * allocator,
    GHTTP_WsRole role, const GHTTP_WsLimits * limits,
    const GHTTP_WsNegotiated * negotiated, GHTTP_WsConn ** out) {
  if (!out || (role != GHTTP_WS_CLIENT && role != GHTTP_WS_SERVER)) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_WsLimits lim;
  if (ghttp_ws_limits_resolve(limits, &lim) != GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  // A whole control frame, masked, has to fit in the queue, or a Ping could
  // never be answered.
  if (lim.max_buffered_bytes < 2 + GHTTP_WS_MAX_CONTROL_PAYLOAD + 4) {
    return GHTTP_ERR_INVALID;
  }
  GHTTP_WsConn * c = gcu_allocator_calloc(allocator, 1, sizeof(*c));
  if (!c) {
    return GHTTP_ERR_OOM;
  }
  c->allocator = allocator;
  c->role = role;
  c->limits = lim;
  ghttp_ws_negotiated_default(&c->neg);
  if (negotiated) {
    size_t n = negotiated->size && negotiated->size < sizeof(c->neg)
        ? negotiated->size : sizeof(c->neg);
    memcpy(&c->neg, negotiated, n);
    c->neg.size = sizeof(c->neg);
    c->neg.extension_rsv &= (GHTTP_WS_RSV2 | GHTTP_WS_RSV3);
  }
  c->rnd = default_random;
  GHTTP_Result r = ghttp_buffer_create(allocator, &c->msg);
  if (r == GHTTP_OK) {
    r = ghttp_buffer_create(allocator, &c->out);
  }
  if (r == GHTTP_OK) {
    r = ghttp_buffer_create(allocator, &c->scratch);
  }
  if (r != GHTTP_OK) {
    ghttp_ws_conn_destroy(c);
    return r;
  }
  *out = c;
  return GHTTP_OK;
}

void ghttp_ws_conn_destroy(GHTTP_WsConn * c) {
  if (!c) {
    return;
  }
  ghttp_ws_deflate_close(c->defl);
  ghttp_buffer_destroy(c->msg);
  ghttp_buffer_destroy(c->out);
  ghttp_buffer_destroy(c->scratch);
  gcu_allocator_free(c->allocator, c);
}

void ghttp_ws_conn_set_random(GHTTP_WsConn * c, GHTTP_WsRandomFn fn, void * ctx) {
  if (!c) {
    return;
  }
  c->rnd = fn ? fn : default_random;
  c->rnd_ctx = fn ? ctx : NULL;
}

void ghttp_ws_conn_set_compress_min(GHTTP_WsConn * c, size_t bytes) {
  if (c) {
    c->compress_min = bytes;
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const uint8_t * ghttp_ws_conn_output(const GHTTP_WsConn * c, size_t * len) {
  if (len) {
    *len = c ? ghttp_buffer_size(c->out) : 0;
  }
  return c ? ghttp_buffer_data(c->out) : NULL;
}

void ghttp_ws_conn_output_consume(GHTTP_WsConn * c, size_t n) {
  if (c) {
    ghttp_buffer_consume(c->out, n);
  }
}

size_t ghttp_ws_conn_output_size(const GHTTP_WsConn * c) {
  return c ? ghttp_buffer_size(c->out) : 0;
}

/** How much more output the queue may take before its limit. */
static size_t queue_room(const GHTTP_WsConn * c) {
  size_t have = ghttp_buffer_size(c->out);
  return have < c->limits.max_buffered_bytes ? c->limits.max_buffered_bytes - have : 0;
}

/**
 * Append one frame to the output. @p key is the masking key of a client's
 * frame and NULL at a server. With @p force the queue's limit is not applied:
 * the Close that ends a failed connection is owed whatever is queued.
 */
static GHTTP_Result queue_frame(GHTTP_WsConn * c, uint8_t opcode, bool fin,
    bool rsv1, const uint8_t * payload, size_t len, const uint8_t * key,
    bool force) {
  GHTTP_WsFrameHeader h;
  memset(&h, 0, sizeof(h));
  h.size = sizeof(h);
  h.fin = fin;
  h.rsv1 = rsv1;
  h.opcode = opcode;
  h.payload_len = len;
  if (key) {
    h.masked = 1;
    memcpy(h.mask_key, key, 4);
  }
  uint8_t hb[GHTTP_WS_MAX_HEADER_LEN];
  size_t hn;
  if (ghttp_ws_frame_header_write(&h, hb, &hn) != GHTTP_OK) {
    return GHTTP_ERR_INTERNAL;
  }
  size_t have = ghttp_buffer_size(c->out);
  if (!force && hn + len > queue_room(c)) {
    return GHTTP_ERR_LIMIT;
  }
  GHTTP_Result r = ghttp_buffer_append(c->out, hb, hn);
  if (key) {
    uint8_t tmp[PIECE];
    for (size_t off = 0; r == GHTTP_OK && off < len;) {
      size_t k = len - off < sizeof(tmp) ? len - off : sizeof(tmp);
      memcpy(tmp, payload + off, k);
      ghttp_ws_mask(tmp, k, key, off);
      r = ghttp_buffer_append(c->out, tmp, k);
      off += k;
    }
  } else if (r == GHTTP_OK) {
    r = ghttp_buffer_append(c->out, payload, len);
  }
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(c->out, have);
  }
  return r;
}

static GHTTP_Result draw_key(GHTTP_WsConn * c, uint8_t key[4]) {
  return c->rnd(c->rnd_ctx, key, 4);
}

/** End the connection: record why, and queue the Close that says so unless one has gone. */
static GHTTP_Result fail(GHTTP_WsConn * c, GHTTP_Result r, uint16_t code,
    const char * reason) {
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  c->failed = r;
  c->err_code = code;
  c->err_reason = reason;
  if (!c->close_sent) {
    uint8_t body[2 + GHTTP_WS_MAX_CONTROL_PAYLOAD - 2];
    body[0] = (uint8_t)(code >> 8);
    body[1] = (uint8_t)code;
    size_t rn = strlen(reason);
    if (rn > sizeof(body) - 2) {
      rn = sizeof(body) - 2;
    }
    memcpy(body + 2, reason, rn);
    uint8_t key[4];
    const uint8_t * kp = NULL;
    GHTTP_Result kr = GHTTP_OK;
    if (c->role == GHTTP_WS_CLIENT) {
      kr = draw_key(c, key);
      kp = key;
    }
    // Best effort: with no memory or no randomness there is no Close to send,
    // and the caller closes the transport on the error anyway.
    if (kr == GHTTP_OK) {
      (void)queue_frame(c, GHTTP_WS_OP_CLOSE, true, false, body, 2 + rn, kp, true);
    }
    c->close_sent = true;
  }
  return r;
}

static GHTTP_Result fail_oom(GHTTP_WsConn * c) {
  return fail(c, GHTTP_ERR_OOM, GHTTP_WS_CLOSE_INTERNAL_ERROR, "out of memory");
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

GHTTP_Result ghttp_ws_conn_error(
    const GHTTP_WsConn * c, uint16_t * code, const char ** reason) {
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

GHTTP_WsState ghttp_ws_conn_state(const GHTTP_WsConn * c) {
  if (c->failed != GHTTP_OK) {
    return GHTTP_WS_STATE_FAILED;
  }
  if (c->close_sent && c->close_received) {
    return GHTTP_WS_STATE_CLOSED;
  }
  if (c->close_sent || c->close_received) {
    return GHTTP_WS_STATE_CLOSING;
  }
  return GHTTP_WS_STATE_OPEN;
}

int ghttp_ws_conn_deflate_active(const GHTTP_WsConn * c) {
  return c && c->neg.deflate;
}

GHTTP_Result ghttp_ws_conn_finish(const GHTTP_WsConn * c) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  return c->failed == GHTTP_OK && c->close_sent && c->close_received
      ? GHTTP_OK : GHTTP_ERR_CORRUPT;
}

void ghttp_ws_conn_tick(GHTTP_WsConn * c, uint64_t now_ms) {
  if (!c) {
    return;
  }
  // A clock that runs backwards also starts an interval, as in h2conn.
  if (!c->have_clock || now_ms < c->interval_start
      || now_ms - c->interval_start >= c->limits.interval_ms) {
    c->interval_start = now_ms;
    c->have_clock = true;
    c->ctl_count = 0;
  }
}

/** The deflate state, made the first time a compressed message is sent or received. */
static GHTTP_Result get_deflate(GHTTP_WsConn * c) {
  if (c->defl) {
    return GHTTP_OK;
  }
  const GHTTP_WsDeflateParams * p = &c->neg.deflate_params;
  bool server = c->role == GHTTP_WS_SERVER;
  return ghttp_ws_deflate_open(c->allocator,
      server ? p->server_max_window_bits : p->client_max_window_bits,
      server ? p->server_no_context_takeover : p->client_no_context_takeover,
      server ? p->client_no_context_takeover : p->server_no_context_takeover,
      c->limits.max_message_bytes, c->limits.max_expansion_ratio, &c->defl);
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

static bool is_control(uint8_t op) {
  return ghttp_ws_opcode_is_control(op) != 0;
}

/** The most compressed octets a message may arrive as: its limit, and what the extension's framing can add. */
static uint64_t wire_cap(uint64_t max_message) {
  uint64_t extra = max_message / 64 + 16;
  return max_message > UINT64_MAX - extra ? UINT64_MAX : max_message + extra;
}

/** A complete frame header is in c->fh: whether the frame may be, and set up to read it. */
static GHTTP_Result on_header(GHTTP_WsConn * c) {
  const GHTTP_WsFrameHeader * fh = &c->fh;
  bool ctl = is_control(fh->opcode);
  if (c->role == GHTTP_WS_SERVER && !fh->masked) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
        "a client frame is not masked");
  }
  if (c->role == GHTTP_WS_CLIENT && fh->masked) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
        "a server frame is masked");
  }
  uint8_t bits = (uint8_t)((fh->rsv1 ? GHTTP_WS_RSV1 : 0)
      | (fh->rsv2 ? GHTTP_WS_RSV2 : 0) | (fh->rsv3 ? GHTTP_WS_RSV3 : 0));
  uint8_t allowed = c->neg.extension_rsv;
  // RSV1 is permessage-deflate's, and only on the first frame of a data
  // message (RFC 7692 section 6): not on a control frame, not on a continuation.
  if (c->neg.deflate && !ctl && fh->opcode != GHTTP_WS_OP_CONTINUATION) {
    allowed |= GHTTP_WS_RSV1;
  }
  if (bits & ~allowed) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
        "a reserved bit is set that no negotiated extension uses");
  }
  if (ctl) {
    if (++c->ctl_count > c->limits.max_control_per_interval) {
      return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_POLICY_VIOLATION,
          "too many control frames");
    }
    c->ctl_len = 0;
    return GHTTP_OK;
  }
  // A compressed frame may be the extension's overhead larger than the message
  // it carries, so its limit is allowed the same slack as a compressed message.
  bool frame_compressed = fh->opcode == GHTTP_WS_OP_CONTINUATION
      ? c->in_message && c->msg_compressed : fh->rsv1 != 0;
  uint64_t frame_cap = frame_compressed ? wire_cap(c->limits.max_frame_payload)
                                        : c->limits.max_frame_payload;
  if (fh->payload_len > frame_cap) {
    return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_MESSAGE_TOO_BIG,
        "a frame is larger than the limit");
  }
  if (fh->opcode == GHTTP_WS_OP_CONTINUATION) {
    if (!c->in_message) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
          "a continuation frame with no message to continue");
    }
  } else if (c->in_message) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
        "a new message began inside a fragmented one");
  }
  uint32_t frames = c->in_message ? c->msg_frames : 0;
  if (frames >= c->limits.max_fragments) {
    return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_MESSAGE_TOO_BIG,
        "a message has more fragments than the limit");
  }
  bool compressed = c->in_message ? c->msg_compressed : fh->rsv1 != 0;
  if (compressed) {
    uint64_t wire = c->in_message ? c->msg_wire : 0;
    uint64_t cap = wire_cap(c->limits.max_message_bytes);
    if (fh->payload_len > cap - (wire < cap ? wire : cap)) {
      return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_MESSAGE_TOO_BIG,
          "a compressed message is larger than the limit");
    }
  } else {
    uint64_t have = c->in_message ? ghttp_buffer_size(c->msg) : 0;
    uint64_t cap = c->limits.max_message_bytes;
    if (fh->payload_len > cap - (have < cap ? have : cap)) {
      return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_MESSAGE_TOO_BIG,
          "a message is larger than the limit");
    }
  }
  if (!c->in_message) {
    c->in_message = true;
    c->msg_opcode = fh->opcode;
    c->msg_compressed = fh->rsv1 != 0;
    c->msg_rsv = (uint8_t)(bits & (GHTTP_WS_RSV2 | GHTTP_WS_RSV3));
    c->msg_frames = 0;
    c->msg_wire = 0;
    ghttp_buffer_clear(c->msg);
    ghttp_ws_utf8_init(&c->utf8);
    if (c->msg_compressed) {
      GHTTP_Result r = get_deflate(c);
      if (r != GHTTP_OK) {
        return fail_oom(c);
      }
      ghttp_ws_inflate_begin(c->defl);
    }
  }
  c->msg_frames++;
  if (c->msg_compressed) {
    c->msg_wire += fh->payload_len;
  }
  return GHTTP_OK;
}

/** Map what the bounded inflate said to the connection's failure. */
static GHTTP_Result inflate_failed(GHTTP_WsConn * c, GHTTP_Result r) {
  switch (r) {
    case GHTTP_ERR_LIMIT:
      return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_MESSAGE_TOO_BIG,
          "a message inflates past the size or expansion limit");
    case GHTTP_ERR_CORRUPT:
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_INVALID_PAYLOAD,
          "the compressed data is not valid");
    case GHTTP_ERR_OOM:
      return fail_oom(c);
    default:
      return fail(c, GHTTP_ERR_INTERNAL, GHTTP_WS_CLOSE_INTERNAL_ERROR,
          "the decompressor failed");
  }
}

/** Text that is going into the message is checked as it arrives. */
static GHTTP_Result check_text(GHTTP_WsConn * c, const uint8_t * p, size_t n) {
  if (c->msg_opcode == GHTTP_WS_OP_TEXT
      && ghttp_ws_utf8_feed(&c->utf8, p, n) != GHTTP_OK) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_INVALID_PAYLOAD,
        "a text message is not valid UTF-8");
  }
  return GHTTP_OK;
}

/** What the decompressor added to the message since it was @p before octets long. */
static GHTTP_Result check_new_text(GHTTP_WsConn * c, size_t before) {
  size_t now = ghttp_buffer_size(c->msg);
  if (now == before) {
    return GHTTP_OK;  // and the buffer may have no storage to point into
  }
  return check_text(c, (const uint8_t *)ghttp_buffer_data(c->msg) + before, now - before);
}

/** Decompress what has been gathered of the current frame, and check the text it made. */
static GHTTP_Result inflate_gathered(GHTTP_WsConn * c) {
  size_t before = ghttp_buffer_size(c->msg);
  size_t n = c->blk_len;
  c->blk_len = 0;
  GHTTP_Result r = ghttp_ws_inflate_update(c->defl, c->blk, n, c->msg);
  if (r != GHTTP_OK) {
    return inflate_failed(c, r);
  }
  return check_new_text(c, before);
}

/**
 * The next piece of the current frame's payload, already unmasked.
 *
 * Whatever is decided about a message must not depend on how the caller's
 * reads fell. Uncompressed text is judged an octet at a time, so any piece
 * size gives the same verdict. A decompressor is different: it can fail with
 * output already made, and which of its failures (corrupt data, a limit, text
 * that is not UTF-8) comes first depends on where its calls end. So its calls
 * are made on units of the stream, PIECE octets of a frame's payload at a time
 * and the rest at the frame's end, and a read that ends elsewhere only waits.
 */
static GHTTP_Result on_payload(GHTTP_WsConn * c, const uint8_t * p, size_t n) {
  if (is_control(c->fh.opcode)) {
    memcpy(c->ctl + c->ctl_len, p, n);
    c->ctl_len += n;
    return GHTTP_OK;
  }
  if (!c->msg_compressed) {
    GHTTP_Result r = check_text(c, p, n);
    if (r != GHTTP_OK) {
      return r;
    }
    if (ghttp_buffer_append(c->msg, p, n) != GHTTP_OK) {
      return fail_oom(c);
    }
    return GHTTP_OK;
  }
  while (n > 0) {
    size_t take = PIECE - c->blk_len < n ? PIECE - c->blk_len : n;
    memcpy(c->blk + c->blk_len, p, take);
    c->blk_len += take;
    p += take;
    n -= take;
    if (c->blk_len == PIECE) {
      GHTTP_Result r = inflate_gathered(c);
      if (r != GHTTP_OK) {
        return r;
      }
    }
  }
  return GHTTP_OK;
}

static GHTTP_Result on_control(GHTTP_WsConn * c, GHTTP_WsEvent * ev) {
  switch (c->fh.opcode) {
    case GHTTP_WS_OP_PING: {
      if (!c->close_sent) {
        uint8_t key[4];
        const uint8_t * kp = NULL;
        if (c->role == GHTTP_WS_CLIENT) {
          if (draw_key(c, key) != GHTTP_OK) {
            return fail(c, GHTTP_ERR_IO, GHTTP_WS_CLOSE_INTERNAL_ERROR,
                "no random source for a masking key");
          }
          kp = key;
        }
        GHTTP_Result r = queue_frame(c, GHTTP_WS_OP_PONG, true, false, c->ctl,
            c->ctl_len, kp, false);
        if (r == GHTTP_ERR_LIMIT) {
          return fail(c, GHTTP_ERR_LIMIT, GHTTP_WS_CLOSE_POLICY_VIOLATION,
              "the output queue is full");
        }
        if (r != GHTTP_OK) {
          return fail_oom(c);
        }
      }
      ev->type = GHTTP_WS_EVENT_PING;
      ev->data = c->ctl_len ? c->ctl : EMPTY;
      ev->data_len = c->ctl_len;
      return GHTTP_OK;
    }
    case GHTTP_WS_OP_PONG:
      ev->type = GHTTP_WS_EVENT_PONG;
      ev->data = c->ctl_len ? c->ctl : EMPTY;
      ev->data_len = c->ctl_len;
      return GHTTP_OK;
    default:
      break;
  }
  // Close (section 5.5.1): nothing, or a two-octet code and a UTF-8 reason.
  uint16_t code = GHTTP_WS_CLOSE_NO_STATUS;
  const uint8_t * reason = EMPTY;
  size_t reason_len = 0;
  if (c->ctl_len == 1) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
        "a Close frame has a one-octet body");
  }
  if (c->ctl_len >= 2) {
    code = (uint16_t)((c->ctl[0] << 8) | c->ctl[1]);
    if (!ghttp_ws_close_code_is_valid(code)) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
          "a Close frame carries a code that may not be sent");
    }
    reason = c->ctl + 2;
    reason_len = c->ctl_len - 2;
    GHTTP_WsUtf8 v;
    ghttp_ws_utf8_init(&v);
    if (ghttp_ws_utf8_feed(&v, reason, reason_len) != GHTTP_OK
        || !ghttp_ws_utf8_complete(&v)) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_INVALID_PAYLOAD,
          "the reason of a Close frame is not valid UTF-8");
    }
  }
  c->close_received = true;
  ghttp_buffer_clear(c->msg);
  c->in_message = false;
  if (!c->close_sent) {
    // The reply carries the code the peer sent (section 5.5.1).
    uint8_t body[2];
    body[0] = (uint8_t)(code >> 8);
    body[1] = (uint8_t)code;
    uint8_t key[4];
    const uint8_t * kp = NULL;
    if (c->role == GHTTP_WS_CLIENT) {
      if (draw_key(c, key) != GHTTP_OK) {
        return fail(c, GHTTP_ERR_IO, GHTTP_WS_CLOSE_INTERNAL_ERROR,
            "no random source for a masking key");
      }
      kp = key;
    }
    GHTTP_Result r = queue_frame(c, GHTTP_WS_OP_CLOSE, true, false, body,
        c->ctl_len >= 2 ? 2 : 0, kp, true);
    if (r != GHTTP_OK) {
      return fail_oom(c);
    }
    c->close_sent = true;
  }
  // The reason stays in ctl, which nothing overwrites before the next frame.
  ev->type = GHTTP_WS_EVENT_CLOSE;
  ev->code = code;
  ev->data = reason;
  ev->data_len = reason_len;
  return GHTTP_OK;
}

/** The last octet of a frame has been read. */
static GHTTP_Result on_frame_end(GHTTP_WsConn * c, GHTTP_WsEvent * ev) {
  if (is_control(c->fh.opcode)) {
    return on_control(c, ev);
  }
  if (c->blk_len > 0) {
    GHTTP_Result r = inflate_gathered(c);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  if (!c->fh.fin) {
    return GHTTP_OK;
  }
  if (c->msg_compressed) {
    size_t before = ghttp_buffer_size(c->msg);
    GHTTP_Result r = ghttp_ws_inflate_end(c->defl, c->msg);
    if (r != GHTTP_OK) {
      return inflate_failed(c, r);
    }
    r = check_new_text(c, before);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  if (c->msg_opcode == GHTTP_WS_OP_TEXT && !ghttp_ws_utf8_complete(&c->utf8)) {
    return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_INVALID_PAYLOAD,
        "a text message ends inside a UTF-8 sequence");
  }
  size_t n = ghttp_buffer_size(c->msg);
  ev->type = c->msg_opcode == GHTTP_WS_OP_TEXT ? GHTTP_WS_EVENT_TEXT
                                               : GHTTP_WS_EVENT_BINARY;
  ev->data = n ? ghttp_buffer_data(c->msg) : EMPTY;
  ev->data_len = n;
  ev->compressed = c->msg_compressed;
  ev->fragments = c->msg_frames;
  ev->rsv = c->msg_rsv;
  c->lent = true;
  c->in_message = false;
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_conn_feed(GHTTP_WsConn * c, const void * data, size_t len,
    size_t * consumed, GHTTP_WsEvent * event) {
  if (!c || (!data && len > 0) || !consumed || !event) {
    return GHTTP_ERR_INVALID;
  }
  *consumed = 0;
  memset(event, 0, sizeof(*event));
  event->size = sizeof(*event);
  if (c->failed != GHTTP_OK) {
    return c->failed;
  }
  if (c->lent) {
    ghttp_buffer_clear(c->msg);
    c->lent = false;
  }
  if (c->close_received) {
    if (len > 0) {
      return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
          "data after a Close frame");
    }
    return GHTTP_OK;
  }
  const uint8_t * in = data;
  size_t i = 0;
  while (i < len) {
    GHTTP_Result r;
    bool frame_complete = false;
    if (c->in_state == IN_HEADER) {
      c->hdr[c->hdr_have++] = in[i++];
      size_t used = 0;
      r = ghttp_ws_frame_header_parse(c->hdr, c->hdr_have, &c->fh, &used);
      if (r != GHTTP_OK) {
        *consumed = i;
        return fail(c, GHTTP_ERR_CORRUPT, GHTTP_WS_CLOSE_PROTOCOL_ERROR,
            "a frame header is not valid");
      }
      if (used == 0) {
        continue;
      }
      c->hdr_have = 0;
      r = on_header(c);
      if (r != GHTTP_OK) {
        *consumed = i;
        return r;
      }
      c->in_state = IN_PAYLOAD;
      c->payload_done = 0;
      frame_complete = c->fh.payload_len == 0;
    } else {
      uint64_t left = c->fh.payload_len - c->payload_done;
      size_t take = len - i < left ? len - i : (size_t)left;
      while (take > 0) {
        uint8_t piece[PIECE];
        size_t k = take < sizeof(piece) ? take : sizeof(piece);
        memcpy(piece, in + i, k);
        if (c->fh.masked) {
          ghttp_ws_mask(piece, k, c->fh.mask_key, c->payload_done);
        }
        r = on_payload(c, piece, k);
        i += k;
        take -= k;
        c->payload_done += k;
        if (r != GHTTP_OK) {
          *consumed = i;
          return r;
        }
      }
      frame_complete = c->payload_done == c->fh.payload_len;
    }
    if (frame_complete) {
      c->in_state = IN_HEADER;
      r = on_frame_end(c, event);
      if (r != GHTTP_OK) {
        *consumed = i;
        return r;
      }
      if (event->type != GHTTP_WS_EVENT_NEED_MORE) {
        break;
      }
    }
  }
  *consumed = i;
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/** What every send checks first. */
static GHTTP_Result send_ready(const GHTTP_WsConn * c) {
  if (!c) {
    return GHTTP_ERR_INVALID;
  }
  if (c->failed != GHTTP_OK || c->close_sent) {
    return GHTTP_ERR_INVALID;
  }
  return GHTTP_OK;
}

static GHTTP_Result send_data(GHTTP_WsConn * c, GHTTP_WsMessageType type,
    const void * data, size_t len, bool fin, bool whole_message) {
  GHTTP_Result r = send_ready(c);
  if (r != GHTTP_OK) {
    return r;
  }
  if ((!data && len > 0) || (type != GHTTP_WS_MESSAGE_TEXT && type != GHTTP_WS_MESSAGE_BINARY)) {
    return GHTTP_ERR_INVALID;
  }
  bool first = !c->send_open;
  if (!first && (whole_message || type != c->send_type)) {
    return GHTTP_ERR_INVALID;
  }
  uint64_t total = (first ? 0 : c->send_total) + len;
  if (total > c->limits.max_message_bytes) {
    return GHTTP_ERR_LIMIT;
  }
  GHTTP_WsUtf8 v;
  if (first) {
    ghttp_ws_utf8_init(&v);
  } else {
    v = c->send_utf8;
  }
  if (type == GHTTP_WS_MESSAGE_TEXT) {
    if (ghttp_ws_utf8_feed(&v, data, len) != GHTTP_OK
        || (fin && !ghttp_ws_utf8_complete(&v))) {
      return GHTTP_ERR_INVALID;
    }
  }
  bool compress = first
      ? (c->neg.deflate && !(whole_message && len < c->compress_min))
      : c->send_compressed;
  // What the frame can come to, so that the queue's limit is judged before
  // the compressor has taken anything it cannot give back.
  size_t extra = (compress ? len / 8 + 128 : 0) + GHTTP_WS_MAX_HEADER_LEN;
  size_t room = queue_room(c);
  if (len > room || extra > room - len) {
    return GHTTP_ERR_LIMIT;
  }
  uint8_t key[4];
  const uint8_t * kp = NULL;
  if (c->role == GHTTP_WS_CLIENT) {
    r = draw_key(c, key);
    if (r != GHTTP_OK) {
      return r;
    }
    kp = key;
  }
  const uint8_t * payload = data;
  size_t plen = len;
  if (compress) {
    r = get_deflate(c);
    if (r != GHTTP_OK) {
      return r;
    }
    ghttp_buffer_clear(c->scratch);
    r = ghttp_ws_deflate_compress(c->defl, data, len, fin, c->scratch);
    if (r != GHTTP_OK) {
      // The compressor has taken input it will not give back: its history no
      // longer matches what the peer has seen, so nothing more can be sent.
      (void)fail(c, r, GHTTP_WS_CLOSE_INTERNAL_ERROR, "the compressor failed");
      return r;
    }
    plen = ghttp_buffer_size(c->scratch);
    payload = plen ? ghttp_buffer_data(c->scratch) : EMPTY;
  }
  if (!payload) {
    payload = EMPTY;
  }
  r = queue_frame(c, first ? (uint8_t)type : GHTTP_WS_OP_CONTINUATION, fin,
      first && compress, payload, plen, kp, false);
  if (r != GHTTP_OK) {
    if (compress) {
      (void)fail(c, r, GHTTP_WS_CLOSE_INTERNAL_ERROR, "a compressed frame could not be queued");
    }
    return r;
  }
  c->send_open = !fin;
  c->send_type = type;
  c->send_compressed = compress;
  c->send_total = fin ? 0 : total;
  c->send_utf8 = v;
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_conn_send_message(GHTTP_WsConn * c,
    GHTTP_WsMessageType type, const void * data, size_t len) {
  return send_data(c, type, data, len, true, true);
}

GHTTP_Result ghttp_ws_conn_send_fragment(GHTTP_WsConn * c,
    GHTTP_WsMessageType type, const void * data, size_t len, int fin) {
  return send_data(c, type, data, len, fin != 0, false);
}

static GHTTP_Result send_control(GHTTP_WsConn * c, uint8_t opcode,
    const void * data, size_t len) {
  GHTTP_Result r = send_ready(c);
  if (r != GHTTP_OK) {
    return r;
  }
  if ((!data && len > 0) || len > GHTTP_WS_MAX_CONTROL_PAYLOAD) {
    return GHTTP_ERR_INVALID;
  }
  uint8_t key[4];
  const uint8_t * kp = NULL;
  if (c->role == GHTTP_WS_CLIENT) {
    r = draw_key(c, key);
    if (r != GHTTP_OK) {
      return r;
    }
    kp = key;
  }
  return queue_frame(c, opcode, true, false, len ? data : EMPTY, len, kp, false);
}

GHTTP_Result ghttp_ws_conn_send_ping(
    GHTTP_WsConn * c, const void * data, size_t len) {
  return send_control(c, GHTTP_WS_OP_PING, data, len);
}

GHTTP_Result ghttp_ws_conn_send_pong(
    GHTTP_WsConn * c, const void * data, size_t len) {
  return send_control(c, GHTTP_WS_OP_PONG, data, len);
}

GHTTP_Result ghttp_ws_conn_close(GHTTP_WsConn * c, uint16_t code,
    const void * reason, size_t reason_len) {
  GHTTP_Result r = send_ready(c);
  if (r != GHTTP_OK) {
    return r;
  }
  if ((!reason && reason_len > 0) || reason_len > GHTTP_WS_MAX_CONTROL_PAYLOAD - 2) {
    return GHTTP_ERR_INVALID;
  }
  uint8_t body[GHTTP_WS_MAX_CONTROL_PAYLOAD];
  size_t n = 0;
  if (code == 0) {
    if (reason_len != 0) {
      return GHTTP_ERR_INVALID;
    }
  } else {
    if (!ghttp_ws_close_code_is_valid(code)) {
      return GHTTP_ERR_INVALID;
    }
    GHTTP_WsUtf8 v;
    ghttp_ws_utf8_init(&v);
    if (ghttp_ws_utf8_feed(&v, reason, reason_len) != GHTTP_OK
        || !ghttp_ws_utf8_complete(&v)) {
      return GHTTP_ERR_INVALID;
    }
    body[0] = (uint8_t)(code >> 8);
    body[1] = (uint8_t)code;
    if (reason_len) {
      memcpy(body + 2, reason, reason_len);
    }
    n = 2 + reason_len;
  }
  uint8_t key[4];
  const uint8_t * kp = NULL;
  if (c->role == GHTTP_WS_CLIENT) {
    r = draw_key(c, key);
    if (r != GHTTP_OK) {
      return r;
    }
    kp = key;
  }
  r = queue_frame(c, GHTTP_WS_OP_CLOSE, true, false, body, n, kp, false);
  if (r == GHTTP_OK) {
    c->close_sent = true;
  }
  return r;
}
