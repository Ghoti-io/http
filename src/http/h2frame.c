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
 * HTTP/2 frame headers, payload validation and writers.
 *
 * Reference: RFC 9113 sections 4 and 6. Formats are read byte by byte with
 * explicit shifts; no struct overlays.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/h2frame.h>
#include "http_internal.h"
#include <string.h>

const char * ghttp_h2_error_string(uint32_t code) {
  switch (code) {
    case GHTTP_H2_NO_ERROR: return "NO_ERROR";
    case GHTTP_H2_PROTOCOL_ERROR: return "PROTOCOL_ERROR";
    case GHTTP_H2_INTERNAL_ERROR: return "INTERNAL_ERROR";
    case GHTTP_H2_FLOW_CONTROL_ERROR: return "FLOW_CONTROL_ERROR";
    case GHTTP_H2_SETTINGS_TIMEOUT: return "SETTINGS_TIMEOUT";
    case GHTTP_H2_STREAM_CLOSED: return "STREAM_CLOSED";
    case GHTTP_H2_FRAME_SIZE_ERROR: return "FRAME_SIZE_ERROR";
    case GHTTP_H2_REFUSED_STREAM: return "REFUSED_STREAM";
    case GHTTP_H2_CANCEL: return "CANCEL";
    case GHTTP_H2_COMPRESSION_ERROR: return "COMPRESSION_ERROR";
    case GHTTP_H2_CONNECT_ERROR: return "CONNECT_ERROR";
    case GHTTP_H2_ENHANCE_YOUR_CALM: return "ENHANCE_YOUR_CALM";
    case GHTTP_H2_INADEQUATE_SECURITY: return "INADEQUATE_SECURITY";
    case GHTTP_H2_HTTP_1_1_REQUIRED: return "HTTP_1_1_REQUIRED";
    default: return "UNKNOWN";
  }
}

const char * ghttp_h2_frame_type_string(uint8_t type) {
  switch (type) {
    case GHTTP_H2_DATA: return "DATA";
    case GHTTP_H2_HEADERS: return "HEADERS";
    case GHTTP_H2_PRIORITY: return "PRIORITY";
    case GHTTP_H2_RST_STREAM: return "RST_STREAM";
    case GHTTP_H2_SETTINGS: return "SETTINGS";
    case GHTTP_H2_PUSH_PROMISE: return "PUSH_PROMISE";
    case GHTTP_H2_PING: return "PING";
    case GHTTP_H2_GOAWAY: return "GOAWAY";
    case GHTTP_H2_WINDOW_UPDATE: return "WINDOW_UPDATE";
    case GHTTP_H2_CONTINUATION: return "CONTINUATION";
    default: return "UNKNOWN";
  }
}

void ghttp_h2_frame_header_parse(
    const uint8_t b[GHTTP_H2_FRAME_HEADER_SIZE], GHTTP_H2FrameHeader * out) {
  out->length = ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
  out->type = b[3];
  out->flags = b[4];
  out->stream_id = (((uint32_t)b[5] & 0x7f) << 24) | ((uint32_t)b[6] << 16)
      | ((uint32_t)b[7] << 8) | b[8];
}

void ghttp_h2_frame_header_write(
    const GHTTP_H2FrameHeader * h, uint8_t out[GHTTP_H2_FRAME_HEADER_SIZE]) {
  out[0] = (uint8_t)(h->length >> 16);
  out[1] = (uint8_t)(h->length >> 8);
  out[2] = (uint8_t)h->length;
  out[3] = h->type;
  out[4] = h->flags;
  out[5] = (uint8_t)((h->stream_id >> 24) & 0x7f);
  out[6] = (uint8_t)(h->stream_id >> 16);
  out[7] = (uint8_t)(h->stream_id >> 8);
  out[8] = (uint8_t)h->stream_id;
}

static uint32_t get32(const uint8_t * p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
      | ((uint32_t)p[2] << 8) | p[3];
}

static GHTTP_Result fail(GHTTP_H2FrameError * err, uint32_t code, int connection,
    uint32_t stream_id) {
  if (err) {
    err->code = code;
    err->connection = connection;
    err->stream_id = connection ? 0 : stream_id;
  }
  return GHTTP_ERR_CORRUPT;
}

GHTTP_Result ghttp_h2_frame_header_check(const GHTTP_H2FrameHeader * h,
    size_t max_frame_size, GHTTP_H2FrameError * err) {
  uint32_t len = h->length;
  bool ack = (h->flags & GHTTP_H2_FLAG_ACK) != 0;
  if (len > max_frame_size) {
    return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
  }
  switch (h->type) {
    case GHTTP_H2_DATA:
      if (h->stream_id == 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      if ((h->flags & GHTTP_H2_FLAG_PADDED) && len < 1) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    case GHTTP_H2_HEADERS: {
      if (h->stream_id == 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      uint32_t need = ((h->flags & GHTTP_H2_FLAG_PADDED) ? 1u : 0u)
          + ((h->flags & GHTTP_H2_FLAG_PRIORITY) ? 5u : 0u);
      if (len < need) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    }
    case GHTTP_H2_PRIORITY:
      if (h->stream_id == 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      if (len != 5) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 0, h->stream_id);
      }
      break;
    case GHTTP_H2_RST_STREAM:
      if (h->stream_id == 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      if (len != 4) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    case GHTTP_H2_SETTINGS:
      if (h->stream_id != 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      if ((ack && len != 0) || len % 6 != 0) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    case GHTTP_H2_PUSH_PROMISE: {
      if (h->stream_id == 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      uint32_t need = 4u + ((h->flags & GHTTP_H2_FLAG_PADDED) ? 1u : 0u);
      if (len < need) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    }
    case GHTTP_H2_PING:
      if (h->stream_id != 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      if (len != 8) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    case GHTTP_H2_GOAWAY:
      if (h->stream_id != 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      if (len < 8) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    case GHTTP_H2_WINDOW_UPDATE:
      if (len != 4) {
        return fail(err, GHTTP_H2_FRAME_SIZE_ERROR, 1, 0);
      }
      break;
    case GHTTP_H2_CONTINUATION:
      if (h->stream_id == 0) {
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      break;
    default:
      break;  // an extension: nothing to check (section 5.5)
  }
  return GHTTP_OK;
}

static void read_priority(const uint8_t * p, GHTTP_H2Priority * out) {
  uint32_t v = get32(p);
  out->exclusive = (v & 0x80000000u) != 0;
  out->dependency = v & 0x7fffffffu;
  out->weight = p[4];
}

GHTTP_Result ghttp_h2_frame_parse(const GHTTP_H2FrameHeader * h,
    const uint8_t * payload, size_t max_frame_size, GHTTP_H2Frame * out,
    GHTTP_H2FrameError * err) {
  GHTTP_Result r = ghttp_h2_frame_header_check(h, max_frame_size, err);
  if (r != GHTTP_OK) {
    return r;
  }
  memset(out, 0, sizeof(*out));
  out->header = *h;
  out->known = 1;
  const uint8_t * p = payload;
  size_t len = h->length;
  switch (h->type) {
    case GHTTP_H2_DATA:
    case GHTTP_H2_HEADERS:
    case GHTTP_H2_PUSH_PROMISE: {
      uint32_t pad = 0;
      if (h->flags & GHTTP_H2_FLAG_PADDED) {
        pad = p[0];
        out->padding = pad + 1;
        p++;
        len--;
      }
      if (h->type == GHTTP_H2_HEADERS) {
        out->end_stream = (h->flags & GHTTP_H2_FLAG_END_STREAM) != 0;
        out->end_headers = (h->flags & GHTTP_H2_FLAG_END_HEADERS) != 0;
        if (h->flags & GHTTP_H2_FLAG_PRIORITY) {
          out->has_priority = 1;
          read_priority(p, &out->priority);
          p += 5;
          len -= 5;
        }
      } else if (h->type == GHTTP_H2_PUSH_PROMISE) {
        out->end_headers = (h->flags & GHTTP_H2_FLAG_END_HEADERS) != 0;
        out->promised_stream_id = get32(p) & 0x7fffffffu;
        p += 4;
        len -= 4;
      } else {
        out->end_stream = (h->flags & GHTTP_H2_FLAG_END_STREAM) != 0;
      }
      if (pad > len) {
        // The padding is as long as the payload or longer (section 6.1).
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, 1, 0);
      }
      out->data = p;
      out->data_len = len - pad;
      break;
    }
    case GHTTP_H2_PRIORITY:
      out->has_priority = 1;
      read_priority(p, &out->priority);
      break;
    case GHTTP_H2_RST_STREAM:
      out->error_code = get32(p);
      break;
    case GHTTP_H2_SETTINGS:
      out->ack = (h->flags & GHTTP_H2_FLAG_ACK) != 0;
      out->settings = p;
      out->settings_count = len / 6;
      break;
    case GHTTP_H2_PING:
      out->ack = (h->flags & GHTTP_H2_FLAG_ACK) != 0;
      memcpy(out->ping, p, 8);
      break;
    case GHTTP_H2_GOAWAY:
      out->last_stream_id = get32(p) & 0x7fffffffu;
      out->error_code = get32(p + 4);
      out->data = p + 8;
      out->data_len = len - 8;
      break;
    case GHTTP_H2_WINDOW_UPDATE:
      out->increment = get32(p) & 0x7fffffffu;
      if (out->increment == 0) {
        // Section 6.9: a stream error, or a connection error for stream 0.
        return fail(err, GHTTP_H2_PROTOCOL_ERROR, h->stream_id == 0,
            h->stream_id);
      }
      break;
    case GHTTP_H2_CONTINUATION:
      out->end_headers = (h->flags & GHTTP_H2_FLAG_END_HEADERS) != 0;
      out->data = p;
      out->data_len = len;
      break;
    default:
      out->known = 0;
      out->data = p;
      out->data_len = len;
      break;
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_frame_setting_at(
    const GHTTP_H2Frame * f, size_t index, uint16_t * id, uint32_t * value) {
  if (!f || f->header.type != GHTTP_H2_SETTINGS || index >= f->settings_count) {
    return GHTTP_ERR_INVALID;
  }
  const uint8_t * p = f->settings + index * 6;
  if (id) {
    *id = (uint16_t)(((unsigned)p[0] << 8) | p[1]);
  }
  if (value) {
    *value = get32(p + 2);
  }
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

static GHTTP_Result put_header(GHTTP_Buffer * out, uint32_t len, uint8_t type,
    uint8_t flags, uint32_t stream_id) {
  uint8_t b[GHTTP_H2_FRAME_HEADER_SIZE];
  GHTTP_H2FrameHeader h = {len, type, flags, stream_id};
  ghttp_h2_frame_header_write(&h, b);
  return ghttp_buffer_append(out, b, sizeof(b));
}

static void put32(uint8_t * p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

/** Append zeros. */
static GHTTP_Result put_zeros(GHTTP_Buffer * out, size_t n) {
  static const uint8_t zeros[64];
  while (n > 0) {
    size_t k = n < sizeof(zeros) ? n : sizeof(zeros);
    GHTTP_Result r = ghttp_buffer_append(out, zeros, k);
    if (r != GHTTP_OK) {
      return r;
    }
    n -= k;
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_h2_write_frame(GHTTP_Buffer * out, uint8_t type,
    uint8_t flags, uint32_t stream_id, const void * payload, size_t len) {
  if (!out || (!payload && len > 0) || len > GHTTP_H2_MAX_MAX_FRAME_SIZE
      || stream_id > GHTTP_H2_MAX_STREAM_ID) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(out);
  GHTTP_Result r = put_header(out, (uint32_t)len, type, flags, stream_id);
  if (r == GHTTP_OK) {
    r = ghttp_buffer_append(out, payload, len);
  }
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(out, mark);
  }
  return r;
}

GHTTP_Result ghttp_h2_write_data(GHTTP_Buffer * out, uint32_t stream_id,
    const void * data, size_t len, int end_stream, int padded,
    uint8_t pad_len) {
  if (!out || (!data && len > 0) || stream_id == 0
      || stream_id > GHTTP_H2_MAX_STREAM_ID
      || len + (padded ? 1u + pad_len : 0u) > GHTTP_H2_MAX_MAX_FRAME_SIZE) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(out);
  uint8_t flags = (uint8_t)((end_stream ? GHTTP_H2_FLAG_END_STREAM : 0)
      | (padded ? GHTTP_H2_FLAG_PADDED : 0));
  GHTTP_Result r = put_header(out,
      (uint32_t)(len + (padded ? 1u + pad_len : 0u)), GHTTP_H2_DATA, flags,
      stream_id);
  if (r == GHTTP_OK && padded) {
    r = ghttp_buffer_append(out, &pad_len, 1);
  }
  if (r == GHTTP_OK) {
    r = ghttp_buffer_append(out, data, len);
  }
  if (r == GHTTP_OK && padded) {
    r = put_zeros(out, pad_len);
  }
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(out, mark);
  }
  return r;
}

GHTTP_Result ghttp_h2_write_header_block(GHTTP_Buffer * out, uint32_t stream_id,
    const void * block, size_t len, int end_stream, size_t max_frame_size) {
  if (!out || (!block && len > 0) || stream_id == 0
      || stream_id > GHTTP_H2_MAX_STREAM_ID
      || max_frame_size < GHTTP_H2_DEFAULT_MAX_FRAME_SIZE
      || max_frame_size > GHTTP_H2_MAX_MAX_FRAME_SIZE) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(out);
  const uint8_t * p = block;
  size_t first = len < max_frame_size ? len : max_frame_size;
  size_t off = first;
  GHTTP_Result r = put_header(out, (uint32_t)first, GHTTP_H2_HEADERS,
      (uint8_t)((end_stream ? GHTTP_H2_FLAG_END_STREAM : 0)
          | (off == len ? GHTTP_H2_FLAG_END_HEADERS : 0)),
      stream_id);
  if (r == GHTTP_OK) {
    r = ghttp_buffer_append(out, p, first);
  }
  while (r == GHTTP_OK && off < len) {
    size_t n = len - off < max_frame_size ? len - off : max_frame_size;
    r = put_header(out, (uint32_t)n, GHTTP_H2_CONTINUATION,
        off + n == len ? GHTTP_H2_FLAG_END_HEADERS : 0, stream_id);
    if (r == GHTTP_OK) {
      r = ghttp_buffer_append(out, p + off, n);
    }
    off += n;
  }
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(out, mark);
  }
  return r;
}

GHTTP_Result ghttp_h2_write_priority(
    GHTTP_Buffer * out, uint32_t stream_id, const GHTTP_H2Priority * pr) {
  if (!pr || pr->dependency > GHTTP_H2_MAX_STREAM_ID || stream_id == 0) {
    return GHTTP_ERR_INVALID;
  }
  uint8_t b[5];
  put32(b, pr->dependency | (pr->exclusive ? 0x80000000u : 0));
  b[4] = pr->weight;
  return ghttp_h2_write_frame(out, GHTTP_H2_PRIORITY, 0, stream_id, b, 5);
}

GHTTP_Result ghttp_h2_write_rst_stream(
    GHTTP_Buffer * out, uint32_t stream_id, uint32_t error_code) {
  if (stream_id == 0) {
    return GHTTP_ERR_INVALID;
  }
  uint8_t b[4];
  put32(b, error_code);
  return ghttp_h2_write_frame(out, GHTTP_H2_RST_STREAM, 0, stream_id, b, 4);
}

GHTTP_Result ghttp_h2_write_settings(GHTTP_Buffer * out, const uint16_t * ids,
    const uint32_t * values, size_t count, int ack) {
  if (!out || (count > 0 && (!ids || !values)) || (ack && count > 0)
      || count > GHTTP_H2_MAX_MAX_FRAME_SIZE / 6) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(out);
  GHTTP_Result r = put_header(out, (uint32_t)(count * 6), GHTTP_H2_SETTINGS,
      ack ? GHTTP_H2_FLAG_ACK : 0, 0);
  for (size_t i = 0; r == GHTTP_OK && i < count; i++) {
    uint8_t b[6];
    b[0] = (uint8_t)(ids[i] >> 8);
    b[1] = (uint8_t)ids[i];
    put32(b + 2, values[i]);
    r = ghttp_buffer_append(out, b, 6);
  }
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(out, mark);
  }
  return r;
}

GHTTP_Result ghttp_h2_write_ping(
    GHTTP_Buffer * out, const uint8_t data[8], int ack) {
  if (!data) {
    return GHTTP_ERR_INVALID;
  }
  return ghttp_h2_write_frame(
      out, GHTTP_H2_PING, ack ? GHTTP_H2_FLAG_ACK : 0, 0, data, 8);
}

GHTTP_Result ghttp_h2_write_goaway(GHTTP_Buffer * out, uint32_t last_stream_id,
    uint32_t error_code, const void * debug, size_t debug_len) {
  if (!out || (!debug && debug_len > 0) || last_stream_id > GHTTP_H2_MAX_STREAM_ID
      || debug_len > GHTTP_H2_MAX_MAX_FRAME_SIZE - 8) {
    return GHTTP_ERR_INVALID;
  }
  size_t mark = ghttp_buffer_size(out);
  uint8_t b[8];
  put32(b, last_stream_id);
  put32(b + 4, error_code);
  GHTTP_Result r = put_header(
      out, (uint32_t)(8 + debug_len), GHTTP_H2_GOAWAY, 0, 0);
  if (r == GHTTP_OK) {
    r = ghttp_buffer_append(out, b, 8);
  }
  if (r == GHTTP_OK) {
    r = ghttp_buffer_append(out, debug, debug_len);
  }
  if (r != GHTTP_OK) {
    ghttp_buffer_truncate(out, mark);
  }
  return r;
}

GHTTP_Result ghttp_h2_write_window_update(
    GHTTP_Buffer * out, uint32_t stream_id, uint32_t increment) {
  if (increment == 0 || increment > GHTTP_H2_MAX_WINDOW) {
    return GHTTP_ERR_INVALID;
  }
  uint8_t b[4];
  put32(b, increment);
  return ghttp_h2_write_frame(out, GHTTP_H2_WINDOW_UPDATE, 0, stream_id, b, 4);
}
