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
 * WebSocket frame headers, masking, incremental UTF-8 validation and the
 * close-code table.
 *
 * Reference: RFC 6455 sections 5.2, 5.3, 5.5, 7.4 and 8.1; RFC 3629 for UTF-8.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/ws_frame.h>
#include "ws_internal.h"
#include <string.h>

int ghttp_ws_opcode_is_control(uint8_t opcode) {
  return (opcode & 0x8) != 0;
}

int ghttp_ws_opcode_is_defined(uint8_t opcode) {
  return opcode <= GHTTP_WS_OP_BINARY
      || (opcode >= GHTTP_WS_OP_CLOSE && opcode <= GHTTP_WS_OP_PONG);
}

GHTTP_Result ghttp_ws_frame_header_parse(const void * data, size_t len,
    GHTTP_WsFrameHeader * out, size_t * used) {
  if (!data || !out || !used) {
    return GHTTP_ERR_INVALID;
  }
  const uint8_t * p = data;
  *used = 0;
  // Each rule is applied at the first octet that decides it, so that the
  // answer for a given prefix never depends on how much of the rest was
  // offered. The connection reads a header one octet at a time through this.
  if (len < 1) {
    return GHTTP_OK;
  }
  uint8_t b0 = p[0];
  uint8_t opcode = b0 & 0x0f;
  int fin = (b0 & 0x80) != 0;
  if (!ghttp_ws_opcode_is_defined(opcode)) {
    return GHTTP_ERR_CORRUPT;
  }
  if (ghttp_ws_opcode_is_control(opcode) && !fin) {
    return GHTTP_ERR_CORRUPT;  // section 5.5: control frames must not be fragmented
  }
  if (len < 2) {
    return GHTTP_OK;
  }
  uint8_t b1 = p[1];
  int masked = (b1 & 0x80) != 0;
  unsigned l7 = b1 & 0x7f;
  if (ghttp_ws_opcode_is_control(opcode) && l7 > GHTTP_WS_MAX_CONTROL_PAYLOAD) {
    return GHTTP_ERR_CORRUPT;  // section 5.5: at most 125 octets
  }
  size_t ext = l7 == 126 ? 2 : (l7 == 127 ? 8 : 0);
  uint64_t plen = l7;
  if (ext == 2) {
    if (len < 4) {
      return GHTTP_OK;
    }
    plen = ((uint64_t)p[2] << 8) | p[3];
    if (plen < 126) {
      return GHTTP_ERR_CORRUPT;  // section 5.2: the minimal encoding
    }
  } else if (ext == 8) {
    // The top bit and the 16-bit range are decided before the last octets.
    if (len >= 3 && (p[2] & 0x80)) {
      return GHTTP_ERR_CORRUPT;  // the most significant bit must be 0
    }
    if (len < 10) {
      return GHTTP_OK;
    }
    plen = 0;
    for (int i = 0; i < 8; i++) {
      plen = (plen << 8) | p[2 + i];
    }
    if (plen <= 0xffff) {
      return GHTTP_ERR_CORRUPT;  // the minimal encoding
    }
  }
  size_t hlen = 2 + ext + (masked ? 4 : 0);
  if (len < hlen) {
    return GHTTP_OK;
  }
  memset(out, 0, sizeof(*out));
  out->size = sizeof(*out);
  out->fin = fin;
  out->rsv1 = (b0 & 0x40) != 0;
  out->rsv2 = (b0 & 0x20) != 0;
  out->rsv3 = (b0 & 0x10) != 0;
  out->opcode = opcode;
  out->masked = masked;
  out->payload_len = plen;
  out->header_len = hlen;
  if (masked) {
    memcpy(out->mask_key, p + 2 + ext, 4);
  }
  *used = hlen;
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_frame_header_write(
    const GHTTP_WsFrameHeader * h, uint8_t * out, size_t * written) {
  if (!h || !out || !written) {
    return GHTTP_ERR_INVALID;
  }
  if (!ghttp_ws_opcode_is_defined(h->opcode)) {
    return GHTTP_ERR_INVALID;
  }
  if (ghttp_ws_opcode_is_control(h->opcode)
      && (!h->fin || h->payload_len > GHTTP_WS_MAX_CONTROL_PAYLOAD)) {
    return GHTTP_ERR_INVALID;
  }
  if (h->payload_len >> 63) {
    return GHTTP_ERR_INVALID;
  }
  size_t o = 0;
  out[o++] = (uint8_t)((h->fin ? 0x80 : 0) | (h->rsv1 ? 0x40 : 0)
      | (h->rsv2 ? 0x20 : 0) | (h->rsv3 ? 0x10 : 0) | (h->opcode & 0x0f));
  uint8_t m = h->masked ? 0x80 : 0;
  if (h->payload_len < 126) {
    out[o++] = (uint8_t)(m | h->payload_len);
  } else if (h->payload_len <= 0xffff) {
    out[o++] = (uint8_t)(m | 126);
    out[o++] = (uint8_t)(h->payload_len >> 8);
    out[o++] = (uint8_t)h->payload_len;
  } else {
    out[o++] = (uint8_t)(m | 127);
    for (int i = 7; i >= 0; i--) {
      out[o++] = (uint8_t)(h->payload_len >> (8 * i));
    }
  }
  if (h->masked) {
    memcpy(out + o, h->mask_key, 4);
    o += 4;
  }
  *written = o;
  return GHTTP_OK;
}

void ghttp_ws_mask(
    void * data, size_t len, const uint8_t key[4], uint64_t offset) {
  uint8_t * p = data;
  unsigned k = (unsigned)(offset & 3);
  size_t i = 0;
  // Bring the position to a multiple of four so the key can be applied a word
  // at a time. The word is built from bytes, so the result does not depend on
  // the host's byte order or on the pointer's alignment.
  while (i < len && k != 0) {
    p[i++] ^= key[k];
    k = (k + 1) & 3;
  }
  for (; i + 4 <= len; i += 4) {
    p[i] ^= key[0];
    p[i + 1] ^= key[1];
    p[i + 2] ^= key[2];
    p[i + 3] ^= key[3];
  }
  while (i < len) {
    p[i++] ^= key[k];
    k = (k + 1) & 3;
  }
}

void ghttp_ws_utf8_init(GHTTP_WsUtf8 * v) {
  v->need = 0;
  v->lo = 0x80;
  v->hi = 0xbf;
}

GHTTP_Result ghttp_ws_utf8_feed(
    GHTTP_WsUtf8 * v, const void * data, size_t len) {
  const uint8_t * p = data;
  uint8_t need = v->need, lo = v->lo, hi = v->hi;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = p[i];
    if (need == 0) {
      if (c < 0x80) {
        continue;
      }
      // The ranges of Unicode table 3-7, which is what rules out overlong
      // forms (C0, C1, E0 80..9F, F0 80..8F), surrogates (ED A0..BF) and
      // anything above U+10FFFF (F4 90.., F5..FF).
      if (c >= 0xc2 && c <= 0xdf) {
        need = 1; lo = 0x80; hi = 0xbf;
      } else if (c == 0xe0) {
        need = 2; lo = 0xa0; hi = 0xbf;
      } else if (c == 0xed) {
        need = 2; lo = 0x80; hi = 0x9f;
      } else if (c >= 0xe1 && c <= 0xef) {
        need = 2; lo = 0x80; hi = 0xbf;
      } else if (c == 0xf0) {
        need = 3; lo = 0x90; hi = 0xbf;
      } else if (c >= 0xf1 && c <= 0xf3) {
        need = 3; lo = 0x80; hi = 0xbf;
      } else if (c == 0xf4) {
        need = 3; lo = 0x80; hi = 0x8f;
      } else {
        return GHTTP_ERR_CORRUPT;
      }
    } else {
      if (c < lo || c > hi) {
        return GHTTP_ERR_CORRUPT;
      }
      need--;
      lo = 0x80;
      hi = 0xbf;
    }
  }
  v->need = need;
  v->lo = lo;
  v->hi = hi;
  return GHTTP_OK;
}

int ghttp_ws_utf8_complete(const GHTTP_WsUtf8 * v) {
  return v->need == 0;
}

int ghttp_ws_close_code_is_valid(uint16_t code) {
  if (code >= 1000 && code <= 1003) {
    return 1;
  }
  if (code >= 1007 && code <= 1014) {
    return 1;
  }
  return code >= 3000 && code <= 4999;
}

void ghttp_ws_limits_default(GHTTP_WsLimits * limits) {
  if (!limits) {
    return;
  }
  memset(limits, 0, sizeof(*limits));
  limits->size = sizeof(*limits);
  limits->max_frame_payload = GHTTP_WS_DEFAULT_MAX_FRAME_PAYLOAD;
  limits->max_message_bytes = GHTTP_WS_DEFAULT_MAX_MESSAGE_BYTES;
  limits->max_fragments = GHTTP_WS_DEFAULT_MAX_FRAGMENTS;
  limits->max_control_per_interval = GHTTP_WS_DEFAULT_MAX_CONTROL_PER_INTERVAL;
  limits->interval_ms = GHTTP_WS_DEFAULT_INTERVAL_MS;
  limits->max_buffered_bytes = GHTTP_WS_DEFAULT_MAX_BUFFERED_BYTES;
  limits->max_handshake_bytes = GHTTP_WS_DEFAULT_MAX_HANDSHAKE_BYTES;
  limits->max_extension_offers = GHTTP_WS_DEFAULT_MAX_EXTENSION_OFFERS;
  limits->max_extension_params = GHTTP_WS_DEFAULT_MAX_EXTENSION_PARAMS;
  limits->max_expansion_ratio = GHTTP_WS_DEFAULT_MAX_EXPANSION_RATIO;
}

GHTTP_Result ghttp_ws_limits_resolve(const GHTTP_WsLimits * in, GHTTP_WsLimits * out) {
  ghttp_ws_limits_default(out);
  if (!in) {
    return GHTTP_OK;
  }
  if (in->size == 0) {
    return GHTTP_ERR_INVALID;
  }
  size_t n = in->size < sizeof(*out) ? in->size : sizeof(*out);
  memcpy(out, in, n);
  out->size = sizeof(*out);
  // Every field is a hard cap and a zero allows none: the one exception is the
  // expansion ratio, where 0 is "no ratio limit". A frame is never larger than
  // the message it is part of.
  if (out->max_frame_payload == 0 || out->max_message_bytes == 0
      || out->max_fragments == 0 || out->max_control_per_interval == 0
      || out->interval_ms == 0 || out->max_buffered_bytes == 0
      || out->max_handshake_bytes == 0 || out->max_extension_offers == 0
      || out->max_extension_params == 0
      || out->max_frame_payload > out->max_message_bytes) {
    return GHTTP_ERR_INVALID;
  }
  return GHTTP_OK;
}
