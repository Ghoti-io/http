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
 * permessage-deflate: the parameter negotiation and the bounded compressor
 * and decompressor behind it.
 *
 * Reference: RFC 7692 sections 5 to 8 (negotiation, 7.2.1 compression, 7.2.2
 * decompression); RFC 1951 for the stream the compress library speaks.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/allocator.h>
#include <ghoti.io/http/ws_deflate.h>
#include "http_internal.h"
#include "ws_internal.h"
#include <ghoti.io/compress/errors.h>
#include <ghoti.io/compress/options.h>
#include <ghoti.io/compress/registry.h>
#include <ghoti.io/compress/stream.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

void ghttp_ws_deflate_params_default(GHTTP_WsDeflateParams * params) {
  if (!params) {
    return;
  }
  memset(params, 0, sizeof(*params));
  params->size = sizeof(*params);
}

/** The value of a window-bits parameter: 8 to 15 as decimal digits with no sign and no leading zero; 0 if it is not. */
static unsigned window_bits_value(const GHTTP_WsParam * p) {
  if (!p->has_value || p->value_len == 0 || p->value_len > 2) {
    return 0;
  }
  unsigned v = 0;
  for (size_t i = 0; i < p->value_len; i++) {
    char c = p->value[i];
    if (c < '0' || c > '9') {
      return 0;
    }
    v = v * 10 + (unsigned)(c - '0');
  }
  if (p->value[0] == '0') {
    return 0;
  }
  return v >= 8 && v <= 15 ? v : 0;
}

/** What the parameters of one extension said, each at most once. */
typedef struct Seen {
  bool snct, cnct;
  bool smwb, cmwb;
  unsigned smwb_value;
  unsigned cmwb_value;  // 0 when the parameter had no value
} Seen;

/**
 * Read the parameters. false if one is unknown, repeated or has a value it
 * may not have. @p response says that client_max_window_bits must then carry a
 * value (RFC 7692 section 7.1.2.2: only an offer may leave it out).
 */
static bool read_params(const GHTTP_WsParam * params, size_t count,
    bool response, Seen * s) {
  memset(s, 0, sizeof(*s));
  for (size_t i = 0; i < count; i++) {
    const GHTTP_WsParam * p = &params[i];
    if (ghttp_ieq(p->name, p->name_len, "server_no_context_takeover")) {
      if (s->snct || p->has_value) {
        return false;
      }
      s->snct = true;
    } else if (ghttp_ieq(p->name, p->name_len, "client_no_context_takeover")) {
      if (s->cnct || p->has_value) {
        return false;
      }
      s->cnct = true;
    } else if (ghttp_ieq(p->name, p->name_len, "server_max_window_bits")) {
      unsigned v = window_bits_value(p);
      if (s->smwb || v == 0) {
        return false;
      }
      s->smwb = true;
      s->smwb_value = v;
    } else if (ghttp_ieq(p->name, p->name_len, "client_max_window_bits")) {
      if (s->cmwb) {
        return false;
      }
      unsigned v = 0;
      if (p->has_value || response) {
        v = window_bits_value(p);
        if (v == 0) {
          return false;
        }
      }
      s->cmwb = true;
      s->cmwb_value = v;
    } else {
      return false;
    }
  }
  return true;
}

/** The smaller of two limits, where 0 means "none". */
static uint8_t tighter(unsigned a, unsigned b) {
  if (a == 0) {
    return (uint8_t)b;
  }
  if (b == 0) {
    return (uint8_t)a;
  }
  return (uint8_t)(a < b ? a : b);
}

GHTTP_Result ghttp_ws_deflate_server_negotiate(const GHTTP_WsParam * params,
    size_t count, const GHTTP_WsDeflateParams * policy,
    GHTTP_WsDeflateParams * agreed, int * accepted) {
  if ((!params && count > 0) || !agreed || !accepted) {
    return GHTTP_ERR_INVALID;
  }
  Seen s;
  if (!read_params(params, count, false, &s)) {
    *accepted = 0;
    return GHTTP_OK;
  }
  GHTTP_WsDeflateParams none;
  if (!policy) {
    ghttp_ws_deflate_params_default(&none);
    policy = &none;
  }
  ghttp_ws_deflate_params_default(agreed);
  agreed->server_no_context_takeover = s.snct || policy->server_no_context_takeover;
  agreed->client_no_context_takeover = s.cnct || policy->client_no_context_takeover;
  agreed->server_max_window_bits = tighter(s.smwb_value, policy->server_max_window_bits);
  // The server may name client_max_window_bits only in answer to an offer
  // that did: RFC 7692 section 7.1.2.2.
  agreed->client_max_window_bits = s.cmwb
      ? tighter(s.cmwb_value, policy->client_max_window_bits) : 0;
  *accepted = 1;
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_deflate_client_verify(const GHTTP_WsParam * params,
    size_t count, const GHTTP_WsDeflateParams * offered,
    GHTTP_WsDeflateParams * agreed, int * ok) {
  if ((!params && count > 0) || !offered || !agreed || !ok) {
    return GHTTP_ERR_INVALID;
  }
  *ok = 0;
  Seen s;
  if (!read_params(params, count, true, &s)) {
    return GHTTP_OK;
  }
  if (s.cmwb) {
    bool offered_it = offered->offer_client_max_window_bits
        || offered->client_max_window_bits != 0;
    if (!offered_it) {
      return GHTTP_OK;
    }
    if (offered->client_max_window_bits != 0
        && s.cmwb_value > offered->client_max_window_bits) {
      return GHTTP_OK;
    }
  }
  if (offered->server_max_window_bits != 0
      && (!s.smwb || s.smwb_value > offered->server_max_window_bits)) {
    return GHTTP_OK;
  }
  if (offered->server_no_context_takeover && !s.snct) {
    return GHTTP_OK;
  }
  ghttp_ws_deflate_params_default(agreed);
  agreed->server_no_context_takeover = s.snct;
  agreed->client_no_context_takeover = s.cnct || offered->client_no_context_takeover;
  agreed->server_max_window_bits = (uint8_t)s.smwb_value;
  agreed->client_max_window_bits = s.cmwb ? (uint8_t)s.cmwb_value
      : offered->client_max_window_bits;
  *ok = 1;
  return GHTTP_OK;
}

static bool bits_ok(unsigned v) {
  return v == 0 || (v >= 8 && v <= 15);
}

GHTTP_Result ghttp_ws_deflate_format(const GHTTP_WsDeflateParams * p,
    int is_response, char * out, size_t cap, size_t * len) {
  if (!p || !out || cap < GHTTP_WS_DEFLATE_TEXT_MAX) {
    return GHTTP_ERR_INVALID;
  }
  if (!bits_ok(p->server_max_window_bits) || !bits_ok(p->client_max_window_bits)) {
    return GHTTP_ERR_INVALID;
  }
  size_t n = (size_t)snprintf(out, cap, "%s", GHTTP_WS_PERMESSAGE_DEFLATE);
  if (is_response) {
    if (p->server_no_context_takeover) {
      n += (size_t)snprintf(out + n, cap - n, "; server_no_context_takeover");
    }
    if (p->client_no_context_takeover) {
      n += (size_t)snprintf(out + n, cap - n, "; client_no_context_takeover");
    }
  } else {
    if (p->client_no_context_takeover) {
      n += (size_t)snprintf(out + n, cap - n, "; client_no_context_takeover");
    }
    if (p->server_no_context_takeover) {
      n += (size_t)snprintf(out + n, cap - n, "; server_no_context_takeover");
    }
  }
  if (p->server_max_window_bits) {
    n += (size_t)snprintf(out + n, cap - n, "; server_max_window_bits=%u",
        (unsigned)p->server_max_window_bits);
  }
  if (p->client_max_window_bits) {
    n += (size_t)snprintf(out + n, cap - n, "; client_max_window_bits=%u",
        (unsigned)p->client_max_window_bits);
  } else if (!is_response && p->offer_client_max_window_bits) {
    n += (size_t)snprintf(out + n, cap - n, "; client_max_window_bits");
  }
  if (len) {
    *len = n;
  }
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// The codec
// ---------------------------------------------------------------------------

/** The scratch the compressor and decompressor write through. */
#define PIECE 8192u
/** What RFC 7692 section 7.2.1 removes and section 7.2.2 puts back. */
static const uint8_t TRAILER[4] = {0x00, 0x00, 0xff, 0xff};
/** Output that no ratio refuses, so that a few octets of input may still make a short message. */
#define RATIO_SLACK 256u

struct GHTTP_WsDeflate {
  const GHTTP_Allocator * allocator;
  unsigned enc_window_bits;
  bool enc_reset;
  bool dec_reset;
  uint64_t max_message;
  uint64_t max_ratio;
  gcomp_encoder_t * enc;
  gcomp_decoder_t * dec;
  // The message being inflated.
  uint64_t in_total;
  uint64_t out_total;
  bool stream_done;  // the decompressor saw a final block
};

GHTTP_Result ghttp_ws_deflate_open(const GHTTP_Allocator * allocator,
    unsigned enc_window_bits, bool enc_reset, bool dec_reset,
    uint64_t max_message, uint64_t max_ratio, GHTTP_WsDeflate ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_WsDeflate * d = gcu_allocator_calloc(allocator, 1, sizeof(*d));
  if (!d) {
    return GHTTP_ERR_OOM;
  }
  d->allocator = allocator;
  d->enc_window_bits = enc_window_bits ? enc_window_bits : 15;
  d->enc_reset = enc_reset;
  d->dec_reset = dec_reset;
  d->max_message = max_message;
  d->max_ratio = max_ratio;
  *out = d;
  return GHTTP_OK;
}

void ghttp_ws_deflate_close(GHTTP_WsDeflate * d) {
  if (!d) {
    return;
  }
  gcomp_encoder_destroy(d->enc);
  gcomp_decoder_destroy(d->dec);
  gcu_allocator_free(d->allocator, d);
}

static GHTTP_Result from_gcomp(gcomp_status_t s) {
  switch (s) {
    case GCOMP_OK: return GHTTP_OK;
    case GCOMP_ERR_MEMORY: return GHTTP_ERR_OOM;
    case GCOMP_ERR_LIMIT: return GHTTP_ERR_LIMIT;
    case GCOMP_ERR_CORRUPT: return GHTTP_ERR_CORRUPT;
    default: return GHTTP_ERR_INTERNAL;
  }
}

/** Options that route the compressor's allocations through the connection's allocator. */
static GHTTP_Result make_options(
    const GHTTP_Allocator * allocator, gcomp_options_t ** out) {
  gcomp_status_t s = gcomp_options_create_with_allocator(allocator, out);
  return from_gcomp(s);
}

/**
 * Make the compressor allocate its staging buffer at full size.
 *
 * The deflate encoder sizes that buffer on the first call that reaches it, and
 * a flush that comes before any update (a first message that is empty, or the
 * first after a reset) sizes it for a flush of nothing: a few hundred octets.
 * The first big update after that renders a block into it that does not fit
 * and returns GCOMP_ERR_LIMIT, which this module would have to take for the
 * output bound it is not. An update with no input does the allocation and
 * nothing else, so one is made before the encoder is first used and after
 * every reset. (Found by the round-trip tests; the encoder is compress's.)
 */
static GHTTP_Result prime_encoder(GHTTP_WsDeflate * d) {
  uint8_t room[1];
  gcomp_buffer_t src = {NULL, 0, 0};
  gcomp_buffer_t dst = {room, sizeof(room), 0};
  return from_gcomp(gcomp_encoder_update(d->enc, &src, &dst));
}

static GHTTP_Result make_encoder(GHTTP_WsDeflate * d) {
  gcomp_options_t * o = NULL;
  GHTTP_Result r = make_options(d->allocator, &o);
  if (r != GHTTP_OK) {
    return r;
  }
  gcomp_status_t s = gcomp_options_set_uint64(o, "deflate.window_bits", d->enc_window_bits);
  if (s == GCOMP_OK) {
    s = gcomp_encoder_create(gcomp_registry_default(), "deflate", o, &d->enc);
  }
  gcomp_options_destroy(o);
  GHTTP_Result made = from_gcomp(s);
  return made == GHTTP_OK ? prime_encoder(d) : made;
}

static GHTTP_Result make_decoder(GHTTP_WsDeflate * d) {
  gcomp_options_t * o = NULL;
  GHTTP_Result r = make_options(d->allocator, &o);
  if (r != GHTTP_OK) {
    return r;
  }
  // This module counts per message, with the connection's limits and a tighter
  // grain than the decompressor's: its own limits count over the whole life of
  // the stream, which context takeover makes a connection.
  gcomp_status_t s = gcomp_options_set_uint64(o, "limits.max_output_bytes", 0);
  if (s == GCOMP_OK) {
    s = gcomp_options_set_uint64(o, "limits.max_expansion_ratio", 0);
  }
  if (s == GCOMP_OK) {
    s = gcomp_decoder_create(gcomp_registry_default(), "deflate", o, &d->dec);
  }
  gcomp_options_destroy(o);
  return from_gcomp(s);
}

GHTTP_Result ghttp_ws_deflate_compress(GHTTP_WsDeflate * d, const void * in,
    size_t n, bool fin, GHTTP_Buffer * out) {
  if (!d->enc) {
    GHTTP_Result r = make_encoder(d);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  size_t start = ghttp_buffer_size(out);
  uint8_t piece[PIECE];
  gcomp_buffer_t src = {in, n, 0};
  while (src.used < src.size) {
    gcomp_buffer_t dst = {piece, sizeof(piece), 0};
    size_t before = src.used;
    gcomp_status_t s = gcomp_encoder_update(d->enc, &src, &dst);
    if (s != GCOMP_OK) {
      return from_gcomp(s);
    }
    GHTTP_Result r = ghttp_buffer_append(out, piece, dst.used);
    if (r != GHTTP_OK) {
      return r;
    }
    if (dst.used == 0 && src.used == before) {
      return GHTTP_ERR_INTERNAL;
    }
  }
  if (!fin) {
    return GHTTP_OK;
  }
  for (;;) {
    gcomp_buffer_t dst = {piece, sizeof(piece), 0};
    gcomp_status_t s = gcomp_encoder_flush(d->enc, &dst, GCOMP_FLUSH_SYNC);
    if (s != GCOMP_OK && s != GCOMP_ERR_LIMIT) {
      return from_gcomp(s);
    }
    GHTTP_Result r = ghttp_buffer_append(out, piece, dst.used);
    if (r != GHTTP_OK) {
      return r;
    }
    if (s == GCOMP_OK) {
      break;
    }
  }
  size_t total = ghttp_buffer_size(out);
  // The flush ends in an empty stored block, and RFC 7692 has it sent without
  // those four octets. Anything else would be a compressor that does not do
  // what zlib's Z_SYNC_FLUSH does, and sending it on would corrupt the stream.
  if (total - start < sizeof(TRAILER)
      || memcmp((const uint8_t *)ghttp_buffer_data(out) + total - sizeof(TRAILER),
             TRAILER, sizeof(TRAILER)) != 0) {
    return GHTTP_ERR_INTERNAL;
  }
  ghttp_buffer_truncate(out, total - sizeof(TRAILER));
  if (d->enc_reset) {
    GHTTP_Result r = from_gcomp(gcomp_encoder_reset(d->enc));
    return r == GHTTP_OK ? prime_encoder(d) : r;
  }
  return GHTTP_OK;
}

void ghttp_ws_inflate_begin(GHTTP_WsDeflate * d) {
  d->in_total = 0;
  d->out_total = 0;
  d->stream_done = false;
}

/** The most output the message may have had by now, whatever has been fed. */
static uint64_t output_allowance(const GHTTP_WsDeflate * d) {
  uint64_t cap = d->max_message;
  uint64_t by_ratio;
  if (d->max_ratio != 0 && d->in_total > (UINT64_MAX - RATIO_SLACK) / d->max_ratio) {
    by_ratio = UINT64_MAX;
  } else {
    by_ratio = d->max_ratio * d->in_total + RATIO_SLACK;
  }
  return by_ratio < cap ? by_ratio : cap;
}

static GHTTP_Result inflate_piece(GHTTP_WsDeflate * d, const uint8_t * in,
    size_t n, GHTTP_Buffer * out) {
  if (!d->dec) {
    GHTTP_Result r = make_decoder(d);
    if (r != GHTTP_OK) {
      return r;
    }
  }
  d->in_total += n;
  gcomp_buffer_t src = {in, n, 0};
  uint8_t piece[PIECE];
  for (;;) {
    uint64_t allow = output_allowance(d);
    if (d->out_total > allow) {
      return GHTTP_ERR_LIMIT;
    }
    // One octet more than may be kept, so that exceeding the limit is seen
    // when it happens and costs nothing beyond that octet.
    uint64_t room = allow - d->out_total;
    size_t want = room >= sizeof(piece) ? sizeof(piece) : (size_t)room + 1;
    gcomp_buffer_t dst = {piece, want, 0};
    size_t before = src.used;
    gcomp_status_t s = gcomp_decoder_update(d->dec, &src, &dst);
    if (s != GCOMP_OK) {
      return from_gcomp(s);
    }
    if (dst.used > room) {
      return GHTTP_ERR_LIMIT;
    }
    GHTTP_Result r = ghttp_buffer_append(out, piece, dst.used);
    if (r != GHTTP_OK) {
      return r;
    }
    d->out_total += dst.used;
    if (dst.used == 0 && src.used == before) {
      break;
    }
  }
  if (src.used < src.size) {
    // The decompressor stopped taking input with some left and nothing to
    // give: the stream ended in a final block, and this is what follows it.
    d->stream_done = true;
    // Zero octets are accepted: RFC 7692 section 7.2.3.4's own example has the
    // octet of the empty stored block that the appended trailer completes,
    // after a block whose BFINAL was set.
    for (size_t i = src.used; i < src.size; i++) {
      if (in[i] != 0) {
        return GHTTP_ERR_CORRUPT;
      }
    }
  }
  return GHTTP_OK;
}

GHTTP_Result ghttp_ws_inflate_update(
    GHTTP_WsDeflate * d, const void * in, size_t n, GHTTP_Buffer * out) {
  return inflate_piece(d, in, n, out);
}

GHTTP_Result ghttp_ws_inflate_end(GHTTP_WsDeflate * d, GHTTP_Buffer * out) {
  GHTTP_Result r = inflate_piece(d, TRAILER, sizeof(TRAILER), out);
  bool final_block = false;
  if (r == GHTTP_ERR_CORRUPT && d->stream_done) {
    // The trailer was not needed: the message's last block was final. That is
    // allowed (RFC 7692 section 7.2.3.4); the decompressor, done with its
    // stream, starts again.
    r = GHTTP_OK;
    final_block = true;
  }
  d->stream_done = false;
  if (r != GHTTP_OK) {
    return r;
  }
  if (final_block || d->dec_reset) {
    return from_gcomp(gcomp_decoder_reset(d->dec));
  }
  return GHTTP_OK;
}
