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
 * The incremental HTTP/1.1 parser.
 *
 * Every decision is made byte by byte or on a complete head, never on how
 * much input a call happened to be given, so the events and the data behind
 * them are the same however the input is split. A head or a trailer section
 * is gathered a byte at a time into a buffer bounded by the limits, then
 * parsed whole; a body is passed through as slices of the caller's own input.
 *
 * Reference: RFC 9112 (messages, section 6 framing, section 7.1 chunked).
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/parser.h>
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

typedef enum {
  ST_HEAD,           // gathering a start line and fields
  ST_BODY_LENGTH,    // Content-Length bytes
  ST_BODY_CLOSE,     // bytes until the peer closes
  ST_CHUNK_SIZE,     // a chunk-size line
  ST_CHUNK_DATA,     // chunk bytes
  ST_CHUNK_DATA_CR,  // the CR after chunk bytes
  ST_CHUNK_DATA_LF,  // the LF after chunk bytes
  ST_TRAILERS,       // gathering trailer fields
  ST_END_PENDING,    // the message is complete; END not yet reported
  ST_TUNNEL          // a tunnel or upgrade began; HTTP reading is over
} State;

typedef enum {
  SZ_DIGITS,  // hex digits
  SZ_EXT,     // inside the extensions
  SZ_LF       // the CR has been read
} SizeState;

// The line-gathering state shared by a head and a trailer section.
typedef struct Collector {
  char * buf;      // completed lines, each with its CRLF
  size_t len;
  size_t cap;
  size_t total;    // every byte consumed, skipped ones included
  size_t line_len; // current line, excluding its CRLF
  size_t lines;    // completed non-empty lines
  bool prev_cr;
  bool done;
} Collector;

struct GHTTP_Parser {
  const GHTTP_Allocator * allocator;
  GHTTP_ParserKind kind;
  GHTTP_Limits limits;
  GHTTP_Result error;
  State state;
  Collector col;
  GHTTP_Request * request;
  GHTTP_Response * response;
  GHTTP_Headers * trailers;
  GHTTP_Framing framing;
  GHTTP_Upgrade upgrade;
  bool tunnel_after;
  bool saw_head;
  uint64_t remaining;
  uint64_t body_total;
  SizeState sz;
  uint64_t chunk_size;
  size_t sz_digits;
  size_t sz_line_len;
  const void * body_ptr;
  size_t body_len;
  bool expect_head;
  bool expect_connect;
};

GHTTP_Result ghttp_parser_create(GHTTP_ParserKind kind,
    const GHTTP_Limits * limits, const GHTTP_Allocator * allocator,
    GHTTP_Parser ** out) {
  if (!out || (kind != GHTTP_PARSE_REQUEST && kind != GHTTP_PARSE_RESPONSE)) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_Parser * p = gcu_allocator_calloc(allocator, 1, sizeof(*p));
  if (!p) {
    return GHTTP_ERR_OOM;
  }
  p->allocator = allocator;
  p->kind = kind;
  if (limits) {
    p->limits = *limits;
  } else {
    ghttp_limits_default(&p->limits);
  }
  p->state = ST_HEAD;
  GHTTP_Result r = (kind == GHTTP_PARSE_REQUEST)
      ? ghttp_request_create(allocator, &p->request)
      : ghttp_response_create(allocator, &p->response);
  if (r == GHTTP_OK) {
    r = ghttp_headers_create(allocator, &p->trailers);
  }
  if (r != GHTTP_OK) {
    ghttp_parser_destroy(p);
    return r;
  }
  *out = p;
  return GHTTP_OK;
}

void ghttp_parser_destroy(GHTTP_Parser * p) {
  if (!p) {
    return;
  }
  gcu_allocator_free(p->allocator, p->col.buf);
  ghttp_request_destroy(p->request);
  ghttp_response_destroy(p->response);
  ghttp_headers_destroy(p->trailers);
  gcu_allocator_free(p->allocator, p);
}

GHTTP_Result ghttp_parser_expect_response_to(
    GHTTP_Parser * p, const char * method) {
  if (!p || !method || p->kind != GHTTP_PARSE_RESPONSE) {
    return GHTTP_ERR_INVALID;
  }
  p->expect_head = strcmp(method, "HEAD") == 0;
  p->expect_connect = strcmp(method, "CONNECT") == 0;
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Gathering a head or a trailer section
// ---------------------------------------------------------------------------

static void collector_reset(Collector * c) {
  c->len = 0;
  c->total = 0;
  c->line_len = 0;
  c->lines = 0;
  c->prev_cr = false;
  c->done = false;
}

static GHTTP_Result collector_put(GHTTP_Parser * p, char b) {
  Collector * c = &p->col;
  void * buf = c->buf;
  GHTTP_Result r =
      ghttp_reserve(p->allocator, &buf, &c->cap, c->len + 1, 1, 512);
  c->buf = buf;
  if (r != GHTTP_OK) {
    return r;
  }
  c->buf[c->len++] = b;
  return GHTTP_OK;
}

// Consume bytes up to and including the empty line that ends the section.
// Bare LF, a CR not followed by LF and NUL are refused where they stand, so a
// byte is judged by its neighbours and never by where a call began.
static GHTTP_Result collect(GHTTP_Parser * p, const unsigned char * in,
    size_t len, size_t * used) {
  Collector * c = &p->col;
  bool trailer = (p->state == ST_TRAILERS);
  size_t max_total =
      trailer ? p->limits.max_trailer_bytes : p->limits.max_head_bytes;
  size_t max_fields =
      trailer ? p->limits.max_trailer_count : p->limits.max_header_count;
  size_t start_lines = trailer ? 0 : 1; // a head's first line is not a field
  while (*used < len && !c->done) {
    unsigned char b = in[(*used)++];
    if (++c->total > max_total) {
      return GHTTP_ERR_LIMIT;
    }
    if (b == '\0') {
      return GHTTP_ERR_CORRUPT;
    }
    GHTTP_Result r;
    if (c->prev_cr) {
      if (b != '\n') {
        return GHTTP_ERR_CORRUPT;
      }
      c->prev_cr = false;
      if (c->line_len == 0) {
        c->len--; // the CR stored when it was read
        if (c->lines == 0 && !trailer) {
          // RFC 9112 section 2.2: a server ignores empty lines before a
          // request line. A response never starts that way.
          if (p->kind == GHTTP_PARSE_RESPONSE) {
            return GHTTP_ERR_CORRUPT;
          }
          continue;
        }
        c->done = true;
        continue;
      }
      c->lines++;
      if (c->lines - start_lines > max_fields && c->lines > start_lines) {
        return GHTTP_ERR_LIMIT;
      }
      c->line_len = 0;
      if ((r = collector_put(p, '\n')) != GHTTP_OK) {
        return r;
      }
      continue;
    }
    if (b == '\r') {
      c->prev_cr = true;
      if ((r = collector_put(p, '\r')) != GHTTP_OK) {
        return r;
      }
      continue;
    }
    if (b == '\n') {
      return GHTTP_ERR_CORRUPT; // a bare LF
    }
    if (++c->line_len > p->limits.max_line_length) {
      return GHTTP_ERR_LIMIT;
    }
    if ((r = collector_put(p, (char)b)) != GHTTP_OK) {
      return r;
    }
  }
  return GHTTP_OK;
}

// The next line of the gathered buffer: [*pos, *pos + n), then CRLF.
static bool next_line(const Collector * c, size_t * pos, const char ** line,
    size_t * n) {
  if (*pos >= c->len) {
    return false;
  }
  const char * start = c->buf + *pos;
  const char * cr = memchr(start, '\r', c->len - *pos);
  if (!cr) {
    return false;
  }
  *line = start;
  *n = (size_t)(cr - start);
  *pos += *n + 2;
  return true;
}

// One field line, "name: value", into a list.
static GHTTP_Result parse_field(
    GHTTP_Headers * h, const char * line, size_t n) {
  const char * colon = memchr(line, ':', n);
  if (!colon) {
    return GHTTP_ERR_CORRUPT;
  }
  size_t nlen = (size_t)(colon - line);
  // Anything but a token before the colon is refused, which covers the space
  // before the colon (RFC 9112 section 5.1) and a line that begins with
  // whitespace, an obsolete line fold (section 5.2).
  if (!ghttp_is_token(line, nlen)) {
    return GHTTP_ERR_CORRUPT;
  }
  const char * v = colon + 1;
  size_t vlen = n - nlen - 1;
  ghttp_trim_ows(&v, &vlen);
  if (!ghttp_is_field_text(v, vlen)) {
    return GHTTP_ERR_CORRUPT;
  }
  return ghttp_headers_add_raw(h, line, nlen, v, vlen);
}

// "HTTP/d.d" -> the minor version; UNSUPPORTED for a version other than 1.0
// and 1.1 that is still well formed.
static GHTTP_Result parse_version(const char * s, size_t n, int * minor) {
  if (n != 8 || memcmp(s, "HTTP/", 5) != 0 || s[5] < '0' || s[5] > '9'
      || s[6] != '.' || s[7] < '0' || s[7] > '9') {
    return GHTTP_ERR_CORRUPT;
  }
  if (s[5] != '1' || (s[7] != '0' && s[7] != '1')) {
    return GHTTP_ERR_UNSUPPORTED;
  }
  *minor = s[7] - '0';
  return GHTTP_OK;
}

static GHTTP_Result parse_request_line(
    GHTTP_Parser * p, const char * line, size_t n) {
  const char * sp1 = memchr(line, ' ', n);
  if (!sp1) {
    return GHTTP_ERR_CORRUPT;
  }
  size_t mlen = (size_t)(sp1 - line);
  const char * target = sp1 + 1;
  size_t rest = n - mlen - 1;
  const char * sp2 = memchr(target, ' ', rest);
  if (!sp2) {
    return GHTTP_ERR_CORRUPT;
  }
  size_t tlen = (size_t)(sp2 - target);
  if (!ghttp_is_token(line, mlen) || !ghttp_is_target_text(target, tlen)) {
    return GHTTP_ERR_CORRUPT;
  }
  int minor = 0;
  GHTTP_Result r = parse_version(sp2 + 1, rest - tlen - 1, &minor);
  if (r != GHTTP_OK) {
    return r;
  }
  return ghttp_request_assign(p->request, line, mlen, target, tlen, minor);
}

static GHTTP_Result parse_status_line(
    GHTTP_Parser * p, const char * line, size_t n) {
  // "HTTP/1.1 200 reason": the space after the code is required even when the
  // reason is empty (RFC 9112 section 4).
  if (n < 13 || line[8] != ' ' || line[12] != ' ') {
    return GHTTP_ERR_CORRUPT;
  }
  int minor = 0;
  GHTTP_Result r = parse_version(line, 8, &minor);
  if (r != GHTTP_OK) {
    return r;
  }
  int status = 0;
  for (int i = 9; i < 12; i++) {
    if (line[i] < '0' || line[i] > '9') {
      return GHTTP_ERR_CORRUPT;
    }
    status = status * 10 + (line[i] - '0');
  }
  if (status < 100) {
    return GHTTP_ERR_CORRUPT;
  }
  if (!ghttp_is_field_text(line + 13, n - 13)) {
    return GHTTP_ERR_CORRUPT;
  }
  return ghttp_response_assign(p->response, status, line + 13, n - 13, minor);
}

static void message_done(GHTTP_Parser * p) {
  p->body_total = 0;
  p->remaining = 0;
  p->body_ptr = NULL;
  p->body_len = 0;
  if (p->kind == GHTTP_PARSE_RESPONSE
      && (ghttp_response_status(p->response) < 100
          || ghttp_response_status(p->response) > 199)) {
    // A final response ends what the method told us; an interim one does not.
    p->expect_head = false;
    p->expect_connect = false;
  }
  p->state = p->tunnel_after ? ST_TUNNEL : ST_HEAD;
}

// A complete head is in the collector: build it, validate it, and decide how
// the body is framed.
static GHTTP_Result finish_head(GHTTP_Parser * p) {
  Collector * c = &p->col;
  GHTTP_Headers * headers = (p->kind == GHTTP_PARSE_REQUEST)
      ? ghttp_request_headers(p->request)
      : ghttp_response_headers(p->response);
  ghttp_headers_clear(headers);
  ghttp_headers_clear(p->trailers);
  p->framing = GHTTP_FRAMING_NONE;
  p->upgrade = GHTTP_UPGRADE_NONE;
  p->tunnel_after = false;
  p->body_total = 0;

  size_t pos = 0;
  const char * line;
  size_t n;
  if (!next_line(c, &pos, &line, &n)) {
    return GHTTP_ERR_INTERNAL;
  }
  GHTTP_Result r = (p->kind == GHTTP_PARSE_REQUEST)
      ? parse_request_line(p, line, n)
      : parse_status_line(p, line, n);
  while (r == GHTTP_OK && next_line(c, &pos, &line, &n)) {
    r = parse_field(headers, line, n);
  }
  if (r != GHTTP_OK) {
    return r;
  }
  collector_reset(c);

  r = (p->kind == GHTTP_PARSE_REQUEST) ? ghttp_request_validate(p->request)
                                       : ghttp_response_validate(p->response);
  if (r != GHTTP_OK) {
    return r;
  }
  int minor = (p->kind == GHTTP_PARSE_REQUEST)
      ? ghttp_request_version(p->request)
      : ghttp_response_version(p->response);
  GHTTP_HeaderFraming hf;
  uint64_t length;
  r = ghttp_framing_from_headers(headers, minor, &hf, &length);
  if (r != GHTTP_OK) {
    return r;
  }

  bool bodyless = false;
  if (p->kind == GHTTP_PARSE_REQUEST) {
    const char * method = ghttp_request_method(p->request);
    if (strcmp(method, "CONNECT") == 0) {
      p->upgrade = GHTTP_UPGRADE_CONNECT;
    } else if (ghttp_headers_find(headers, "upgrade", 0) != GHTTP_HEADERS_NPOS
        && ghttp_headers_list_has(headers, "connection", "upgrade")) {
      p->upgrade = GHTTP_UPGRADE_UPGRADE;
    }
  } else {
    // RFC 9112 section 6.3: these have no body whatever the headers say.
    int status = ghttp_response_status(p->response);
    bodyless = p->expect_head || (status >= 100 && status <= 199)
        || status == 204 || status == 304;
    if (status == 101) {
      p->upgrade = GHTTP_UPGRADE_UPGRADE;
      p->tunnel_after = true;
    } else if (p->expect_connect && status >= 200 && status <= 299) {
      p->upgrade = GHTTP_UPGRADE_CONNECT;
      p->tunnel_after = true;
      bodyless = true;
    }
  }

  if (bodyless) {
    p->framing = GHTTP_FRAMING_NONE;
    p->state = ST_END_PENDING;
  } else if (hf == GHTTP_HF_CHUNKED) {
    p->framing = GHTTP_FRAMING_CHUNKED;
    p->state = ST_CHUNK_SIZE;
    p->sz = SZ_DIGITS;
    p->chunk_size = 0;
    p->sz_digits = 0;
    p->sz_line_len = 0;
  } else if (hf == GHTTP_HF_LENGTH) {
    if (length > p->limits.max_body_bytes) {
      return GHTTP_ERR_LIMIT;
    }
    p->framing = GHTTP_FRAMING_LENGTH;
    p->remaining = length;
    p->state = length == 0 ? ST_END_PENDING : ST_BODY_LENGTH;
  } else if (p->kind == GHTTP_PARSE_RESPONSE) {
    p->framing = GHTTP_FRAMING_CLOSE;
    p->state = ST_BODY_CLOSE;
  } else {
    p->framing = GHTTP_FRAMING_NONE;
    p->state = ST_END_PENDING;
  }
  p->saw_head = true;
  return GHTTP_OK;
}

static GHTTP_Result finish_trailers(GHTTP_Parser * p) {
  Collector * c = &p->col;
  ghttp_headers_clear(p->trailers);
  size_t pos = 0;
  const char * line;
  size_t n;
  GHTTP_Result r = GHTTP_OK;
  while (r == GHTTP_OK && next_line(c, &pos, &line, &n)) {
    r = parse_field(p->trailers, line, n);
  }
  if (r == GHTTP_OK) {
    r = ghttp_trailers_validate(p->trailers);
  }
  collector_reset(c);
  if (r != GHTTP_OK) {
    return r;
  }
  p->state = ST_END_PENDING;
  return GHTTP_OK;
}

static int hex_value(unsigned char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

// A chunk-size line is judged a byte at a time with no buffer:
//   chunk-size [ ";" extensions ] CRLF
// No whitespace is allowed before the ";". RFC 9112 section 7.1.1 writes BWS
// there, but "5 ;a" is the shape llhttp, h11 and Go's net/http all refuse (the
// differential in tools/oracle found it was the one chunk-size form this
// library took that none of them did), and a chunk-size line is exactly where
// parsers have disagreed about framing, so it is refused.
static GHTTP_Result chunk_size_byte(GHTTP_Parser * p, unsigned char c) {
  if (c == '\0') {
    return GHTTP_ERR_CORRUPT;
  }
  if (p->sz == SZ_LF) {
    if (c != '\n') {
      return GHTTP_ERR_CORRUPT;
    }
    return GHTTP_OK; // the caller sees sz == SZ_LF and finishes the line
  }
  if (c == '\r') {
    if (p->sz == SZ_DIGITS && p->sz_digits == 0) {
      return GHTTP_ERR_CORRUPT;
    }
    p->sz = SZ_LF;
    return GHTTP_OK;
  }
  if (++p->sz_line_len > p->limits.max_line_length) {
    return GHTTP_ERR_LIMIT;
  }
  switch (p->sz) {
    case SZ_DIGITS: {
      int d = hex_value(c);
      if (d >= 0) {
        if (p->chunk_size > (UINT64_MAX >> 4)) {
          return GHTTP_ERR_LIMIT;
        }
        p->chunk_size = (p->chunk_size << 4) | (uint64_t)d;
        p->sz_digits++;
        return GHTTP_OK;
      }
      if (p->sz_digits == 0) {
        return GHTTP_ERR_CORRUPT;
      }
      if (c == ';') {
        p->sz = SZ_EXT;
        return GHTTP_OK;
      }
      return GHTTP_ERR_CORRUPT;
    }
    case SZ_EXT:
      if (c == '\n' || (c < 0x20 && c != '\t') || c == 0x7f) {
        return GHTTP_ERR_CORRUPT;
      }
      return GHTTP_OK;
    case SZ_LF:
    default:
      return GHTTP_ERR_INTERNAL;
  }
}

static GHTTP_Result chunk_line_done(GHTTP_Parser * p) {
  uint64_t size = p->chunk_size;
  p->sz = SZ_DIGITS;
  p->chunk_size = 0;
  p->sz_digits = 0;
  p->sz_line_len = 0;
  if (size == 0) {
    collector_reset(&p->col);
    p->state = ST_TRAILERS;
    return GHTTP_OK;
  }
  if (size > p->limits.max_chunk_size
      || size > p->limits.max_body_bytes - p->body_total) {
    return GHTTP_ERR_LIMIT;
  }
  p->remaining = size;
  p->state = ST_CHUNK_DATA;
  return GHTTP_OK;
}

static GHTTP_Result feed_inner(GHTTP_Parser * p, const unsigned char * in,
    size_t len, size_t * consumed, GHTTP_Event * event) {
  size_t used = 0;
  GHTTP_Result r;
  for (;;) {
    size_t avail = len - used;
    switch (p->state) {
      case ST_END_PENDING:
        message_done(p);
        *consumed = used;
        *event = GHTTP_EVENT_END;
        return GHTTP_OK;

      case ST_HEAD:
        if ((r = collect(p, in, len, &used)) != GHTTP_OK) {
          return r;
        }
        if (!p->col.done) {
          *consumed = used;
          *event = GHTTP_EVENT_NEED_MORE;
          return GHTTP_OK;
        }
        if ((r = finish_head(p)) != GHTTP_OK) {
          return r;
        }
        *consumed = used;
        *event = GHTTP_EVENT_HEAD;
        return GHTTP_OK;

      case ST_TRAILERS:
        if ((r = collect(p, in, len, &used)) != GHTTP_OK) {
          return r;
        }
        if (!p->col.done) {
          *consumed = used;
          *event = GHTTP_EVENT_NEED_MORE;
          return GHTTP_OK;
        }
        if ((r = finish_trailers(p)) != GHTTP_OK) {
          return r;
        }
        message_done(p);
        *consumed = used;
        *event = GHTTP_EVENT_END;
        return GHTTP_OK;

      case ST_BODY_LENGTH:
      case ST_CHUNK_DATA: {
        if (avail == 0) {
          *consumed = used;
          *event = GHTTP_EVENT_NEED_MORE;
          return GHTTP_OK;
        }
        size_t take = avail;
        if ((uint64_t)take > p->remaining) {
          take = (size_t)p->remaining;
        }
        p->body_ptr = in + used;
        p->body_len = take;
        used += take;
        p->remaining -= take;
        p->body_total += take;
        if (p->remaining == 0) {
          p->state = (p->state == ST_BODY_LENGTH) ? ST_END_PENDING
                                                  : ST_CHUNK_DATA_CR;
        }
        *consumed = used;
        *event = GHTTP_EVENT_BODY;
        return GHTTP_OK;
      }

      case ST_BODY_CLOSE: {
        if (avail == 0) {
          *consumed = used;
          *event = GHTTP_EVENT_NEED_MORE;
          return GHTTP_OK;
        }
        // Deliver up to the cap and refuse the byte after it, so that the
        // bytes handed out before the error do not depend on the split.
        uint64_t room = p->limits.max_body_bytes - p->body_total;
        if (room == 0) {
          return GHTTP_ERR_LIMIT;
        }
        size_t take = avail;
        if ((uint64_t)take > room) {
          take = (size_t)room;
        }
        p->body_ptr = in + used;
        p->body_len = take;
        used += take;
        p->body_total += take;
        *consumed = used;
        *event = GHTTP_EVENT_BODY;
        return GHTTP_OK;
      }

      case ST_CHUNK_SIZE:
        while (used < len) {
          unsigned char c = in[used++];
          if ((r = chunk_size_byte(p, c)) != GHTTP_OK) {
            return r;
          }
          if (p->sz == SZ_LF && c == '\n') {
            if ((r = chunk_line_done(p)) != GHTTP_OK) {
              return r;
            }
            break;
          }
        }
        if (p->state == ST_CHUNK_SIZE) {
          *consumed = used;
          *event = GHTTP_EVENT_NEED_MORE;
          return GHTTP_OK;
        }
        continue;

      case ST_CHUNK_DATA_CR:
      case ST_CHUNK_DATA_LF:
        if (avail == 0) {
          *consumed = used;
          *event = GHTTP_EVENT_NEED_MORE;
          return GHTTP_OK;
        }
        if (in[used++] != (p->state == ST_CHUNK_DATA_CR ? '\r' : '\n')) {
          return GHTTP_ERR_CORRUPT;
        }
        p->state = (p->state == ST_CHUNK_DATA_CR) ? ST_CHUNK_DATA_LF
                                                  : ST_CHUNK_SIZE;
        continue;

      case ST_TUNNEL:
      default:
        return GHTTP_ERR_INTERNAL;
    }
  }
}

GHTTP_Result ghttp_parser_feed(GHTTP_Parser * p, const void * data, size_t len,
    size_t * consumed, GHTTP_Event * event) {
  if (!p || !consumed || !event || (!data && len > 0)) {
    return GHTTP_ERR_INVALID;
  }
  if (p->error != GHTTP_OK) {
    return p->error;
  }
  if (p->state == ST_TUNNEL) {
    // Nothing more is HTTP. Reporting that as NEED_MORE with nothing used
    // ends the documented feed loop; the caller sees the tunnel through
    // ghttp_parser_upgrade and that the input was not all used.
    *consumed = 0;
    *event = GHTTP_EVENT_NEED_MORE;
    return GHTTP_OK;
  }
  size_t used = 0;
  GHTTP_Event ev = GHTTP_EVENT_NEED_MORE;
  GHTTP_Result r = feed_inner(p, data, len, &used, &ev);
  if (r != GHTTP_OK) {
    p->error = r;
    return r;
  }
  *consumed = used;
  *event = ev;
  return GHTTP_OK;
}

GHTTP_Result ghttp_parser_finish(GHTTP_Parser * p, GHTTP_Event * event) {
  if (!p || !event) {
    return GHTTP_ERR_INVALID;
  }
  if (p->error != GHTTP_OK) {
    return p->error;
  }
  switch (p->state) {
    case ST_TUNNEL:
      *event = GHTTP_EVENT_NEED_MORE;
      return GHTTP_OK;
    case ST_END_PENDING:
      message_done(p);
      *event = GHTTP_EVENT_END;
      return GHTTP_OK;
    case ST_BODY_CLOSE:
      message_done(p);
      *event = GHTTP_EVENT_END;
      return GHTTP_OK;
    case ST_HEAD:
      if (p->col.len == 0 && p->col.line_len == 0 && !p->col.prev_cr) {
        *event = GHTTP_EVENT_NEED_MORE; // between messages: a clean end
        return GHTTP_OK;
      }
      // fall through
    default:
      p->error = GHTTP_ERR_CORRUPT; // cut short mid-message
      return p->error;
  }
}

const GHTTP_Request * ghttp_parser_request(const GHTTP_Parser * p) {
  return (p && p->saw_head) ? p->request : NULL;
}

const GHTTP_Response * ghttp_parser_response(const GHTTP_Parser * p) {
  return (p && p->saw_head) ? p->response : NULL;
}

void ghttp_parser_body(
    const GHTTP_Parser * p, const void ** data, size_t * len) {
  if (data) {
    *data = p ? p->body_ptr : NULL;
  }
  if (len) {
    *len = p ? p->body_len : 0;
  }
}

const GHTTP_Headers * ghttp_parser_trailers(const GHTTP_Parser * p) {
  return p ? p->trailers : NULL;
}

GHTTP_Framing ghttp_parser_framing(const GHTTP_Parser * p) {
  return p ? p->framing : GHTTP_FRAMING_NONE;
}

GHTTP_Upgrade ghttp_parser_upgrade(const GHTTP_Parser * p) {
  return p ? p->upgrade : GHTTP_UPGRADE_NONE;
}
