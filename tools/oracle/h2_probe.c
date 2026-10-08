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
 * The HTTP/2 differential's side of this library: one line in, one line out.
 *
 * Reads tab-separated cases on stdin
 *
 *     id  kind  split  arg  hex
 *
 * and writes `id  split  json`, every string hex-encoded so that no byte needs
 * an escape. The three kinds, and the shape of each answer, are the spec the
 * reference drivers follow (containers/refs/; README of the h2 oracle in
 * notes/http/README.md):
 *
 *   h2  the hex is a client's whole byte stream, preface first. This library
 *       is run as a server over it, whole (`whole`) or a byte at a time
 *       (`byte`):
 *       {"msgs":[{"stream":N,"method":hex|null,"scheme":hex|null,
 *                 "authority":hex|null,"path":hex|null,
 *                 "headers":[[n,v]...],"body":hex,"trailers":[[n,v]...],
 *                 "ended":bool}...],
 *        "resets":[[stream,code]...],"conn_error":null|code,
 *        "incomplete":bool,"err":text}
 *   hd  the hex is one HPACK block, decoded by a decoder whose table is `arg`
 *       octets: {"list":[[n,v]...],"error":bool,"err":text}
 *   he  `arg` is the table size the peer allows (the encoder, created for the
 *       default 4096, is told of it and announces it) and the hex is a field blob (a
 *       4-octet name length, the name, a 4-octet value length, the value,
 *       repeated): {"hex":the encoded block}
 *
 * `arg` of an h2 case is `-`, or `xc` for a server that enables Extended CONNECT
 * (RFC 8441): then SETTINGS_ENABLE_CONNECT_PROTOCOL is sent, a request's
 * `:protocol` is reported as a field named `:protocol` (the references report
 * an unknown pseudo-header field in the same list), and a CONNECT that has one
 * reports its `:path` like any other request.
 *
 * "incomplete" is this library's only (ghttp_h2_conn_finish): the input ended
 * inside a frame or a header block. A msg is a request that was accepted whole. The Host field this library adds
 * from :authority (RFC 9113 section 8.3.1) is left out of "headers" so that
 * what is compared is what the peer sent.
 *
 * This is not a test. A differential needs this library's answer to leave the
 * process, and a GoogleTest binary cannot be piped into a comparison.
 */

#include <ghoti.io/http/http.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

typedef struct {
  char * data;
  size_t len;
  size_t cap;
} Buf;

static void buf_put(Buf * b, const void * p, size_t n) {
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 256;
    while (b->len + n + 1 > cap) {
      cap *= 2;
    }
    b->data = realloc(b->data, cap);
    if (!b->data) {
      fputs("h2_probe: out of memory\n", stderr);
      exit(2);
    }
    b->cap = cap;
  }
  memcpy(b->data + b->len, p, n);
  b->len += n;
  b->data[b->len] = '\0';
}

static void buf_str(Buf * b, const char * s) {
  buf_put(b, s, strlen(s));
}

static void buf_hex(Buf * b, const void * p, size_t n) {
  static const char digits[] = "0123456789abcdef";
  const unsigned char * u = p;
  for (size_t i = 0; i < n; i++) {
    char two[2] = {digits[u[i] >> 4], digits[u[i] & 15]};
    buf_put(b, two, 2);
  }
}

/** A hex string or null. */
static void buf_opt(Buf * b, const char * s) {
  if (!s) {
    buf_str(b, "null");
    return;
  }
  buf_str(b, "\"");
  buf_hex(b, s, strlen(s));
  buf_str(b, "\"");
}

/** The fields of @p h as [[n,v]...], dropping a leading Host equal to @p authority. */
static void buf_fields(Buf * b, const GHTTP_Headers * h, const char * authority,
    const char * protocol) {
  buf_str(b, "[");
  size_t n = ghttp_headers_count(h);
  size_t out = 0;
  if (protocol) {
    buf_str(b, "[\"");
    buf_hex(b, ":protocol", 9);
    buf_str(b, "\",\"");
    buf_hex(b, protocol, strlen(protocol));
    buf_str(b, "\"]");
    out++;
  }
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    if (ghttp_headers_at(h, i, &f) != GHTTP_OK) {
      continue;
    }
    if (i == 0 && authority && f.name_len == 4 && memcmp(f.name, "host", 4) == 0
        && f.value_len == strlen(authority) && memcmp(f.value, authority, f.value_len) == 0) {
      continue;
    }
    buf_str(b, out++ ? ",[\"" : "[\"");
    buf_hex(b, f.name, f.name_len);
    buf_str(b, "\",\"");
    buf_hex(b, f.value, f.value_len);
    buf_str(b, "\"]");
  }
  buf_str(b, "]");
}

static int unhex(char c) {
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

// ---------------------------------------------------------------------------
// kind h2
// ---------------------------------------------------------------------------

typedef struct {
  uint32_t stream;
  Buf head;      // "method":...,"scheme":...,"authority":...,"path":...,"headers":[...]
  Buf body;
  Buf trailers;  // [..]
  int ended;
  int open;
} Msg;

#define MAX_MSGS 4096
#define MAX_RESETS 4096

typedef struct {
  Msg msgs[MAX_MSGS];
  size_t nmsgs;
  uint32_t reset_stream[MAX_RESETS];
  uint32_t reset_code[MAX_RESETS];
  size_t nresets;
} H2Run;

static Msg * find_msg(H2Run * r, uint32_t stream) {
  for (size_t i = r->nmsgs; i-- > 0;) {
    if (r->msgs[i].stream == stream) {
      return &r->msgs[i];
    }
  }
  return NULL;
}

static void h2_event(H2Run * r, GHTTP_H2Conn * c, const GHTTP_H2Event * ev) {
  switch (ev->type) {
  case GHTTP_H2_EVENT_HEADERS: {
    if (r->nmsgs >= MAX_MSGS) {
      return;
    }
    Msg * m = &r->msgs[r->nmsgs++];
    memset(m, 0, sizeof *m);
    m->stream = ev->stream_id;
    m->ended = ev->end_stream;
    const GHTTP_Request * q = ghttp_h2_conn_request(c);
    const char * method = ghttp_request_method(q);
    const char * target = ghttp_request_target(q);
    const char * protocol = ghttp_request_protocol(q);
    int connect = strcmp(method, "CONNECT") == 0 && !protocol;
    Buf * h = &m->head;
    buf_str(h, "\"method\":");
    buf_opt(h, method);
    buf_str(h, ",\"scheme\":");
    buf_opt(h, ev->scheme);
    buf_str(h, ",\"authority\":");
    buf_opt(h, ev->authority);
    buf_str(h, ",\"path\":");
    buf_opt(h, connect ? NULL : target);
    buf_str(h, ",\"headers\":");
    buf_fields(h, ghttp_request_headers_const(q), ev->authority, protocol);
    buf_str(&m->trailers, "[]");
    break;
  }
  case GHTTP_H2_EVENT_DATA: {
    Msg * m = find_msg(r, ev->stream_id);
    if (m) {
      buf_put(&m->body, ev->data, ev->data_len);
      m->ended = m->ended || ev->end_stream;
    }
    break;
  }
  case GHTTP_H2_EVENT_TRAILERS: {
    Msg * m = find_msg(r, ev->stream_id);
    if (m) {
      m->trailers.len = 0;
      buf_fields(&m->trailers, ghttp_h2_conn_trailers(c), NULL, NULL);
      m->ended = 1;
    }
    break;
  }
  case GHTTP_H2_EVENT_STREAM_ERROR:
    if (r->nresets < MAX_RESETS) {
      r->reset_stream[r->nresets] = ev->stream_id;
      r->reset_code[r->nresets++] = ev->error_code;
    }
    break;
  default:
    break;
  }
}

static GHTTP_Result h2_piece(H2Run * r, GHTTP_H2Conn * c,
    const unsigned char * piece, size_t len) {
  size_t off = 0;
  GHTTP_H2Event ev;
  do {
    size_t used = 0;
    GHTTP_Result res = ghttp_h2_conn_feed(c, piece + off, len - off, &used, &ev);
    if (res != GHTTP_OK) {
      return res;
    }
    off += used;
    h2_event(r, c, &ev);
  } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
  return GHTTP_OK;
}

static void run_h2(const char * id, const char * arg, int bytewise,
    const unsigned char * data, size_t len) {
  GHTTP_H2Conn * c = NULL;
  GHTTP_H2Limits limits;
  ghttp_h2_limits_default(&limits);
  limits.enable_connect_protocol = strcmp(arg, "xc") == 0;
  if (ghttp_h2_conn_create(NULL, GHTTP_H2_SERVER, &limits, &c) != GHTTP_OK) {
    fputs("h2_probe: cannot create a connection\n", stderr);
    exit(2);
  }
  H2Run * r = calloc(1, sizeof *r);
  if (!r) {
    exit(2);
  }
  GHTTP_Result err = GHTTP_OK;
  if (bytewise) {
    for (size_t i = 0; i < len && err == GHTTP_OK; i++) {
      err = h2_piece(r, c, data + i, 1);
    }
  } else {
    err = h2_piece(r, c, data, len);
  }
  uint32_t code = 0;
  const char * why = "";
  int incomplete = 0;
  if (err != GHTTP_OK) {
    ghttp_h2_conn_error(c, &code, &why);
  } else {
    // The input ends here: inside a frame, or a header block left open?
    incomplete = ghttp_h2_conn_finish(c) != GHTTP_OK;
  }
  Buf out = {0};
  buf_str(&out, "{\"msgs\":[");
  for (size_t i = 0; i < r->nmsgs; i++) {
    Msg * m = &r->msgs[i];
    char num[48];
    snprintf(num, sizeof num, "%s{\"stream\":%u,", i ? "," : "", (unsigned)m->stream);
    buf_str(&out, num);
    buf_put(&out, m->head.data ? m->head.data : "", m->head.len);
    buf_str(&out, ",\"body\":\"");
    buf_hex(&out, m->body.data ? m->body.data : "", m->body.len);
    buf_str(&out, "\",\"trailers\":");
    buf_put(&out, m->trailers.data ? m->trailers.data : "[]", m->trailers.data ? m->trailers.len : 2);
    buf_str(&out, m->ended ? ",\"ended\":true}" : ",\"ended\":false}");
    free(m->head.data);
    free(m->body.data);
    free(m->trailers.data);
  }
  buf_str(&out, "],\"resets\":[");
  for (size_t i = 0; i < r->nresets; i++) {
    char num[48];
    snprintf(num, sizeof num, "%s[%u,%u]", i ? "," : "", (unsigned)r->reset_stream[i],
        (unsigned)r->reset_code[i]);
    buf_str(&out, num);
  }
  buf_str(&out, "],\"conn_error\":");
  if (err != GHTTP_OK) {
    char num[24];
    snprintf(num, sizeof num, "%u", (unsigned)code);
    buf_str(&out, num);
  } else {
    buf_str(&out, "null");
  }
  buf_str(&out, incomplete ? ",\"incomplete\":true" : ",\"incomplete\":false");
  buf_str(&out, ",\"err\":\"");
  buf_hex(&out, why, strlen(why));
  buf_str(&out, "\"}");
  printf("%s\t%s\t%s\n", id, bytewise ? "byte" : "whole", out.data);
  free(out.data);
  free(r);
  ghttp_h2_conn_destroy(c);
}

// ---------------------------------------------------------------------------
// kind hd and he
// ---------------------------------------------------------------------------

static void run_hd(const char * id, size_t table, const unsigned char * data, size_t len) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_header_list_bytes = (size_t)1 << 30;
  lim.max_field_bytes = (size_t)1 << 30;
  lim.max_header_count = (size_t)1 << 20;
  lim.max_table_size = table;
  GHTTP_HpackDecoder * d = NULL;
  GHTTP_Headers * h = NULL;
  if (ghttp_hpack_decoder_create(NULL, &lim, table, &d) != GHTTP_OK
      || ghttp_headers_create(NULL, &h) != GHTTP_OK) {
    fputs("h2_probe: cannot create a decoder\n", stderr);
    exit(2);
  }
  // The size is the maximum this decoder advertised, and the peer has seen it.
  ghttp_hpack_decoder_set_max_table_size(d, table);
  GHTTP_Result r = ghttp_hpack_decode(d, data, len, h);
  Buf out = {0};
  buf_str(&out, "{\"list\":");
  buf_fields(&out, h, NULL, NULL);
  buf_str(&out, r == GHTTP_OK ? ",\"error\":false,\"err\":\"\"}" : ",\"error\":true,\"err\":\"");
  if (r != GHTTP_OK) {
    buf_str(&out, ghttp_result_string(r));
    buf_str(&out, "\"}");
  }
  printf("%s\twhole\t%s\n", id, out.data);
  free(out.data);
  ghttp_headers_destroy(h);
  ghttp_hpack_decoder_destroy(d);
}

static unsigned long be32(const unsigned char * p) {
  return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16)
      | ((unsigned long)p[2] << 8) | p[3];
}

static void run_he(const char * id, size_t table, const unsigned char * data, size_t len) {
  GHTTP_HpackLimits lim;
  ghttp_hpack_limits_default(&lim);
  lim.max_table_size = table > 4096 ? table : 4096;
  GHTTP_HpackEncoder * e = NULL;
  GHTTP_Buffer * b = NULL;
  // The peer's table is the protocol default until its SETTINGS say otherwise;
  // announcing a different size is what the encoder then does, as in HTTP/2.
  if (ghttp_hpack_encoder_create(NULL, &lim, GHTTP_HPACK_DEFAULT_TABLE_SIZE, &e) != GHTTP_OK
      || ghttp_buffer_create(NULL, &b) != GHTTP_OK
      || ghttp_hpack_encoder_set_peer_table_size(e, table) != GHTTP_OK) {
    fputs("h2_probe: cannot create an encoder\n", stderr);
    exit(2);
  }
  size_t off = 0;
  GHTTP_Result r = GHTTP_OK;
  while (off + 4 <= len && r == GHTTP_OK) {
    size_t nl = be32(data + off);
    off += 4;
    if (nl > len - off || len - off - nl < 4) {
      fputs("h2_probe: a bad field blob\n", stderr);
      exit(2);
    }
    const unsigned char * name = data + off;
    off += nl;
    size_t vl = be32(data + off);
    off += 4;
    if (vl > len - off) {
      fputs("h2_probe: a bad field blob\n", stderr);
      exit(2);
    }
    r = ghttp_hpack_encode_field(e, (const char *)name, nl, (const char *)data + off, vl,
        GHTTP_HPACK_INDEX_SAFE, GHTTP_HPACK_HUFFMAN_AUTO, b);
    off += vl;
  }
  Buf out = {0};
  buf_str(&out, "{\"hex\":\"");
  buf_hex(&out, ghttp_buffer_data(b) ? ghttp_buffer_data(b) : "", ghttp_buffer_size(b));
  buf_str(&out, r == GHTTP_OK ? "\"}" : "\",\"error\":true}");
  printf("%s\twhole\t%s\n", id, out.data);
  free(out.data);
  ghttp_buffer_destroy(b);
  ghttp_hpack_encoder_destroy(e);
}

// One line, any length, without getline (which Windows has not got, and which
// -std=c17 does not declare under mingw). Returns its length without the
// newline, or -1 at the end of input with nothing read.
static long read_line(char ** line, size_t * cap, FILE * in) {
  size_t len = 0;
  for (;;) {
    if (*cap - len < 2) {
      size_t grown = *cap ? *cap * 2 : 4096;
      char * bigger = realloc(*line, grown);
      if (!bigger) {
        fputs("h2_probe: out of memory\n", stderr);
        exit(2);
      }
      *line = bigger;
      *cap = grown;
    }
    if (!fgets(*line + len, (int)(*cap - len), in)) {
      break;
    }
    len += strlen(*line + len);
    if (len > 0 && (*line)[len - 1] == '\n') {
      (*line)[--len] = '\0';
      return (long)len;
    }
  }
  if (len == 0) {
    return -1;
  }
  (*line)[len] = '\0';
  return (long)len;
}

int main(void) {
#ifdef _WIN32
  // The answers are compared byte for byte with another platform's: no CRLF
  // translation on either stream.
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  char * line = NULL;
  size_t cap = 0;
  long got;
  while ((got = read_line(&line, &cap, stdin)) >= 0) {
    char * f[5];
    char * at = line;
    int i;
    for (i = 0; i < 5; i++) {
      f[i] = at;
      char * tab = i < 4 ? strchr(at, '\t') : NULL;
      if (i < 4 && !tab) {
        break;
      }
      if (tab) {
        *tab = '\0';
        at = tab + 1;
      }
    }
    if (i < 5) {
      fputs("h2_probe: a case needs five tab-separated fields\n", stderr);
      return 2;
    }
    size_t hl = strlen(f[4]);
    if (hl % 2) {
      fputs("h2_probe: odd hex\n", stderr);
      return 2;
    }
    unsigned char * data = malloc(hl / 2 + 1);
    for (size_t k = 0; k < hl / 2; k++) {
      int a = unhex(f[4][2 * k]);
      int b = unhex(f[4][2 * k + 1]);
      if (a < 0 || b < 0) {
        fputs("h2_probe: bad hex\n", stderr);
        return 2;
      }
      data[k] = (unsigned char)(a << 4 | b);
    }
    if (strcmp(f[1], "h2") == 0) {
      run_h2(f[0], f[3], strcmp(f[2], "byte") == 0, data, hl / 2);
    } else if (strcmp(f[1], "hd") == 0) {
      run_hd(f[0], (size_t)strtoul(f[3], NULL, 10), data, hl / 2);
    } else if (strcmp(f[1], "he") == 0) {
      run_he(f[0], (size_t)strtoul(f[3], NULL, 10), data, hl / 2);
    } else {
      fputs("h2_probe: unknown kind\n", stderr);
      return 2;
    }
    free(data);
  }
  free(line);
  return 0;
}
