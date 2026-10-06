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
 * The differential's side of this library: one line in, one line out.
 *
 * Reads tab-separated cases on stdin
 *
 *     id  kind  method  split  hex
 *
 * where kind is `req` or `res`, method is the request method a response
 * answers (`-` for none), split is `whole` (one call) or `byte` (one byte per
 * call) and hex is the stream, and writes `id  split  json`, where the JSON is
 * the same shape the reference drivers write, with every string hex-encoded so
 * that no byte needs an escape:
 *
 *     {"msgs":[{"start":{...},"headers":[[name,value]...],
 *               "body":hex,"trailers":[[name,value]...],"upgrade":bool}],
 *      "end":"clean"|"incomplete"|"error","err":"CORRUPT"}
 *
 * A message is listed only when it ended. `incomplete` is the stream ending
 * inside a message (ghttp_parser_finish said so), `error` is a refusal.
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
      fputs("http_probe: out of memory\n", stderr);
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

static void buf_fields(Buf * b, const GHTTP_Headers * h) {
  buf_str(b, "[");
  size_t n = ghttp_headers_count(h);
  for (size_t i = 0; i < n; i++) {
    GHTTP_Field f;
    if (ghttp_headers_at(h, i, &f) != GHTTP_OK) {
      continue;
    }
    buf_str(b, i ? ",[\"" : "[\"");
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

typedef struct {
  Buf out;       // the finished messages, comma separated
  size_t count;  // how many
  Buf head;      // the current message's start and headers
  Buf body;      // the current message's body
  int upgrade;   // the current message asks for a tunnel or an upgrade
} Run;

static void run_head(Run * r, GHTTP_ParserKind kind, GHTTP_Parser * p) {
  r->head.len = 0;
  r->body.len = 0;
  r->upgrade = ghttp_parser_upgrade(p) != GHTTP_UPGRADE_NONE;
  Buf * h = &r->head;
  if (kind == GHTTP_PARSE_REQUEST) {
    const GHTTP_Request * q = ghttp_parser_request(p);
    char ver[16];
    snprintf(ver, sizeof ver, "1.%d", ghttp_request_version(q));
    buf_str(h, "\"start\":{\"method\":\"");
    buf_hex(h, ghttp_request_method(q), strlen(ghttp_request_method(q)));
    buf_str(h, "\",\"target\":\"");
    buf_hex(h, ghttp_request_target(q), strlen(ghttp_request_target(q)));
    buf_str(h, "\",\"ver\":\"");
    buf_str(h, ver);
    buf_str(h, "\"},\"headers\":");
    buf_fields(h, ghttp_request_headers_const(q));
  } else {
    const GHTTP_Response * q = ghttp_parser_response(p);
    char tail[64];
    snprintf(tail, sizeof tail, "\"status\":%d,\"ver\":\"1.%d\"},\"headers\":",
        ghttp_response_status(q), ghttp_response_version(q));
    buf_str(h, "\"start\":{\"reason\":\"");
    buf_hex(h, ghttp_response_reason(q), strlen(ghttp_response_reason(q)));
    buf_str(h, "\",");
    buf_str(h, tail);
    buf_fields(h, ghttp_response_headers_const(q));
  }
}

static void run_end(Run * r, GHTTP_Parser * p) {
  if (r->count++) {
    buf_str(&r->out, ",");
  }
  buf_str(&r->out, "{");
  buf_put(&r->out, r->head.data ? r->head.data : "", r->head.len);
  buf_str(&r->out, ",\"body\":\"");
  buf_hex(&r->out, r->body.data ? r->body.data : "", r->body.len);
  buf_str(&r->out, "\",\"trailers\":");
  buf_fields(&r->out, ghttp_parser_trailers(p));
  buf_str(&r->out, r->upgrade ? ",\"upgrade\":true}" : ",\"upgrade\":false}");
}

// Feed one piece. Returns GHTTP_OK or the refusal.
static GHTTP_Result run_piece(Run * r, GHTTP_ParserKind kind, GHTTP_Parser * p,
    const unsigned char * piece, size_t len) {
  size_t off = 0;
  GHTTP_Event ev;
  do {
    size_t used = 0;
    GHTTP_Result res = ghttp_parser_feed(p, piece + off, len - off, &used, &ev);
    if (res != GHTTP_OK) {
      return res;
    }
    off += used;
    switch (ev) {
    case GHTTP_EVENT_HEAD:
      run_head(r, kind, p);
      break;
    case GHTTP_EVENT_BODY: {
      const void * d;
      size_t n;
      ghttp_parser_body(p, &d, &n);
      buf_put(&r->body, d, n);
      break;
    }
    case GHTTP_EVENT_END:
      run_end(r, p);
      break;
    case GHTTP_EVENT_NEED_MORE:
      break;
    }
  } while (ev != GHTTP_EVENT_NEED_MORE);
  return GHTTP_OK;
}

static void run_case(const char * id, int is_response, const char * method,
    int bytewise, const unsigned char * data, size_t len) {
  GHTTP_ParserKind kind = is_response ? GHTTP_PARSE_RESPONSE : GHTTP_PARSE_REQUEST;
  GHTTP_Parser * p = NULL;
  if (ghttp_parser_create(kind, NULL, NULL, &p) != GHTTP_OK) {
    fputs("http_probe: cannot create a parser\n", stderr);
    exit(2);
  }
  if (is_response && strcmp(method, "-") != 0) {
    ghttp_parser_expect_response_to(p, method);
  }
  Run r;
  memset(&r, 0, sizeof r);
  const char * end = "clean";
  GHTTP_Result err = GHTTP_OK;
  if (bytewise) {
    for (size_t i = 0; i < len && err == GHTTP_OK; i++) {
      err = run_piece(&r, kind, p, data + i, 1);
    }
  } else {
    err = run_piece(&r, kind, p, data, len);
  }
  if (err != GHTTP_OK) {
    end = "error";
  } else {
    GHTTP_Event ev;
    GHTTP_Result fin = ghttp_parser_finish(p, &ev);
    if (fin != GHTTP_OK) {
      end = "incomplete";
      err = fin;
    } else if (ev == GHTTP_EVENT_END) {
      run_end(&r, p);
    }
  }
  printf("%s\t%s\t{\"msgs\":[%s],\"end\":\"%s\",\"err\":\"%s\"}\n", id,
      bytewise ? "byte" : "whole", r.out.data ? r.out.data : "", end,
      err == GHTTP_OK ? "" : ghttp_result_string(err));
  ghttp_parser_destroy(p);
  free(r.out.data);
  free(r.head.data);
  free(r.body.data);
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
        fputs("http_probe: out of memory\n", stderr);
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
      fputs("http_probe: a case needs five tab-separated fields\n", stderr);
      return 2;
    }
    size_t hl = strlen(f[4]);
    if (hl % 2) {
      fputs("http_probe: odd hex\n", stderr);
      return 2;
    }
    unsigned char * data = malloc(hl / 2 + 1);
    for (size_t k = 0; k < hl / 2; k++) {
      int a = unhex(f[4][2 * k]);
      int b = unhex(f[4][2 * k + 1]);
      if (a < 0 || b < 0) {
        fputs("http_probe: bad hex\n", stderr);
        return 2;
      }
      data[k] = (unsigned char)(a << 4 | b);
    }
    run_case(f[0], strcmp(f[1], "res") == 0, f[2], strcmp(f[3], "byte") == 0,
        data, hl / 2);
    free(data);
  }
  free(line);
  return 0;
}
