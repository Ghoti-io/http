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
 * The WebSocket differential's side of this library: one line in, one line out.
 *
 * Reads tab-separated cases on stdin
 *
 *     id  kind  split  arg  hex
 *
 * and writes `id  split  json`, every string hex-encoded so that no byte needs
 * an escape. `split` is `whole` or `byte` (kinds ws and wc only; the others are
 * always `whole`). The five kinds, and the shape of each answer, are the spec
 * the reference drivers follow (containers/refs/ref-wsproto.py,
 * ref-websockets.py, gows/main.go; and "The WebSocket differential" in
 * notes/http/README.md).
 *
 * `arg` is a spec: `-` for nothing, else `;`-separated tokens
 *
 *     role=client|server   which end this library is (wr only)
 *     p=a,b,c              subprotocols: the server's, in preference order (hs)
 *                          or the client's offer (hc)
 *     d                    permessage-deflate (agreed in ws, wc, wr; policy in
 *                          hs; offered in hc)
 *     snct, cnct           server_no_context_takeover, client_no_context_takeover
 *     smb=N, cmb=N         server_max_window_bits, client_max_window_bits
 *     ocmb                 (hc) offer client_max_window_bits without a value
 *
 *   ws  The hex is a client's byte stream after the opening handshake; this
 *       library is a SERVER (permessage-deflate agreed as the spec says).
 *   wc  The hex is a server's byte stream after the handshake; this library is
 *       a CLIENT. Both answer
 *         {"evs":[[kind,data,code]...],"sent":[[opcode,payload]...],
 *          "end":"open"|"closed"|"failed","fail":hex,"err":hex}
 *       evs: what the application was given, in order: kind is text, binary,
 *       ping, pong or close; data is the message, the payload or the close
 *       reason; code is the close code (1005 when the frame had none) or null.
 *       sent: the frames this implementation itself queued (the Pongs it
 *       answered with, the Close it echoed or failed with), unmasked. end:
 *       closed = a Close was received and answered; failed = the connection
 *       was ended for a violation; open = neither (the input ended). "fail" is
 *       the reason text of a failure, "err" the result code.
 *   hs  The hex is a client's HTTP request head; arg is the server's policy.
 *         {"status":N,"accept":hex|null,"protocol":hex|null,
 *          "extensions":hex|null,"parse_error":bool,"err":hex}
 *       status is 0 when the head never completed.
 *   hc  The hex is a server's HTTP response head to the request a client built
 *       with the RFC 6455 example key and the offer in arg.
 *         {"accepted":bool,"protocol":hex|null,
 *          "deflate":null|{"snct":0|1,"cnct":0|1,"smb":N,"cmb":N},
 *          "parse_error":bool,"err":hex}
 *       smb and cmb are 0 for "not limited".
 *   wr  The hex is a script (records: one letter, a 4-octet length, that many
 *       octets); this library, in the role arg names, sends it, and the answer
 *       is the bytes it wrote: {"hex":wire,"err":hex}. Letters: T and B a whole
 *       text or binary message, a/z the first-or-middle and last fragment of a
 *       text message, b/y those of a binary one, p a Ping, o an unsolicited
 *       Pong, c a Close (the first two octets are the code, the rest the
 *       reason; no data is a Close with no body). The driver then runs the
 *       bytes through every reference as the peer.
 *
 * The limits are the same ones the reference drivers set: a message and a
 * frame are at most 1 MiB (websockets' own default max_size). Everything else
 * is this library's default, except the output queue, which holds 4 MiB so that
 * a script (wr) can queue a message of the cap whole.
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

#define ORACLE_MAX_MESSAGE ((uint64_t)1 << 20)

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
      fputs("ws_probe: out of memory\n", stderr);
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

/** A hex string, quoted. */
static void buf_hexq(Buf * b, const void * p, size_t n) {
  buf_str(b, "\"");
  buf_hex(b, p, n);
  buf_str(b, "\"");
}

/** A hex string or null. */
static void buf_opt(Buf * b, const char * s) {
  if (!s) {
    buf_str(b, "null");
    return;
  }
  buf_hexq(b, s, strlen(s));
}

static void buf_num(Buf * b, unsigned long v) {
  char num[32];
  snprintf(num, sizeof num, "%lu", v);
  buf_str(b, num);
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
// The spec in `arg`
// ---------------------------------------------------------------------------

#define MAX_PROTOS 16

typedef struct {
  int client;  // role=client
  char protos_text[512];
  const char * protos[MAX_PROTOS];
  size_t nprotos;
  int deflate;
  int snct, cnct;
  int smb, cmb;
  int ocmb;
} Spec;

static void parse_spec(const char * arg, Spec * s) {
  memset(s, 0, sizeof *s);
  if (strcmp(arg, "-") == 0) {
    return;
  }
  char text[1024];
  if (strlen(arg) >= sizeof text) {
    fputs("ws_probe: arg too long\n", stderr);
    exit(2);
  }
  strcpy(text, arg);
  char * at = text;
  while (*at) {
    char * tok = at;
    char * semi = strchr(at, ';');
    if (semi) {
      *semi = '\0';
      at = semi + 1;
    } else {
      at += strlen(at);
    }
    if (strcmp(tok, "role=client") == 0) {
      s->client = 1;
    } else if (strcmp(tok, "role=server") == 0) {
      s->client = 0;
    } else if (strncmp(tok, "p=", 2) == 0) {
      if (strlen(tok + 2) >= sizeof s->protos_text) {
        fputs("ws_probe: subprotocols too long\n", stderr);
        exit(2);
      }
      strcpy(s->protos_text, tok + 2);
      char * q = s->protos_text;
      while (*q && s->nprotos < MAX_PROTOS) {
        s->protos[s->nprotos++] = q;
        char * comma = strchr(q, ',');
        if (!comma) {
          break;
        }
        *comma = '\0';
        q = comma + 1;
      }
    } else if (strcmp(tok, "d") == 0) {
      s->deflate = 1;
    } else if (strcmp(tok, "snct") == 0) {
      s->snct = 1;
    } else if (strcmp(tok, "cnct") == 0) {
      s->cnct = 1;
    } else if (strncmp(tok, "smb=", 4) == 0) {
      s->smb = atoi(tok + 4);
    } else if (strncmp(tok, "cmb=", 4) == 0) {
      s->cmb = atoi(tok + 4);
    } else if (strcmp(tok, "ocmb") == 0) {
      s->ocmb = 1;
    } else {
      fprintf(stderr, "ws_probe: unknown spec token %s\n", tok);
      exit(2);
    }
  }
}

static void params_of(const Spec * s, GHTTP_WsDeflateParams * p) {
  ghttp_ws_deflate_params_default(p);
  p->server_no_context_takeover = s->snct;
  p->client_no_context_takeover = s->cnct;
  p->server_max_window_bits = (uint8_t)s->smb;
  p->client_max_window_bits = (uint8_t)s->cmb;
  p->offer_client_max_window_bits = s->ocmb;
}

static void limits_of(GHTTP_WsLimits * lim) {
  ghttp_ws_limits_default(lim);
  lim->max_frame_payload = ORACLE_MAX_MESSAGE;
  lim->max_message_bytes = ORACLE_MAX_MESSAGE;
  // A message of the cap, queued whole to be written (wr), has to fit in the
  // queue; the default queue is the size of one such message.
  lim->max_buffered_bytes = (size_t)4 * ORACLE_MAX_MESSAGE;
}

// ---------------------------------------------------------------------------
// Frames in what this library wrote (parsed here, not by the library)
// ---------------------------------------------------------------------------

/** The frames in @p out as [[opcode,payload-hex]...]. A cut frame ends the list. */
static void buf_frames(Buf * b, const unsigned char * out, size_t n) {
  buf_str(b, "[");
  size_t i = 0, count = 0;
  while (i + 2 <= n) {
    unsigned op = out[i] & 15;
    int masked = (out[i + 1] & 0x80) != 0;
    unsigned long long len = out[i + 1] & 0x7f;
    size_t at = i + 2;
    if (len == 126) {
      if (at + 2 > n) {
        break;
      }
      len = ((unsigned long long)out[at] << 8) | out[at + 1];
      at += 2;
    } else if (len == 127) {
      if (at + 8 > n) {
        break;
      }
      len = 0;
      for (int k = 0; k < 8; k++) {
        len = (len << 8) | out[at + k];
      }
      at += 8;
    }
    unsigned char key[4] = {0, 0, 0, 0};
    if (masked) {
      if (at + 4 > n) {
        break;
      }
      memcpy(key, out + at, 4);
      at += 4;
    }
    if (len > n - at) {
      break;
    }
    buf_str(b, count++ ? ",[" : "[");
    buf_num(b, op);
    buf_str(b, ",\"");
    static const char digits[] = "0123456789abcdef";
    for (size_t k = 0; k < len; k++) {
      unsigned char c = (unsigned char)(out[at + k] ^ key[k % 4]);
      char two[2] = {digits[c >> 4], digits[c & 15]};
      buf_put(b, two, 2);
    }
    buf_str(b, "\"]");
    i = at + (size_t)len;
  }
  buf_str(b, "]");
}

// ---------------------------------------------------------------------------
// kinds ws and wc
// ---------------------------------------------------------------------------

static GHTTP_Result count_random(void * ctx, void * out, size_t n) {
  unsigned * c = ctx;
  unsigned char * p = out;
  for (size_t i = 0; i < n; i++) {
    *c = *c * 1664525u + 1013904223u;
    p[i] = (unsigned char)(*c >> 24);
  }
  return GHTTP_OK;
}

typedef struct {
  Buf evs;
  size_t nevs;
  int closed;
  Buf out;  // what the connection queued, taken after every event as the documented loop does
} Stream;

/** Take the connection's output: a Pong not yet taken is replaced by the next Ping's. */
static void take_output(Stream * s, GHTTP_WsConn * c) {
  size_t n = 0;
  const unsigned char * p = ghttp_ws_conn_output(c, &n);
  if (n > 0) {
    buf_put(&s->out, (const char *)p, n);
    ghttp_ws_conn_output_consume(c, n);
  }
}

static void stream_event(Stream * s, const GHTTP_WsEvent * ev) {
  const char * kind = NULL;
  switch (ev->type) {
  case GHTTP_WS_EVENT_TEXT:
    kind = "text";
    break;
  case GHTTP_WS_EVENT_BINARY:
    kind = "binary";
    break;
  case GHTTP_WS_EVENT_PING:
    kind = "ping";
    break;
  case GHTTP_WS_EVENT_PONG:
    kind = "pong";
    break;
  case GHTTP_WS_EVENT_CLOSE:
    kind = "close";
    s->closed = 1;
    break;
  default:
    return;
  }
  buf_str(&s->evs, s->nevs++ ? ",[\"" : "[\"");
  buf_str(&s->evs, kind);
  buf_str(&s->evs, "\",");
  buf_hexq(&s->evs, ev->data ? ev->data : (const unsigned char *)"", ev->data_len);
  buf_str(&s->evs, ",");
  if (ev->type == GHTTP_WS_EVENT_CLOSE) {
    buf_num(&s->evs, ev->code);
  } else {
    buf_str(&s->evs, "null");
  }
  buf_str(&s->evs, "]");
}

static GHTTP_Result stream_piece(Stream * s, GHTTP_WsConn * c,
    const unsigned char * piece, size_t len) {
  size_t off = 0;
  GHTTP_WsEvent ev;
  do {
    size_t used = 0;
    GHTTP_Result res = ghttp_ws_conn_feed(c, piece + off, len - off, &used, &ev);
    if (res != GHTTP_OK) {
      take_output(s, c);
      return res;
    }
    off += used;
    stream_event(s, &ev);
    take_output(s, c);
  } while (ev.type != GHTTP_WS_EVENT_NEED_MORE);
  return GHTTP_OK;
}

static void run_stream(const char * id, int client, int bytewise, const char * arg,
    const unsigned char * data, size_t len) {
  Spec spec;
  parse_spec(arg, &spec);
  GHTTP_WsNegotiated neg;
  ghttp_ws_negotiated_default(&neg);
  if (spec.deflate) {
    neg.deflate = 1;
    params_of(&spec, &neg.deflate_params);
  }
  GHTTP_WsLimits lim;
  limits_of(&lim);
  GHTTP_WsConn * c = NULL;
  if (ghttp_ws_conn_create(NULL, client ? GHTTP_WS_CLIENT : GHTTP_WS_SERVER, &lim, &neg, &c)
      != GHTTP_OK) {
    fputs("ws_probe: cannot create a connection\n", stderr);
    exit(2);
  }
  unsigned rng = 12345;
  ghttp_ws_conn_set_random(c, count_random, &rng);
  Stream s;
  memset(&s, 0, sizeof s);
  GHTTP_Result err = GHTTP_OK;
  if (bytewise) {
    for (size_t i = 0; i < len && err == GHTTP_OK; i++) {
      err = stream_piece(&s, c, data + i, 1);
    }
  } else {
    err = stream_piece(&s, c, data, len);
  }
  uint16_t code = 0;
  const char * why = "";
  if (err != GHTTP_OK) {
    ghttp_ws_conn_error(c, &code, &why);
  }
  take_output(&s, c);
  Buf o = {0};
  buf_str(&o, "{\"evs\":[");
  buf_put(&o, s.evs.data ? s.evs.data : "", s.evs.len);
  buf_str(&o, "],\"sent\":");
  buf_frames(&o, (const unsigned char *)(s.out.data ? s.out.data : ""), s.out.len);
  buf_str(&o, ",\"end\":\"");
  buf_str(&o, err != GHTTP_OK ? "failed" : (s.closed ? "closed" : "open"));
  buf_str(&o, "\",\"fail\":");
  buf_hexq(&o, why, strlen(why));
  buf_str(&o, ",\"err\":");
  buf_hexq(&o, err == GHTTP_OK ? "" : ghttp_result_string(err),
      err == GHTTP_OK ? 0 : strlen(ghttp_result_string(err)));
  buf_str(&o, "}");
  printf("%s\t%s\t%s\n", id, bytewise ? "byte" : "whole", o.data);
  free(o.data);
  free(s.evs.data);
  free(s.out.data);
  ghttp_ws_conn_destroy(c);
}

// ---------------------------------------------------------------------------
// kind wr
// ---------------------------------------------------------------------------

static unsigned long be32(const unsigned char * p) {
  return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16)
      | ((unsigned long)p[2] << 8) | p[3];
}

static void run_wr(const char * id, const char * arg, const unsigned char * data, size_t len) {
  Spec spec;
  parse_spec(arg, &spec);
  GHTTP_WsNegotiated neg;
  ghttp_ws_negotiated_default(&neg);
  if (spec.deflate) {
    neg.deflate = 1;
    params_of(&spec, &neg.deflate_params);
  }
  GHTTP_WsLimits lim;
  limits_of(&lim);
  GHTTP_WsConn * c = NULL;
  if (ghttp_ws_conn_create(NULL, spec.client ? GHTTP_WS_CLIENT : GHTTP_WS_SERVER, &lim, &neg, &c)
      != GHTTP_OK) {
    fputs("ws_probe: cannot create a connection\n", stderr);
    exit(2);
  }
  unsigned rng = 777;
  ghttp_ws_conn_set_random(c, count_random, &rng);
  GHTTP_Result r = GHTTP_OK;
  size_t off = 0;
  while (off + 5 <= len && r == GHTTP_OK) {
    char op = (char)data[off];
    size_t n = be32(data + off + 1);
    off += 5;
    if (n > len - off) {
      fputs("ws_probe: a bad script\n", stderr);
      exit(2);
    }
    const unsigned char * d = data + off;
    switch (op) {
    case 'T':
      r = ghttp_ws_conn_send_message(c, GHTTP_WS_MESSAGE_TEXT, d, n);
      break;
    case 'B':
      r = ghttp_ws_conn_send_message(c, GHTTP_WS_MESSAGE_BINARY, d, n);
      break;
    case 'a':
      r = ghttp_ws_conn_send_fragment(c, GHTTP_WS_MESSAGE_TEXT, d, n, 0);
      break;
    case 'z':
      r = ghttp_ws_conn_send_fragment(c, GHTTP_WS_MESSAGE_TEXT, d, n, 1);
      break;
    case 'b':
      r = ghttp_ws_conn_send_fragment(c, GHTTP_WS_MESSAGE_BINARY, d, n, 0);
      break;
    case 'y':
      r = ghttp_ws_conn_send_fragment(c, GHTTP_WS_MESSAGE_BINARY, d, n, 1);
      break;
    case 'p':
      r = ghttp_ws_conn_send_ping(c, d, n);
      break;
    case 'o':
      r = ghttp_ws_conn_send_pong(c, d, n);
      break;
    case 'c':
      if (n >= 2) {
        r = ghttp_ws_conn_close(c, (uint16_t)((d[0] << 8) | d[1]), d + 2, n - 2);
      } else {
        r = ghttp_ws_conn_close(c, 0, NULL, 0);
      }
      break;
    default:
      fputs("ws_probe: an unknown script letter\n", stderr);
      exit(2);
    }
    off += n;
  }
  size_t outn = 0;
  const unsigned char * out = ghttp_ws_conn_output(c, &outn);
  Buf o = {0};
  buf_str(&o, "{\"hex\":");
  buf_hexq(&o, out ? out : (const unsigned char *)"", outn);
  buf_str(&o, ",\"err\":");
  buf_hexq(&o, r == GHTTP_OK ? "" : ghttp_result_string(r), r == GHTTP_OK ? 0 : strlen(ghttp_result_string(r)));
  buf_str(&o, "}");
  printf("%s\twhole\t%s\n", id, o.data);
  free(o.data);
  ghttp_ws_conn_destroy(c);
}

// ---------------------------------------------------------------------------
// kinds hs and hc
// ---------------------------------------------------------------------------

/** Parse one message head from @p data. 1: head parsed; 0: input ended first; -1: refused. */
static int parse_head(GHTTP_ParserKind kind, const unsigned char * data, size_t len,
    GHTTP_Parser ** pp) {
  if (ghttp_parser_create(kind, NULL, NULL, pp) != GHTTP_OK) {
    fputs("ws_probe: cannot create a parser\n", stderr);
    exit(2);
  }
  size_t off = 0;
  GHTTP_Event ev;
  do {
    size_t used = 0;
    GHTTP_Result res = ghttp_parser_feed(*pp, data + off, len - off, &used, &ev);
    if (res != GHTTP_OK) {
      return -1;
    }
    off += used;
    if (ev == GHTTP_EVENT_HEAD) {
      return 1;
    }
  } while (ev != GHTTP_EVENT_NEED_MORE);
  return 0;
}

static const char * header_value(const GHTTP_Headers * h, const char * name, char * buf, size_t cap) {
  size_t i = ghttp_headers_find(h, name, 0);
  if (i == GHTTP_HEADERS_NPOS) {
    return NULL;
  }
  GHTTP_Field f;
  if (ghttp_headers_at(h, i, &f) != GHTTP_OK || f.value_len >= cap) {
    return NULL;
  }
  memcpy(buf, f.value, f.value_len);
  buf[f.value_len] = '\0';
  return buf;
}

static void run_hs(const char * id, const char * arg, const unsigned char * data, size_t len) {
  Spec spec;
  parse_spec(arg, &spec);
  GHTTP_Parser * p = NULL;
  int got = parse_head(GHTTP_PARSE_REQUEST, data, len, &p);
  Buf o = {0};
  if (got != 1) {
    buf_str(&o, got < 0 ? "{\"status\":400,\"accept\":null,\"protocol\":null,\"extensions\":null,\"parse_error\":true,\"err\":\"\"}"
                        : "{\"status\":0,\"accept\":null,\"protocol\":null,\"extensions\":null,\"parse_error\":false,\"err\":\"\"}");
    printf("%s\twhole\t%s\n", id, o.data);
    free(o.data);
    ghttp_parser_destroy(p);
    return;
  }
  GHTTP_WsServerOptions opt;
  ghttp_ws_server_options_default(&opt);
  GHTTP_WsLimits lim;
  limits_of(&lim);
  opt.limits = &lim;
  opt.subprotocols = spec.protos;
  opt.subprotocol_count = spec.nprotos;
  if (spec.deflate) {
    opt.enable_deflate = 1;
    params_of(&spec, &opt.deflate);
  }
  GHTTP_Response * resp = NULL;
  if (ghttp_response_create(NULL, &resp) != GHTTP_OK) {
    exit(2);
  }
  GHTTP_WsServerResult res;
  memset(&res, 0, sizeof res);
  GHTTP_Result r = ghttp_ws_server_handshake(ghttp_parser_request(p), &opt, resp, &res);
  const GHTTP_Headers * h = ghttp_response_headers_const(resp);
  char accept[128], proto[256], ext[512];
  buf_str(&o, "{\"status\":");
  buf_num(&o, (unsigned long)ghttp_response_status(resp));
  buf_str(&o, ",\"accept\":");
  buf_opt(&o, header_value(h, "Sec-WebSocket-Accept", accept, sizeof accept));
  buf_str(&o, ",\"protocol\":");
  buf_opt(&o, header_value(h, "Sec-WebSocket-Protocol", proto, sizeof proto));
  buf_str(&o, ",\"extensions\":");
  buf_opt(&o, header_value(h, "Sec-WebSocket-Extensions", ext, sizeof ext));
  buf_str(&o, ",\"parse_error\":false,\"err\":");
  buf_hexq(&o, r == GHTTP_OK ? "" : ghttp_result_string(r), r == GHTTP_OK ? 0 : strlen(ghttp_result_string(r)));
  buf_str(&o, "}");
  printf("%s\twhole\t%s\n", id, o.data);
  free(o.data);
  ghttp_response_destroy(resp);
  ghttp_parser_destroy(p);
}

static void run_hc(const char * id, const char * arg, const unsigned char * data, size_t len) {
  Spec spec;
  parse_spec(arg, &spec);
  static const uint8_t NONCE[16] = "the sample nonce";  // the RFC 6455 section 1.3 key
  GHTTP_WsClientOptions opt;
  ghttp_ws_client_options_default(&opt);
  GHTTP_WsLimits lim;
  limits_of(&lim);
  opt.limits = &lim;
  opt.host = "server.example.com";
  opt.target = "/chat";
  opt.nonce = NONCE;
  opt.subprotocols = spec.protos;
  opt.subprotocol_count = spec.nprotos;
  if (spec.deflate) {
    opt.enable_deflate = 1;
    params_of(&spec, &opt.deflate);
  }
  GHTTP_Request * req = NULL;
  GHTTP_WsClientHandshake * hs = NULL;
  if (ghttp_request_create(NULL, &req) != GHTTP_OK
      || ghttp_ws_client_handshake_create(NULL, &opt, req, &hs) != GHTTP_OK) {
    fputs("ws_probe: cannot build a client handshake\n", stderr);
    exit(2);
  }
  GHTTP_Parser * p = NULL;
  int got = parse_head(GHTTP_PARSE_RESPONSE, data, len, &p);
  Buf o = {0};
  if (got != 1) {
    buf_str(&o, "{\"accepted\":false,\"protocol\":null,\"deflate\":null,\"parse_error\":");
    buf_str(&o, got < 0 ? "true" : "false");
    buf_str(&o, ",\"err\":\"\"}");
  } else {
    GHTTP_WsClientResult res;
    memset(&res, 0, sizeof res);
    GHTTP_Result r = ghttp_ws_client_handshake_finish(hs, ghttp_parser_response(p), &res);
    buf_str(&o, res.accepted ? "{\"accepted\":true,\"protocol\":" : "{\"accepted\":false,\"protocol\":");
    if (res.accepted && res.negotiated.subprotocol[0]) {
      buf_opt(&o, res.negotiated.subprotocol);
    } else {
      buf_str(&o, "null");
    }
    buf_str(&o, ",\"deflate\":");
    if (res.accepted && res.negotiated.deflate) {
      const GHTTP_WsDeflateParams * d = &res.negotiated.deflate_params;
      buf_str(&o, "{\"snct\":");
      buf_num(&o, d->server_no_context_takeover != 0);
      buf_str(&o, ",\"cnct\":");
      buf_num(&o, d->client_no_context_takeover != 0);
      buf_str(&o, ",\"smb\":");
      buf_num(&o, d->server_max_window_bits);
      buf_str(&o, ",\"cmb\":");
      buf_num(&o, d->client_max_window_bits);
      buf_str(&o, "}");
    } else {
      buf_str(&o, "null");
    }
    buf_str(&o, ",\"parse_error\":false,\"err\":");
    buf_hexq(&o, r == GHTTP_OK ? "" : ghttp_result_string(r), r == GHTTP_OK ? 0 : strlen(ghttp_result_string(r)));
    buf_str(&o, "}");
  }
  printf("%s\twhole\t%s\n", id, o.data);
  free(o.data);
  ghttp_parser_destroy(p);
  ghttp_ws_client_handshake_destroy(hs);
  ghttp_request_destroy(req);
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
        fputs("ws_probe: out of memory\n", stderr);
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
      fputs("ws_probe: a case needs five tab-separated fields\n", stderr);
      return 2;
    }
    size_t hl = strlen(f[4]);
    if (hl % 2) {
      fputs("ws_probe: odd hex\n", stderr);
      return 2;
    }
    unsigned char * data = malloc(hl / 2 + 1);
    for (size_t k = 0; k < hl / 2; k++) {
      int a = unhex(f[4][2 * k]);
      int b = unhex(f[4][2 * k + 1]);
      if (a < 0 || b < 0) {
        fputs("ws_probe: bad hex\n", stderr);
        return 2;
      }
      data[k] = (unsigned char)(a << 4 | b);
    }
    int bytewise = strcmp(f[2], "byte") == 0;
    if (strcmp(f[1], "ws") == 0) {
      run_stream(f[0], 0, bytewise, f[3], data, hl / 2);
    } else if (strcmp(f[1], "wc") == 0) {
      run_stream(f[0], 1, bytewise, f[3], data, hl / 2);
    } else if (strcmp(f[1], "hs") == 0) {
      run_hs(f[0], f[3], data, hl / 2);
    } else if (strcmp(f[1], "hc") == 0) {
      run_hc(f[0], f[3], data, hl / 2);
    } else if (strcmp(f[1], "wr") == 0) {
      run_wr(f[0], f[3], data, hl / 2);
    } else {
      fputs("ws_probe: unknown kind\n", stderr);
      return 2;
    }
    free(data);
  }
  free(line);
  return 0;
}
