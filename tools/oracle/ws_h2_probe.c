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
 * This library's side of the Extended CONNECT interoperability check
 * (interop_ws_h2.py). The HTTP/2 connection is this process's stdin and stdout,
 * so the harness joins it to a reference at the other end with two pipes.
 *
 *   ws_h2_probe server [--raw]
 *       Enable Extended CONNECT. For a CONNECT with `:protocol` websocket accept
 *       the WebSocket (subprotocol `chat`, permessage-deflate) and echo every
 *       message; with --raw answer 200 to any Extended CONNECT and echo the
 *       tunnel's octets. Exits 0 when the peer closes the connection after the
 *       stream ended cleanly (a completed closing handshake, or in --raw mode
 *       both directions ended).
 *   ws_h2_probe client [--raw] [--deflate] SIZE...
 *       Open an Extended CONNECT and send a message of each SIZE (text for even
 *       positions, binary for odd), each waiting for its echo to be the same,
 *       then close with 1000. With --raw there is no WebSocket: SIZE... are
 *       summed, that many octets of a fixed pattern are written to the tunnel,
 *       the stream is ended, and the echo must be the same octets and end.
 *       Exits 0 when everything matched and the stream ended cleanly.
 *
 *   ws_h2_probe        (no arguments)
 *       Read lines from stdin, each `[--deflate] SIZE...`, and for each run a
 *       client and a server of this library wired to each other in this
 *       process with the client's masking keys fixed, the same messages as
 *       `client` sends, and print one line: the number of octets each way and a
 *       digest of the HTTP/2 bytes each way. The answers are the same on every
 *       target and compiler (suite/tools/xarch/http.sh compares them), which is
 *       what shows that the adapter, the handshake and the codecs agree beneath
 *       the byte order, the word size and the strictness of the platform.
 *
 * The probe says what it did on stderr; only the exit status is the verdict.
 */

#define _POSIX_C_SOURCE 200809L

#include <ghoti.io/http/http.h>
#include <stdio.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int raw = 0;
static int deflate_on = 0;

static void say(const char * what) {
  fprintf(stderr, "ws_h2_probe: %s\n", what);
}

static int die(const char * what) {
  say(what);
  return 1;
}

// ---- a growable byte string -------------------------------------------------------

typedef struct {
  unsigned char * p;
  size_t n;
  size_t cap;
} Bytes;

static void bytes_add(Bytes * b, const void * d, size_t n) {
  if (b->n + n > b->cap) {
    b->cap = (b->n + n) * 2 + 64;
    b->p = realloc(b->p, b->cap);
    if (!b->p) {
      exit(2);
    }
  }
  memcpy(b->p + b->n, d, n);
  b->n += n;
}

static void bytes_drop(Bytes * b, size_t n) {
  memmove(b->p, b->p + n, b->n - n);
  b->n -= n;
}

// ---- the connection -----------------------------------------------------------------

typedef struct {
  GHTTP_H2Conn * h2;
  GHTTP_H2Role role;
  uint32_t stream;
  GHTTP_WsConn * ws;
  GHTTP_WsH2 * ad;
  GHTTP_WsClientHandshake * hs;
  GHTTP_Request * req;
  Bytes echo;        // raw mode: octets to send back
  int echo_end;      // raw mode: end the stream when echo is empty
  int remote_ended;
  int local_ended;
  int failed;
  // client
  size_t nsizes;
  size_t * sizes;
  size_t sent;       // messages sent
  unsigned char * want;
  size_t want_len;
  int want_text;
  int closed_sent;
  Bytes rawgot;      // raw client: what came back
  size_t rawwant;
  int opened;
  // loop mode: output goes to the peer's input queue, with a digest
  Bytes * sink;
  uint64_t digest;
  size_t sent_octets;
  uint32_t mask_state;
} Conn;

// What was read from stdin while output was waiting to be written, and whether
// stdin has ended. See flush_out().
static Bytes inq;
static int in_eof;

static void flush_out(Conn * c) {
  size_t n = 0;
  const uint8_t * p = ghttp_h2_conn_output(c->h2, &n);
  if (c->sink) {
    for (size_t i = 0; i < n; i++) {
      c->digest = (c->digest ^ p[i]) * 1099511628211ull;
    }
    c->sent_octets += n;
    bytes_add(c->sink, p, n);
    ghttp_h2_conn_output_consume(c->h2, n);
    return;
  }
  // The two ends of this connection are single-threaded programs joined by
  // pipes. If each blocked in write() while the other did the same, neither would
  // ever read and both would stall for good (a Go client sending a megabyte while
  // this end echoes it did, under load). So while output waits, input is read
  // (and queued for the main loop), and a write is made only when the pipe has
  // room for it.
  while (n > 0) {
    struct pollfd fds[2] = {{1, POLLOUT, 0}, {0, POLLIN, 0}};
    if (poll(fds, in_eof ? 1 : 2, -1) < 0) {
      exit(3);
    }
    if (!in_eof && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
      unsigned char tmp[65536];
      ssize_t got = read(0, tmp, sizeof tmp);
      if (got > 0) {
        bytes_add(&inq, tmp, (size_t)got);
      } else {
        in_eof = 1;
      }
    }
    if (fds[0].revents & (POLLERR | POLLHUP)) {
      exit(3);
    }
    if (fds[0].revents & POLLOUT) {
      ssize_t w = write(1, p, n < 4096 ? n : 4096);  // PIPE_BUF: room was promised for this much
      if (w <= 0) {
        exit(3);
      }
      p += w;
      n -= (size_t)w;
    }
  }
  ghttp_h2_conn_output_consume(c->h2, ghttp_h2_conn_output_size(c->h2));
}

static unsigned char pat(size_t i, size_t salt) {
  uint32_t x = (uint32_t)(i * 2654435761u) ^ (uint32_t)(salt * 40503u);
  x ^= x >> 13;
  x *= 0x5bd1e995u;
  x ^= x >> 15;
  return (unsigned char)(x & 0xff);
}

/** Message @p i of @p n octets: ASCII for text, any octet for binary. */
static unsigned char * message(size_t i, size_t n, int text) {
  unsigned char * m = malloc(n + 1);
  for (size_t k = 0; k < n; k++) {
    m[k] = text ? (unsigned char)(' ' + pat(k, i) % 90) : pat(k, i);
  }
  return m;
}

// ---- echo for raw mode ------------------------------------------------------------

static void raw_pump(Conn * c) {
  if (c->local_ended || !ghttp_h2_conn_stream_is_active(c->h2, c->stream)) {
    return;
  }
  while (c->echo.n > 0) {
    size_t acc = 0;
    if (ghttp_h2_conn_send_data(c->h2, c->stream, c->echo.p, c->echo.n, 0, &acc) != GHTTP_OK) {
      c->failed = 1;
      return;
    }
    if (acc == 0) {
      return;
    }
    bytes_drop(&c->echo, acc);
  }
  if (c->echo_end) {
    size_t acc = 0;
    if (ghttp_h2_conn_send_data(c->h2, c->stream, NULL, 0, 1, &acc) == GHTTP_OK) {
      c->local_ended = 1;
    } else {
      c->failed = 1;
    }
  }
}

// ---- the WebSocket ----------------------------------------------------------------

static void send_next(Conn * c) {
  if (c->sent >= c->nsizes) {
    if (!c->closed_sent) {
      c->closed_sent = 1;
      if (ghttp_ws_conn_close(c->ws, 1000, "bye", 3) != GHTTP_OK) {
        c->failed = 1;
      }
    }
    return;
  }
  free(c->want);
  c->want_text = c->sent % 2 == 0;
  c->want_len = c->sizes[c->sent];
  c->want = message(c->sent, c->want_len, c->want_text);
  if (ghttp_ws_conn_send_message(c->ws, c->want_text ? GHTTP_WS_MESSAGE_TEXT : GHTTP_WS_MESSAGE_BINARY,
          c->want, c->want_len) != GHTTP_OK) {
    c->failed = 1;
  }
  c->sent++;
}

static void ws_events(Conn * c) {
  if (!c->ad) {
    return;
  }
  for (;;) {
    GHTTP_WsEvent e;
    GHTTP_Result r = ghttp_ws_h2_next(c->ad, &e);
    if (r != GHTTP_OK) {
      say("the WebSocket failed");
      c->failed = 1;
      break;
    }
    if (e.type == GHTTP_WS_EVENT_NEED_MORE) {
      break;
    }
    if (e.type == GHTTP_WS_EVENT_TEXT || e.type == GHTTP_WS_EVENT_BINARY) {
      if (c->role == GHTTP_H2_SERVER) {
        if (ghttp_ws_conn_send_message(c->ws,
                e.type == GHTTP_WS_EVENT_TEXT ? GHTTP_WS_MESSAGE_TEXT : GHTTP_WS_MESSAGE_BINARY,
                e.data, e.data_len) != GHTTP_OK) {
          c->failed = 1;
        }
      } else {
        int text = e.type == GHTTP_WS_EVENT_TEXT;
        if (text != c->want_text || e.data_len != c->want_len
            || (e.data_len && memcmp(e.data, c->want, e.data_len) != 0)) {
          say("an echo differs from the message sent");
          c->failed = 1;
        } else {
          send_next(c);
        }
      }
    }
  }
  if (ghttp_ws_h2_pump(c->ad) != GHTTP_OK) {
    c->failed = 1;
  }
}

static GHTTP_Result fixed_random(void * ctx, void * out, size_t n) {
  uint32_t * s = ctx;
  unsigned char * o = out;
  for (size_t i = 0; i < n; i++) {
    *s = *s * 1103515245u + 12345u;
    o[i] = (unsigned char)(*s >> 16);
  }
  return GHTTP_OK;
}

static int attach(Conn * c, const GHTTP_WsNegotiated * n, GHTTP_WsRole role) {
  if (ghttp_ws_conn_create(NULL, role, NULL, n, &c->ws) != GHTTP_OK
      || ghttp_ws_h2_create(NULL, c->h2, c->stream, c->ws, &c->ad) != GHTTP_OK) {
    return 0;
  }
  if (c->sink) {
    c->mask_state = 1;
    ghttp_ws_conn_set_random(c->ws, fixed_random, &c->mask_state);
  }
  return 1;
}

// ---- events -----------------------------------------------------------------------

static void on_event(Conn * c, const GHTTP_H2Event * ev) {
  if (c->role == GHTTP_H2_SERVER) {
    if (ev->type == GHTTP_H2_EVENT_HEADERS && !c->stream) {
      const GHTTP_Request * q = ghttp_h2_conn_request(c->h2);
      c->stream = ev->stream_id;
      GHTTP_Response * resp = NULL;
      ghttp_response_create(NULL, &resp);
      if (raw) {
        ghttp_response_set_status(resp, 200, "");
        if (ghttp_h2_conn_send_response(c->h2, c->stream, resp, 0) != GHTTP_OK) {
          c->failed = 1;
        }
        c->remote_ended = ev->end_stream;
      } else if (ghttp_ws_is_h2_request(q)) {
        static const char * const protos[] = {"chat"};
        GHTTP_WsServerOptions o;
        ghttp_ws_server_options_default(&o);
        o.subprotocols = protos;
        o.subprotocol_count = 1;
        o.enable_deflate = 1;
        GHTTP_WsServerResult sr;
        if (ghttp_ws_server_handshake_h2(q, &o, resp, &sr) != GHTTP_OK
            || ghttp_h2_conn_send_response(c->h2, c->stream, resp, !sr.accepted) != GHTTP_OK) {
          c->failed = 1;
        } else if (!sr.accepted) {
          say(sr.reason);
          c->failed = 1;
        } else if (!attach(c, &sr.negotiated, GHTTP_WS_SERVER)) {
          c->failed = 1;
        } else {
          ghttp_ws_h2_input(c->ad, ev);
        }
      } else {
        say("a request that is not a WebSocket");
        c->failed = 1;
      }
      ghttp_response_destroy(resp);
      return;
    }
  } else if (ev->type == GHTTP_H2_EVENT_SETTINGS && !c->opened) {
    if (!ghttp_h2_conn_can_send_extended_connect(c->h2)) {
      return;
    }
    c->opened = 1;
    GHTTP_WsClientOptions o;
    ghttp_ws_client_options_default(&o);
    o.host = "server.example.com";
    o.target = "/chat";
    static const char * const protos[] = {"chat"};
    o.subprotocols = protos;
    o.subprotocol_count = 1;
    o.enable_deflate = deflate_on;
    ghttp_request_create(NULL, &c->req);
    if (raw) {
      ghttp_request_set_method(c->req, "CONNECT");
      ghttp_request_set_target(c->req, "/chat");
      ghttp_request_set_protocol(c->req, "websocket");
      ghttp_headers_add(ghttp_request_headers(c->req), "host", "server.example.com");
    } else if (ghttp_ws_client_handshake_create_h2(NULL, &o, c->req, &c->hs) != GHTTP_OK) {
      c->failed = 1;
      return;
    }
    if (ghttp_h2_conn_send_request(c->h2, c->req, "https", 0, &c->stream) != GHTTP_OK) {
      c->failed = 1;
    }
    return;
  } else if (ev->type == GHTTP_H2_EVENT_HEADERS && ev->stream_id == c->stream && !ev->interim
      && !c->ad && !c->remote_ended) {
    const GHTTP_Response * rs = ghttp_h2_conn_response(c->h2);
    if (raw) {
      if (ghttp_response_status(rs) != 200 || !ev->tunnel) {
        say("the tunnel was refused");
        c->failed = 1;
        return;
      }
      c->opened = 2;
      // write the octets: done by the main loop through raw_client_send
      return;
    }
    GHTTP_WsClientResult cr;
    if (ghttp_ws_client_handshake_finish_h2(c->hs, rs, &cr) != GHTTP_OK || !cr.accepted || !ev->tunnel) {
      say(cr.reason);
      c->failed = 1;
      return;
    }
    if (!attach(c, &cr.negotiated, GHTTP_WS_CLIENT)) {
      c->failed = 1;
      return;
    }
    ghttp_ws_h2_input(c->ad, ev);
    send_next(c);
    return;
  }
  if (c->ad) {
    ghttp_ws_h2_input(c->ad, ev);
    return;
  }
  // raw mode
  if (ev->stream_id != c->stream && ev->type != GHTTP_H2_EVENT_WINDOW_UPDATE) {
    return;
  }
  switch (ev->type) {
    case GHTTP_H2_EVENT_DATA:
      if (c->role == GHTTP_H2_SERVER) {
        bytes_add(&c->echo, ev->data, ev->data_len);
        if (ev->end_stream) {
          c->echo_end = 1;
        }
      } else {
        bytes_add(&c->rawgot, ev->data, ev->data_len);
      }
      if (ev->end_stream) {
        c->remote_ended = 1;
      }
      break;
    case GHTTP_H2_EVENT_HEADERS:
      if (ev->end_stream) {
        c->remote_ended = 1;
        if (c->role == GHTTP_H2_SERVER) {
          c->echo_end = 1;
        }
      }
      break;
    case GHTTP_H2_EVENT_STREAM_RESET:
    case GHTTP_H2_EVENT_STREAM_ERROR:
      say("the stream was reset");
      c->failed = 1;
      break;
    default:
      break;
  }
}

/** Raw client: write the octets as the windows allow, then end the stream. */
static void raw_client_send(Conn * c, Bytes * out) {
  if (c->opened != 2 || c->local_ended) {
    return;
  }
  while (out->n > 0) {
    size_t acc = 0;
    if (ghttp_h2_conn_send_data(c->h2, c->stream, out->p, out->n, 0, &acc) != GHTTP_OK) {
      c->failed = 1;
      return;
    }
    if (acc == 0) {
      return;
    }
    bytes_drop(out, acc);
  }
  size_t acc = 0;
  if (ghttp_h2_conn_send_data(c->h2, c->stream, NULL, 0, 1, &acc) == GHTTP_OK) {
    c->local_ended = 1;
  } else {
    c->failed = 1;
  }
}

/** Raw client: see raw_client_send(). */
static Bytes rawout_global;

/** Feed one read to a connection and act on its events. 0, or 1 if the peer broke HTTP/2. */
static int process_input(Conn * c, const unsigned char * buf, size_t got) {
  size_t off = 0;
  GHTTP_H2Event ev;
  do {
    size_t used = 0;
    GHTTP_Result r = ghttp_h2_conn_feed(c->h2, buf + off, got - off, &used, &ev);
    if (r != GHTTP_OK) {
      flush_out(c);
      uint32_t code = 0;
      const char * why = "";
      ghttp_h2_conn_error(c->h2, &code, &why);
      fprintf(stderr, "ws_h2_probe: the peer broke HTTP/2: %s (%s)\n", ghttp_h2_error_string(code), why);
      return 1;
    }
    off += used;
    if (ev.type != GHTTP_H2_EVENT_NEED_MORE) {
      on_event(c, &ev);
      ws_events(c);
      if (raw) {
        if (c->role == GHTTP_H2_SERVER) raw_pump(c); else raw_client_send(c, &rawout_global);
      }
    }
  } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
  if (raw) {
    if (c->role == GHTTP_H2_SERVER) raw_pump(c); else raw_client_send(c, &rawout_global);
  }
  ws_events(c);
  flush_out(c);
  return 0;
}

static void conn_limits(GHTTP_H2Limits * l, GHTTP_H2Role role) {
  ghttp_h2_limits_default(l);
  l->enable_connect_protocol = role == GHTTP_H2_SERVER;
  l->initial_window_size = 1 << 20;
  l->connection_window = 1 << 22;
  l->max_buffered_bytes = 1 << 23;
}

static void conn_free(Conn * c) {
  ghttp_ws_h2_destroy(c->ad);
  ghttp_ws_conn_destroy(c->ws);
  ghttp_ws_client_handshake_destroy(c->hs);
  ghttp_request_destroy(c->req);
  ghttp_h2_conn_destroy(c->h2);
  free(c->sizes);
  free(c->want);
  free(c->echo.p);
  free(c->rawgot.p);
}

/** One line of the loop mode: `[--deflate] SIZE...`. */
static int loop_line(char * line) {
  Conn cl, sv;
  memset(&cl, 0, sizeof cl);
  memset(&sv, 0, sizeof sv);
  cl.role = GHTTP_H2_CLIENT;
  sv.role = GHTTP_H2_SERVER;
  raw = 0;
  deflate_on = 0;
  for (char * tok = strtok(line, " \t\r\n"); tok; tok = strtok(NULL, " \t\r\n")) {
    if (strcmp(tok, "--deflate") == 0) {
      deflate_on = 1;
    } else {
      cl.sizes = realloc(cl.sizes, (cl.nsizes + 1) * sizeof *cl.sizes);
      cl.sizes[cl.nsizes++] = (size_t)strtoull(tok, NULL, 10);
    }
  }
  GHTTP_H2Limits l;
  conn_limits(&l, GHTTP_H2_CLIENT);
  Bytes to_server = {0}, to_client = {0};
  cl.sink = &to_server;
  sv.sink = &to_client;
  cl.digest = sv.digest = 1469598103934665603ull;
  int bad = ghttp_h2_conn_create(NULL, GHTTP_H2_CLIENT, &l, &cl.h2) != GHTTP_OK;
  conn_limits(&l, GHTTP_H2_SERVER);
  bad = bad || ghttp_h2_conn_create(NULL, GHTTP_H2_SERVER, &l, &sv.h2) != GHTTP_OK;
  if (!bad) {
    flush_out(&cl);
    flush_out(&sv);
    for (int round = 0; round < 100000 && !bad; round++) {
      if (to_server.n == 0 && to_client.n == 0) {
        break;
      }
      if (to_server.n) {
        Bytes in = to_server;
        memset(&to_server, 0, sizeof to_server);
        bad = process_input(&sv, in.p, in.n) || sv.failed;
        free(in.p);
      }
      if (to_client.n && !bad) {
        Bytes in = to_client;
        memset(&to_client, 0, sizeof to_client);
        bad = process_input(&cl, in.p, in.n) || cl.failed;
        free(in.p);
      }
    }
  }
  int ok = !bad && cl.ad && sv.ad;
  if (ok) {
    GHTTP_WsH2Status a, b;
    ghttp_ws_h2_status(cl.ad, &a);
    ghttp_ws_h2_status(sv.ad, &b);
    ok = a.state == GHTTP_WS_H2_CLOSED && b.state == GHTTP_WS_H2_CLOSED && cl.sent == cl.nsizes;
  }
  printf("%s c2s=%zu:%016llx s2c=%zu:%016llx\n", ok ? "ok" : "FAILED", cl.sent_octets,
      (unsigned long long)cl.digest, sv.sent_octets, (unsigned long long)sv.digest);
  free(to_server.p);
  free(to_client.p);
  conn_free(&cl);
  conn_free(&sv);
  return ok ? 0 : 1;
}

int main(int argc, char ** argv) {
  if (argc == 1) {
    char * line = NULL;
    size_t cap = 0;
    int rc = 0;
    ssize_t got;
    while ((got = getline(&line, &cap, stdin)) >= 0) {
      rc |= loop_line(line);
    }
    free(line);
    return rc;
  }
  Conn c;
  memset(&c, 0, sizeof c);
  c.role = strcmp(argv[1], "server") == 0 ? GHTTP_H2_SERVER : GHTTP_H2_CLIENT;
  size_t total = 0;
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--raw") == 0) {
      raw = 1;
    } else if (strcmp(argv[i], "--deflate") == 0) {
      deflate_on = 1;
    } else {
      c.sizes = realloc(c.sizes, (c.nsizes + 1) * sizeof *c.sizes);
      c.sizes[c.nsizes++] = (size_t)strtoull(argv[i], NULL, 10);
      total += c.sizes[c.nsizes - 1];
    }
  }
  GHTTP_H2Limits l;
  conn_limits(&l, c.role);
  if (ghttp_h2_conn_create(NULL, c.role, &l, &c.h2) != GHTTP_OK) {
    return die("cannot create the connection");
  }
  Bytes * rawout = &rawout_global;
  if (raw && c.role == GHTTP_H2_CLIENT) {
    c.rawwant = total;
    for (size_t i = 0; i < total; i++) {
      unsigned char b = pat(i, 99);
      bytes_add(rawout, &b, 1);
    }
  }
  flush_out(&c);
  unsigned char buf[65536];
  for (;;) {
    ssize_t got;
    if (inq.n > 0) {
      // Read while output was waiting.
      got = (ssize_t)(inq.n < sizeof buf ? inq.n : sizeof buf);
      memcpy(buf, inq.p, (size_t)got);
      bytes_drop(&inq, (size_t)got);
    } else if (in_eof) {
      break;
    } else {
      got = read(0, buf, sizeof buf);
    }
    if (got <= 0) {
      break;
    }
    if (process_input(&c, buf, (size_t)got)) {
      return 1;
    }
    if (c.failed) {
      return die("failed");
    }
    // Both directions of the stream have ended: nothing more can come, and the
    // peer may be waiting for this end of the connection to close.
    if (raw ? (c.remote_ended && c.local_ended) : 0) {
      break;
    }
    if (c.ad) {
      GHTTP_WsH2Status st;
      ghttp_ws_h2_status(c.ad, &st);
      if (st.remote_ended && st.local_ended) {
        break;
      }
    }
  }
  flush_out(&c);
  // The peer closed the connection: was everything done?
  int ok = !c.failed;
  if (raw) {
    if (c.role == GHTTP_H2_CLIENT) {
      ok = ok && c.remote_ended && c.local_ended && c.rawgot.n == c.rawwant;
      for (size_t i = 0; ok && i < c.rawgot.n; i++) {
        ok = c.rawgot.p[i] == pat(i, 99);
      }
    } else {
      ok = ok && c.remote_ended && c.local_ended;
    }
  } else if (c.ad) {
    GHTTP_WsH2Status st;
    ghttp_ws_h2_status(c.ad, &st);
    ok = ok && st.state == GHTTP_WS_H2_CLOSED;
    if (c.role == GHTTP_H2_CLIENT) {
      ok = ok && c.sent == c.nsizes && c.closed_sent;
    }
  } else {
    ok = 0;
  }
  if (!ok) {
    say("the connection ended before the stream's end was reached");
  }
  conn_free(&c);
  free(rawout->p);
  return ok ? 0 : 1;
}
