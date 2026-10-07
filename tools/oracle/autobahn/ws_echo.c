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
 * The WebSocket echo program the Autobahn|Testsuite drives (run.py).
 *
 *   ws_echo server [port]                  listen on 127.0.0.1; 0 or no port
 *                                          picks one. Prints "listening PORT".
 *   ws_echo client <host> <port> <agent>   the fuzzingserver protocol client:
 *                                          getCaseCount, every case, then
 *                                          updateReports.
 *
 * Everything about the protocol is this library's: the HTTP/1.1 parser and
 * writer for the opening handshake, ghttp_ws_server_handshake() or
 * ghttp_ws_client_handshake_create()/_finish(), and ghttp_ws_conn_* for the
 * frames. What is the program's own is the socket, which the library does not
 * have: poll(), recv() and send() around the codec's bytes-in, bytes-out.
 *
 * The echo is the one Autobahn expects: every text or binary message goes back
 * as the same type, a Ping is answered by the codec itself (the Pong is queued
 * when the Ping is reported), and a Close is answered by the codec. Nothing is
 * decided here that the codec could decide, so a case that fails is the
 * codec's.
 *
 * Limits. Autobahn's section 9 sends messages of up to 16 MiB (case 9.1.6 and
 * 9.2.6 are exactly 16 MiB), in frames as small as 64 octets, so a message of
 * 16 MiB is 262144 frames: the defaults (a 1024-frame cap) would refuse the
 * suite's own cases for a reason that is policy and not protocol. The limits
 * here are set above anything Autobahn sends, and the message size cap is
 * 32 MiB so that "exactly the largest" is not tested against "the cap".
 *
 * Exit status: 0 on success; 1 for a failure of the program's own work (a
 * socket, a handshake the peer refused, a case that could not be run); 2 for
 * usage. A connection a case ends with a protocol error is the case, not a
 * failure.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ghoti.io/http/http.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define IDLE_MS 60000  /* a case that goes silent this long is a hung case */
#define DRAIN_MS 3000  /* after our last byte, how long to read until EOF */
#define CLIENT_EOF_MS 5000

#define BREAK_ECHO_ENV "GHOTI_WS_ECHO_BREAK"

static void limits_for_autobahn(GHTTP_WsLimits * l) {
  ghttp_ws_limits_default(l);
  l->max_frame_payload = (uint64_t)32 << 20;
  l->max_message_bytes = (uint64_t)32 << 20;
  l->max_fragments = 1u << 20;
  /* the echo of one 16 MiB message, compressed or not, plus slack for the
   * replies queued behind it while the peer is slow to read */
  l->max_buffered_bytes = (size_t)96 << 20;
}

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---- socket helpers ---------------------------------------------------- */

static int send_all(int fd, const void * data, size_t len) {
  const uint8_t * p = data;
  while (len > 0) {
    ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN) {
        struct pollfd pf = {fd, POLLOUT, 0};
        poll(&pf, 1, IDLE_MS);
        continue;
      }
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

/* Wait for input for at most @p ms. 1 readable, 0 timeout, -1 error. */
static int wait_readable(int fd, int ms) {
  struct pollfd pf = {fd, POLLIN, 0};
  for (;;) {
    int r = poll(&pf, 1, ms);
    if (r < 0 && errno == EINTR) {
      continue;
    }
    return r < 0 ? -1 : (r == 0 ? 0 : 1);
  }
}

/*
 * After the last byte is out: say so (FIN), then read until the peer closes or
 * DRAIN_MS pass. Closing with unread input would reset the connection and the
 * peer could lose the Close frame that was just sent.
 */
static void linger_close(int fd, int ms) {
  uint8_t sink[4096];
  uint64_t end = now_ms() + (uint64_t)ms;
  shutdown(fd, SHUT_WR);
  for (;;) {
    uint64_t t = now_ms();
    if (t >= end) {
      break;
    }
    int r = wait_readable(fd, (int)(end - t));
    if (r <= 0) {
      break;
    }
    ssize_t n = recv(fd, sink, sizeof(sink), 0);
    if (n <= 0) {
      break;
    }
  }
  close(fd);
}

/* ---- the connection loop, the same at both ends ------------------------ */

typedef struct Capture {
  char * text;  /* the first text message, for getCaseCount */
  size_t len;
} Capture;

typedef struct Loop {
  GHTTP_WsConn * conn;
  int fd;
  int is_server;
  int broken;  /* the control for run.py: echo wrongly on purpose */
  Capture * capture;
  const char * why;  /* what ended it, for stderr */
} Loop;

static int flush_output(Loop * lp) {
  size_t n = 0;
  const uint8_t * out = ghttp_ws_conn_output(lp->conn, &n);
  if (n == 0) {
    return 0;
  }
  if (send_all(lp->fd, out, n) != 0) {
    return -1;
  }
  ghttp_ws_conn_output_consume(lp->conn, n);
  return 0;
}

/* One event from the codec. Returns -1 to stop the loop. */
static int on_event(Loop * lp, const GHTTP_WsEvent * ev) {
  switch (ev->type) {
    case GHTTP_WS_EVENT_TEXT:
    case GHTTP_WS_EVENT_BINARY: {
      if (lp->capture && ev->type == GHTTP_WS_EVENT_TEXT && !lp->capture->text) {
        lp->capture->text = malloc(ev->data_len + 1);
        if (lp->capture->text) {
          memcpy(lp->capture->text, ev->data, ev->data_len);
          lp->capture->text[ev->data_len] = 0;
          lp->capture->len = ev->data_len;
        }
      }
      if (lp->capture) {
        return 0;  /* getCaseCount: read it, do not echo it */
      }
      if (ghttp_ws_conn_state(lp->conn) != GHTTP_WS_STATE_OPEN) {
        return 0;
      }
      GHTTP_WsMessageType type = ev->type == GHTTP_WS_EVENT_TEXT
          ? GHTTP_WS_MESSAGE_TEXT : GHTTP_WS_MESSAGE_BINARY;
      if (lp->broken) {
        /* The control: a wrong echo, which run.py must see as a failure. */
        type = GHTTP_WS_MESSAGE_BINARY;
      }
      GHTTP_Result r = ghttp_ws_conn_send_message(lp->conn, type, ev->data, ev->data_len);
      if (r != GHTTP_OK) {
        fprintf(stderr, "ws_echo: send_message: %s\n", ghttp_result_string(r));
        lp->why = "send_message failed";
        ghttp_ws_conn_close(lp->conn, 1011, "echo failed", 11);
        return -1;
      }
      return 0;
    }
    case GHTTP_WS_EVENT_CLOSE:
    case GHTTP_WS_EVENT_PING:
    case GHTTP_WS_EVENT_PONG:
    case GHTTP_WS_EVENT_NEED_MORE:
    default:
      return 0;
  }
}

/*
 * Feed @p len octets, reporting every event. Returns 0 to go on, 1 when the
 * connection is over cleanly (both Closes), -1 on a connection error (whose
 * Close is queued) or a local failure.
 */
static int feed_all(Loop * lp, const uint8_t * data, size_t len) {
  size_t off = 0;
  for (;;) {
    size_t used = 0;
    GHTTP_WsEvent ev;
    GHTTP_Result r = ghttp_ws_conn_feed(lp->conn, data + off, len - off, &used, &ev);
    if (r != GHTTP_OK) {
      uint16_t code = 0;
      const char * reason = "";
      ghttp_ws_conn_error(lp->conn, &code, &reason);
      lp->why = "connection error";
      return -1;
    }
    off += used;
    if (ev.type == GHTTP_WS_EVENT_NEED_MORE) {
      break;
    }
    if (on_event(lp, &ev) != 0) {
      return -1;
    }
    /* The documented loop takes the output after every event: Autobahn 2.10
     * sends ten Pings in one read and wants ten Pongs, and the codec answers
     * only the latest of Pings whose Pong has not yet been taken. */
    if (flush_output(lp) != 0) {
      lp->why = "write failed";
      return -1;
    }
    if (ghttp_ws_conn_state(lp->conn) == GHTTP_WS_STATE_CLOSED) {
      /* Anything after both Closes is not read: the transport ends here. */
      return 1;
    }
  }
  return ghttp_ws_conn_state(lp->conn) == GHTTP_WS_STATE_CLOSED ? 1 : 0;
}

/*
 * Run the connection to its end. @p pre are octets that arrived behind the
 * handshake. Returns 0 if the connection ended by the closing handshake, a
 * connection error the codec answered with a Close, or the peer's EOF; 1 for
 * the program's own failure (a socket error, a hung case).
 */
static int run_loop(Loop * lp, const uint8_t * pre, size_t pre_len) {
  static uint8_t buf[256 * 1024];
  int rc = 0;
  int state = 0;  /* 0 go on, 1 closed cleanly, -1 failed */

  ghttp_ws_conn_tick(lp->conn, now_ms());
  if (pre_len > 0) {
    state = feed_all(lp, pre, pre_len);
  }
  uint64_t last_input = now_ms();
  while (state == 0) {
    size_t pending = ghttp_ws_conn_output_size(lp->conn);
    struct pollfd pf = {lp->fd, (short)(POLLIN | (pending ? POLLOUT : 0)), 0};
    int r = poll(&pf, 1, 1000);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      rc = 1;
      lp->why = "poll failed";
      break;
    }
    if (r == 0) {
      if (now_ms() - last_input > IDLE_MS) {
        rc = 1;
        lp->why = "idle timeout";
        break;
      }
      continue;
    }
    if (pf.revents & POLLOUT) {
      size_t n = 0;
      const uint8_t * out = ghttp_ws_conn_output(lp->conn, &n);
      ssize_t w = send(lp->fd, out, n, MSG_NOSIGNAL);
      if (w > 0) {
        ghttp_ws_conn_output_consume(lp->conn, (size_t)w);
      } else if (w < 0 && errno != EAGAIN && errno != EINTR) {
        rc = 1;
        lp->why = "send failed";
        break;
      }
    }
    if (pf.revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = recv(lp->fd, buf, sizeof(buf), 0);
      if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
        continue;
      }
      if (n <= 0) {
        /* The peer went without a closing handshake (1006), or reset. */
        lp->why = n == 0 ? "peer closed the transport" : "recv failed";
        /* ghttp_ws_conn_finish() says whether the handshake was complete. */
        if (ghttp_ws_conn_finish(lp->conn) != GHTTP_OK) {
          rc = 0;  /* a case may do this on purpose; the report decides */
        }
        close(lp->fd);
        lp->fd = -1;
        return rc;
      }
      last_input = now_ms();
      ghttp_ws_conn_tick(lp->conn, last_input);
      state = feed_all(lp, buf, (size_t)n);
    }
  }
  if (lp->fd >= 0) {
    /* Whatever is queued (the Close of an error, the reply to a Close) goes
     * out, then the transport ends: the server first, as RFC 6455 7.1.1 has it;
     * the client waits for the server to do it. */
    if (flush_output(lp) != 0) {
      close(lp->fd);
      lp->fd = -1;
      return rc;
    }
    linger_close(lp->fd, lp->is_server && state == 1 ? 0 : (lp->is_server ? DRAIN_MS : CLIENT_EOF_MS));
    lp->fd = -1;
  }
  return rc;
}

/* ---- server ------------------------------------------------------------ */

/*
 * Read the request head with the parser. Returns 0 with @p *request set to the
 * parser's request and @p *rest, @p *rest_len the octets behind the head.
 */
static int read_head_request(int fd, GHTTP_Parser * parser, uint8_t * buf,
    size_t cap, size_t * rest_off, size_t * rest_len) {
  size_t have = 0;
  for (;;) {
    if (wait_readable(fd, 10000) <= 0) {
      return -1;
    }
    ssize_t n = recv(fd, buf + have, cap - have, 0);
    if (n <= 0) {
      return -1;
    }
    size_t base = have;
    have += (size_t)n;
    size_t off = base;
    GHTTP_Event ev;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_parser_feed(parser, buf + off, have - off, &used, &ev);
      if (r != GHTTP_OK) {
        return -1;
      }
      off += used;
      if (ev == GHTTP_EVENT_HEAD) {
        *rest_off = off;
        *rest_len = have - off;
        return 0;
      }
    } while (ev != GHTTP_EVENT_NEED_MORE);
    if (have == cap) {
      return -1;
    }
  }
}

static void serve_one(int fd, int broken) {
  GHTTP_Parser * parser = NULL;
  GHTTP_Response * response = NULL;
  GHTTP_Buffer * out = NULL;
  GHTTP_WsConn * conn = NULL;
  static uint8_t head[64 * 1024];
  size_t rest_off = 0, rest_len = 0;
  GHTTP_WsLimits limits;
  limits_for_autobahn(&limits);

  if (ghttp_parser_create(GHTTP_PARSE_REQUEST, NULL, NULL, &parser) != GHTTP_OK
      || ghttp_response_create(NULL, &response) != GHTTP_OK
      || ghttp_buffer_create(NULL, &out) != GHTTP_OK) {
    goto done;
  }
  if (read_head_request(fd, parser, head, sizeof(head), &rest_off, &rest_len) != 0) {
    goto done;
  }
  GHTTP_WsServerOptions so;
  ghttp_ws_server_options_default(&so);
  so.enable_deflate = 1;
  so.limits = &limits;
  GHTTP_WsServerResult sr;
  if (ghttp_ws_server_handshake(ghttp_parser_request(parser), &so, response, &sr) != GHTTP_OK
      || ghttp_write_response_head(out, response) != GHTTP_OK) {
    goto done;
  }
  if (send_all(fd, ghttp_buffer_data(out), ghttp_buffer_size(out)) != 0) {
    goto done;
  }
  if (!sr.accepted) {
    fprintf(stderr, "ws_echo: handshake refused: %s\n", sr.reason);
    linger_close(fd, 1000);
    fd = -1;
    goto done;
  }
  if (ghttp_ws_conn_create(NULL, GHTTP_WS_SERVER, &limits, &sr.negotiated, &conn) != GHTTP_OK) {
    goto done;
  }
  Loop lp = {conn, fd, 1, broken, NULL, ""};
  run_loop(&lp, head + rest_off, rest_len);
  fd = lp.fd;
done:
  if (fd >= 0) {
    close(fd);
  }
  ghttp_ws_conn_destroy(conn);
  ghttp_buffer_destroy(out);
  ghttp_response_destroy(response);
  ghttp_parser_destroy(parser);
}

static int do_server(const char * port_text) {
  int port = port_text ? atoi(port_text) : 0;
  int broken = getenv(BREAK_ECHO_ENV) != NULL;
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) {
    perror("socket");
    return 1;
  }
  int one = 1;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons((uint16_t)port);
  socklen_t alen = sizeof(a);
  if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 64) != 0
      || getsockname(ls, (struct sockaddr *)&a, &alen) != 0) {
    perror("bind/listen");
    return 1;
  }
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  printf("listening %d\n", ntohs(a.sin_port));
  fflush(stdout);
  pid_t parent = getpid();
  for (;;) {
    int fd = accept(ls, NULL, NULL);
    if (fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("accept");
      return 1;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    pid_t pid = fork();
    if (pid < 0) {
      close(fd);
      continue;
    }
    if (pid == 0) {
      /* A connection must not outlive the server that was told to stop. */
      prctl(PR_SET_PDEATHSIG, SIGTERM);
      if (getppid() != parent) {
        _exit(0);
      }
      close(ls);
      serve_one(fd, broken);
      fflush(NULL);
      _exit(0);
    }
    close(fd);
  }
}

/* ---- client ------------------------------------------------------------ */

static int connect_to(const char * host, const char * port) {
  struct addrinfo hints, * res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &res) != 0) {
    return -1;
  }
  int fd = -1;
  for (struct addrinfo * p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd >= 0) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  }
  return fd;
}

/* Read the response head; the same shape as the server's, with the response parser. */
static int read_head_response(int fd, GHTTP_Parser * parser, uint8_t * buf,
    size_t cap, size_t * rest_off, size_t * rest_len) {
  /* The request parser's loop does not care which kind it is. */
  return read_head_request(fd, parser, buf, cap, rest_off, rest_len);
}

/*
 * One WebSocket client session. @p capture non-NULL: the first text message is
 * kept and not echoed. Returns 0, or 1 if the handshake or the socket failed.
 */
static int client_session(const char * host, const char * port, const char * target,
    Capture * capture, int patient) {
  GHTTP_Request * request = NULL;
  GHTTP_Buffer * out = NULL;
  GHTTP_Parser * parser = NULL;
  GHTTP_WsClientHandshake * hs = NULL;
  GHTTP_WsConn * conn = NULL;
  static uint8_t head[64 * 1024];
  size_t rest_off = 0, rest_len = 0;
  int rc = 1;
  int fd = -1;
  char hostport[300];
  GHTTP_WsLimits limits;
  limits_for_autobahn(&limits);

  snprintf(hostport, sizeof(hostport), "%s:%s", host, port);
  fd = connect_to(host, port);
  /* The fuzzingserver prints that it will run its cases a moment before it
   * listens; the first connection of a run waits for it, up to 10 seconds. */
  for (int tries = 0; fd < 0 && patient && tries < 100; tries++) {
    poll(NULL, 0, 100);
    fd = connect_to(host, port);
  }
  if (fd < 0) {
    fprintf(stderr, "ws_echo: cannot connect to %s\n", hostport);
    return 1;
  }
  GHTTP_WsClientOptions co;
  ghttp_ws_client_options_default(&co);
  co.host = hostport;
  co.target = target;
  co.enable_deflate = 1;
  ghttp_ws_deflate_params_default(&co.deflate);
  co.deflate.offer_client_max_window_bits = 1;
  co.limits = &limits;

  if (ghttp_request_create(NULL, &request) != GHTTP_OK
      || ghttp_buffer_create(NULL, &out) != GHTTP_OK
      || ghttp_parser_create(GHTTP_PARSE_RESPONSE, NULL, NULL, &parser) != GHTTP_OK
      || ghttp_ws_client_handshake_create(NULL, &co, request, &hs) != GHTTP_OK
      || ghttp_write_request_head(out, request) != GHTTP_OK) {
    fprintf(stderr, "ws_echo: cannot build the request for %s\n", target);
    goto done;
  }
  if (send_all(fd, ghttp_buffer_data(out), ghttp_buffer_size(out)) != 0) {
    goto done;
  }
  if (read_head_response(fd, parser, head, sizeof(head), &rest_off, &rest_len) != 0) {
    fprintf(stderr, "ws_echo: no response head for %s\n", target);
    goto done;
  }
  GHTTP_WsClientResult cr;
  if (ghttp_ws_client_handshake_finish(hs, ghttp_parser_response(parser), &cr) != GHTTP_OK
      || !cr.accepted) {
    fprintf(stderr, "ws_echo: handshake for %s refused: %s\n", target, cr.reason);
    goto done;
  }
  if (ghttp_ws_conn_create(NULL, GHTTP_WS_CLIENT, &limits, &cr.negotiated, &conn) != GHTTP_OK) {
    goto done;
  }
  Loop lp = {conn, fd, 0, 0, capture, ""};
  run_loop(&lp, head + rest_off, rest_len);
  fd = lp.fd;
  rc = 0;
done:
  if (fd >= 0) {
    close(fd);
  }
  ghttp_ws_conn_destroy(conn);
  ghttp_ws_client_handshake_destroy(hs);
  ghttp_parser_destroy(parser);
  ghttp_buffer_destroy(out);
  ghttp_request_destroy(request);
  return rc;
}

static int do_client(const char * host, const char * port, const char * agent) {
  signal(SIGPIPE, SIG_IGN);
  Capture cap = {NULL, 0};
  if (client_session(host, port, "/getCaseCount", &cap, 1) != 0 || !cap.text) {
    fprintf(stderr, "ws_echo: getCaseCount failed\n");
    free(cap.text);
    return 1;
  }
  char * end = NULL;
  long count = strtol(cap.text, &end, 10);
  if (end == cap.text || count <= 0 || count > 100000) {
    fprintf(stderr, "ws_echo: getCaseCount answered %s\n", cap.text);
    free(cap.text);
    return 1;
  }
  free(cap.text);
  printf("cases %ld\n", count);
  fflush(stdout);
  int failed = 0;
  for (long i = 1; i <= count; i++) {
    char target[400];
    snprintf(target, sizeof(target), "/runCase?case=%ld&agent=%s", i, agent);
    if (client_session(host, port, target, NULL, 0) != 0) {
      fprintf(stderr, "ws_echo: case %ld could not be run\n", i);
      failed++;
    }
  }
  char target[400];
  snprintf(target, sizeof(target), "/updateReports?agent=%s", agent);
  if (client_session(host, port, target, NULL, 0) != 0) {
    fprintf(stderr, "ws_echo: updateReports failed\n");
    failed++;
  }
  printf("done %ld cases, %d failed\n", count, failed);
  fflush(stdout);
  return failed ? 1 : 0;
}

int main(int argc, char ** argv) {
  if (argc >= 2 && strcmp(argv[1], "server") == 0 && argc <= 3) {
    return do_server(argc == 3 ? argv[2] : NULL);
  }
  if (argc == 5 && strcmp(argv[1], "client") == 0) {
    return do_client(argv[2], argv[3], argv[4]);
  }
  fprintf(stderr, "usage: ws_echo server [port]\n       ws_echo client <host> <port> <agent>\n");
  return 2;
}
