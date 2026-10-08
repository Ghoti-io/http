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
 * libFuzzer harness for WebSocket over HTTP/2 (RFC 8441): a client and a
 * server h2 connection wired in memory, an Extended CONNECT handshake between
 * them, and a program of sends taken from the input, with the requirement that
 * what is sent is what arrives, in order, whatever the windows hold back and
 * wherever the wire is cut; and that a Close ends both sides cleanly, the
 * streams gone.
 *
 * Byte 0: bit 0 permessage-deflate, bit 1 a small initial window (so the
 * adapter's pump holds data back), bit 2 end the stream abruptly at the end
 * instead of closing (both sides must then report 1006), bit 3 the hostile
 * mode (below). Byte 1 seeds how the
 * wire is cut. Then operations, a control byte and what it needs:
 *   0x0n  text of the next bytes made valid UTF-8, n of 16 sizes
 *   0x1n  binary
 *   0x3n  a ping with up to n octets
 *   0x4n  a Close and finish
 * from the client or the server by the control byte's top bit.
 *
 * Hostile mode: the operations are instead (by the control byte's bits 4 to 6)
 * 0 raw octets as tunnel DATA from the client, 1 the same from the server, 2 or 3
 * END_STREAM from the client or the server, 4 or 5 RST_STREAM from them, 6 a valid
 * message from the client, 7 a Close from the server. The bytes are not WebSocket
 * frames, resets and half-closes come anywhere, and a connection error of the h2
 * connection is told to the adapter. What is checked is that nothing crashes and
 * that the adapters' answers stay coherent: every call returns what its
 * documentation allows, a closed WebSocket stays closed, an abnormal one has a
 * close code, a reset or a failed connection is never reported as open.
 *
 * Build with: make fuzz-ws-h2
 * Run:        make fuzz-run-ws-h2 FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <deque>

#include "fuzz_ws_common.h"

namespace {

std::string utf8_of(const std::string & raw) {
  std::string s;
  for (unsigned char c : raw) {
    uint32_t cp = c;
    if (c >= 0xe0) {
      cp = 0x800 + ((c - 0xe0) << 8) + c;
    } else if (c >= 0x80) {
      cp = 0x80 + c;
    }
    if (cp < 0x80) {
      s.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      s.push_back(static_cast<char>(0xc0 | (cp >> 6)));
      s.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
      s.push_back(static_cast<char>(0xe0 | (cp >> 12)));
      s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      s.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
  }
  return s;
}

bool g_hostile = false;

struct End {
  bool dead = false;  // hostile mode: its h2 connection failed
  GHTTP_H2Role role = GHTTP_H2_CLIENT;
  GHTTP_H2Conn * h2 = nullptr;
  GHTTP_WsConn * ws = nullptr;
  GHTTP_WsH2 * ad = nullptr;
  uint32_t stream = 0;
  GHTTP_Request * req = nullptr;
  GHTTP_WsClientHandshake * hs = nullptr;
  std::deque<std::string> expect;
  bool deflate = false;
  uint32_t rng = 1;

  void attach(const GHTTP_WsNegotiated * n, GHTTP_WsRole r) {
    REQUIRE(ghttp_ws_conn_create(nullptr, r, nullptr, n, &ws) == GHTTP_OK, "ws create");
    REQUIRE(ghttp_ws_h2_create(nullptr, h2, stream, ws, &ad) == GHTTP_OK, "adapter create");
    if (r == GHTTP_WS_CLIENT) {
      ghttp_ws_conn_set_random(ws, fuzz::ws_fixed_random, &rng);
    }
  }
  void drain_ws() {
    if (!ad) {
      return;
    }
    for (;;) {
      GHTTP_WsEvent e;
      GHTTP_Result r = ghttp_ws_h2_next(ad, &e);
      if (g_hostile && (r == GHTTP_ERR_CORRUPT || r == GHTTP_ERR_LIMIT)) {
        REQUIRE(e.type == GHTTP_WS_EVENT_NEED_MORE && e.data == nullptr, "an event after a failure");
        break;
      }
      REQUIRE(r == GHTTP_OK, "a peer's own output was refused");
      if (e.type == GHTTP_WS_EVENT_NEED_MORE) {
        break;
      }
      if (!g_hostile && (e.type == GHTTP_WS_EVENT_TEXT || e.type == GHTTP_WS_EVENT_BINARY)) {
        REQUIRE(!expect.empty(), "a message arrived that was not sent");
        std::string got(e.type == GHTTP_WS_EVENT_TEXT ? "T" : "B");
        got.append(reinterpret_cast<const char *>(e.data), e.data_len);
        REQUIRE(got == expect.front(), "a message arrived different from what was sent");
        expect.pop_front();
      }
    }
    REQUIRE(ghttp_ws_h2_pump(ad) == GHTTP_OK, "pump");
  }
  void on_event(const GHTTP_H2Event & ev, bool deflate_on) {
    if (ev.type == GHTTP_H2_EVENT_HEADERS && role == GHTTP_H2_SERVER && !ad) {
      GHTTP_Response * resp = nullptr;
      REQUIRE(ghttp_response_create(nullptr, &resp) == GHTTP_OK, "response");
      GHTTP_WsServerOptions o;
      ghttp_ws_server_options_default(&o);
      o.enable_deflate = deflate_on;
      GHTTP_WsServerResult sr;
      REQUIRE(ghttp_ws_server_handshake_h2(ghttp_h2_conn_request(h2), &o, resp, &sr) == GHTTP_OK, "handshake");
      REQUIRE(sr.accepted && sr.status == 200, "the handshake was refused");
      stream = ev.stream_id;
      REQUIRE(ghttp_h2_conn_send_response(h2, stream, resp, 0) == GHTTP_OK, "send response");
      ghttp_response_destroy(resp);
      attach(&sr.negotiated, GHTTP_WS_SERVER);
      REQUIRE(ghttp_ws_h2_input(ad, &ev) == GHTTP_OK, "input");
    } else if (ev.type == GHTTP_H2_EVENT_HEADERS && role == GHTTP_H2_CLIENT && !ad && !ev.interim) {
      GHTTP_WsClientResult cr;
      REQUIRE(ghttp_ws_client_handshake_finish_h2(hs, ghttp_h2_conn_response(h2), &cr) == GHTTP_OK, "finish");
      REQUIRE(cr.accepted && ev.tunnel, "the response was refused");
      attach(&cr.negotiated, GHTTP_WS_CLIENT);
      REQUIRE(ghttp_ws_h2_input(ad, &ev) == GHTTP_OK, "input");
    } else if (ad) {
      REQUIRE(ghttp_ws_h2_input(ad, &ev) == GHTTP_OK, "input");
    }
  }
  void feed(const std::string & bytes, bool deflate_on) {
    if (dead) {
      return;
    }
    size_t off = 0;
    GHTTP_H2Event ev;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_h2_conn_feed(h2, bytes.data() + off, bytes.size() - off, &used, &ev);
      if (r != GHTTP_OK && g_hostile) {
        // The hostile bytes broke HTTP/2: the connection is gone, and the
        // caller tells the adapter, as the documentation says to.
        dead = true;
        if (ad) {
          REQUIRE(ghttp_ws_h2_connection_failed(ad, r) == GHTTP_OK, "connection_failed");
        }
        return;
      }
      REQUIRE(r == GHTTP_OK, "a peer's own h2 output was refused");
      off += used;
      if (ev.type != GHTTP_H2_EVENT_NEED_MORE) {
        on_event(ev, deflate_on);
        drain_ws();
      }
    } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
  }
  std::string take() {
    size_t n = 0;
    const uint8_t * p = ghttp_h2_conn_output(h2, &n);
    std::string s(reinterpret_cast<const char *>(p), n);
    ghttp_h2_conn_output_consume(h2, n);
    return s;
  }
  ~End() {
    ghttp_ws_h2_destroy(ad);
    ghttp_ws_conn_destroy(ws);
    ghttp_ws_client_handshake_destroy(hs);
    ghttp_request_destroy(req);
    ghttp_h2_conn_destroy(h2);
  }
};

void run(End & c, End & s, uint8_t seed, bool deflate_on) {
  for (int round = 0; round < 400; round++) {
    c.drain_ws();
    s.drain_ws();
    std::string x = c.take();
    std::string y = s.take();
    if (x.empty() && y.empty()) {
      return;
    }
    for (auto & piece : fuzz::random_pieces(x, static_cast<uint8_t>(seed + round))) {
      if (!piece.empty()) s.feed(piece, deflate_on);
    }
    for (auto & piece : fuzz::random_pieces(y, static_cast<uint8_t>(seed + round + 1))) {
      if (!piece.empty()) c.feed(piece, deflate_on);
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  g_hostile = (data[0] & 8) != 0;
  bool deflate_on = data[0] & 1;
  bool small_window = data[0] & 2;
  bool abrupt = data[0] & 4;
  uint8_t seed = data[1];
  GHTTP_H2Limits cl, sl;
  ghttp_h2_limits_default(&cl);
  ghttp_h2_limits_default(&sl);
  sl.enable_connect_protocol = 1;
  cl.max_buffered_bytes = sl.max_buffered_bytes = 1 << 22;
  cl.max_body_bytes = sl.max_body_bytes = 1 << 24;
  if (small_window) {
    cl.initial_window_size = sl.initial_window_size = 100;
  }
  End c, s;
  c.role = GHTTP_H2_CLIENT;
  s.role = GHTTP_H2_SERVER;
  REQUIRE(ghttp_h2_conn_create(nullptr, GHTTP_H2_CLIENT, &cl, &c.h2) == GHTTP_OK, "create");
  REQUIRE(ghttp_h2_conn_create(nullptr, GHTTP_H2_SERVER, &sl, &s.h2) == GHTTP_OK, "create");
  run(c, s, seed, deflate_on);
  REQUIRE(ghttp_h2_conn_can_send_extended_connect(c.h2), "the server's SETTINGS did not enable it");
  GHTTP_WsClientOptions co;
  ghttp_ws_client_options_default(&co);
  co.host = "h";
  co.enable_deflate = deflate_on;
  REQUIRE(ghttp_request_create(nullptr, &c.req) == GHTTP_OK, "request");
  REQUIRE(ghttp_ws_client_handshake_create_h2(nullptr, &co, c.req, &c.hs) == GHTTP_OK, "client handshake");
  REQUIRE(ghttp_h2_conn_send_request(c.h2, c.req, "https", 0, &c.stream) == GHTTP_OK, "send request");
  run(c, s, seed, deflate_on);
  REQUIRE(c.ad && s.ad, "the tunnel did not open");

  size_t pos = 2;
  bool closed = false;
  if (g_hostile) {
    for (int ops = 0; pos < size && ops < 60; ops++) {
      uint8_t op = data[pos++];
      unsigned kind = (op >> 4) & 7;
      size_t len = std::min<size_t>(op & 15, size - pos) * 9;
      len = std::min(len, size - pos);
      std::string raw(reinterpret_cast<const char *>(data + pos), len);
      pos += len;
      End & who = (kind & 1) ? s : c;
      size_t acc = 0;
      bool live = !who.dead && who.stream != 0 && ghttp_h2_conn_stream_is_active(who.h2, who.stream);
      switch (kind) {
        case 0: case 1:
          if (live && !raw.empty()) (void)ghttp_h2_conn_send_data(who.h2, who.stream, raw.data(), raw.size(), 0, &acc);
          break;
        case 2: case 3:
          if (live) (void)ghttp_h2_conn_send_data(who.h2, who.stream, nullptr, 0, 1, &acc);
          break;
        case 4: case 5:
          if (live) (void)ghttp_h2_conn_reset_stream(who.h2, who.stream, GHTTP_H2_CANCEL);
          break;
        case 6:
          if (!c.dead) (void)ghttp_ws_conn_send_message(c.ws, GHTTP_WS_MESSAGE_BINARY, raw.data(), raw.size());
          break;
        default:
          if (!s.dead) (void)ghttp_ws_conn_close(s.ws, 1000, "bye", 3);
          break;
      }
      for (End * e : {&c, &s}) {
        if (!e->dead) REQUIRE(ghttp_ws_h2_pump(e->ad) == GHTTP_OK, "pump");
      }
      run(c, s, seed, deflate_on);
      for (End * e : {&c, &s}) {
        GHTTP_WsH2Status st;
        REQUIRE(ghttp_ws_h2_status(e->ad, &st) == GHTTP_OK, "status");
        GHTTP_WsState ws = ghttp_ws_conn_state(e->ws);
        if (ws == GHTTP_WS_STATE_CLOSED) {
          REQUIRE(st.state == GHTTP_WS_H2_CLOSED, "a closed WebSocket is not reported closed");
        }
        if (st.state == GHTTP_WS_H2_CLOSED) {
          REQUIRE(ws == GHTTP_WS_STATE_CLOSED, "closed with no closing handshake");
        }
        if (st.state == GHTTP_WS_H2_ABNORMAL) {
          REQUIRE(st.code >= 1000 && st.code < 5000, "an abnormal end with no close code");
        }
        if (e->dead) {
          REQUIRE(st.connection_failed && st.state != GHTTP_WS_H2_OPEN, "a failed connection is open");
        }
        if ((st.reset || st.connection_failed) && ws != GHTTP_WS_STATE_CLOSED) {
          REQUIRE(st.state == GHTTP_WS_H2_ABNORMAL, "a reset or dead stream is not abnormal");
        }
      }
    }
    return 0;
  }
  for (int ops = 0; pos < size && ops < 40 && !closed; ops++) {
    uint8_t op = data[pos++];
    End & from = (op & 0x80) ? s : c;
    End & to = (op & 0x80) ? c : s;
    unsigned kind = (op >> 4) & 7;
    unsigned n = op & 15;
    size_t len = n < 8 ? n * 13 : (n - 7) * 1500;
    len = std::min(len, size - pos);
    std::string raw(reinterpret_cast<const char *>(data + pos), len);
    pos += len;
    switch (kind) {
      case 0: {
        std::string m = utf8_of(raw);
        REQUIRE(ghttp_ws_conn_send_message(from.ws, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()) == GHTTP_OK, "send text");
        to.expect.push_back("T" + m);
        break;
      }
      case 1:
        REQUIRE(ghttp_ws_conn_send_message(from.ws, GHTTP_WS_MESSAGE_BINARY, raw.data(), raw.size()) == GHTTP_OK, "send binary");
        to.expect.push_back("B" + raw);
        break;
      case 3:
        REQUIRE(ghttp_ws_conn_send_ping(from.ws, raw.data(), std::min<size_t>(raw.size(), 125)) == GHTTP_OK, "send ping");
        break;
      default:
        if (!abrupt) {
          REQUIRE(ghttp_ws_conn_close(from.ws, 1000, "bye", 3) == GHTTP_OK, "close");
        }
        closed = true;
        break;
    }
    REQUIRE(ghttp_ws_h2_pump(from.ad) == GHTTP_OK, "pump");
    run(c, s, seed, deflate_on);
  }
  GHTTP_WsH2Status cs, ss;
  if (closed && abrupt) {
    size_t acc = 0;
    REQUIRE(ghttp_h2_conn_send_data(c.h2, c.stream, nullptr, 0, 1, &acc) == GHTTP_OK, "end stream");
    run(c, s, seed, deflate_on);
    REQUIRE(ghttp_ws_h2_status(s.ad, &ss) == GHTTP_OK, "status");
    REQUIRE(ss.state == GHTTP_WS_H2_ABNORMAL && ss.code == 1006, "an abrupt end is not 1006");
    REQUIRE(!ghttp_h2_conn_stream_is_active(s.h2, s.stream), "the server left the stream half-open");
  } else if (closed) {
    run(c, s, seed, deflate_on);
    REQUIRE(ghttp_ws_h2_status(c.ad, &cs) == GHTTP_OK && ghttp_ws_h2_status(s.ad, &ss) == GHTTP_OK, "status");
    REQUIRE(cs.state == GHTTP_WS_H2_CLOSED && ss.state == GHTTP_WS_H2_CLOSED, "a close handshake did not complete");
    REQUIRE(!ghttp_h2_conn_stream_is_active(c.h2, c.stream) && !ghttp_h2_conn_stream_is_active(s.h2, s.stream),
        "a stream outlived the close handshake");
  }
  REQUIRE(c.expect.empty() && s.expect.empty(), "a message was sent and never arrived");
  return 0;
}
