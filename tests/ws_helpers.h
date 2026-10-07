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
 * What the WebSocket tests share: frames built by hand (so that they do not
 * borrow the library's own header writer), a connection wrapper that records
 * what it said, and two connections wired together in memory.
 */

#ifndef GHOTI_IO_GHTTP_TESTS_WS_HELPERS_H
#define GHOTI_IO_GHTTP_TESTS_WS_HELPERS_H

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"

namespace ghttptest {

inline const char * ws_type_name(GHTTP_WsEventType t) {
  switch (t) {
    case GHTTP_WS_EVENT_NEED_MORE: return "NEED_MORE";
    case GHTTP_WS_EVENT_TEXT: return "TEXT";
    case GHTTP_WS_EVENT_BINARY: return "BINARY";
    case GHTTP_WS_EVENT_PING: return "PING";
    case GHTTP_WS_EVENT_PONG: return "PONG";
    case GHTTP_WS_EVENT_CLOSE: return "CLOSE";
  }
  return "?";
}

/** One event as the tests compare it. */
struct WsEv {
  GHTTP_WsEventType type = GHTTP_WS_EVENT_NEED_MORE;
  std::string data;
  uint16_t code = 0;
  bool compressed = false;
  uint32_t fragments = 0;
  uint8_t rsv = 0;
  bool operator==(const WsEv &) const = default;
};

inline std::ostream & operator<<(std::ostream & os, const WsEv & e) {
  os << ws_type_name(e.type) << "(" << e.data.size() << " bytes";
  if (e.type == GHTTP_WS_EVENT_CLOSE) os << ", code " << e.code;
  if (e.data.size() <= 40) os << ", \"" << e.data << "\"";
  return os << ")";
}

inline std::string text_of(const WsEv & e) { return e.data; }

/** An event of a type, with its data. */
inline WsEv ev(GHTTP_WsEventType t, const std::string & data = "") {
  WsEv e;
  e.type = t;
  e.data = data;
  return e;
}

inline WsEv ev_text(const std::string & d, uint32_t fragments = 1, bool compressed = false) {
  WsEv e = ev(GHTTP_WS_EVENT_TEXT, d);
  e.fragments = fragments;
  e.compressed = compressed;
  return e;
}

inline WsEv ev_binary(const std::string & d, uint32_t fragments = 1, bool compressed = false) {
  WsEv e = ev(GHTTP_WS_EVENT_BINARY, d);
  e.fragments = fragments;
  e.compressed = compressed;
  return e;
}

inline WsEv ev_close(uint16_t code, const std::string & reason = "") {
  WsEv e = ev(GHTTP_WS_EVENT_CLOSE, reason);
  e.code = code;
  return e;
}

/**
 * A frame, written by hand from RFC 6455 section 5.2.
 *
 * @param form 0 picks the shortest length encoding; 7, 16 or 64 forces that
 *   one, for the non-minimal forms the codec must refuse.
 */
inline std::string wsf(int opcode, const std::string & payload = "",
    bool fin = true, bool masked = true, int rsv = 0,
    uint32_t key = 0x37fa213d, int form = 0) {
  std::string s;
  s.push_back(static_cast<char>((fin ? 0x80 : 0) | ((rsv & 7) << 4) | (opcode & 15)));
  size_t n = payload.size();
  int mask_bit = masked ? 0x80 : 0;
  if (form == 0) form = n < 126 ? 7 : (n <= 0xffff ? 16 : 64);
  if (form == 7) {
    s.push_back(static_cast<char>(mask_bit | n));
  } else if (form == 16) {
    s.push_back(static_cast<char>(mask_bit | 126));
    s.push_back(static_cast<char>(n >> 8));
    s.push_back(static_cast<char>(n));
  } else {
    s.push_back(static_cast<char>(mask_bit | 127));
    for (int i = 7; i >= 0; i--) s.push_back(static_cast<char>(static_cast<uint64_t>(n) >> (8 * i)));
  }
  std::string k;
  for (int i = 3; i >= 0; i--) k.push_back(static_cast<char>(key >> (8 * i)));
  if (masked) s += k;
  for (size_t i = 0; i < n; i++) {
    s.push_back(static_cast<char>(payload[i] ^ (masked ? k[i % 4] : 0)));
  }
  return s;
}

/** A frame whose header claims @p claimed bytes but carries none: for the limits, which act on the header. */
inline std::string wsf_header_only(int opcode, uint64_t claimed, bool fin = true,
    bool masked = true, int rsv = 0) {
  std::string s;
  s.push_back(static_cast<char>((fin ? 0x80 : 0) | ((rsv & 7) << 4) | (opcode & 15)));
  int mask_bit = masked ? 0x80 : 0;
  if (claimed < 126) {
    s.push_back(static_cast<char>(mask_bit | claimed));
  } else if (claimed <= 0xffff) {
    s.push_back(static_cast<char>(mask_bit | 126));
    s.push_back(static_cast<char>(claimed >> 8));
    s.push_back(static_cast<char>(claimed));
  } else {
    s.push_back(static_cast<char>(mask_bit | 127));
    for (int i = 7; i >= 0; i--) s.push_back(static_cast<char>(claimed >> (8 * i)));
  }
  if (masked) s += std::string("\x01\x02\x03\x04", 4);
  return s;
}

inline std::string text(const std::string & s, bool masked = true) { return wsf(1, s, true, masked); }
inline std::string binary(const std::string & s, bool masked = true) { return wsf(2, s, true, masked); }
inline std::string ping(const std::string & s = "", bool masked = true) { return wsf(9, s, true, masked); }
inline std::string pong(const std::string & s = "", bool masked = true) { return wsf(10, s, true, masked); }

/** A Close frame with a code and a reason; @p code 0 sends no body. */
inline std::string close_frame(uint16_t code = 0, const std::string & reason = "",
    bool masked = true) {
  std::string body;
  if (code != 0) {
    body.push_back(static_cast<char>(code >> 8));
    body.push_back(static_cast<char>(code));
    body += reason;
  }
  return wsf(8, body, true, masked);
}

/** The frames in a stream of bytes, as the peer would read them (no masking is assumed to be wrong). */
struct WsFrame {
  int opcode;
  bool fin;
  int rsv;
  bool masked;
  std::string payload;
};

inline std::vector<WsFrame> ws_parse_frames(const std::string & bytes) {
  std::vector<WsFrame> out;
  size_t i = 0;
  while (i + 2 <= bytes.size()) {
    uint8_t b0 = static_cast<uint8_t>(bytes[i]);
    uint8_t b1 = static_cast<uint8_t>(bytes[i + 1]);
    i += 2;
    uint64_t n = b1 & 0x7f;
    if (n == 126) {
      n = (static_cast<uint8_t>(bytes[i]) << 8) | static_cast<uint8_t>(bytes[i + 1]);
      i += 2;
    } else if (n == 127) {
      n = 0;
      for (int k = 0; k < 8; k++) n = (n << 8) | static_cast<uint8_t>(bytes[i + k]);
      i += 8;
    }
    bool masked = (b1 & 0x80) != 0;
    std::string key;
    if (masked) {
      key = bytes.substr(i, 4);
      i += 4;
    }
    EXPECT_LE(i + n, bytes.size()) << "a frame cut short";
    std::string p = bytes.substr(i, n);
    if (masked) {
      for (size_t k = 0; k < p.size(); k++) p[k] = static_cast<char>(p[k] ^ key[k % 4]);
    }
    i += n;
    out.push_back({b0 & 15, (b0 & 0x80) != 0, (b0 >> 4) & 7, masked, p});
  }
  EXPECT_EQ(i, bytes.size()) << "trailing octets that are not a frame";
  return out;
}

/** The close code in a Close frame's body, or -1 if it has none. */
inline int ws_close_code(const WsFrame & f) {
  if (f.opcode != 8 || f.payload.size() < 2) return -1;
  return (static_cast<uint8_t>(f.payload[0]) << 8) | static_cast<uint8_t>(f.payload[1]);
}

/** A masking source that counts, so that a test's bytes are the same every run. */
inline GHTTP_Result ws_counting_random(void * ctx, void * out, size_t n) {
  uint32_t * c = static_cast<uint32_t *>(ctx);
  uint8_t * p = static_cast<uint8_t *>(out);
  for (size_t i = 0; i < n; i++) {
    *c = *c * 1664525u + 1013904223u;
    p[i] = static_cast<uint8_t>(*c >> 24);
  }
  return GHTTP_OK;
}

inline GHTTP_WsNegotiated ws_deflate_negotiated(bool server_nct = false,
    bool client_nct = false, int server_bits = 0, int client_bits = 0) {
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  n.deflate = 1;
  n.deflate_params.server_no_context_takeover = server_nct;
  n.deflate_params.client_no_context_takeover = client_nct;
  n.deflate_params.server_max_window_bits = static_cast<uint8_t>(server_bits);
  n.deflate_params.client_max_window_bits = static_cast<uint8_t>(client_bits);
  return n;
}

/** What a feed of some bytes came to. */
struct WsRun {
  GHTTP_Result result = GHTTP_OK;
  std::vector<WsEv> events;
  std::string output;       // what the connection queued
  uint16_t code = 0;        // the connection error's close code
  std::string reason;
  bool operator==(const WsRun & o) const {
    return result == o.result && events == o.events && output == o.output && code == o.code;
  }
};

inline std::ostream & operator<<(std::ostream & os, const WsRun & r) {
  os << "result " << r.result << " code " << r.code << " events [";
  for (auto & e : r.events) os << " " << e;
  return os << " ] output " << r.output.size() << " bytes";
}

/** A connection with the helpers a test wants around it. */
class WsSide {
public:
  explicit WsSide(GHTTP_WsRole role, const GHTTP_WsLimits * limits = nullptr,
      const GHTTP_WsNegotiated * neg = nullptr, const GHTTP_Allocator * a = nullptr)
      : role_(role) {
    GHTTP_Result r = ghttp_ws_conn_create(a, role, limits, neg, &conn_);
    created_ = r;
    if (r == GHTTP_OK) ghttp_ws_conn_set_random(conn_, ws_counting_random, &rng_);
  }
  ~WsSide() { ghttp_ws_conn_destroy(conn_); }
  WsSide(const WsSide &) = delete;
  WsSide & operator=(const WsSide &) = delete;

  GHTTP_Result created() const { return created_; }
  GHTTP_WsConn * get() { return conn_; }
  GHTTP_WsRole role() const { return role_; }

  /**
   * Feed bytes in pieces of @p piece (0: all at once), running each piece to
   * NEED_MORE, and report events, output and the error.
   */
  WsRun feed(const std::string & bytes, size_t piece = 0) {
    WsRun run;
    size_t off = 0;
    size_t step = piece ? piece : (bytes.empty() ? 1 : bytes.size());
    do {
      size_t n = std::min(step, bytes.size() - off);
      size_t pos = 0;
      for (;;) {
        size_t used = 0;
        GHTTP_WsEvent e;
        GHTTP_Result r = ghttp_ws_conn_feed(conn_, bytes.data() + off + pos, n - pos, &used, &e);
        if (r != GHTTP_OK) {
          run.result = r;
          ghttp_ws_conn_error(conn_, &run.code, nullptr);
          take_output(run);
          return run;
        }
        pos += used;
        if (e.type == GHTTP_WS_EVENT_NEED_MORE) break;
        WsEv we;
        we.type = e.type;
        if (e.data_len) we.data.assign(reinterpret_cast<const char *>(e.data), e.data_len);
        we.code = e.code;
        we.compressed = e.compressed != 0;
        we.fragments = e.fragments;
        we.rsv = e.rsv;
        run.events.push_back(we);
        // The documented loop takes the output after every event, and a Pong
        // not yet taken is replaced by the next Ping's, so take it here.
        run.output += take_output();
      }
      off += n;
    } while (off < bytes.size());
    take_output(run);
    return run;
  }

  /** Every byte as its own call, and every two-way split: the same answer as the whole. */
  WsRun feed_bytes(const std::string & bytes) { return feed(bytes, 1); }

  /** What the connection has queued, taken. */
  std::string take_output() {
    size_t n = 0;
    const uint8_t * p = ghttp_ws_conn_output(conn_, &n);
    std::string s(reinterpret_cast<const char *>(p), n);
    ghttp_ws_conn_output_consume(conn_, n);
    return s;
  }

  std::vector<WsFrame> take_frames() { return ws_parse_frames(take_output()); }

private:
  void take_output(WsRun & run) { run.output += take_output(); }

  GHTTP_WsRole role_;
  GHTTP_WsConn * conn_ = nullptr;
  GHTTP_Result created_ = GHTTP_OK;
  uint32_t rng_ = 12345;
};

/** A client and a server wired together in memory. */
class WsPair {
public:
  explicit WsPair(const GHTTP_WsNegotiated * neg = nullptr,
      const GHTTP_WsLimits * limits = nullptr)
      : client(GHTTP_WS_CLIENT, limits, neg), server(GHTTP_WS_SERVER, limits, neg) {}

  /** Move bytes between them until neither has any, feeding in pieces of @p piece. */
  void pump(size_t piece = 0) {
    for (int round = 0; round < 100; round++) {
      to_server += client.take_output();
      to_client += server.take_output();
      if (to_server.empty() && to_client.empty()) return;
      if (!to_server.empty()) {
        std::string bytes;
        bytes.swap(to_server);
        WsRun r = server.feed(bytes, piece);
        append(server_events, r.events);
        to_client += r.output;
        if (r.result != GHTTP_OK) server_result = r.result;
      }
      if (!to_client.empty()) {
        std::string bytes;
        bytes.swap(to_client);
        WsRun r = client.feed(bytes, piece);
        append(client_events, r.events);
        to_server += r.output;
        if (r.result != GHTTP_OK) client_result = r.result;
      }
    }
    ADD_FAILURE() << "the two ends never went quiet";
  }

  WsSide client;
  WsSide server;
  std::vector<WsEv> client_events;
  std::vector<WsEv> server_events;
  GHTTP_Result client_result = GHTTP_OK;
  GHTTP_Result server_result = GHTTP_OK;
  std::string to_server;  // bytes in flight, so that a feed's own output is not lost
  std::string to_client;

private:
  static void append(std::vector<WsEv> & to, const std::vector<WsEv> & from) {
    to.insert(to.end(), from.begin(), from.end());
  }
};

/** Deterministic text of a size, with enough repetition to compress and enough variety to need a window. */
inline std::string ws_lorem(size_t n, uint32_t seed = 1) {
  static const char * words[] = {"lorem", "ipsum", "dolor", "sit", "amet", "consectetur",
      "adipiscing", "elit", "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore"};
  std::string s;
  uint32_t x = seed;
  while (s.size() < n) {
    x = x * 1103515245u + 12345u;
    s += words[(x >> 16) % 15];
    s += ' ';
  }
  s.resize(n);
  return s;
}

/** Incompressible bytes of a size. */
inline std::string ws_random_bytes(size_t n, uint32_t seed = 7) {
  std::string s;
  uint32_t x = seed;
  for (size_t i = 0; i < n; i++) {
    x = x * 1664525u + 1013904223u;
    s.push_back(static_cast<char>(x >> 24));
  }
  return s;
}

} // namespace ghttptest

#endif // GHOTI_IO_GHTTP_TESTS_WS_HELPERS_H
