/**
 * @file
 *
 * Helpers for the HTTP/2 tests: byte builders for frames and header blocks, a
 * wrapper that feeds a connection from any split of its input and records what
 * it reported as text, and a parser for the frames a connection wrote.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GHTTP_TEST_H2_HELPERS_H
#define GHOTI_IO_GHTTP_TEST_H2_HELPERS_H

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"

namespace ghttptest {

using HList = std::vector<std::pair<std::string, std::string>>;

inline std::string h2hex(const std::string & s) {
  static const char * d = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s) {
    out.push_back(d[c >> 4]);
    out.push_back(d[c & 15]);
  }
  return out;
}

/** A short name for a result: CORRUPT, LIMIT, OOM, ... */
inline const char * rname(GHTTP_Result r) {
  switch (r) {
    case GHTTP_OK: return "OK";
    case GHTTP_ERR_CORRUPT: return "CORRUPT";
    case GHTTP_ERR_LIMIT: return "LIMIT";
    case GHTTP_ERR_OOM: return "OOM";
    case GHTTP_ERR_INVALID: return "INVALID";
    case GHTTP_ERR_INTERNAL: return "INTERNAL";
    default: return "OTHER";
  }
}

inline std::string u32(uint32_t v) {
  std::string s;
  for (int i = 3; i >= 0; i--) s.push_back(static_cast<char>(v >> (8 * i)));
  return s;
}

/** One frame as bytes. */
inline std::string frame(uint8_t type, uint8_t flags, uint32_t stream,
    const std::string & payload) {
  std::string s;
  s.push_back(static_cast<char>(payload.size() >> 16));
  s.push_back(static_cast<char>(payload.size() >> 8));
  s.push_back(static_cast<char>(payload.size()));
  s.push_back(static_cast<char>(type));
  s.push_back(static_cast<char>(flags));
  s += u32(stream);
  return s + payload;
}

inline std::string settings(
    std::initializer_list<std::pair<uint16_t, uint32_t>> kv, bool ack = false) {
  std::string p;
  for (auto & e : kv) {
    p.push_back(static_cast<char>(e.first >> 8));
    p.push_back(static_cast<char>(e.first));
    p += u32(e.second);
  }
  return frame(GHTTP_H2_SETTINGS, ack ? 1 : 0, 0, p);
}

inline std::string settings_ack() { return settings({}, true); }

inline std::string headers(uint32_t stream, const std::string & block,
    uint8_t flags = GHTTP_H2_FLAG_END_HEADERS) {
  return frame(GHTTP_H2_HEADERS, flags, stream, block);
}

inline std::string continuation(uint32_t stream, const std::string & block,
    bool end = true) {
  return frame(GHTTP_H2_CONTINUATION, end ? GHTTP_H2_FLAG_END_HEADERS : 0, stream, block);
}

inline std::string data(uint32_t stream, const std::string & d, bool end = false) {
  return frame(GHTTP_H2_DATA, end ? GHTTP_H2_FLAG_END_STREAM : 0, stream, d);
}

inline std::string rst(uint32_t stream, uint32_t code) {
  return frame(GHTTP_H2_RST_STREAM, 0, stream, u32(code));
}

inline std::string window_update(uint32_t stream, uint32_t inc) {
  return frame(GHTTP_H2_WINDOW_UPDATE, 0, stream, u32(inc));
}

inline std::string ping(const std::string & d8 = "12345678", bool ack = false) {
  return frame(GHTTP_H2_PING, ack ? 1 : 0, 0, d8);
}

inline std::string goaway(uint32_t last, uint32_t code, const std::string & dbg = "") {
  return frame(GHTTP_H2_GOAWAY, 0, 0, u32(last) + u32(code) + dbg);
}

inline std::string priority(uint32_t stream, uint32_t dep = 0) {
  return frame(GHTTP_H2_PRIORITY, 0, stream, u32(dep) + std::string(1, '\x0f'));
}

/** A header block made by a real HPACK encoder, so a test can chain blocks. */
struct Block {
  GHTTP_HpackEncoder * e = nullptr;
  explicit Block(size_t table = 4096) {
    EXPECT_EQ(ghttp_hpack_encoder_create(nullptr, nullptr, table, &e), GHTTP_OK);
  }
  ~Block() { ghttp_hpack_encoder_destroy(e); }
  std::string operator()(const HList & l,
      GHTTP_HpackIndexing ix = GHTTP_HPACK_INDEX_AUTO,
      GHTTP_HpackHuffman hf = GHTTP_HPACK_HUFFMAN_AUTO) {
    GHTTP_Buffer * b = nullptr;
    EXPECT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
    for (auto & f : l) {
      EXPECT_EQ(ghttp_hpack_encode_field(e, f.first.data(), f.first.size(),
                    f.second.data(), f.second.size(), ix, hf, b),
          GHTTP_OK);
    }
    std::string s(static_cast<const char *>(ghttp_buffer_data(b)), ghttp_buffer_size(b));
    ghttp_buffer_destroy(b);
    return s;
  }
};

/** The usual request pseudo-headers. */
inline HList request_list(const std::string & method = "GET",
    const std::string & path = "/", const HList & extra = {},
    const std::string & authority = "example.com", const std::string & scheme = "https") {
  HList l = {{":method", method}, {":scheme", scheme}, {":authority", authority},
      {":path", path}};
  for (auto & e : extra) l.push_back(e);
  return l;
}

inline HList response_list(int status = 200, const HList & extra = {}) {
  HList l = {{":status", std::to_string(status)}};
  for (auto & e : extra) l.push_back(e);
  return l;
}

inline const uint8_t END_STREAM = GHTTP_H2_FLAG_END_STREAM;
inline const uint8_t END_HEADERS = GHTTP_H2_FLAG_END_HEADERS;

/** What a connection wrote, as frames. */
struct OutFrame {
  uint8_t type;
  uint8_t flags;
  uint32_t stream;
  std::string payload;
  uint32_t u32at(size_t off) const {
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++) v = (v << 8) | static_cast<uint8_t>(payload[off + i]);
    return v;
  }
};

inline std::vector<OutFrame> parse_frames(const std::string & bytes, bool preface = false) {
  std::vector<OutFrame> out;
  size_t off = 0;
  if (preface) {
    EXPECT_EQ(bytes.substr(0, GHTTP_H2_PREFACE_SIZE), GHTTP_H2_PREFACE);
    off = GHTTP_H2_PREFACE_SIZE;
  }
  while (off + 9 <= bytes.size()) {
    GHTTP_H2FrameHeader h;
    ghttp_h2_frame_header_parse(reinterpret_cast<const uint8_t *>(bytes.data()) + off, &h);
    EXPECT_LE(off + 9 + h.length, bytes.size()) << "a frame cut short";
    OutFrame f{h.type, h.flags, h.stream_id, bytes.substr(off + 9, h.length)};
    out.push_back(f);
    off += 9 + h.length;
  }
  EXPECT_EQ(off, bytes.size()) << "trailing octets that are not a frame";
  return out;
}

inline std::string fields_text(const GHTTP_Headers * h) {
  std::string s;
  for (size_t i = 0; i < ghttp_headers_count(h); i++) {
    GHTTP_Field f;
    ghttp_headers_at(h, i, &f);
    s += " [" + std::string(f.name, f.name_len) + ": " + std::string(f.value, f.value_len) + "]";
  }
  return s;
}

/** A connection with a recorder. */
struct Side {
  GHTTP_H2Conn * c = nullptr;
  GHTTP_H2Role role;
  std::vector<std::string> events;
  std::string out;  // everything the connection has written, drained
  GHTTP_Result result = GHTTP_OK;
  std::vector<std::string> data_by_stream;

  /** @param must_succeed false: an allocator may refuse the connection itself. */
  Side(GHTTP_H2Role r, const GHTTP_H2Limits * lim = nullptr,
      const GHTTP_Allocator * a = nullptr, bool must_succeed = true)
      : role(r) {
    GHTTP_Result cr = ghttp_h2_conn_create(a, r, lim, &c);
    if (must_succeed) {
      EXPECT_EQ(cr, GHTTP_OK);
    } else if (cr != GHTTP_OK) {
      c = nullptr;
      result = cr;
    }
    drain();
  }
  ~Side() { ghttp_h2_conn_destroy(c); }
  Side(const Side &) = delete;

  /** Move queued output into `out`. */
  std::string drain() {
    if (!c) return "";
    size_t n = 0;
    const uint8_t * p = ghttp_h2_conn_output(c, &n);
    std::string s(reinterpret_cast<const char *>(p), n);
    ghttp_h2_conn_output_consume(c, n);
    out += s;
    return s;
  }

  std::string describe(const GHTTP_H2Event & ev) {
    std::ostringstream o;
    switch (ev.type) {
      case GHTTP_H2_EVENT_SETTINGS: o << "SETTINGS"; break;
      case GHTTP_H2_EVENT_SETTINGS_ACK: o << "SETTINGS_ACK"; break;
      case GHTTP_H2_EVENT_HEADERS:
        o << "HEADERS " << ev.stream_id << (ev.end_stream ? " end" : "")
          << (ev.interim ? " interim" : "");
        if (role == GHTTP_H2_SERVER) {
          const GHTTP_Request * r = ghttp_h2_conn_request(c);
          o << " " << ghttp_request_method(r) << " " << ghttp_request_target(r)
            << fields_text(ghttp_request_headers_const(r))
            << " scheme=" << (ev.scheme ? ev.scheme : "-")
            << " authority=" << (ev.authority ? ev.authority : "-");
        } else {
          const GHTTP_Response * r = ghttp_h2_conn_response(c);
          o << " " << ghttp_response_status(r)
            << fields_text(ghttp_response_headers_const(r));
        }
        break;
      case GHTTP_H2_EVENT_DATA:
        o << "DATA " << ev.stream_id << (ev.end_stream ? " end" : "") << " \""
          << std::string(reinterpret_cast<const char *>(ev.data), ev.data_len) << "\"";
        break;
      case GHTTP_H2_EVENT_TRAILERS:
        o << "TRAILERS " << ev.stream_id << fields_text(ghttp_h2_conn_trailers(c));
        break;
      case GHTTP_H2_EVENT_STREAM_RESET:
        o << "RESET " << ev.stream_id << " " << ghttp_h2_error_string(ev.error_code);
        break;
      case GHTTP_H2_EVENT_STREAM_ERROR:
        o << "STREAM_ERROR " << ev.stream_id << " " << ghttp_h2_error_string(ev.error_code);
        break;
      case GHTTP_H2_EVENT_GOAWAY:
        o << "GOAWAY last=" << ev.last_stream_id << " "
          << ghttp_h2_error_string(ev.error_code) << " \""
          << std::string(reinterpret_cast<const char *>(ev.data), ev.data_len) << "\"";
        break;
      case GHTTP_H2_EVENT_PING:
        o << "PING " << std::string(reinterpret_cast<const char *>(ev.data), ev.data_len);
        break;
      case GHTTP_H2_EVENT_PING_ACK:
        o << "PING_ACK " << std::string(reinterpret_cast<const char *>(ev.data), ev.data_len);
        break;
      case GHTTP_H2_EVENT_WINDOW_UPDATE:
        o << "WINDOW " << ev.stream_id << " +" << ev.increment;
        break;
      case GHTTP_H2_EVENT_NEED_MORE: o << "NEED_MORE"; break;
    }
    return o.str();
  }

  /**
   * Feed @p pieces, each to the end (the documented loop). Stops at the first
   * connection error, which is recorded as "ERROR <result> <code>".
   */
  void feed(const std::vector<std::string> & pieces) {
    if (!c) return;
    for (const std::string & piece : pieces) {
      if (result != GHTTP_OK) break;
      size_t off = 0;
      GHTTP_H2Event ev;
      do {
        size_t used = 0;
        GHTTP_Result r = ghttp_h2_conn_feed(c, piece.data() + off, piece.size() - off, &used, &ev);
        if (r != GHTTP_OK) {
          result = r;
          uint32_t code;
          const char * why;
          ghttp_h2_conn_error(c, &code, &why);
          events.push_back(std::string("ERROR ") + rname(r) + " "
              + ghttp_h2_error_string(code));
          break;
        }
        off += used;
        EXPECT_EQ(ev.size, sizeof(GHTTP_H2Event));
        if (ev.type != GHTTP_H2_EVENT_NEED_MORE) {
          events.push_back(describe(ev));
        }
      } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
      drain();
    }
    drain();
  }
  void feed(const std::string & bytes) { feed(std::vector<std::string>{bytes}); }

  std::vector<std::string> take_events() {
    auto e = events;
    events.clear();
    return e;
  }

  /** Output not yet handed to the peer by pump(). */
  size_t sent_pos = 0;
  std::string unsent() {
    drain();
    std::string s = out.substr(sent_pos);
    sent_pos = out.size();
    return s;
  }

  /** The frames written so far (after the client preface if this is a client). */
  std::vector<OutFrame> frames() {
    drain();
    return parse_frames(out, role == GHTTP_H2_CLIENT);
  }
  /** Written frames from the last call to mark(). */
  size_t marked = 0;
  void mark() { drain(); marked = out.size(); }
  std::vector<OutFrame> frames_since_mark() {
    drain();
    return parse_frames(out.substr(marked));
  }
};

/** Cut @p s into pieces at the given offsets. */
inline std::vector<std::string> cut(const std::string & s, std::vector<size_t> at) {
  std::vector<std::string> out;
  size_t prev = 0;
  for (size_t a : at) {
    out.push_back(s.substr(prev, a - prev));
    prev = a;
  }
  out.push_back(s.substr(prev));
  return out;
}

inline std::vector<std::string> bytewise(const std::string & s) {
  std::vector<std::string> out;
  for (char c : s) out.push_back(std::string(1, c));
  return out;
}

/** Two connections wired together. Returns when both are quiet. */
inline void pump(Side & a, Side & b, int rounds = 200) {
  for (int i = 0; i < rounds; i++) {
    std::string x = a.unsent();
    std::string y = b.unsent();
    if (x.empty() && y.empty()) return;
    if (!x.empty() && b.result == GHTTP_OK) b.feed(x);
    if (!y.empty() && a.result == GHTTP_OK) a.feed(y);
  }
}

inline GHTTP_H2Limits limits() {
  GHTTP_H2Limits l;
  ghttp_h2_limits_default(&l);
  return l;
}

/** The standard opening a peer sends: the preface (for a client) and SETTINGS. */
inline std::string client_open(std::initializer_list<std::pair<uint16_t, uint32_t>> kv = {}) {
  return std::string(GHTTP_H2_PREFACE) + settings(kv);
}

} // namespace ghttptest

#endif // GHOTI_IO_GHTTP_TEST_H2_HELPERS_H
