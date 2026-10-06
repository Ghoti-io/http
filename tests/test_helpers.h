/**
 * @file
 *
 * Shared helpers for the Ghoti.io HTTP unit tests: a harness that feeds a
 * parser from any split of its input and records what it reported, so that
 * "the same however it is split" is an equality between two Outcomes.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GHTTP_TEST_HELPERS_H
#define GHOTI_IO_GHTTP_TEST_HELPERS_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/http/http.h>

#include "failing_allocator.h"

namespace ghttptest {

/** "a\nb\n" -> "a\r\nb\r\n", so that fixtures stay readable. */
inline std::string crlf(const std::string & s) {
  std::string out;
  for (char c : s) {
    if (c == '\n') {
      out += '\r';
    }
    out += c;
  }
  return out;
}

struct Field {
  std::string name;
  std::string value;
  bool operator==(const Field &) const = default;
};

/** Everything the parser said about one message. */
struct Msg {
  bool is_request = true;
  std::string method;
  std::string target;
  int minor = 1;
  int status = 0;
  std::string reason;
  std::vector<Field> fields;
  std::string body;
  std::vector<Field> trailers;
  GHTTP_Framing framing = GHTTP_FRAMING_NONE;
  GHTTP_Upgrade upgrade = GHTTP_UPGRADE_NONE;
  bool ended = false;
  bool operator==(const Msg &) const = default;
};

inline std::ostream & operator<<(std::ostream & os, const Msg & m) {
  if (m.is_request) {
    os << m.method << ' ' << m.target << " HTTP/1." << m.minor;
  } else {
    os << "HTTP/1." << m.minor << ' ' << m.status << ' ' << m.reason;
  }
  for (const Field & f : m.fields) {
    os << " [" << f.name << ": " << f.value << ']';
  }
  os << " body(" << m.body.size() << ")=\"" << m.body << "\"";
  for (const Field & f : m.trailers) {
    os << " {" << f.name << ": " << f.value << '}';
  }
  os << " framing=" << m.framing << " upgrade=" << m.upgrade
     << (m.ended ? " ended" : " UNFINISHED");
  return os;
}

struct Outcome {
  GHTTP_Result result = GHTTP_OK;
  std::vector<Msg> msgs;
  bool operator==(const Outcome &) const = default;
};

inline std::ostream & operator<<(std::ostream & os, const Outcome & o) {
  os << "result=" << ghttp_result_string(o.result) << " msgs=" << o.msgs.size();
  for (const Msg & m : o.msgs) {
    os << "\n  " << m;
  }
  return os;
}

struct Options {
  GHTTP_ParserKind kind = GHTTP_PARSE_REQUEST;
  GHTTP_Limits limits = defaults();
  /** For a response parser, the method each response answers, in order. */
  std::vector<std::string> methods;
  const GHTTP_Allocator * allocator = nullptr;
  /** Call finish() after the last piece. */
  bool finish = true;

  static GHTTP_Limits defaults() {
    GHTTP_Limits l;
    ghttp_limits_default(&l);
    return l;
  }
};

inline Options responses() {
  Options o;
  o.kind = GHTTP_PARSE_RESPONSE;
  return o;
}

inline std::vector<Field> fields_of(const GHTTP_Headers * h) {
  std::vector<Field> out;
  for (size_t i = 0; i < ghttp_headers_count(h); i++) {
    GHTTP_Field f;
    EXPECT_EQ(ghttp_headers_at(h, i, &f), GHTTP_OK);
    out.push_back({std::string(f.name, f.name_len),
        std::string(f.value, f.value_len)});
  }
  return out;
}

/**
 * Feed @p pieces to a fresh parser, one call loop per piece, and record the
 * head, body and trailers of every message and how the stream ended.
 */
inline Outcome run(const std::vector<std::string> & pieces,
    const Options & opt = Options()) {
  Outcome out;
  GHTTP_Parser * p = nullptr;
  out.result = ghttp_parser_create(
      opt.kind, &opt.limits, opt.allocator, &p);
  if (out.result != GHTTP_OK) {
    return out;
  }
  size_t method_index = 0;
  size_t told = static_cast<size_t>(-1);
  // Told once per request, as a client would: the parser must keep the method
  // across interim (1xx) responses and forget it after the final one.
  auto set_method = [&]() {
    if (opt.kind == GHTTP_PARSE_RESPONSE && method_index < opt.methods.size()
        && told != method_index) {
      told = method_index;
      EXPECT_EQ(ghttp_parser_expect_response_to(
                    p, opt.methods[method_index].c_str()),
          GHTTP_OK);
    }
  };
  set_method();
  Msg cur;
  bool open = false;
  auto on_event = [&](GHTTP_Event ev) {
    switch (ev) {
      case GHTTP_EVENT_HEAD: {
        cur = Msg();
        open = true;
        cur.framing = ghttp_parser_framing(p);
        cur.upgrade = ghttp_parser_upgrade(p);
        if (opt.kind == GHTTP_PARSE_REQUEST) {
          const GHTTP_Request * r = ghttp_parser_request(p);
          cur.is_request = true;
          cur.method = ghttp_request_method(r);
          cur.target = ghttp_request_target(r);
          cur.minor = ghttp_request_version(r);
          cur.fields = fields_of(ghttp_request_headers_const(r));
        } else {
          const GHTTP_Response * r = ghttp_parser_response(p);
          cur.is_request = false;
          cur.status = ghttp_response_status(r);
          cur.reason = ghttp_response_reason(r);
          cur.minor = ghttp_response_version(r);
          cur.fields = fields_of(ghttp_response_headers_const(r));
        }
        break;
      }
      case GHTTP_EVENT_BODY: {
        const void * d = nullptr;
        size_t n = 0;
        ghttp_parser_body(p, &d, &n);
        EXPECT_GT(n, 0u) << "a BODY event carries bytes";
        cur.body.append(static_cast<const char *>(d), n);
        break;
      }
      case GHTTP_EVENT_END: {
        EXPECT_TRUE(open) << "END without HEAD";
        cur.trailers = fields_of(ghttp_parser_trailers(p));
        cur.ended = true;
        out.msgs.push_back(cur);
        open = false;
        if (opt.kind == GHTTP_PARSE_RESPONSE
            && !(cur.status >= 100 && cur.status < 200 && cur.status != 101)) {
          method_index++;
        }
        set_method();
        break;
      }
      case GHTTP_EVENT_NEED_MORE:
        break;
    }
  };
  bool failed = false;
  for (const std::string & piece : pieces) {
    size_t off = 0;
    GHTTP_Event ev;
    int guard = 0;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_parser_feed(
          p, piece.data() + off, piece.size() - off, &used, &ev);
      if (r != GHTTP_OK) {
        out.result = r;
        failed = true;
        break;
      }
      off += used;
      on_event(ev);
      if (++guard > 1000000) {
        ADD_FAILURE() << "parser made no progress";
        failed = true;
        break;
      }
    } while (ev != GHTTP_EVENT_NEED_MORE);
    if (failed) {
      break;
    }
  }
  if (!failed && opt.finish) {
    GHTTP_Event ev;
    GHTTP_Result r = ghttp_parser_finish(p, &ev);
    if (r != GHTTP_OK) {
      out.result = r;
      failed = true;
    } else {
      on_event(ev);
    }
  }
  if (open) {
    out.msgs.push_back(cur); // cut short: recorded as UNFINISHED
  }
  ghttp_parser_destroy(p);
  return out;
}

inline Outcome run(const std::string & whole, const Options & opt = Options()) {
  return run(std::vector<std::string>{whole}, opt);
}

inline std::vector<std::string> by_bytes(const std::string & s) {
  std::vector<std::string> out;
  for (char c : s) {
    out.emplace_back(1, c);
  }
  return out;
}

inline std::vector<std::string> split_at(const std::string & s, size_t i) {
  return {s.substr(0, i), s.substr(i)};
}

inline std::vector<std::string> by_size(const std::string & s, size_t k) {
  std::vector<std::string> out;
  for (size_t i = 0; i < s.size(); i += k) {
    out.push_back(s.substr(i, k));
  }
  return out;
}

/** The result of parsing @p s whole. */
inline GHTTP_Result result_of(const std::string & s, const Options & opt = Options()) {
  return run(s, opt).result;
}

/** A valid HTTP/1.1 request with a Host field. */
inline std::string get(const std::string & extra = "") {
  return crlf("GET /x HTTP/1.1\nHost: h\n" + (extra.empty() ? "" : extra + "\n") + "\n");
}

} // namespace ghttptest

#endif // GHOTI_IO_GHTTP_TEST_HELPERS_H
