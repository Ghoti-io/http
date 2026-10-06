/**
 * @file
 *
 * What the two libFuzzer harnesses share: a recorder that feeds a parser from
 * a chosen split and reduces what it reports to a transcript string, and the
 * options byte that picks limits.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GHTTP_FUZZ_COMMON_H
#define GHOTI_IO_GHTTP_FUZZ_COMMON_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <ghoti.io/http/http.h>

#include "../failing_allocator.h"

namespace fuzz {

[[noreturn]] inline void broken(const char * what) {
  std::fprintf(stderr, "http invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what) \
  do {                      \
    if (!(cond)) {          \
      fuzz::broken(what);   \
    }                       \
  } while (0)

/**
 * The options byte selects a limit profile. Small values make every cap bite
 * on a short input, which is what lets a few hundred bytes reach the LIMIT
 * paths; the top profile is the library default.
 */
inline GHTTP_Limits limits_for(uint8_t profile) {
  GHTTP_Limits l;
  ghttp_limits_default(&l);
  switch (profile & 7) {
    case 0: l.max_head_bytes = 64; break;
    case 1: l.max_line_length = 24; break;
    case 2: l.max_header_count = 2; break;
    case 3: l.max_body_bytes = 10; l.max_chunk_size = 4; break;
    case 4: l.max_trailer_bytes = 12; l.max_trailer_count = 1; break;
    case 5: l.max_body_bytes = 0; break;
    case 6: l.max_chunk_size = 1; break;
    default: break;
  }
  return l;
}

/** Large enough that a second pass over rewritten bytes meets no cap. */
inline GHTTP_Limits unlimited() {
  GHTTP_Limits l;
  l.max_head_bytes = SIZE_MAX;
  l.max_line_length = SIZE_MAX;
  l.max_header_count = SIZE_MAX;
  l.max_trailer_bytes = SIZE_MAX;
  l.max_trailer_count = SIZE_MAX;
  l.max_body_bytes = UINT64_MAX;
  l.max_chunk_size = UINT64_MAX;
  return l;
}

struct Parsed {
  GHTTP_Result result = GHTTP_OK;
  /** Everything reported, in a form two runs can be compared as strings. */
  std::string transcript;
  size_t ended = 0;
};

inline void put_fields(std::string & t, const GHTTP_Headers * h) {
  for (size_t i = 0; i < ghttp_headers_count(h); i++) {
    GHTTP_Field f;
    REQUIRE(ghttp_headers_at(h, i, &f) == GHTTP_OK, "field out of range");
    t.append(f.name, f.name_len).append(":").append(f.value, f.value_len);
    t.push_back('\n');
  }
}

/**
 * Feed @p pieces, in order, to a fresh parser. The transcript holds each head,
 * the concatenated body of each message (never its slicing) and its
 * trailers, so two splits of one input produce equal transcripts.
 */
inline Parsed parse(GHTTP_ParserKind kind, const GHTTP_Limits & limits,
    const std::vector<std::string> & pieces, bool finish,
    const GHTTP_Allocator * allocator = nullptr) {
  Parsed out;
  GHTTP_Parser * p = nullptr;
  out.result = ghttp_parser_create(kind, &limits, allocator, &p);
  if (out.result != GHTTP_OK) {
    REQUIRE(out.result == GHTTP_ERR_OOM, "create failed other than by OOM");
    return out;
  }
  std::string & t = out.transcript;
  bool failed = false;
  for (const std::string & piece : pieces) {
    size_t off = 0;
    GHTTP_Event ev;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_parser_feed(
          p, piece.data() + off, piece.size() - off, &used, &ev);
      if (r != GHTTP_OK) {
        REQUIRE(r != GHTTP_ERR_INVALID && r != GHTTP_ERR_INTERNAL,
            "feed returned an argument or internal error");
        out.result = r;
        failed = true;
        break;
      }
      REQUIRE(used <= piece.size() - off, "consumed more than was given");
      off += used;
      switch (ev) {
        case GHTTP_EVENT_HEAD:
          if (kind == GHTTP_PARSE_REQUEST) {
            const GHTTP_Request * q = ghttp_parser_request(p);
            REQUIRE(q != nullptr, "HEAD without a request");
            t += std::string("REQ ") + ghttp_request_method(q) + " "
                + ghttp_request_target(q) + " "
                + std::to_string(ghttp_request_version(q)) + "\n";
            put_fields(t, ghttp_request_headers_const(q));
          } else {
            const GHTTP_Response * q = ghttp_parser_response(p);
            REQUIRE(q != nullptr, "HEAD without a response");
            t += "RESP " + std::to_string(ghttp_response_status(q)) + " "
                + ghttp_response_reason(q) + " "
                + std::to_string(ghttp_response_version(q)) + "\n";
            put_fields(t, ghttp_response_headers_const(q));
          }
          t += "F" + std::to_string(ghttp_parser_framing(p)) + "U"
              + std::to_string(ghttp_parser_upgrade(p)) + "\n";
          break;
        case GHTTP_EVENT_BODY: {
          const void * d = nullptr;
          size_t n = 0;
          ghttp_parser_body(p, &d, &n);
          REQUIRE(n > 0 && d != nullptr, "empty BODY event");
          t.append(static_cast<const char *>(d), n);
          break;
        }
        case GHTTP_EVENT_END:
          t += "\nT\n";
          put_fields(t, ghttp_parser_trailers(p));
          t += "END\n";
          out.ended++;
          break;
        case GHTTP_EVENT_NEED_MORE:
          REQUIRE(off == piece.size() || kind == GHTTP_PARSE_RESPONSE,
              "NEED_MORE with input left");
          break;
      }
      if (ev == GHTTP_EVENT_NEED_MORE) {
        break; // an upgrade leaves input unused; otherwise off == size
      }
    } while (true);
    if (failed) {
      break;
    }
  }
  if (!failed && finish) {
    GHTTP_Event ev;
    GHTTP_Result r = ghttp_parser_finish(p, &ev);
    if (r != GHTTP_OK) {
      REQUIRE(r == GHTTP_ERR_CORRUPT, "finish failed other than as truncation");
      out.result = r;
    } else if (ev == GHTTP_EVENT_END) {
      t += "\nT\n";
      put_fields(t, ghttp_parser_trailers(p));
      t += "END\n";
      out.ended++;
    }
  }
  ghttp_parser_destroy(p);
  return out;
}

/** Pieces of pseudo-random size 1..16 from @p seed. */
inline std::vector<std::string> random_pieces(
    const std::string & s, uint32_t seed) {
  std::vector<std::string> out;
  uint32_t x = seed * 2654435761u + 1;
  size_t pos = 0;
  while (pos < s.size()) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    size_t n = 1 + x % 16;
    out.push_back(s.substr(pos, n));
    pos += n;
  }
  return out;
}

} // namespace fuzz

#endif // GHOTI_IO_GHTTP_FUZZ_COMMON_H
