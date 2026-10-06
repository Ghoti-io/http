/**
 * @file
 *
 * libFuzzer harness for parse, write, parse.
 *
 * The input is parsed; every message it completed is rebuilt through the
 * public setters, serialised by the writer (a body as Content-Length bytes,
 * chunks of pseudo-random size, or bytes to the end, as its framing says),
 * and parsed again. The second parse must return exactly the messages the
 * first one did. Byte 0 picks requests or responses and the limits of the
 * first parse; byte 1 seeds the chunking.
 *
 * What this cannot see: a parser and writer that agree on a wrong answer
 * (the unit tests hold the literal bytes), and a refusal both share.
 *
 * Build with: make fuzz-roundtrip
 * Run:        make fuzz-run-roundtrip FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_common.h"

namespace {

struct Message {
  std::string method, target, reason;
  int minor = 1;
  int status = 0;
  std::vector<std::pair<std::string, std::string>> fields;
  std::string body;
  std::vector<std::pair<std::string, std::string>> trailers;
  GHTTP_Framing framing = GHTTP_FRAMING_NONE;
};

// A recorder like fuzz::parse, but keeping the messages themselves.
struct Recorded {
  std::vector<Message> messages;
  GHTTP_Result result = GHTTP_OK;
};

std::vector<std::pair<std::string, std::string>> fields_of(const GHTTP_Headers * h) {
  std::vector<std::pair<std::string, std::string>> out;
  for (size_t i = 0; i < ghttp_headers_count(h); i++) {
    GHTTP_Field f;
    REQUIRE(ghttp_headers_at(h, i, &f) == GHTTP_OK, "field out of range");
    out.emplace_back(std::string(f.name, f.name_len), std::string(f.value, f.value_len));
  }
  return out;
}

Recorded record(GHTTP_ParserKind kind, const GHTTP_Limits & limits,
    const std::vector<std::string> & pieces) {
  Recorded rec;
  GHTTP_Parser * p = nullptr;
  REQUIRE(ghttp_parser_create(kind, &limits, nullptr, &p) == GHTTP_OK, "create");
  Message cur;
  bool open = false;
  bool failed = false;
  for (const std::string & piece : pieces) {
    size_t off = 0;
    GHTTP_Event ev;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_parser_feed(
          p, piece.data() + off, piece.size() - off, &used, &ev);
      if (r != GHTTP_OK) {
        rec.result = r;
        failed = true;
        break;
      }
      off += used;
      if (ev == GHTTP_EVENT_HEAD) {
        cur = Message();
        open = true;
        cur.framing = ghttp_parser_framing(p);
        if (kind == GHTTP_PARSE_REQUEST) {
          const GHTTP_Request * q = ghttp_parser_request(p);
          cur.method = ghttp_request_method(q);
          cur.target = ghttp_request_target(q);
          cur.minor = ghttp_request_version(q);
          cur.fields = fields_of(ghttp_request_headers_const(q));
        } else {
          const GHTTP_Response * q = ghttp_parser_response(p);
          cur.status = ghttp_response_status(q);
          cur.reason = ghttp_response_reason(q);
          cur.minor = ghttp_response_version(q);
          cur.fields = fields_of(ghttp_response_headers_const(q));
        }
      } else if (ev == GHTTP_EVENT_BODY) {
        const void * d;
        size_t n;
        ghttp_parser_body(p, &d, &n);
        cur.body.append(static_cast<const char *>(d), n);
      } else if (ev == GHTTP_EVENT_END) {
        cur.trailers = fields_of(ghttp_parser_trailers(p));
        rec.messages.push_back(cur);
        open = false;
      }
    } while (ev != GHTTP_EVENT_NEED_MORE);
    if (failed) {
      break;
    }
  }
  if (!failed) {
    GHTTP_Event ev;
    GHTTP_Result r = ghttp_parser_finish(p, &ev);
    if (r != GHTTP_OK) {
      rec.result = r;
    } else if (ev == GHTTP_EVENT_END && open) {
      cur.trailers = fields_of(ghttp_parser_trailers(p));
      rec.messages.push_back(cur);
    }
  }
  ghttp_parser_destroy(p);
  return rec;
}

void add_fields(GHTTP_Headers * h,
    const std::vector<std::pair<std::string, std::string>> & fields) {
  for (const auto & f : fields) {
    REQUIRE(ghttp_headers_add(h, f.first.c_str(), f.second.c_str()) == GHTTP_OK,
        "a field the parser accepted was refused by the setter");
  }
}

void write_message(GHTTP_ParserKind kind, const Message & m, uint32_t seed,
    GHTTP_Buffer * out) {
  if (kind == GHTTP_PARSE_REQUEST) {
    GHTTP_Request * r = nullptr;
    REQUIRE(ghttp_request_create(nullptr, &r) == GHTTP_OK, "request create");
    REQUIRE(ghttp_request_set_method(r, m.method.c_str()) == GHTTP_OK, "method");
    REQUIRE(ghttp_request_set_target(r, m.target.c_str()) == GHTTP_OK, "target");
    REQUIRE(ghttp_request_set_version(r, m.minor) == GHTTP_OK, "version");
    add_fields(ghttp_request_headers(r), m.fields);
    REQUIRE(ghttp_write_request_head(out, r) == GHTTP_OK,
        "the writer refused a request head the parser accepted");
    ghttp_request_destroy(r);
  } else {
    GHTTP_Response * r = nullptr;
    REQUIRE(ghttp_response_create(nullptr, &r) == GHTTP_OK, "response create");
    REQUIRE(ghttp_response_set_status(r, m.status, m.reason.c_str()) == GHTTP_OK,
        "status");
    REQUIRE(ghttp_response_set_version(r, m.minor) == GHTTP_OK, "version");
    add_fields(ghttp_response_headers(r), m.fields);
    REQUIRE(ghttp_write_response_head(out, r) == GHTTP_OK,
        "the writer refused a response head the parser accepted");
    ghttp_response_destroy(r);
  }
  switch (m.framing) {
    case GHTTP_FRAMING_NONE:
      REQUIRE(m.body.empty(), "a bodyless message had a body");
      break;
    case GHTTP_FRAMING_LENGTH:
    case GHTTP_FRAMING_CLOSE:
      REQUIRE(ghttp_buffer_append(out, m.body.data(), m.body.size()) == GHTTP_OK,
          "append");
      break;
    case GHTTP_FRAMING_CHUNKED: {
      uint32_t x = seed * 2654435761u + 1;
      size_t pos = 0;
      while (pos < m.body.size()) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        size_t n = 1 + x % 9;
        if (n > m.body.size() - pos) {
          n = m.body.size() - pos;
        }
        REQUIRE(ghttp_write_chunk(out, m.body.data() + pos, n) == GHTTP_OK, "chunk");
        pos += n;
      }
      GHTTP_Headers * t = nullptr;
      REQUIRE(ghttp_headers_create(nullptr, &t) == GHTTP_OK, "trailers");
      add_fields(t, m.trailers);
      REQUIRE(ghttp_write_chunked_end(out, t) == GHTTP_OK,
          "the writer refused trailers the parser accepted");
      ghttp_headers_destroy(t);
      break;
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  GHTTP_ParserKind kind = (data[0] & 1) ? GHTTP_PARSE_RESPONSE : GHTTP_PARSE_REQUEST;
  GHTTP_Limits limits = fuzz::limits_for(static_cast<uint8_t>(data[0] >> 1));
  uint32_t seed = data[1];
  std::string input(reinterpret_cast<const char *>(data + 2), size - 2);

  Recorded first = record(kind, limits, {input});

  GHTTP_Buffer * out = nullptr;
  REQUIRE(ghttp_buffer_create(nullptr, &out) == GHTTP_OK, "buffer");
  for (const Message & m : first.messages) {
    write_message(kind, m, seed, out);
  }
  std::string written(static_cast<const char *>(ghttp_buffer_data(out)),
      ghttp_buffer_size(out));
  ghttp_buffer_destroy(out);

  Recorded second = record(kind, fuzz::unlimited(), {written});
  REQUIRE(second.result == GHTTP_OK, "rewritten messages did not parse cleanly");
  REQUIRE(second.messages.size() == first.messages.size(),
      "a different number of messages came back");
  for (size_t i = 0; i < first.messages.size(); i++) {
    const Message & a = first.messages[i];
    const Message & b = second.messages[i];
    REQUIRE(a.method == b.method && a.target == b.target && a.status == b.status
            && a.reason == b.reason && a.minor == b.minor,
        "a start line changed in the round trip");
    REQUIRE(a.fields == b.fields, "fields changed in the round trip");
    REQUIRE(a.body == b.body, "a body changed in the round trip");
    REQUIRE(a.trailers == b.trailers, "trailers changed in the round trip");
    REQUIRE(a.framing == b.framing, "framing changed in the round trip");
  }
  return 0;
}
