/**
 * @file
 *
 * What the HTTP/2 fuzz harnesses share: a recorder that drives a connection
 * from a chosen split of its input and reduces what it reported (and what it
 * wrote) to a string, the limit profiles the options byte picks, and the
 * check that everything the codec writes is a well-formed frame sequence.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GHTTP_FUZZ_H2_COMMON_H
#define GHOTI_IO_GHTTP_FUZZ_H2_COMMON_H

#include "fuzz_common.h"

namespace fuzz {

/** Small values make every cap bite on a short input. */
inline GHTTP_H2Limits h2_limits_for(uint8_t profile) {
  GHTTP_H2Limits l;
  ghttp_h2_limits_default(&l);
  switch (profile & 7) {
    case 0: break;
    case 1: l.max_concurrent_streams = 1; l.max_streams = 2; break;
    case 2: l.initial_window_size = 10; l.connection_window = 65535;
            l.manual_flow_control = 1; break;
    case 3: l.max_header_list_bytes = 100; l.max_header_count = 3;
            l.max_field_bytes = 16; break;
    case 4: l.max_continuation_frames = 1; l.max_header_block_bytes = 60; break;
    case 5: l.max_rst_per_interval = 2; l.max_settings_per_interval = 3;
            l.max_ping_per_interval = 2; l.max_empty_data_frames = 2;
            l.max_priority_per_interval = 2; l.max_extension_per_interval = 2;
            l.max_ignored_window_updates_per_interval = 2; break;
    case 6: l.max_frame_size = 16384;
            l.max_buffered_bytes = l.max_frame_size + GHTTP_H2_FRAME_HEADER_SIZE;  // the smallest allowed
            l.max_closed_streams = 2; break;
    default: l.max_table_size = 64; l.max_encoder_table_size = 64;
             l.max_body_bytes = 20; break;
  }
  return l;
}

inline void put_h2_fields(std::string & t, const GHTTP_Headers * h) {
  for (size_t i = 0; i < ghttp_headers_count(h); i++) {
    GHTTP_Field f;
    REQUIRE(ghttp_headers_at(h, i, &f) == GHTTP_OK, "field out of range");
    t.append(f.name, f.name_len).append(":").append(f.value, f.value_len).append("\n");
  }
}

struct H2Run {
  GHTTP_Result result = GHTTP_OK;
  std::string transcript;  // events, in order
  std::string output;      // every octet the connection wrote
  bool oom = false;        // an allocation was refused and reported, anywhere
};

/** Everything written must be whole frames the frame parser accepts. */
inline void check_output(const std::string & out, bool client) {
  size_t off = client ? GHTTP_H2_PREFACE_SIZE : 0;
  REQUIRE(!client || out.size() >= off, "client output shorter than the preface");
  while (off < out.size()) {
    REQUIRE(out.size() - off >= GHTTP_H2_FRAME_HEADER_SIZE, "output ends inside a frame header");
    GHTTP_H2FrameHeader h;
    ghttp_h2_frame_header_parse(reinterpret_cast<const uint8_t *>(out.data()) + off, &h);
    REQUIRE(out.size() - off - GHTTP_H2_FRAME_HEADER_SIZE >= h.length, "output ends inside a frame");
    GHTTP_H2Frame f;
    GHTTP_H2FrameError err;
    GHTTP_Result r = ghttp_h2_frame_parse(&h,
        reinterpret_cast<const uint8_t *>(out.data()) + off + GHTTP_H2_FRAME_HEADER_SIZE,
        GHTTP_H2_MAX_MAX_FRAME_SIZE, &f, &err);
    REQUIRE(r == GHTTP_OK, "the codec wrote a frame its own parser refuses");
    off += GHTTP_H2_FRAME_HEADER_SIZE + h.length;
  }
}

/**
 * Drive a connection. On HEADERS a server answers (the status the stream
 * number's low bits pick), on DATA it echoes what the windows allow, so the
 * send side and flow control are exercised by whatever the input does.
 */
inline H2Run h2_run(GHTTP_H2Role role, const GHTTP_H2Limits & limits,
    const std::vector<std::string> & pieces, const GHTTP_Allocator * alloc,
    bool send_first) {
  H2Run run;
  GHTTP_H2Conn * c = nullptr;
  run.result = ghttp_h2_conn_create(alloc, role, &limits, &c);
  if (run.result != GHTTP_OK) {
    REQUIRE(run.result == GHTTP_ERR_OOM, "create failed other than by OOM");
    return run;
  }
  std::string & t = run.transcript;
  auto drain = [&]() {
    size_t n = 0;
    const uint8_t * p = ghttp_h2_conn_output(c, &n);
    run.output.append(reinterpret_cast<const char *>(p), n);
    ghttp_h2_conn_output_consume(c, n);
  };
  auto note = [&](GHTTP_Result r) {
    if (r == GHTTP_ERR_OOM) run.oom = true;
    if (r == GHTTP_ERR_OOM && run.result == GHTTP_OK) run.result = r;
    REQUIRE(r != GHTTP_ERR_INTERNAL, "a send returned an internal error");
  };
  if (send_first && role == GHTTP_H2_CLIENT) {
    GHTTP_Request * rq = nullptr;
    if (ghttp_request_create(alloc, &rq) == GHTTP_OK) {
      uint32_t id = 0;
      note(ghttp_h2_conn_send_request(c, rq, "https", 0, &id));
      ghttp_request_destroy(rq);
    } else {
      run.result = GHTTP_ERR_OOM;
      run.oom = true;
    }
  }
  drain();
  bool failed = false;
  for (const std::string & piece : pieces) {
    size_t off = 0;
    GHTTP_H2Event ev;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_h2_conn_feed(c, piece.data() + off, piece.size() - off, &used, &ev);
      if (r != GHTTP_OK) {
        REQUIRE(r == GHTTP_ERR_CORRUPT || r == GHTTP_ERR_LIMIT || r == GHTTP_ERR_OOM,
            "feed returned an argument or internal error");
        run.result = r;
        if (r == GHTTP_ERR_OOM) run.oom = true;
        uint32_t code = 0;
        const char * why = nullptr;
        REQUIRE(ghttp_h2_conn_error(c, &code, &why) == r, "error() disagrees with feed()");
        t += "ERROR " + std::to_string(r) + " " + std::to_string(code) + "\n";
        // Sticky: the same answer, nothing consumed, nothing more written.
        drain();
        size_t before = run.output.size();
        size_t u2 = 77;
        GHTTP_H2Event e2;
        REQUIRE(ghttp_h2_conn_feed(c, "x", 1, &u2, &e2) == r, "an error is not sticky");
        drain();
        REQUIRE(run.output.size() == before, "output after a connection error");
        failed = true;
        break;
      }
      REQUIRE(used <= piece.size() - off, "consumed more than was given");
      off += used;
      REQUIRE(ev.size == sizeof(GHTTP_H2Event), "event size");
      if (ev.type != GHTTP_H2_EVENT_NEED_MORE) t += "E" + std::to_string(ev.type) + " s" + std::to_string(ev.stream_id)
          + " e" + std::to_string(ev.end_stream) + " i" + std::to_string(ev.interim)
          + " c" + std::to_string(ev.error_code) + " l" + std::to_string(ev.last_stream_id)
          + " w" + std::to_string(ev.increment) + "\n";
      switch (ev.type) {
        case GHTTP_H2_EVENT_HEADERS:
          if (role == GHTTP_H2_SERVER) {
            const GHTTP_Request * q = ghttp_h2_conn_request(c);
            t += std::string("REQ ") + ghttp_request_method(q) + " " + ghttp_request_target(q) + "\n";
            put_h2_fields(t, ghttp_request_headers_const(q));
            t += std::string("SA ") + (ev.scheme ? ev.scheme : "-") + " "
                + (ev.authority ? ev.authority : "-") + "\n";
            GHTTP_Response * rs = nullptr;
            if (ghttp_response_create(alloc, &rs) == GHTTP_OK) {
              GHTTP_Result sr = ghttp_response_set_status(
                  rs, 200 + static_cast<int>(ev.stream_id & 3), "");
              note(sr);
              if (sr == GHTTP_OK) {
                note(ghttp_h2_conn_send_response(c, ev.stream_id, rs, ev.end_stream));
              }
              ghttp_response_destroy(rs);
            } else {
              run.result = GHTTP_ERR_OOM;
              run.oom = true;
            }
          } else {
            const GHTTP_Response * q = ghttp_h2_conn_response(c);
            t += "RESP " + std::to_string(ghttp_response_status(q)) + "\n";
            put_h2_fields(t, ghttp_response_headers_const(q));
          }
          break;
        case GHTTP_H2_EVENT_TRAILERS:
          put_h2_fields(t, ghttp_h2_conn_trailers(c));
          break;
        case GHTTP_H2_EVENT_DATA: {
          t.append(reinterpret_cast<const char *>(ev.data), ev.data_len).append("\n");
          if (role == GHTTP_H2_SERVER && ev.data_len > 0) {
            size_t acc = 0;
            note(ghttp_h2_conn_send_data(c, ev.stream_id, ev.data, ev.data_len, 0, &acc));
          }
          if (limits.manual_flow_control && ev.data_len > 0) {
            note(ghttp_h2_conn_consume(c, ev.stream_id, ev.data_len));
          }
          break;
        }
        case GHTTP_H2_EVENT_GOAWAY:
        case GHTTP_H2_EVENT_PING:
        case GHTTP_H2_EVENT_PING_ACK:
          t.append(reinterpret_cast<const char *>(ev.data), ev.data_len).append("\n");
          break;
        default:
          break;
      }
      drain();
      REQUIRE(ghttp_h2_conn_connection_send_window(c) <= static_cast<int64_t>(GHTTP_H2_MAX_WINDOW),
          "send window above 2^31-1");
      REQUIRE(ghttp_h2_conn_connection_recv_window(c) >= 0, "receive window below zero");
    } while (ev.type != GHTTP_H2_EVENT_NEED_MORE);
    if (failed) break;
  }
  drain();
  check_output(run.output, role == GHTTP_H2_CLIENT);
  ghttp_h2_conn_destroy(c);
  return run;
}

} // namespace fuzz

#endif // GHOTI_IO_GHTTP_FUZZ_H2_COMMON_H
