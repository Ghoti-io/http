/**
 * @file
 *
 * What the WebSocket harnesses share: limit profiles from an options byte, a
 * runner that feeds a connection a chosen split and reduces what it reports to
 * a transcript, and the check that everything a connection wrote is whole
 * frames of the right shape.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GHTTP_FUZZ_WS_COMMON_H
#define GHOTI_IO_GHTTP_FUZZ_WS_COMMON_H

#include <string>
#include <vector>

#include "fuzz_common.h"

namespace fuzz {

inline GHTTP_WsLimits ws_limits_for(uint8_t profile) {
  GHTTP_WsLimits l;
  ghttp_ws_limits_default(&l);
  switch (profile & 7) {
    case 0: break;
    case 1: l.max_frame_payload = 20; break;
    case 2: l.max_message_bytes = 30; break;
    case 3: l.max_fragments = 3; break;
    case 4: l.max_control_per_interval = 3; break;
    case 5: l.max_buffered_bytes = 2 + GHTTP_WS_MAX_CONTROL_PAYLOAD + 4; break;
    case 6: l.max_message_bytes = 4096; l.max_expansion_ratio = 8; break;
    default: l.max_frame_payload = 64; l.max_message_bytes = 100; l.max_fragments = 5;
             l.max_control_per_interval = 5; break;
  }
  if (l.max_frame_payload > l.max_message_bytes) {
    l.max_frame_payload = l.max_message_bytes;  // a frame is never larger than its message
  }
  return l;
}

/** The negotiated parameters an options byte picks: nothing, or deflate with each variant. */
inline GHTTP_WsNegotiated ws_negotiated_for(uint8_t v) {
  GHTTP_WsNegotiated n;
  ghttp_ws_negotiated_default(&n);
  if (v & 1) {
    n.deflate = 1;
    n.deflate_params.server_no_context_takeover = (v >> 1) & 1;
    n.deflate_params.client_no_context_takeover = (v >> 2) & 1;
    n.deflate_params.server_max_window_bits = (v & 0x08) ? static_cast<uint8_t>(8 + (v >> 4) % 8) : 0;
    n.deflate_params.client_max_window_bits = (v & 0x80) ? static_cast<uint8_t>(8 + (v >> 4) % 8) : 0;
  }
  if (v & 0x40) n.extension_rsv = GHTTP_WS_RSV2;
  return n;
}

struct WsFuzzRun {
  GHTTP_Result result = GHTTP_OK;
  uint16_t code = 0;
  std::string transcript;  // events, in order
  std::string output;      // every octet the connection wrote
  bool oom = false;
};

/** A masking source that is the same every run. */
inline GHTTP_Result ws_fixed_random(void * ctx, void * out, size_t n) {
  uint32_t * c = static_cast<uint32_t *>(ctx);
  uint8_t * p = static_cast<uint8_t *>(out);
  for (size_t i = 0; i < n; i++) {
    *c = *c * 1664525u + 1013904223u;
    p[i] = static_cast<uint8_t>(*c >> 24);
  }
  return GHTTP_OK;
}

/**
 * Everything written must be whole frames of the shape this end sends: a
 * server's unmasked and a client's masked, control frames final and of at
 * most 125 octets, every Close with a valid code and a UTF-8 reason, no
 * reserved bit beyond what was negotiated, text that is UTF-8.
 */
inline void ws_check_output(const std::string & out, GHTTP_WsRole role, bool deflate) {
  size_t off = 0;
  while (off < out.size()) {
    GHTTP_WsFrameHeader h;
    size_t used = 0;
    GHTTP_Result r = ghttp_ws_frame_header_parse(out.data() + off, out.size() - off, &h, &used);
    REQUIRE(r == GHTTP_OK, "the codec wrote a frame header its own parser refuses");
    REQUIRE(used > 0, "output ends inside a frame header");
    REQUIRE((h.masked != 0) == (role == GHTTP_WS_CLIENT), "the codec wrote a frame with the wrong masking for its role");
    REQUIRE(out.size() - off - used >= h.payload_len, "output ends inside a frame");
    REQUIRE(!h.rsv2 && !h.rsv3, "a reserved bit was written");
    if (h.rsv1) {
      REQUIRE(deflate && !ghttp_ws_opcode_is_control(h.opcode) && h.opcode != GHTTP_WS_OP_CONTINUATION,
          "RSV1 written where permessage-deflate does not allow it");
    }
    std::string payload(out.data() + off + used, static_cast<size_t>(h.payload_len));
    if (h.masked) ghttp_ws_mask(payload.data(), payload.size(), h.mask_key, 0);
    if (h.opcode == GHTTP_WS_OP_CLOSE) {
      REQUIRE(payload.size() != 1, "a Close with a one-octet body");
      if (payload.size() >= 2) {
        uint16_t code = static_cast<uint16_t>((static_cast<uint8_t>(payload[0]) << 8) | static_cast<uint8_t>(payload[1]));
        REQUIRE(ghttp_ws_close_code_is_valid(code), "a Close with a code that may not be sent");
        GHTTP_WsUtf8 v;
        ghttp_ws_utf8_init(&v);
        REQUIRE(ghttp_ws_utf8_feed(&v, payload.data() + 2, payload.size() - 2) == GHTTP_OK
                && ghttp_ws_utf8_complete(&v),
            "a Close reason that is not UTF-8");
      }
    }
    off += used + static_cast<size_t>(h.payload_len);
  }
}

/**
 * Drive a connection with @p pieces. With @p echo every message delivered is
 * sent back (so the send side and the compressor are exercised by whatever the
 * input is), and every Ping's payload is also sent as a Ping of our own.
 */
inline WsFuzzRun ws_run(GHTTP_WsRole role, const GHTTP_WsLimits & limits,
    const GHTTP_WsNegotiated & neg, const std::vector<std::string> & pieces,
    const GHTTP_Allocator * alloc, bool echo) {
  WsFuzzRun run;
  GHTTP_WsConn * c = nullptr;
  run.result = ghttp_ws_conn_create(alloc, role, &limits, &neg, &c);
  if (run.result != GHTTP_OK) {
    REQUIRE(run.result == GHTTP_ERR_OOM, "create failed other than by OOM");
    return run;
  }
  uint32_t rng = 99;
  ghttp_ws_conn_set_random(c, ws_fixed_random, &rng);
  std::string & t = run.transcript;
  auto drain = [&]() {
    size_t n = 0;
    const uint8_t * p = ghttp_ws_conn_output(c, &n);
    run.output.append(reinterpret_cast<const char *>(p), n);
    ghttp_ws_conn_output_consume(c, n);
  };
  auto note = [&](GHTTP_Result r) {
    if (r == GHTTP_ERR_OOM) {
      run.oom = true;
      if (run.result == GHTTP_OK) run.result = r;
    }
    REQUIRE(r != GHTTP_ERR_INTERNAL, "a send returned an internal error");
  };
  bool failed = false;
  for (const std::string & piece : pieces) {
    size_t off = 0;
    GHTTP_WsEvent ev;
    do {
      size_t used = 0;
      GHTTP_Result r = ghttp_ws_conn_feed(c, piece.data() + off, piece.size() - off, &used, &ev);
      if (r != GHTTP_OK) {
        REQUIRE(r == GHTTP_ERR_CORRUPT || r == GHTTP_ERR_LIMIT || r == GHTTP_ERR_OOM,
            "feed returned an argument or internal error");
        run.result = r;
        if (r == GHTTP_ERR_OOM) run.oom = true;
        uint16_t code = 0;
        const char * why = nullptr;
        REQUIRE(ghttp_ws_conn_error(c, &code, &why) == r, "error() disagrees with feed()");
        REQUIRE(why != nullptr && *why != '\0', "an error without a reason");
        run.code = code;
        t += "ERROR " + std::to_string(r) + " " + std::to_string(code) + "\n";
        drain();
        REQUIRE(ghttp_ws_conn_state(c) == GHTTP_WS_STATE_FAILED, "failed but not in the failed state");
        // Sticky: the same answer, nothing consumed, nothing more written.
        size_t before = run.output.size();
        size_t u2 = 77;
        GHTTP_WsEvent e2;
        REQUIRE(ghttp_ws_conn_feed(c, "x", 1, &u2, &e2) == r, "an error is not sticky");
        REQUIRE(u2 == 0 && e2.type == GHTTP_WS_EVENT_NEED_MORE, "an error consumed or reported something after it");
        drain();
        REQUIRE(run.output.size() == before, "output after a connection error");
        failed = true;
        break;
      }
      REQUIRE(used <= piece.size() - off, "consumed more than was given");
      REQUIRE(ev.size == sizeof(GHTTP_WsEvent), "event size");
      off += used;
      if (ev.type != GHTTP_WS_EVENT_NEED_MORE) {
        t += "E" + std::to_string(ev.type) + " c" + std::to_string(ev.code) + " z" + std::to_string(ev.compressed)
            + " f" + std::to_string(ev.fragments) + " r" + std::to_string(ev.rsv) + " ";
        REQUIRE(ev.data != nullptr || ev.data_len == 0, "an event with data_len but no data");
        t.append(reinterpret_cast<const char *>(ev.data), ev.data_len).append("\n");
      }
      if (ev.type == GHTTP_WS_EVENT_TEXT) {
        GHTTP_WsUtf8 v;
        ghttp_ws_utf8_init(&v);
        REQUIRE(ghttp_ws_utf8_feed(&v, ev.data, ev.data_len) == GHTTP_OK && ghttp_ws_utf8_complete(&v),
            "a text message that is not UTF-8 was delivered");
      }
      if (ev.type == GHTTP_WS_EVENT_TEXT || ev.type == GHTTP_WS_EVENT_BINARY) {
        REQUIRE(ev.data_len <= limits.max_message_bytes, "a message over the limit was delivered");
        REQUIRE(ev.fragments >= 1 && ev.fragments <= limits.max_fragments, "fragment count out of range");
      }
      if (ev.type == GHTTP_WS_EVENT_CLOSE) {
        REQUIRE(ev.code == GHTTP_WS_CLOSE_NO_STATUS || ghttp_ws_close_code_is_valid(ev.code),
            "a Close event with a code that may not be sent");
        REQUIRE(ghttp_ws_conn_state(c) == GHTTP_WS_STATE_CLOSED || ghttp_ws_conn_state(c) == GHTTP_WS_STATE_CLOSING,
            "a Close was received and the state is not closing or closed");
      }
      if (echo) {
        if (ev.type == GHTTP_WS_EVENT_TEXT) {
          note(ghttp_ws_conn_send_message(c, GHTTP_WS_MESSAGE_TEXT, ev.data, ev.data_len));
        } else if (ev.type == GHTTP_WS_EVENT_BINARY) {
          note(ghttp_ws_conn_send_message(c, GHTTP_WS_MESSAGE_BINARY, ev.data, ev.data_len));
        } else if (ev.type == GHTTP_WS_EVENT_PING) {
          note(ghttp_ws_conn_send_ping(c, ev.data, ev.data_len));
        }
      }
      drain();
    } while (ev.type != GHTTP_WS_EVENT_NEED_MORE);
    if (failed) break;
  }
  drain();
  ws_check_output(run.output, role, neg.deflate != 0);
  ghttp_ws_conn_destroy(c);
  return run;
}

} // namespace fuzz

#endif // GHOTI_IO_GHTTP_FUZZ_WS_COMMON_H
