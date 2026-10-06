/**
 * @file
 *
 * libFuzzer harness for the WebSocket sender and receiver together: a client
 * and a server wired in memory, a program of sends taken from the input, and
 * the requirement that what is sent is what arrives, in order, with the right
 * type, however it was fragmented, compressed, masked and cut.
 *
 * Byte 0 picks the negotiation (permessage-deflate, takeover, window bits; as
 * ws_negotiated_for), byte 1 seeds how the wire is cut between the ends. Then a
 * sequence of operations, each a control byte and what it needs:
 *   0x0n  send a text message of the next bytes made valid UTF-8, n of 16 sizes
 *   0x1n  send a binary message
 *   0x2n  send a message in fragments, the fragment sizes taken from the input
 *   0x3n  send a ping with up to n octets
 *   0x4n  send a Close and finish
 * from the client or the server by the control byte's top bit.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <deque>

#include "fuzz_ws_common.h"

namespace {

/** Valid UTF-8 from arbitrary bytes: each octet becomes a code point of one to three octets. */
std::string utf8_of(const std::string & raw) {
  std::string s;
  for (unsigned char c : raw) {
    uint32_t cp = c;
    if (c >= 0xe0) {
      cp = 0x800 + ((c - 0xe0) << 8) + c;  // three-octet range, no surrogates below 0xd800
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

struct End {
  GHTTP_WsConn * c = nullptr;
  uint32_t rng = 1;
  std::string inbox;  // messages delivered here, as "T<data>" or "B<data>" lines with lengths
  std::deque<std::string> expect;
  bool failed = false;
};

void pump(End & a, End & b, uint8_t seed) {
  for (int round = 0; round < 64; round++) {
    bool moved = false;
    for (End * from : {&a, &b}) {
      End * to = from == &a ? &b : &a;
      size_t n = 0;
      const uint8_t * p = ghttp_ws_conn_output(from->c, &n);
      if (n == 0) {
        continue;
      }
      std::string bytes(reinterpret_cast<const char *>(p), n);
      ghttp_ws_conn_output_consume(from->c, n);
      moved = true;
      auto pieces = fuzz::random_pieces(bytes, seed + round);
      for (const std::string & piece : pieces) {
        size_t off = 0;
        GHTTP_WsEvent ev;
        do {
          size_t used = 0;
          GHTTP_Result r = ghttp_ws_conn_feed(to->c, piece.data() + off, piece.size() - off, &used, &ev);
          REQUIRE(r == GHTTP_OK, "a peer's own output was refused");
          off += used;
          if (ev.type == GHTTP_WS_EVENT_TEXT || ev.type == GHTTP_WS_EVENT_BINARY) {
            REQUIRE(!to->expect.empty(), "a message arrived that was not sent");
            std::string got((ev.type == GHTTP_WS_EVENT_TEXT ? "T" : "B"));
            got.append(reinterpret_cast<const char *>(ev.data), ev.data_len);
            REQUIRE(got == to->expect.front(), "a message arrived different from what was sent");
            to->expect.pop_front();
          }
        } while (ev.type != GHTTP_WS_EVENT_NEED_MORE);
      }
    }
    if (!moved) {
      return;
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  GHTTP_WsNegotiated neg = fuzz::ws_negotiated_for(data[0] & 0x3f);
  uint8_t seed = data[1];
  GHTTP_WsLimits limits;
  ghttp_ws_limits_default(&limits);
  limits.max_buffered_bytes = 1 << 22;
  limits.max_control_per_interval = 1000000;  // the program sends as many pings as it likes
  limits.max_fragments = 1000000;
  End client, server;
  REQUIRE(ghttp_ws_conn_create(nullptr, GHTTP_WS_CLIENT, &limits, &neg, &client.c) == GHTTP_OK, "create");
  REQUIRE(ghttp_ws_conn_create(nullptr, GHTTP_WS_SERVER, &limits, &neg, &server.c) == GHTTP_OK, "create");
  ghttp_ws_conn_set_random(client.c, fuzz::ws_fixed_random, &client.rng);
  size_t pos = 2;
  bool closed = false;
  for (int ops = 0; pos < size && ops < 40 && !closed; ops++) {
    uint8_t op = data[pos++];
    End & from = (op & 0x80) ? server : client;
    End & to = (op & 0x80) ? client : server;
    unsigned kind = (op >> 4) & 7;
    unsigned n = op & 15;
    size_t len = n < 8 ? n * 13 : (n - 7) * 1500;
    len = std::min(len, size - pos);
    std::string raw(reinterpret_cast<const char *>(data + pos), len);
    pos += len;
    switch (kind) {
      case 0: {
        std::string m = utf8_of(raw);
        REQUIRE(ghttp_ws_conn_send_message(from.c, GHTTP_WS_MESSAGE_TEXT, m.data(), m.size()) == GHTTP_OK, "send text");
        to.expect.push_back("T" + m);
        break;
      }
      case 1:
        REQUIRE(ghttp_ws_conn_send_message(from.c, GHTTP_WS_MESSAGE_BINARY, raw.data(), raw.size()) == GHTTP_OK, "send binary");
        to.expect.push_back("B" + raw);
        break;
      case 2: {
        // Fragments of a text message: the cuts are anywhere, inside code points too.
        std::string m = utf8_of(raw);
        size_t off = 0;
        uint32_t x = seed + 1;
        do {
          x = x * 1103515245u + 12345u;
          size_t k = std::min(m.size() - off, static_cast<size_t>((x >> 16) % 40));
          bool fin = off + k >= m.size();
          REQUIRE(ghttp_ws_conn_send_fragment(from.c, GHTTP_WS_MESSAGE_TEXT, m.data() + off, k, fin) == GHTTP_OK, "send fragment");
          off += k;
          if (!fin && (x & 0x100)) {
            REQUIRE(ghttp_ws_conn_send_ping(from.c, "mid", 3) == GHTTP_OK, "ping between fragments");
          }
          if (fin) break;
        } while (true);
        to.expect.push_back("T" + m);
        break;
      }
      case 3:
        REQUIRE(ghttp_ws_conn_send_ping(from.c, raw.data(), std::min<size_t>(raw.size(), 125)) == GHTTP_OK, "send ping");
        break;
      default:
        REQUIRE(ghttp_ws_conn_close(from.c, 1000, "bye", 3) == GHTTP_OK, "close");
        closed = true;
        break;
    }
    pump(client, server, seed);
  }
  if (closed) {
    pump(client, server, seed);
    REQUIRE(ghttp_ws_conn_state(client.c) == GHTTP_WS_STATE_CLOSED && ghttp_ws_conn_state(server.c) == GHTTP_WS_STATE_CLOSED,
        "a close handshake did not complete");
  }
  REQUIRE(client.expect.empty() && server.expect.empty(), "a message was sent and never arrived");
  ghttp_ws_conn_destroy(client.c);
  ghttp_ws_conn_destroy(server.c);
  return 0;
}
