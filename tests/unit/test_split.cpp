/**
 * @file
 *
 * The central property: a message and any split of its bytes give the same
 * head, fields, body and trailers as the message whole. Every fixture is cut
 * at every byte boundary, fed one byte at a time, and fed in fixed sizes.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <random>

#include "test_helpers.h"

using namespace ghttptest;

namespace {

struct Fixture {
  const char * name;
  std::string bytes;
  Options opt;
  size_t messages;
};

std::vector<Fixture> fixtures() {
  std::vector<Fixture> f;
  Options req;
  Options resp = responses();
  f.push_back({"simple get", get("Accept: */*"), req, 1});
  f.push_back({"leading empty lines", "\r\n\r\n" + get(), req, 1});
  f.push_back({"content-length body",
      crlf("POST /p HTTP/1.1\nHost: h\nContent-Length: 11\n\n") + "hello world", req, 1});
  f.push_back({"zero content-length",
      crlf("POST /p HTTP/1.1\nHost: h\nContent-Length: 0\n\n"), req, 1});
  f.push_back({"chunked with extensions and trailers",
      crlf("POST /c HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
          + "5\r\nhello\r\n6;a=b;c\r\n world\r\n0;done\r\nT1: x\r\nT2:  y \r\n\r\n",
      req, 1});
  f.push_back({"chunked with no trailers",
      crlf("POST /c HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
          + "1\r\na\r\n0\r\n\r\n",
      req, 1});
  f.push_back({"pipelined",
      get() + crlf("PUT /b HTTP/1.1\nHost: h\nContent-Length: 3\n\nabc")
          + crlf("POST /c HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
          + "2\r\nab\r\n0\r\n\r\n" + get("X: y"),
      req, 4});
  f.push_back({"connect", crlf("CONNECT a.example:443 HTTP/1.1\nHost: a.example:443\n\n"),
      req, 1});
  f.push_back({"upgrade request",
      crlf("GET /s HTTP/1.1\nHost: h\nConnection: Upgrade\nUpgrade: x\n\n"), req, 1});
  f.push_back({"response with length",
      crlf("HTTP/1.1 200 OK\nContent-Length: 6\nServer: s\n\n") + "abcdef", resp, 1});
  f.push_back({"response interim then final",
      crlf("HTTP/1.1 100 Continue\n\nHTTP/1.1 200 OK\nContent-Length: 2\n\n") + "ok", resp,
      2});
  f.push_back({"response chunked with trailer",
      crlf("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n")
          + "3\r\nabc\r\n0\r\nExpires: never\r\n\r\n",
      resp, 1});
  f.push_back({"response close-delimited",
      crlf("HTTP/1.1 200 OK\nServer: s\n\n") + "to the end of the connection", resp, 1});
  Options head = responses();
  head.methods = {"HEAD", "GET"};
  f.push_back({"response to head",
      crlf("HTTP/1.1 200 OK\nContent-Length: 500\n\n")
          + crlf("HTTP/1.1 204 No Content\n\n"),
      head, 2});
  Options conn = responses();
  conn.methods = {"CONNECT"};
  f.push_back({"response to connect",
      crlf("HTTP/1.1 200 Connection established\n\n"), conn, 1});
  f.push_back({"upgrade response", crlf("HTTP/1.1 101 Switching\nUpgrade: x\n\n"), resp, 1});
  return f;
}

} // namespace

TEST(Split, EveryTwoWaySplitGivesTheSameResultAsTheWholeMessage) {
  for (const Fixture & fx : fixtures()) {
    Outcome whole = run(fx.bytes, fx.opt);
    ASSERT_EQ(whole.result, GHTTP_OK) << fx.name << "\n" << whole;
    ASSERT_EQ(whole.msgs.size(), fx.messages) << fx.name;
    for (const Msg & m : whole.msgs) {
      ASSERT_TRUE(m.ended) << fx.name;
    }
    for (size_t cut = 0; cut <= fx.bytes.size(); cut++) {
      Outcome split = run(split_at(fx.bytes, cut), fx.opt);
      ASSERT_EQ(split, whole) << fx.name << " cut at " << cut;
    }
  }
}

TEST(Split, OneByteAtATimeGivesTheSameResultAsTheWholeMessage) {
  for (const Fixture & fx : fixtures()) {
    ASSERT_EQ(run(by_bytes(fx.bytes), fx.opt), run(fx.bytes, fx.opt)) << fx.name;
  }
}

TEST(Split, EveryFixedPieceSizeGivesTheSameResult) {
  for (const Fixture & fx : fixtures()) {
    Outcome whole = run(fx.bytes, fx.opt);
    for (size_t k = 1; k <= 24; k++) {
      ASSERT_EQ(run(by_size(fx.bytes, k), fx.opt), whole) << fx.name << " k=" << k;
    }
  }
}

TEST(Split, EveryThreeWaySplitOfASmallMessageGivesTheSameResult) {
  std::string s = crlf("POST /c HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "2;e\r\nab\r\n0\r\nT: v\r\n\r\n";
  Outcome whole = run(s);
  ASSERT_EQ(whole.result, GHTTP_OK);
  for (size_t a = 0; a <= s.size(); a++) {
    for (size_t b = a; b <= s.size(); b++) {
      std::vector<std::string> pieces = {s.substr(0, a), s.substr(a, b - a),
          s.substr(b)};
      ASSERT_EQ(run(pieces), whole) << a << "," << b;
    }
  }
}

TEST(Split, RandomSplitsOfAWholeFixtureSetGiveTheSameResult) {
  std::mt19937 rng(12345);
  for (const Fixture & fx : fixtures()) {
    Outcome whole = run(fx.bytes, fx.opt);
    for (int round = 0; round < 200; round++) {
      std::vector<std::string> pieces;
      size_t pos = 0;
      while (pos < fx.bytes.size()) {
        size_t n = 1 + rng() % 17;
        pieces.push_back(fx.bytes.substr(pos, n));
        pos += n;
      }
      ASSERT_EQ(run(pieces, fx.opt), whole) << fx.name << " round " << round;
    }
  }
}

TEST(Split, ErrorsAreTheSameAtEverySplitToo) {
  // The refused inputs of the other suites, cut at every boundary: the same
  // error, and the same messages reported before it.
  const std::vector<std::string> bad = {
      crlf("POST / HTTP/1.1\nHost: h\nContent-Length: 5\nTransfer-Encoding: chunked\n\n0\n\n"),
      crlf("POST / HTTP/1.1\nHost: h\nContent-Length: 5\nContent-Length: 6\n\nabcdef"),
      crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked, gzip\n\n"),
      crlf("GET / HTTP/1.1\nHost : h\n\n"),
      crlf("GET / HTTP/1.1\nHost: h\nX: a\n b\n\n"),
      "GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n",
      "GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n",
      get() + crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\nz\r\n"),
      get() + crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
          + "3\r\nabcX\r\n",
      crlf("GET / HTTP/2.0\nHost: h\n\n"),
      crlf("GET / HTTP/1.1\n\n"),
  };
  for (const std::string & s : bad) {
    Outcome whole = run(s);
    ASSERT_NE(whole.result, GHTTP_OK) << s;
    ASSERT_EQ(run(by_bytes(s)), whole) << s;
    for (size_t cut = 0; cut <= s.size(); cut++) {
      ASSERT_EQ(run(split_at(s, cut)), whole) << s << " cut " << cut;
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
