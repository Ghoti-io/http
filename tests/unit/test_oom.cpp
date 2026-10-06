/**
 * @file
 *
 * Allocation failure at every allocation: the parser reports GHTTP_ERR_OOM or
 * the same answer as without a failure, and nothing leaks.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace ghttptest;

namespace {

struct Case {
  const char * name;
  std::string bytes;
  Options opt;
};

std::vector<Case> cases() {
  std::vector<Case> c;
  c.push_back({"request with fields", get("A: 1\nB: 2\nC: 3"), Options()});
  c.push_back({"content-length",
      crlf("POST /p HTTP/1.1\nHost: h\nContent-Length: 5\n\n") + "hello", Options()});
  c.push_back({"chunked with trailers",
      crlf("POST /p HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
          + "3\r\nabc\r\n0\r\nT: v\r\nU: w\r\n\r\n",
      Options()});
  c.push_back({"pipelined", get() + get("X: y") + get(), Options()});
  c.push_back({"response",
      crlf("HTTP/1.1 200 OK\nServer: s\nContent-Length: 2\n\n") + "ok", responses()});
  c.push_back({"refused head", crlf("GET / HTTP/1.1\n\n"), Options()});
  return c;
}

} // namespace

TEST(Oom, EveryAllocationFailingInTurnIsOomOrTheSameAnswerAndNeverALeak) {
  for (const Case & c : cases()) {
    Options base = c.opt;
    Outcome expected = run(c.bytes, base);
    // How many allocations a clean run makes, so the sweep knows when it is done.
    FailingAllocator counter(static_cast<size_t>(-1));
    Options counted = c.opt;
    counted.allocator = counter.get();
    ASSERT_EQ(run(c.bytes, counted), expected) << c.name;
    ASSERT_EQ(counter.live(), 0u) << c.name;
    size_t total = counter.requests();
    ASSERT_GT(total, 0u);
    size_t oom = 0;
    for (size_t run_len : {size_t(1), size_t(0), size_t(2)}) {
      for (size_t k = 0; k <= total + 1; k++) {
        FailingAllocator fa(k, run_len);
        Options o = c.opt;
        o.allocator = fa.get();
        Outcome got = run(c.bytes, o);
        if (fa.failed()) {
          // A refused allocation is reported as such, or - for a refusal in an
          // optional growth - the answer is unchanged. Either way, no leak.
          if (got.result == GHTTP_ERR_OOM) {
            oom++;
          } else {
            EXPECT_EQ(got, expected) << c.name << " k=" << k << " run=" << run_len;
          }
        } else {
          EXPECT_EQ(got, expected) << c.name << " k=" << k;
        }
        EXPECT_EQ(fa.live(), 0u) << c.name << " k=" << k << " run=" << run_len;
      }
    }
    EXPECT_GT(oom, 0u) << c.name << ": the sweep never saw an OOM";
  }
}

TEST(Oom, ByteAtATimeInputFailsAtEveryAllocationToo) {
  std::string s = crlf("POST /p HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "3\r\nabc\r\n0\r\nT: v\r\n\r\n";
  Outcome expected = run(s);
  FailingAllocator counter(static_cast<size_t>(-1));
  Options counted;
  counted.allocator = counter.get();
  ASSERT_EQ(run(by_bytes(s), counted), expected);
  size_t total = counter.requests();
  for (size_t k = 0; k <= total; k++) {
    FailingAllocator fa(k, 0);
    Options o;
    o.allocator = fa.get();
    Outcome got = run(by_bytes(s), o);
    if (fa.failed()) {
      EXPECT_EQ(got.result, GHTTP_ERR_OOM) << k;
    }
    EXPECT_EQ(fa.live(), 0u) << k;
  }
}

TEST(Oom, ParserCreationFailureIsOomAndLeaksNothing) {
  for (size_t k = 0; k < 12; k++) {
    FailingAllocator fa(k, 0);
    GHTTP_Parser * p = nullptr;
    GHTTP_Result r = ghttp_parser_create(
        GHTTP_PARSE_REQUEST, nullptr, fa.get(), &p);
    if (r == GHTTP_OK) {
      ghttp_parser_destroy(p);
    } else {
      EXPECT_EQ(r, GHTTP_ERR_OOM);
      EXPECT_EQ(p, nullptr);
    }
    EXPECT_EQ(fa.live(), 0u) << k;
  }
}

TEST(Oom, ObjectCreationFailureIsOomAndLeaksNothing) {
  for (size_t k = 0; k < 12; k++) {
    FailingAllocator fa(k, 0);
    GHTTP_Request * q = nullptr;
    GHTTP_Result r = ghttp_request_create(fa.get(), &q);
    if (r == GHTTP_OK) {
      ghttp_request_destroy(q);
    } else {
      EXPECT_EQ(r, GHTTP_ERR_OOM);
    }
    GHTTP_Response * s = nullptr;
    GHTTP_Result r2 = ghttp_response_create(fa.get(), &s);
    if (r2 == GHTTP_OK) {
      ghttp_response_destroy(s);
    }
    EXPECT_EQ(fa.live(), 0u) << k;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
