/**
 * @file
 *
 * The writer: exact bytes, refusal of what the parser would refuse, and the
 * round trip build, serialise, parse.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace ghttptest;

namespace {

struct Req {
  GHTTP_Request * r = nullptr;
  Req() { EXPECT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK); }
  ~Req() { ghttp_request_destroy(r); }
  void add(const char * n, const char * v) {
    EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(r), n, v), GHTTP_OK);
  }
};

struct Resp {
  GHTTP_Response * r = nullptr;
  Resp() { EXPECT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK); }
  ~Resp() { ghttp_response_destroy(r); }
  void add(const char * n, const char * v) {
    EXPECT_EQ(ghttp_headers_add(ghttp_response_headers(r), n, v), GHTTP_OK);
  }
};

struct Buf {
  GHTTP_Buffer * b = nullptr;
  Buf() { EXPECT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK); }
  ~Buf() { ghttp_buffer_destroy(b); }
  std::string str() const {
    return std::string(static_cast<const char *>(ghttp_buffer_data(b)),
        ghttp_buffer_size(b));
  }
};

} // namespace

TEST(Writer, RequestHeadBytes) {
  Req q;
  ASSERT_EQ(ghttp_request_set_method(q.r, "POST"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_target(q.r, "/a?b=c"), GHTTP_OK);
  q.add("Host", "example.com");
  q.add("Content-Length", "4");
  q.add("X-Empty", "");
  Buf b;
  ASSERT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_OK);
  EXPECT_EQ(b.str(),
      "POST /a?b=c HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n"
      "X-Empty:\r\n\r\n");
}

TEST(Writer, ResponseHeadBytes) {
  Resp s;
  ASSERT_EQ(ghttp_response_set_status(s.r, 404, "Not Found"), GHTTP_OK);
  s.add("Content-Length", "0");
  Buf b;
  ASSERT_EQ(ghttp_write_response_head(b.b, s.r), GHTTP_OK);
  EXPECT_EQ(b.str(), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  ASSERT_EQ(ghttp_response_set_status(s.r, 204, nullptr), GHTTP_OK);
  ASSERT_EQ(ghttp_response_set_version(s.r, 0), GHTTP_OK);
  ghttp_buffer_clear(b.b);
  ASSERT_EQ(ghttp_write_response_head(b.b, s.r), GHTTP_OK);
  EXPECT_EQ(b.str(), "HTTP/1.0 204 \r\nContent-Length: 0\r\n\r\n")
      << "the separator after the code stays even with no reason";
}

TEST(Writer, ChunkAndLastChunkBytes) {
  Buf b;
  ASSERT_EQ(ghttp_write_chunk(b.b, "hello", 5), GHTTP_OK);
  std::string big(300, 'z');
  ASSERT_EQ(ghttp_write_chunk(b.b, big.data(), big.size()), GHTTP_OK);
  GHTTP_Headers * t = nullptr;
  ASSERT_EQ(ghttp_headers_create(nullptr, &t), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t, "Digest", "abc"), GHTTP_OK);
  ASSERT_EQ(ghttp_write_chunked_end(b.b, t), GHTTP_OK);
  ghttp_headers_destroy(t);
  EXPECT_EQ(b.str(), "5\r\nhello\r\n12c\r\n" + big + "\r\n0\r\nDigest: abc\r\n\r\n");
  Buf plain;
  ASSERT_EQ(ghttp_write_chunked_end(plain.b, nullptr), GHTTP_OK);
  EXPECT_EQ(plain.str(), "0\r\n\r\n");
}

TEST(Writer, ARequestHeadTheParserWouldRefuseIsInvalidAndWritesNothing) {
  Buf b;
  ASSERT_EQ(ghttp_buffer_append(b.b, "keep", 4), GHTTP_OK);
  {
    Req q; // HTTP/1.1 with no Host
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID);
  }
  {
    Req q;
    q.add("Host", "a");
    q.add("Host", "b");
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID);
  }
  {
    Req q;
    q.add("Host", "a");
    q.add("Content-Length", "1");
    q.add("Transfer-Encoding", "chunked");
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID);
  }
  {
    Req q;
    q.add("Host", "a");
    q.add("Content-Length", "1");
    q.add("content-length", "2");
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID);
  }
  {
    Req q;
    q.add("Host", "a");
    q.add("Transfer-Encoding", "chunked, gzip");
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID);
  }
  {
    Req q;
    q.add("Host", "a");
    q.add("Content-Length", "99999999999999999999999");
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID)
        << "a limit in the parser is an invalid argument to the writer";
  }
  {
    Req q;
    q.add("Host", "a");
    ASSERT_EQ(ghttp_request_set_method(q.r, "CONNECT"), GHTTP_OK);
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID)
        << "CONNECT's target is an authority";
  }
  {
    Req q;
    q.add("Host", "a");
    ASSERT_EQ(ghttp_request_set_version(q.r, 0), GHTTP_OK);
    q.add("Transfer-Encoding", "chunked");
    EXPECT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_ERR_INVALID);
  }
  EXPECT_EQ(b.str(), "keep");
  EXPECT_EQ(ghttp_write_request_head(nullptr, nullptr), GHTTP_ERR_INVALID);
}

TEST(Writer, CrLfInAValueNeverReachesTheWire) {
  // The setters refuse it, so the only way to the writer is to be refused first.
  Req q;
  EXPECT_EQ(ghttp_headers_add(ghttp_request_headers(q.r), "X", "a\r\nHost: evil"),
      GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_target(q.r, "/a\r\n\r\nGET /evil"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_method(q.r, "GET\r\nX:y"), GHTTP_ERR_INVALID);
  Resp s;
  EXPECT_EQ(ghttp_response_set_status(s.r, 200, "OK\r\nSet-Cookie: x"),
      GHTTP_ERR_INVALID);
}

TEST(Writer, ChunkArgumentsAndTrailers) {
  Buf b;
  EXPECT_EQ(ghttp_write_chunk(b.b, "x", 0), GHTTP_ERR_INVALID)
      << "a zero-size chunk would end the body";
  EXPECT_EQ(ghttp_write_chunk(b.b, nullptr, 3), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_write_chunk(nullptr, "x", 1), GHTTP_ERR_INVALID);
  GHTTP_Headers * t = nullptr;
  ASSERT_EQ(ghttp_headers_create(nullptr, &t), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t, "Content-Length", "3"), GHTTP_OK);
  EXPECT_EQ(ghttp_write_chunked_end(b.b, t), GHTTP_ERR_INVALID)
      << "the parser refuses framing in trailers";
  ghttp_headers_clear(t);
  ASSERT_EQ(ghttp_headers_add(t, "Transfer-Encoding", "chunked"), GHTTP_OK);
  EXPECT_EQ(ghttp_write_chunked_end(b.b, t), GHTTP_ERR_INVALID);
  ghttp_headers_destroy(t);
  EXPECT_EQ(b.str(), "");
}

TEST(Writer, RequestRoundTripWithContentLength) {
  Req q;
  ASSERT_EQ(ghttp_request_set_method(q.r, "PUT"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_set_target(q.r, "/items/7?x=%20y"), GHTTP_OK);
  q.add("Host", "api.example");
  q.add("Content-Type", "application/json");
  q.add("Content-Length", "13");
  q.add("X-Dup", "1");
  q.add("x-dup", "2");
  Buf b;
  ASSERT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_OK);
  ASSERT_EQ(ghttp_buffer_append(b.b, "{\"ok\":true,1}", 13), GHTTP_OK);
  Outcome o = run(b.str());
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_EQ(o.msgs[0].method, "PUT");
  EXPECT_EQ(o.msgs[0].target, "/items/7?x=%20y");
  EXPECT_EQ(o.msgs[0].fields, fields_of(ghttp_request_headers_const(q.r)));
  EXPECT_EQ(o.msgs[0].body, "{\"ok\":true,1}");
}

TEST(Writer, ResponseRoundTripChunkedWithTrailers) {
  Resp s;
  ASSERT_EQ(ghttp_response_set_status(s.r, 201, "Created"), GHTTP_OK);
  s.add("Transfer-Encoding", "chunked");
  s.add("Server", "t");
  Buf b;
  ASSERT_EQ(ghttp_write_response_head(b.b, s.r), GHTTP_OK);
  ASSERT_EQ(ghttp_write_chunk(b.b, "first ", 6), GHTTP_OK);
  ASSERT_EQ(ghttp_write_chunk(b.b, "second", 6), GHTTP_OK);
  GHTTP_Headers * t = nullptr;
  ASSERT_EQ(ghttp_headers_create(nullptr, &t), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t, "Checksum", "abc123"), GHTTP_OK);
  ASSERT_EQ(ghttp_write_chunked_end(b.b, t), GHTTP_OK);
  Outcome o = run(b.str(), responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_EQ(o.msgs[0].status, 201);
  EXPECT_EQ(o.msgs[0].reason, "Created");
  EXPECT_EQ(o.msgs[0].body, "first second");
  EXPECT_EQ(o.msgs[0].trailers, fields_of(t));
  EXPECT_EQ(o.msgs[0].fields, fields_of(ghttp_response_headers_const(s.r)));
  ghttp_headers_destroy(t);
}

TEST(Writer, EveryTargetFormRoundTrips) {
  struct Case { const char * method; const char * target; };
  for (Case c : {Case{"GET", "/"}, Case{"GET", "http://h.example/p?q"},
           Case{"CONNECT", "h.example:443"}, Case{"OPTIONS", "*"},
           Case{"M-SEARCH", "/x"}}) {
    Req q;
    ASSERT_EQ(ghttp_request_set_method(q.r, c.method), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(q.r, c.target), GHTTP_OK);
    q.add("Host", "h.example");
    Buf b;
    ASSERT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_OK) << c.method;
    Outcome o = run(b.str());
    ASSERT_EQ(o.result, GHTTP_OK) << c.method << ' ' << c.target;
    EXPECT_EQ(o.msgs[0].method, c.method);
    EXPECT_EQ(o.msgs[0].target, c.target);
  }
}

TEST(Writer, Http10MessagesRoundTripWithoutHost) {
  Req q;
  ASSERT_EQ(ghttp_request_set_version(q.r, 0), GHTTP_OK);
  Buf b;
  ASSERT_EQ(ghttp_write_request_head(b.b, q.r), GHTTP_OK);
  EXPECT_EQ(b.str(), "GET / HTTP/1.0\r\n\r\n");
  Outcome o = run(b.str());
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].minor, 0);
}

TEST(Writer, AFailedWriteLeavesTheBufferAsItWas) {
  Req q;
  q.add("Host", "h");
  // Enough fields that the buffer must grow while the head is written.
  for (int i = 0; i < 20; i++) {
    q.add(("X-Field-" + std::to_string(i)).c_str(),
        "a value of a length that fills the buffer");
  }
  size_t failures_seen = 0;
  for (size_t run_len : {size_t(1), size_t(0)}) {
    for (size_t k = 0; k < 40; k++) {
      FailingAllocator fa(k, run_len);
      GHTTP_Buffer * b = nullptr;
      if (ghttp_buffer_create(fa.get(), &b) != GHTTP_OK) {
        EXPECT_EQ(fa.live(), 0u);
        continue;
      }
      GHTTP_Result r = ghttp_buffer_append(b, "keep", 4);
      if (r == GHTTP_OK) {
        r = ghttp_write_request_head(b, q.r);
        if (r != GHTTP_OK) {
          failures_seen++;
          EXPECT_EQ(r, GHTTP_ERR_OOM);
          EXPECT_EQ(ghttp_buffer_size(b), 4u) << "k=" << k;
        }
      }
      ghttp_buffer_destroy(b);
      EXPECT_EQ(fa.live(), 0u) << "k=" << k;
    }
  }
  EXPECT_GT(failures_seen, 0u) << "the sweep reached a failing write";
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
