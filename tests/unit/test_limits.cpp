/**
 * @file
 *
 * Every GHTTP_Limits field: the input at the bound is accepted, one past it
 * is GHTTP_ERR_LIMIT, nothing is truncated, and the answer is the same
 * however the input is split.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace ghttptest;

namespace {

/** Run whole and byte by byte; the two must agree, and the result is returned. */
Outcome both(const std::string & s, const Options & o) {
  Outcome whole = run(s, o);
  Outcome bytes = run(by_bytes(s), o);
  EXPECT_EQ(whole, bytes) << "split-dependent result for a limit";
  return whole;
}

Options with(void (*set)(GHTTP_Limits &, size_t), size_t v) {
  Options o;
  set(o.limits, v);
  return o;
}

std::string post(const std::string & body_headers, const std::string & body) {
  return crlf("POST / HTTP/1.1\nHost: h\n" + body_headers + "\n\n") + body;
}

} // namespace

TEST(Limits, HeadBytesCountsEverythingThroughTheFinalEmptyLine) {
  std::string s = get();
  Options at = with([](GHTTP_Limits & l, size_t v) { l.max_head_bytes = v; }, s.size());
  Outcome ok = both(s, at);
  EXPECT_EQ(ok.result, GHTTP_OK);
  EXPECT_EQ(ok.msgs.size(), 1u);
  Options under = with([](GHTTP_Limits & l, size_t v) { l.max_head_bytes = v; }, s.size() - 1);
  Outcome over = both(s, under);
  EXPECT_EQ(over.result, GHTTP_ERR_LIMIT);
  EXPECT_TRUE(over.msgs.empty()) << "no head is reported past the cap";
}

TEST(Limits, HeadBytesAlsoCountsEmptyLinesBeforeTheRequestLine) {
  std::string s = "\r\n\r\n" + get();
  Options at = with([](GHTTP_Limits & l, size_t v) { l.max_head_bytes = v; }, s.size());
  EXPECT_EQ(both(s, at).result, GHTTP_OK);
  Options under = with([](GHTTP_Limits & l, size_t v) { l.max_head_bytes = v; }, s.size() - 1);
  EXPECT_EQ(both(s, under).result, GHTTP_ERR_LIMIT);
  // An endless run of empty lines is bounded, not a way to hold a connection.
  std::string empties;
  for (int i = 0; i < 200; i++) {
    empties += "\r\n";
  }
  Options small = with([](GHTTP_Limits & l, size_t v) { l.max_head_bytes = v; }, 100);
  EXPECT_EQ(both(empties, small).result, GHTTP_ERR_LIMIT);
}

TEST(Limits, LineLengthBoundsTheStartLineAndEachFieldLine) {
  // Start line "GET /<pad> HTTP/1.1".
  for (size_t pad : {0u, 1u, 50u}) {
    std::string target = "/" + std::string(pad, 'a');
    std::string line = "GET " + target + " HTTP/1.1";
    std::string s = line + "\r\nHost: h\r\n\r\n";
    Options at = with([](GHTTP_Limits & l, size_t v) { l.max_line_length = v; }, line.size());
    EXPECT_EQ(both(s, at).result, GHTTP_OK) << pad;
    Options under = with([](GHTTP_Limits & l, size_t v) { l.max_line_length = v; }, line.size() - 1);
    EXPECT_EQ(both(s, under).result, GHTTP_ERR_LIMIT) << pad;
  }
  std::string field = "X: " + std::string(40, 'v');
  std::string s = "GET / HTTP/1.1\r\nHost: h\r\n" + field + "\r\n\r\n";
  Options at = with([](GHTTP_Limits & l, size_t v) { l.max_line_length = v; }, field.size());
  EXPECT_EQ(both(s, at).result, GHTTP_OK);
  Options under = with([](GHTTP_Limits & l, size_t v) { l.max_line_length = v; }, field.size() - 1);
  EXPECT_EQ(both(s, under).result, GHTTP_ERR_LIMIT);
}

TEST(Limits, LineLengthIsCheckedBeforeTheLineEnds) {
  // A line that never ends must stop at the cap, not at the end of input.
  Options o = with([](GHTTP_Limits & l, size_t v) { l.max_line_length = v; }, 16);
  Outcome r = both("GET /" + std::string(1000, 'a'), o);
  EXPECT_EQ(r.result, GHTTP_ERR_LIMIT);
}

TEST(Limits, HeaderCountBoundsTheFieldsAndNotTheStartLine) {
  std::string s = "GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\n\r\n";
  Options at = with([](GHTTP_Limits & l, size_t v) { l.max_header_count = v; }, 3);
  EXPECT_EQ(both(s, at).result, GHTTP_OK);
  Options under = with([](GHTTP_Limits & l, size_t v) { l.max_header_count = v; }, 2);
  EXPECT_EQ(both(s, under).result, GHTTP_ERR_LIMIT);
  Options none = with([](GHTTP_Limits & l, size_t v) { l.max_header_count = v; }, 0);
  EXPECT_EQ(both("GET / HTTP/1.0\r\n\r\n", none).result, GHTTP_OK);
  EXPECT_EQ(both("GET / HTTP/1.0\r\nA: 1\r\n\r\n", none).result, GHTTP_ERR_LIMIT);
}

TEST(Limits, ContentLengthOverTheBodyCapIsRefusedAtTheHead) {
  Options o = with([](GHTTP_Limits & l, size_t v) { l.max_body_bytes = v; }, 5);
  Outcome ok = both(post("Content-Length: 5", "hello"), o);
  EXPECT_EQ(ok.result, GHTTP_OK);
  EXPECT_EQ(ok.msgs[0].body, "hello");
  Outcome over = both(post("Content-Length: 6", "hello!"), o);
  EXPECT_EQ(over.result, GHTTP_ERR_LIMIT);
  EXPECT_TRUE(over.msgs.empty()) << "refused before the head is reported";
}

TEST(Limits, BodyCapDoesNotApplyToAHeadResponsesAdvertisedLength) {
  Options o = responses();
  o.limits.max_body_bytes = 5;
  o.methods = {"HEAD"};
  EXPECT_EQ(both(crlf("HTTP/1.1 200 OK\nContent-Length: 1000000\n\n"), o).result,
      GHTTP_OK);
}

TEST(Limits, ChunkedBodyTotalIsCappedAndNeverTruncated) {
  Options o = with([](GHTTP_Limits & l, size_t v) { l.max_body_bytes = v; }, 6);
  std::string h = "Transfer-Encoding: chunked";
  Outcome ok = both(post(h, "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"), o);
  EXPECT_EQ(ok.result, GHTTP_OK);
  EXPECT_EQ(ok.msgs[0].body, "abcdef");
  Outcome over = both(post(h, "3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"), o);
  EXPECT_EQ(over.result, GHTTP_ERR_LIMIT);
  ASSERT_EQ(over.msgs.size(), 1u);
  EXPECT_FALSE(over.msgs[0].ended);
  EXPECT_EQ(over.msgs[0].body, "abc")
      << "bytes delivered before the refusal are exactly those before the chunk";
}

TEST(Limits, ChunkSizeIsCappedByTheDeclaredSizeBeforeAnyOfItIsRead) {
  Options o = with([](GHTTP_Limits & l, size_t v) { l.max_chunk_size = v; }, 4);
  std::string h = "Transfer-Encoding: chunked";
  EXPECT_EQ(both(post(h, "4\r\nabcd\r\n0\r\n\r\n"), o).result, GHTTP_OK);
  Outcome over = both(post(h, "5\r\n"), o);
  EXPECT_EQ(over.result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(both(post(h, "ffffffffffffffff\r\n"), o).result, GHTTP_ERR_LIMIT);
  EXPECT_EQ(both(post(h, "10000000000000000\r\n"), o).result, GHTTP_ERR_LIMIT)
      << "a size beyond 64 bits does not wrap to something small";
  EXPECT_EQ(both(post(h, "00000000000000000000000000000004\r\nabcd\r\n0\r\n\r\n"),
                Options())
                .result,
      GHTTP_OK)
      << "leading zeros are not a size";
}

TEST(Limits, ChunkSizeLineLengthCountsTheExtensions) {
  Options o = with([](GHTTP_Limits & l, size_t v) { l.max_line_length = v; }, 10);
  std::string h = "Transfer-Encoding: chunked";
  Options wide;
  wide.limits.max_line_length = 4000;
  std::string ext(3000, 'e');
  EXPECT_EQ(both(post(h, "1;" + ext + "\r\nx\r\n0\r\n\r\n"), wide).result, GHTTP_OK);
  wide.limits.max_line_length = 2999;
  EXPECT_EQ(both(post(h, "1;" + ext + "\r\nx\r\n0\r\n\r\n"), wide).result,
      GHTTP_ERR_LIMIT);
  wide.limits.max_line_length = 3002;
  EXPECT_EQ(both(post(h, "1;" + ext + "\r\nx\r\n0\r\n\r\n"), wide).result, GHTTP_OK);
  wide.limits.max_line_length = 3001;
  EXPECT_EQ(both(post(h, "1;" + ext + "\r\nx\r\n0\r\n\r\n"), wide).result,
      GHTTP_ERR_LIMIT);
}

TEST(Limits, TrailerBytesAndCountAreCappedSeparatelyFromTheHead) {
  std::string h = "Transfer-Encoding: chunked";
  std::string trailers = "T1: a\r\nT2: b\r\n\r\n";
  std::string s = post(h, "0\r\n" + trailers);
  Options at;
  at.limits.max_trailer_bytes = trailers.size();
  EXPECT_EQ(both(s, at).result, GHTTP_OK);
  at.limits.max_trailer_bytes = trailers.size() - 1;
  EXPECT_EQ(both(s, at).result, GHTTP_ERR_LIMIT);
  Options count;
  count.limits.max_trailer_count = 2;
  EXPECT_EQ(both(s, count).result, GHTTP_OK);
  count.limits.max_trailer_count = 1;
  EXPECT_EQ(both(s, count).result, GHTTP_ERR_LIMIT);
  Options zero;
  zero.limits.max_trailer_count = 0;
  zero.limits.max_trailer_bytes = 2;
  EXPECT_EQ(both(post(h, "0\r\n\r\n"), zero).result, GHTTP_OK);
}

TEST(Limits, ACloseDelimitedBodyIsCappedAndDeliveredUpToTheCapOnly) {
  Options o = responses();
  o.limits.max_body_bytes = 8;
  Outcome ok = both(crlf("HTTP/1.1 200 OK\n\n") + "12345678", o);
  EXPECT_EQ(ok.result, GHTTP_OK);
  EXPECT_EQ(ok.msgs[0].body, "12345678");
  Outcome over = both(crlf("HTTP/1.1 200 OK\n\n") + "123456789", o);
  EXPECT_EQ(over.result, GHTTP_ERR_LIMIT);
  ASSERT_EQ(over.msgs.size(), 1u);
  EXPECT_EQ(over.msgs[0].body, "12345678")
      << "the body stops at the bound however the input was split";
}

TEST(Limits, ALimitErrorIsStickyAndNothingFurtherIsReported) {
  GHTTP_Parser * p = nullptr;
  GHTTP_Limits l;
  ghttp_limits_default(&l);
  l.max_header_count = 0;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, &l, nullptr, &p), GHTTP_OK);
  std::string bad = "GET / HTTP/1.0\r\nA: 1\r\n\r\n";
  size_t used;
  GHTTP_Event ev;
  EXPECT_EQ(ghttp_parser_feed(p, bad.data(), bad.size(), &used, &ev),
      GHTTP_ERR_LIMIT);
  std::string good = "GET / HTTP/1.0\r\n\r\n";
  EXPECT_EQ(ghttp_parser_feed(p, good.data(), good.size(), &used, &ev),
      GHTTP_ERR_LIMIT);
  ghttp_parser_destroy(p);
}

TEST(Limits, EveryZeroLimitRefusesItsQuantityAndNothingElse) {
  std::string s = get() + post("Content-Length: 1", "x");
  Options o;
  o.limits.max_body_bytes = 0;
  Outcome r = both(s, o);
  EXPECT_EQ(r.result, GHTTP_ERR_LIMIT);
  ASSERT_EQ(r.msgs.size(), 1u) << "the first request has no body and is fine";
}

TEST(Limits, SmallLimitsNeverMakeTheResultDependOnTheSplit) {
  // Sweep each cap from zero through a little past what a fixture needs.
  std::string s = crlf("POST /p HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nT: v\r\n\r\n";
  for (size_t v = 0; v < 120; v++) {
    for (int field = 0; field < 7; field++) {
      Options o;
      GHTTP_Limits & l = o.limits;
      switch (field) {
        case 0: l.max_head_bytes = v; break;
        case 1: l.max_line_length = v; break;
        case 2: l.max_header_count = v; break;
        case 3: l.max_trailer_bytes = v; break;
        case 4: l.max_trailer_count = v; break;
        case 5: l.max_body_bytes = v; break;
        case 6: l.max_chunk_size = v; break;
      }
      Outcome whole = run(s, o);
      for (size_t cut = 1; cut < s.size(); cut++) {
        Outcome split = run(split_at(s, cut), o);
        ASSERT_EQ(whole, split) << "field " << field << " limit " << v << " cut " << cut;
      }
      ASSERT_EQ(whole, run(by_bytes(s), o)) << "field " << field << " limit " << v;
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
