/**
 * @file
 *
 * Request parsing: framing, the smuggling shapes RFC 9112 forbids, and the
 * syntax the parser refuses rather than guesses at.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace ghttptest;

TEST(RequestParse, ReadsTheRequestExampleOfRfc9112Section2_1) {
  // RFC 9112 section 2.1.
  Outcome o = run(crlf("GET /hello.txt HTTP/1.1\n"
                       "User-Agent: curl/7.64.1\n"
                       "Host: www.example.com\n"
                       "Accept-Language: en, mi\n\n"));
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  const Msg & m = o.msgs[0];
  EXPECT_EQ(m.method, "GET");
  EXPECT_EQ(m.target, "/hello.txt");
  EXPECT_EQ(m.minor, 1);
  EXPECT_EQ(m.fields, (std::vector<Field>{{"User-Agent", "curl/7.64.1"},
                          {"Host", "www.example.com"},
                          {"Accept-Language", "en, mi"}}));
  EXPECT_EQ(m.framing, GHTTP_FRAMING_NONE);
  EXPECT_TRUE(m.ended);
}

TEST(RequestParse, ContentLengthBodyEndsAfterItsLengthAndLeavesTheRest) {
  std::string first = crlf("POST /p HTTP/1.1\nHost: h\nContent-Length: 5\n\n") + "hello";
  std::string second = get();
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, nullptr, nullptr, &p),
      GHTTP_OK);
  std::string all = first + second;
  size_t off = 0;
  int ends = 0;
  std::string body;
  size_t end_at = 0;
  GHTTP_Event ev;
  do {
    size_t used;
    ASSERT_EQ(ghttp_parser_feed(p, all.data() + off, all.size() - off, &used,
                  &ev),
        GHTTP_OK);
    off += used;
    if (ev == GHTTP_EVENT_BODY) {
      const void * d;
      size_t n;
      ghttp_parser_body(p, &d, &n);
      body.append(static_cast<const char *>(d), n);
    }
    if (ev == GHTTP_EVENT_END && ++ends == 1) {
      end_at = off;
    }
  } while (ev != GHTTP_EVENT_NEED_MORE);
  EXPECT_EQ(body, "hello");
  EXPECT_EQ(ends, 2);
  EXPECT_EQ(end_at, first.size()) << "the first message ends exactly at its body";
  EXPECT_EQ(off, all.size());
  ghttp_parser_destroy(p);
}

TEST(RequestParse, PipelinedRequestsAreSeparateMessages) {
  Outcome o = run(get() + crlf("POST /y HTTP/1.1\nHost: h\nContent-Length: 2\n\nab")
      + get("X: 1"));
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 3u);
  EXPECT_EQ(o.msgs[1].body, "ab");
  EXPECT_EQ(o.msgs[2].fields.back(), (Field{"X", "1"}));
}

TEST(RequestParse, ZeroContentLengthIsAnEmptyBody) {
  Outcome o = run(crlf("POST / HTTP/1.1\nHost: h\nContent-Length: 0\n\n"));
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_EQ(o.msgs[0].framing, GHTTP_FRAMING_LENGTH);
  EXPECT_EQ(o.msgs[0].body, "");
  EXPECT_TRUE(o.msgs[0].ended);
}

TEST(RequestParse, ARequestWithNoLengthHasNoBody) {
  Outcome o = run(get() + get());
  ASSERT_EQ(o.msgs.size(), 2u);
  EXPECT_EQ(o.msgs[0].framing, GHTTP_FRAMING_NONE);
}

TEST(RequestParse, IgnoresEmptyLinesBeforeTheRequestLine) {
  // RFC 9112 section 2.2.
  Outcome o = run("\r\n\r\n" + get());
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_EQ(o.msgs[0].target, "/x");
}

TEST(RequestParse, EmptyLinesBeforeARequestAreIgnoredWhateverTheSplit) {
  std::string s = "\r\n" + get();
  EXPECT_EQ(run(by_bytes(s)), run(s));
  EXPECT_EQ(run(split_at(s, 1)), run(s));
}

TEST(RequestParse, ChunkedBodyIsDechunkedWithExtensionsAndTrailers) {
  Outcome o = run(crlf("POST /c HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "5\r\nhello\r\n"
        "6;name=value;other\r\n world\r\n"
        "0;last\r\n"
        "Trailer-A: 1\r\n"
        "Trailer-B:  two  \r\n"
        "\r\n");
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_EQ(o.msgs[0].framing, GHTTP_FRAMING_CHUNKED);
  EXPECT_EQ(o.msgs[0].body, "hello world");
  EXPECT_EQ(o.msgs[0].trailers,
      (std::vector<Field>{{"Trailer-A", "1"}, {"Trailer-B", "two"}}));
}

TEST(RequestParse, TrailersOfOneMessageAreNotReportedWithTheNext) {
  const std::string chunked =
      crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "1\r\na\r\n0\r\nT: v\r\n\r\n";
  for (const std::string & next :
      {crlf("POST / HTTP/1.1\nHost: h\nContent-Length: 1\n\nb"),
          crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
              + "1\r\nb\r\n0\r\n\r\n"}) {
    Outcome o = run(chunked + next);
    ASSERT_EQ(o.result, GHTTP_OK);
    ASSERT_EQ(o.msgs.size(), 2u);
    EXPECT_EQ(o.msgs[0].trailers, (std::vector<Field>{{"T", "v"}}));
    EXPECT_TRUE(o.msgs[1].trailers.empty());
  }
}

TEST(RequestParse, ChunkedBodyWithNoTrailersHasNone) {
  Outcome o = run(crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "3\r\nabc\r\n0\r\n\r\n");
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].body, "abc");
  EXPECT_TRUE(o.msgs[0].trailers.empty());
}

TEST(RequestParse, ChunkSizesAreCaseInsensitiveHexWithLeadingZeros) {
  Outcome o = run(crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "00000A\r\n0123456789\r\na\r\nabcdefghij\r\n0\r\n\r\n");
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].body, "0123456789abcdefghij");
}

TEST(RequestParse, TransferEncodingListsMayCarryOtherCodingsBeforeChunked) {
  Outcome o = run(crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: gzip, chunked\n\n")
      + "1\r\nx\r\n0\r\n\r\n");
  ASSERT_EQ(o.result, GHTTP_OK) << "content codings are the caller's";
  EXPECT_EQ(o.msgs[0].framing, GHTTP_FRAMING_CHUNKED);
}

TEST(RequestParse, TransferEncodingIsCaseInsensitiveAndMayBeSplitAcrossFields) {
  Outcome o = run(crlf("POST / HTTP/1.1\nHost: h\nTRANSFER-encoding: gzip\n"
                       "Transfer-Encoding: CHUNKED\n\n")
      + "1\r\nx\r\n0\r\n\r\n");
  EXPECT_EQ(o.result, GHTTP_OK);
}

TEST(RequestParse, DuplicateIdenticalContentLengthsAreOneLength) {
  // RFC 9112 section 6.3 item 5 allows replacing identical values with one.
  for (const char * cl : {"Content-Length: 3\nContent-Length: 3",
           "Content-Length: 3, 3", "Content-Length: 3\nContent-Length: 03"}) {
    Outcome o = run(crlf(std::string("POST / HTTP/1.1\nHost: h\n") + cl
        + "\n\nabc"));
    EXPECT_EQ(o.result, GHTTP_OK) << cl;
    ASSERT_EQ(o.msgs.size(), 1u) << cl;
    EXPECT_EQ(o.msgs[0].body, "abc") << cl;
  }
}

TEST(RequestParse, ObservesTheMethodAndTargetVerbatim) {
  Outcome o = run(crlf("M-SEARCH /a%2Fb?x=%20&y HTTP/1.1\nHost: h\n\n"));
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].method, "M-SEARCH");
  EXPECT_EQ(o.msgs[0].target, "/a%2Fb?x=%20&y");
}

TEST(RequestParse, FieldValuesLoseSurroundingWhitespaceAndKeepTheRest) {
  Outcome o = run(crlf("GET / HTTP/1.1\nHost:h\nA:   a  b \t\nB:\nC: \xc3\xa9\n\n"));
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].fields,
      (std::vector<Field>{{"Host", "h"}, {"A", "a  b"}, {"B", ""},
          {"C", "\xc3\xa9"}}));
}

TEST(RequestParse, Http10RequestNeedsNoHost) {
  Outcome o = run("GET / HTTP/1.0\r\n\r\n");
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].minor, 0);
}

TEST(RequestParse, ReportsConnectAndUpgradeWithoutActingOnThem) {
  Outcome c = run(crlf("CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\n"));
  ASSERT_EQ(c.result, GHTTP_OK);
  EXPECT_EQ(c.msgs[0].upgrade, GHTTP_UPGRADE_CONNECT);
  Outcome u = run(crlf("GET /ws HTTP/1.1\nHost: h\nConnection: keep-alive, Upgrade\n"
                       "Upgrade: websocket\n\n")
      + get());
  ASSERT_EQ(u.result, GHTTP_OK);
  ASSERT_EQ(u.msgs.size(), 2u) << "an Upgrade request is parsed as an ordinary one";
  EXPECT_EQ(u.msgs[0].upgrade, GHTTP_UPGRADE_UPGRADE);
  EXPECT_EQ(u.msgs[1].upgrade, GHTTP_UPGRADE_NONE);
  // Upgrade without Connection: upgrade is not an upgrade request.
  Outcome n = run(crlf("GET /ws HTTP/1.1\nHost: h\nUpgrade: websocket\n\n"));
  EXPECT_EQ(n.msgs[0].upgrade, GHTTP_UPGRADE_NONE);
}

TEST(RequestParse, AnOptionsAsteriskAndAnAbsoluteTargetAreAccepted) {
  EXPECT_EQ(result_of(crlf("OPTIONS * HTTP/1.1\nHost: h\n\n")), GHTTP_OK);
  EXPECT_EQ(result_of(crlf("GET http://example.com/a HTTP/1.1\nHost: h\n\n")),
      GHTTP_OK);
}

// ---------------------------------------------------------------------------
// Smuggling shapes: refused, never guessed at.

TEST(RequestSmuggling, ContentLengthWithTransferEncodingIsCorrupt) {
  for (const char * f : {"Content-Length: 5\nTransfer-Encoding: chunked",
           "Transfer-Encoding: chunked\nContent-Length: 5",
           "Content-Length: 0\nTransfer-Encoding: chunked"}) {
    EXPECT_EQ(result_of(crlf(std::string("POST / HTTP/1.1\nHost: h\n") + f
                  + "\n\n0\n\n")),
        GHTTP_ERR_CORRUPT)
        << f;
  }
}

TEST(RequestSmuggling, DifferingContentLengthsAreCorrupt) {
  for (const char * f : {"Content-Length: 5\nContent-Length: 6",
           "Content-Length: 5, 6", "Content-Length: 0\nContent-Length: 1"}) {
    EXPECT_EQ(result_of(crlf(std::string("POST / HTTP/1.1\nHost: h\n") + f
                  + "\n\nabcdef")),
        GHTTP_ERR_CORRUPT)
        << f;
  }
}

TEST(RequestSmuggling, MalformedContentLengthIsCorrupt) {
  for (const char * v : {"+5", "-5", "5 5", "0x5", "5.0", "", ",", "5,", ",5",
           "5,,5", "five", "\xc3\xa9"}) {
    EXPECT_EQ(result_of(crlf(std::string("POST / HTTP/1.1\nHost: h\nContent-Length: ")
                  + v + "\n\nabcdef")),
        GHTTP_ERR_CORRUPT)
        << "Content-Length: " << v;
  }
}

TEST(RequestSmuggling, ContentLengthBeyond64BitsIsALimitNotAWrap) {
  EXPECT_EQ(result_of(crlf("POST / HTTP/1.1\nHost: h\n"
                           "Content-Length: 18446744073709551616\n\n")),
      GHTTP_ERR_LIMIT);
  EXPECT_EQ(result_of(crlf("POST / HTTP/1.1\nHost: h\n"
                           "Content-Length: 99999999999999999999999999\n\n")),
      GHTTP_ERR_LIMIT);
}

TEST(RequestSmuggling, ContentLengthBeyond64BitsStillMeetsATransferEncodingFirst) {
  EXPECT_EQ(result_of(crlf("POST / HTTP/1.1\nHost: h\n"
                           "Content-Length: 99999999999999999999999999\n"
                           "Transfer-Encoding: chunked\n\n")),
      GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, ChunkedMustBeTheFinalTransferCoding) {
  for (const char * te : {"chunked, gzip", "chunked,gzip", "gzip", "identity",
           "chunked, chunked", "chunked\nTransfer-Encoding: gzip", "chunkedx",
           "x-chunked", ",", ""}) {
    EXPECT_EQ(result_of(crlf(std::string("POST / HTTP/1.1\nHost: h\n"
                                         "Transfer-Encoding: ")
                  + te + "\n\n0\n\n")),
        GHTTP_ERR_CORRUPT)
        << "Transfer-Encoding: " << te;
  }
}

TEST(RequestSmuggling, ABadTransferEncodingElementBeforeChunkedIsCorrupt) {
  for (const char * te : {"x y, chunked", "gzip;q=1, chunked", "g(zip, chunked"}) {
    EXPECT_EQ(result_of(crlf(std::string("POST / HTTP/1.1\nHost: h\n"
                                         "Transfer-Encoding: ")
                  + te + "\n\n0\n\n")),
        GHTTP_ERR_CORRUPT)
        << "Transfer-Encoding: " << te;
  }
}

TEST(RequestSmuggling, ATransferEncodingParameterIsNotAChunkedCoding) {
  EXPECT_EQ(result_of(crlf("POST / HTTP/1.1\nHost: h\n"
                           "Transfer-Encoding: chunked;q=1\n\n0\n\n")),
      GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, TransferEncodingInAnHttp10RequestIsCorrupt) {
  EXPECT_EQ(result_of(crlf("POST / HTTP/1.0\nTransfer-Encoding: chunked\n\n0\n\n")),
      GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, WhitespaceBeforeTheFieldColonIsCorrupt) {
  for (const char * f : {"Content-Length : 5", "Content-Length\t: 5",
           "Transfer-Encoding : chunked", "Host : h"}) {
    EXPECT_EQ(result_of(crlf(std::string("POST / HTTP/1.1\nHost: h\n") + f
                  + "\n\n")),
        GHTTP_ERR_CORRUPT)
        << f;
  }
}

TEST(RequestSmuggling, ObsoleteLineFoldingIsCorrupt) {
  EXPECT_EQ(result_of(crlf("GET / HTTP/1.1\nHost: h\nX: a\n b\n\n")),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("GET / HTTP/1.1\nHost: h\nX: a\n\tb\n\n")),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("GET / HTTP/1.1\n Host: h\n\n")), GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, ABareLfIsCorruptInTheStartLineAndInAField) {
  EXPECT_EQ(result_of("GET / HTTP/1.1\nHost: h\r\n\r\n"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\nHost: h\r\n\n"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, ABareCrIsCorruptInTheStartLineAndInAField) {
  EXPECT_EQ(result_of("GET /a\rb HTTP/1.1\r\nHost: h\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\nHost: h\r\n\rX"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\r\nHost: h\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, NulAndControlCharactersAreCorrupt) {
  EXPECT_EQ(result_of(std::string("GET / HTTP/1.1\r\nHost: h\0x\r\n\r\n", 29)),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\nHost: h\x01\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET / HTTP/1.1\r\nHost: h\x7f\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET /\x01 HTTP/1.1\r\nHost: h\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of("GET /\x7f HTTP/1.1\r\nHost: h\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
}

TEST(RequestSmuggling, AnHttp11RequestNeedsExactlyOneHost) {
  EXPECT_EQ(result_of(crlf("GET / HTTP/1.1\n\n")), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("GET / HTTP/1.1\nHost: a\nHost: b\n\n")),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("GET / HTTP/1.1\nHost: a\nhost: a\n\n")),
      GHTTP_ERR_CORRUPT);
}

// ---------------------------------------------------------------------------
// Syntax.

TEST(RequestSyntax, RefusesMalformedRequestLines) {
  for (const char * line : {"GET / HTTP/1.1 ", "GET  / HTTP/1.1", "GET /  HTTP/1.1",
           " GET / HTTP/1.1", "GET / HTTP/1.1 x", "GET /", "GET", "GET / ",
           "GET / http/1.1", "GET / HTTP/1.", "GET / HTTP/11", "GET / HTTP/1.11",
           "GET / HTTP/x.y", "G(T / HTTP/1.1", "/ GET HTTP/1.1",
           "GET / HTTP/1.1\tx", "GET\t/ HTTP/1.1", "GET /a\xc3\xa9 HTTP/1.1",
           "GET relative HTTP/1.1", "GET * HTTP/1.1", "CONNECT /x HTTP/1.1",
           "OPTIONS x HTTP/1.1"}) {
    EXPECT_EQ(result_of(std::string(line) + "\r\nHost: h\r\n\r\n"),
        GHTTP_ERR_CORRUPT)
        << line;
  }
}

TEST(RequestSyntax, WellFormedOtherVersionsAreUnsupportedNotCorrupt) {
  for (const char * v : {"HTTP/2.0", "HTTP/0.9", "HTTP/1.2", "HTTP/3.0",
           "HTTP/9.9"}) {
    EXPECT_EQ(result_of(std::string("GET / ") + v + "\r\nHost: h\r\n\r\n"),
        GHTTP_ERR_UNSUPPORTED)
        << v;
  }
  // The HTTP/2 connection preface starts like a request line.
  EXPECT_EQ(result_of("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), GHTTP_ERR_UNSUPPORTED);
}

TEST(RequestSyntax, RefusesMalformedFieldLines) {
  for (const char * line : {"NoColon", ": v", "A B: v", "A(: v", "A\x01: v",
           "\xc3\xa9: v", "A: v\x01", "A: v\x7f"}) {
    EXPECT_EQ(result_of(crlf(std::string("GET / HTTP/1.1\nHost: h\n") + line
                  + "\n\n")),
        GHTTP_ERR_CORRUPT)
        << line;
  }
}

TEST(RequestSyntax, AnEmptyInputOrOnlyEmptyLinesIsNoMessage) {
  Outcome o = run("");
  EXPECT_EQ(o.result, GHTTP_OK);
  EXPECT_TRUE(o.msgs.empty());
  Outcome e = run("\r\n\r\n");
  EXPECT_EQ(e.result, GHTTP_OK);
  EXPECT_TRUE(e.msgs.empty());
}

TEST(RequestSyntax, AHeadCutShortIsCorruptAtTheEndOfInput) {
  std::string s = get();
  for (size_t i = 1; i < s.size(); i++) {
    Outcome o = run(s.substr(0, i));
    EXPECT_EQ(o.result, GHTTP_ERR_CORRUPT) << "prefix of " << i << " bytes";
  }
}

TEST(RequestChunked, RefusesMalformedSizeLines) {
  const std::string head =
      crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n");
  for (const char * line : {"\r\n", "x\r\n", "-1\r\n", "+1\r\n", "0x5\r\n",
           "5x\r\n", " 5\r\n", "5 \r\n", "5\t\r\n", "5 x\r\n", "5;\x01\r\n",
           "5 ;a=b\r\n", "5\t;a\r\n", "5  ;\r\n",
           "5\n", "5\rx", "5;a\nb\r\n", "g\r\n", "\xc3\xa9\r\n", "5;a\x7f\r\n"}) {
    EXPECT_EQ(result_of(head + line + "hello\r\n0\r\n\r\n"),
        GHTTP_ERR_CORRUPT)
        << "size line [" << line << "]";
  }
}

TEST(RequestChunked, ChunkDataMustBeFollowedByExactlyCrLf) {
  const std::string head =
      crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n");
  for (const char * after : {"\n", "\r", "xx", "\r\r", "\n\r", " \r\n"}) {
    EXPECT_EQ(result_of(head + "5\r\nhello" + after + "0\r\n\r\n"),
        GHTTP_ERR_CORRUPT)
        << "after data [" << after << "]";
  }
}

TEST(RequestChunked, ChunkSizeLargerThanTheDataCannotHideTheNextRequest) {
  // A chunk declaring more bytes than are sent swallows what follows; the
  // truncated message is reported as such, never as a complete one.
  Outcome o = run(crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n")
      + "ff\r\nshort");
  EXPECT_EQ(o.result, GHTTP_ERR_CORRUPT);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_FALSE(o.msgs[0].ended);
}

TEST(RequestChunked, TrailersMayNotCarryFraming) {
  const std::string head =
      crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n") + "0\r\n";
  EXPECT_EQ(result_of(head + "Content-Length: 5\r\n\r\n"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(head + "transfer-encoding: chunked\r\n\r\n"),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(head + "X-Ok: 1\r\n\r\n"), GHTTP_OK);
}

TEST(RequestChunked, TrailerLinesAreHeldToTheFieldRules) {
  const std::string head =
      crlf("POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n") + "0\r\n";
  EXPECT_EQ(result_of(head + "X : 1\r\n\r\n"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(head + "X: 1\n\r\n"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(head + "X: 1\r\n y\r\n\r\n"), GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(head + "nocolon\r\n\r\n"), GHTTP_ERR_CORRUPT);
}

TEST(ParserApi, ErrorsAreStickyAndTheParserIsNotRecoverable) {
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, nullptr, nullptr, &p),
      GHTTP_OK);
  std::string bad = "GET / HTTP/1.1\nHost: h\r\n\r\n";
  std::string good = get();
  size_t used;
  GHTTP_Event ev;
  EXPECT_EQ(ghttp_parser_feed(p, bad.data(), bad.size(), &used, &ev),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(ghttp_parser_feed(p, good.data(), good.size(), &used, &ev),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(ghttp_parser_finish(p, &ev), GHTTP_ERR_CORRUPT);
  ghttp_parser_destroy(p);
}

TEST(ParserApi, RejectsBadArguments) {
  GHTTP_Parser * p = nullptr;
  EXPECT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, nullptr, nullptr, nullptr),
      GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_create(static_cast<GHTTP_ParserKind>(7), nullptr,
                nullptr, &p),
      GHTTP_ERR_INVALID);
  EXPECT_EQ(p, nullptr);
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, nullptr, nullptr, &p),
      GHTTP_OK);
  size_t used;
  GHTTP_Event ev;
  EXPECT_EQ(ghttp_parser_feed(p, nullptr, 1, &used, &ev), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_feed(nullptr, "x", 1, &used, &ev), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_feed(p, "x", 1, nullptr, &ev), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_feed(p, "x", 1, &used, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_feed(p, nullptr, 0, &used, &ev), GHTTP_OK)
      << "an empty feed is allowed and is how a pending END is collected";
  EXPECT_EQ(ghttp_parser_expect_response_to(p, "GET"), GHTTP_ERR_INVALID)
      << "a request parser has no use for it";
  EXPECT_EQ(ghttp_parser_request(p), nullptr) << "no head yet";
  EXPECT_EQ(ghttp_parser_response(p), nullptr);
  ghttp_parser_destroy(p);
  ghttp_parser_destroy(nullptr);
}

TEST(ParserApi, ARequestParserHasNoResponseAndViceVersa) {
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, nullptr, nullptr, &p),
      GHTTP_OK);
  std::string s = get();
  size_t used;
  GHTTP_Event ev;
  ASSERT_EQ(ghttp_parser_feed(p, s.data(), s.size(), &used, &ev), GHTTP_OK);
  ASSERT_EQ(ev, GHTTP_EVENT_HEAD);
  EXPECT_NE(ghttp_parser_request(p), nullptr);
  EXPECT_EQ(ghttp_parser_response(p), nullptr);
  ghttp_parser_destroy(p);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
