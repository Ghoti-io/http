/**
 * @file
 *
 * Response parsing and body framing, RFC 9112 section 6.3.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace ghttptest;

TEST(ResponseParse, ReadsTheResponseExampleOfRfc9112Section2_1) {
  // RFC 9112 section 2.1: a 200 with a 51-byte body.
  std::string body = "Hello World! My content includes a trailing CRLF.\r\n";
  ASSERT_EQ(body.size(), 51u);
  Outcome o = run(crlf("HTTP/1.1 200 OK\n"
                       "Date: Mon, 27 Jul 2009 12:28:53 GMT\n"
                       "Server: Apache\n"
                       "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\n"
                       "ETag: \"34aa387-d-1568eb00\"\n"
                       "Accept-Ranges: bytes\n"
                       "Content-Length: 51\n"
                       "Vary: Accept-Encoding\n"
                       "Content-Type: text/plain\n\n")
          + body,
      responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  const Msg & m = o.msgs[0];
  EXPECT_FALSE(m.is_request);
  EXPECT_EQ(m.status, 200);
  EXPECT_EQ(m.reason, "OK");
  EXPECT_EQ(m.fields.size(), 8u);
  EXPECT_EQ(m.fields[3], (Field{"ETag", "\"34aa387-d-1568eb00\""}));
  EXPECT_EQ(m.body, body);
  EXPECT_EQ(m.framing, GHTTP_FRAMING_LENGTH);
}

TEST(ResponseParse, TheReasonPhraseMayBeEmptyButItsSeparatorIsRequired) {
  Outcome o = run("HTTP/1.1 204 \r\n\r\n", responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].reason, "");
  EXPECT_EQ(result_of("HTTP/1.1 204\r\n\r\n", responses()), GHTTP_ERR_CORRUPT);
}

TEST(ResponseParse, ReasonPhraseKeepsInnerSpacesAndTabs) {
  Outcome o = run("HTTP/1.1 404 Not  Found\there\r\nContent-Length: 0\r\n\r\n",
      responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].reason, "Not  Found\there");
}

TEST(ResponseParse, RefusesMalformedStatusLines) {
  for (const char * line : {"HTTP/1.1 20 OK", "HTTP/1.1 2000 OK", "HTTP/1.1 abc OK",
           "HTTP/1.1  200 OK", "HTTP/1.1\t200 OK", "HTTP/1.1 200\tOK",
           "HTTP/1.1 099 OK", "http/1.1 200 OK", "HTTP/1.1", "200 OK",
           "HTTP/1.1 200 O\x01K", "HTTP/1.1 +200 OK", " HTTP/1.1 200 OK",
           "HTTP/1.11 200 OK"}) {
    EXPECT_EQ(result_of(std::string(line) + "\r\nContent-Length: 0\r\n\r\n",
                  responses()),
        GHTTP_ERR_CORRUPT)
        << line;
  }
}

TEST(ResponseParse, AResponseMayNotStartWithAnEmptyLine) {
  EXPECT_EQ(result_of("\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                responses()),
      GHTTP_ERR_CORRUPT);
}

TEST(ResponseParse, OtherVersionsAreUnsupported) {
  EXPECT_EQ(result_of("HTTP/2.0 200 OK\r\n\r\n", responses()),
      GHTTP_ERR_UNSUPPORTED);
  EXPECT_EQ(result_of("HTTP/0.9 200 OK\r\n\r\n", responses()),
      GHTTP_ERR_UNSUPPORTED);
}

TEST(ResponseFraming, ResponseToHeadHasNoBodyWhateverItsHeadersSay) {
  Options o = responses();
  o.methods = {"HEAD", "GET"};
  Outcome out = run(crlf("HTTP/1.1 200 OK\nContent-Length: 1000\n\n")
          + crlf("HTTP/1.1 200 OK\nContent-Length: 2\n\n") + "ok",
      o);
  ASSERT_EQ(out.result, GHTTP_OK);
  ASSERT_EQ(out.msgs.size(), 2u);
  EXPECT_EQ(out.msgs[0].framing, GHTTP_FRAMING_NONE);
  EXPECT_EQ(out.msgs[0].body, "");
  EXPECT_EQ(out.msgs[1].body, "ok");
}

TEST(ResponseFraming, ResponseToHeadWithChunkedOrNoLengthHasNoBody) {
  Options o = responses();
  o.methods = {"HEAD", "HEAD", "GET"};
  Outcome out = run(crlf("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n")
          + crlf("HTTP/1.1 200 OK\n\n") + crlf("HTTP/1.1 200 OK\nContent-Length: 0\n\n"),
      o);
  ASSERT_EQ(out.result, GHTTP_OK);
  ASSERT_EQ(out.msgs.size(), 3u);
  for (const Msg & m : out.msgs) {
    EXPECT_EQ(m.body, "");
    EXPECT_TRUE(m.ended);
  }
}

TEST(ResponseFraming, NoContentAndNotModifiedHaveNoBody) {
  for (int status : {204, 304}) {
    std::string r = "HTTP/1.1 " + std::to_string(status)
        + " X\r\nContent-Length: 7\r\n\r\n";
    std::string next = crlf("HTTP/1.1 200 OK\nContent-Length: 1\n\nz");
    Outcome o = run(r + next, responses());
    ASSERT_EQ(o.result, GHTTP_OK) << status;
    ASSERT_EQ(o.msgs.size(), 2u) << status;
    EXPECT_EQ(o.msgs[0].framing, GHTTP_FRAMING_NONE);
    EXPECT_EQ(o.msgs[0].body, "");
    EXPECT_EQ(o.msgs[1].body, "z");
  }
}

TEST(ResponseFraming, InformationalResponsesAreFollowedByTheFinalOne) {
  Options o = responses();
  o.methods = {"HEAD"};
  Outcome out = run(crlf("HTTP/1.1 100 Continue\n\n")
          + crlf("HTTP/1.1 103 Early Hints\nLink: </a>; rel=preload\n\n")
          + crlf("HTTP/1.1 200 OK\nContent-Length: 5\n\n"),
      o);
  ASSERT_EQ(out.result, GHTTP_OK);
  ASSERT_EQ(out.msgs.size(), 3u);
  EXPECT_EQ(out.msgs[0].status, 100);
  EXPECT_EQ(out.msgs[1].status, 103);
  EXPECT_EQ(out.msgs[2].status, 200);
  EXPECT_EQ(out.msgs[2].framing, GHTTP_FRAMING_NONE)
      << "the HEAD still applies to the final response after interim ones";
}

TEST(ResponseFraming, TheMethodIsForgottenAfterAFinalResponse) {
  Options o = responses();
  o.methods = {"HEAD"}; // the second response gets the default, a GET
  Outcome out = run(crlf("HTTP/1.1 200 OK\nContent-Length: 4\n\n")
          + crlf("HTTP/1.1 200 OK\nContent-Length: 2\n\n") + "ok",
      o);
  ASSERT_EQ(out.result, GHTTP_OK);
  ASSERT_EQ(out.msgs.size(), 2u);
  EXPECT_EQ(out.msgs[1].body, "ok");
}

TEST(ResponseFraming, ChunkedResponseWithTrailers) {
  Outcome o = run(crlf("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n")
          + "4\r\nWiki\r\n5\r\npedia\r\n0\r\nExpires: never\r\n\r\n",
      responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  EXPECT_EQ(o.msgs[0].body, "Wikipedia");
  EXPECT_EQ(o.msgs[0].trailers, (std::vector<Field>{{"Expires", "never"}}));
}

TEST(ResponseFraming, ABodyWithNoLengthRunsToTheEndOfTheConnection) {
  std::string s = crlf("HTTP/1.1 200 OK\nServer: x\n\n") + "until the end";
  Outcome o = run(s, responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_EQ(o.msgs[0].framing, GHTTP_FRAMING_CLOSE);
  EXPECT_EQ(o.msgs[0].body, "until the end");
  EXPECT_TRUE(o.msgs[0].ended);
}

TEST(ResponseFraming, ACloseDelimitedBodyIsNotCompleteWithoutTheClose) {
  Options opt = responses();
  opt.finish = false;
  Outcome o = run(crlf("HTTP/1.1 200 OK\n\n") + "partial", opt);
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_FALSE(o.msgs[0].ended) << "END is reported only by finish()";
  EXPECT_EQ(o.msgs[0].body, "partial");
}

TEST(ResponseFraming, AnEmptyCloseDelimitedBodyEndsAtTheClose) {
  Outcome o = run(crlf("HTTP/1.0 200 OK\n\n"), responses());
  ASSERT_EQ(o.result, GHTTP_OK);
  ASSERT_EQ(o.msgs.size(), 1u);
  EXPECT_TRUE(o.msgs[0].ended);
  EXPECT_EQ(o.msgs[0].body, "");
}

TEST(ResponseFraming, ATruncatedBodyIsNeverReportedAsComplete) {
  Outcome length = run(crlf("HTTP/1.1 200 OK\nContent-Length: 10\n\n") + "short",
      responses());
  EXPECT_EQ(length.result, GHTTP_ERR_CORRUPT);
  ASSERT_EQ(length.msgs.size(), 1u);
  EXPECT_FALSE(length.msgs[0].ended);
  EXPECT_EQ(length.msgs[0].body, "short");
  Outcome chunked = run(crlf("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n")
          + "5\r\nhello\r\n",
      responses());
  EXPECT_EQ(chunked.result, GHTTP_ERR_CORRUPT);
  Outcome trailers = run(crlf("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n")
          + "0\r\nX: y\r\n",
      responses());
  EXPECT_EQ(trailers.result, GHTTP_ERR_CORRUPT);
}

TEST(ResponseFraming, TheEndOfInputBetweenMessagesIsClean) {
  Outcome o = run(crlf("HTTP/1.1 200 OK\nContent-Length: 1\n\nx"), responses());
  EXPECT_EQ(o.result, GHTTP_OK);
  Outcome none = run("", responses());
  EXPECT_EQ(none.result, GHTTP_OK);
  EXPECT_TRUE(none.msgs.empty());
}

TEST(ResponseFraming, ContentLengthWithTransferEncodingIsCorruptHere) {
  EXPECT_EQ(result_of(crlf("HTTP/1.1 200 OK\nContent-Length: 1\n"
                           "Transfer-Encoding: chunked\n\nx"),
                responses()),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("HTTP/1.1 200 OK\nContent-Length: 1\nContent-Length: 2\n\nx"),
                responses()),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("HTTP/1.1 200 OK\nTransfer-Encoding: chunked, gzip\n\n"),
                responses()),
      GHTTP_ERR_CORRUPT)
      << "RFC 9112 would read this to the end of the connection; the codec refuses";
}

TEST(ResponseFraming, ConflictsAreRefusedEvenWhereTheBodyWouldNotBeRead) {
  Options o = responses();
  o.methods = {"HEAD"};
  EXPECT_EQ(result_of(crlf("HTTP/1.1 200 OK\nContent-Length: 1\nContent-Length: 2\n\n"), o),
      GHTTP_ERR_CORRUPT);
  EXPECT_EQ(result_of(crlf("HTTP/1.1 204 No Content\nContent-Length: 1\n"
                           "Transfer-Encoding: chunked\n\n"),
                responses()),
      GHTTP_ERR_CORRUPT);
}

TEST(ResponseUpgrade, A101EndsHttpReadingAndLeavesTheRest) {
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_RESPONSE, nullptr, nullptr, &p),
      GHTTP_OK);
  std::string head = crlf("HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\n"
                          "Upgrade: websocket\n\n");
  std::string all = head + "\x81\x05hello";
  size_t off = 0;
  GHTTP_Event ev;
  int heads = 0, ends = 0;
  do {
    size_t used;
    ASSERT_EQ(ghttp_parser_feed(p, all.data() + off, all.size() - off, &used, &ev),
        GHTTP_OK);
    off += used;
    heads += ev == GHTTP_EVENT_HEAD;
    ends += ev == GHTTP_EVENT_END;
    if (ev == GHTTP_EVENT_HEAD) {
      EXPECT_EQ(ghttp_parser_upgrade(p), GHTTP_UPGRADE_UPGRADE);
    }
    if (ev == GHTTP_EVENT_END) {
      break;
    }
  } while (ev != GHTTP_EVENT_NEED_MORE);
  EXPECT_EQ(heads, 1);
  EXPECT_EQ(ends, 1);
  EXPECT_EQ(off, head.size()) << "the bytes after the head are not HTTP";
  size_t used = 99;
  EXPECT_EQ(ghttp_parser_feed(p, all.data() + off, all.size() - off, &used, &ev),
      GHTTP_OK);
  EXPECT_EQ(ev, GHTTP_EVENT_NEED_MORE);
  EXPECT_EQ(used, 0u) << "the parser reads nothing after a tunnel begins";
  EXPECT_EQ(ghttp_parser_finish(p, &ev), GHTTP_OK);
  EXPECT_EQ(ev, GHTTP_EVENT_NEED_MORE);
  ghttp_parser_destroy(p);
}

TEST(ResponseUpgrade, A2xxToConnectStartsATunnel) {
  Options o = responses();
  o.methods = {"CONNECT"};
  Outcome out = run(crlf("HTTP/1.1 200 Connection Established\n\n"), o);
  ASSERT_EQ(out.result, GHTTP_OK);
  ASSERT_EQ(out.msgs.size(), 1u);
  EXPECT_EQ(out.msgs[0].upgrade, GHTTP_UPGRADE_CONNECT);
  EXPECT_EQ(out.msgs[0].framing, GHTTP_FRAMING_NONE);
  EXPECT_TRUE(out.msgs[0].ended);

  // Bytes after the head belong to the tunnel and are not consumed.
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_RESPONSE, nullptr, nullptr, &p),
      GHTTP_OK);
  ASSERT_EQ(ghttp_parser_expect_response_to(p, "CONNECT"), GHTTP_OK);
  std::string head = crlf("HTTP/1.1 200 OK\n\n");
  std::string all = head + "tunnel bytes";
  size_t off = 0;
  GHTTP_Event ev;
  do {
    size_t used;
    ASSERT_EQ(ghttp_parser_feed(p, all.data() + off, all.size() - off, &used, &ev),
        GHTTP_OK);
    off += used;
  } while (ev != GHTTP_EVENT_NEED_MORE);
  EXPECT_EQ(off, head.size());
  ghttp_parser_destroy(p);
}

TEST(ResponseUpgrade, AConnectFailureIsNotATunnelAndTheNextResponseIsOrdinary) {
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_RESPONSE, nullptr, nullptr, &p),
      GHTTP_OK);
  ASSERT_EQ(ghttp_parser_expect_response_to(p, "CONNECT"), GHTTP_OK);
  // No second expect_response_to: the CONNECT is forgotten after the 403.
  std::string all = crlf("HTTP/1.1 403 Forbidden\nContent-Length: 0\n\n")
      + crlf("HTTP/1.1 200 OK\nContent-Length: 2\n\n") + "ok";
  size_t off = 0;
  GHTTP_Event ev;
  int heads = 0;
  std::string body;
  do {
    size_t used;
    ASSERT_EQ(ghttp_parser_feed(p, all.data() + off, all.size() - off, &used, &ev),
        GHTTP_OK);
    off += used;
    if (ev == GHTTP_EVENT_HEAD) {
      heads++;
      EXPECT_EQ(ghttp_parser_upgrade(p), GHTTP_UPGRADE_NONE);
    }
    if (ev == GHTTP_EVENT_BODY) {
      const void * d;
      size_t n;
      ghttp_parser_body(p, &d, &n);
      body.append(static_cast<const char *>(d), n);
    }
  } while (ev != GHTTP_EVENT_NEED_MORE);
  EXPECT_EQ(heads, 2);
  EXPECT_EQ(body, "ok");
  EXPECT_EQ(off, all.size());
  ghttp_parser_destroy(p);
}

TEST(ResponseUpgrade, ANon2xxToConnectIsAnOrdinaryResponse) {
  Options o = responses();
  o.methods = {"CONNECT", "GET"};
  Outcome out = run(crlf("HTTP/1.1 403 Forbidden\nContent-Length: 2\n\nno")
          + crlf("HTTP/1.1 200 OK\nContent-Length: 0\n\n"),
      o);
  ASSERT_EQ(out.result, GHTTP_OK);
  ASSERT_EQ(out.msgs.size(), 2u);
  EXPECT_EQ(out.msgs[0].upgrade, GHTTP_UPGRADE_NONE);
  EXPECT_EQ(out.msgs[0].body, "no");
}

TEST(ParserApi, ExpectResponseToNeedsAResponseParserAndAMethod) {
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_RESPONSE, nullptr, nullptr, &p),
      GHTTP_OK);
  EXPECT_EQ(ghttp_parser_expect_response_to(p, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_expect_response_to(nullptr, "GET"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_parser_expect_response_to(p, "HEAD"), GHTTP_OK);
  EXPECT_EQ(ghttp_parser_request(p), nullptr);
  ghttp_parser_destroy(p);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
