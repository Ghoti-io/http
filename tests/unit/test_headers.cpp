/**
 * @file
 *
 * The header list, the request and response objects and the buffer.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace ghttptest;

namespace {
struct Headers {
  GHTTP_Headers * h = nullptr;
  Headers() { EXPECT_EQ(ghttp_headers_create(nullptr, &h), GHTTP_OK); }
  ~Headers() { ghttp_headers_destroy(h); }
};
} // namespace

TEST(Headers, KeepsOrderCaseAndDuplicates) {
  Headers t;
  ASSERT_EQ(ghttp_headers_add(t.h, "Set-Cookie", "a=1"), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t.h, "X-Other", "v"), GHTTP_OK);
  ASSERT_EQ(ghttp_headers_add(t.h, "set-cookie", "b=2"), GHTTP_OK);
  std::vector<Field> expect = {
      {"Set-Cookie", "a=1"}, {"X-Other", "v"}, {"set-cookie", "b=2"}};
  EXPECT_EQ(fields_of(t.h), expect);
}

TEST(Headers, FindIgnoresCaseAndWalksDuplicates) {
  Headers t;
  ghttp_headers_add(t.h, "Via", "1");
  ghttp_headers_add(t.h, "Other", "x");
  ghttp_headers_add(t.h, "VIA", "2");
  EXPECT_EQ(ghttp_headers_find(t.h, "via", 0), 0u);
  EXPECT_EQ(ghttp_headers_find(t.h, "via", 1), 2u);
  EXPECT_EQ(ghttp_headers_find(t.h, "via", 3), GHTTP_HEADERS_NPOS);
  EXPECT_EQ(ghttp_headers_find(t.h, "vi", 0), GHTTP_HEADERS_NPOS);
  EXPECT_EQ(ghttp_headers_find(t.h, "viaa", 0), GHTTP_HEADERS_NPOS);
}

TEST(Headers, ValueIsStoredWithoutSurroundingWhitespace) {
  Headers t;
  ASSERT_EQ(ghttp_headers_add(t.h, "A", " \t v w \t "), GHTTP_OK);
  GHTTP_Field f;
  ASSERT_EQ(ghttp_headers_at(t.h, 0, &f), GHTTP_OK);
  EXPECT_EQ(std::string(f.value, f.value_len), "v w");
  EXPECT_EQ(f.value[f.value_len], '\0');
  EXPECT_EQ(f.name[f.name_len], '\0');
}

TEST(Headers, AnEmptyValueIsAllowed) {
  Headers t;
  ASSERT_EQ(ghttp_headers_add(t.h, "A", ""), GHTTP_OK);
  EXPECT_EQ(fields_of(t.h), (std::vector<Field>{{"A", ""}}));
}

TEST(Headers, RefusesCrLfAndNulAndOtherControlsInAValue) {
  Headers t;
  for (const char * bad : {"a\r\nX: y", "a\nb", "a\rb", "a\x01 b", "a\x7f"
                           "b"}) {
    EXPECT_EQ(ghttp_headers_add(t.h, "A", bad), GHTTP_ERR_INVALID) << bad;
  }
  EXPECT_EQ(ghttp_headers_count(t.h), 0u);
}

TEST(Headers, AcceptsTabAndHighBytesInAValue) {
  Headers t;
  EXPECT_EQ(ghttp_headers_add(t.h, "A", "a\tb\xc3\xa9"), GHTTP_OK);
}

TEST(Headers, RefusesANameThatIsNotAToken) {
  Headers t;
  for (const char * bad : {"", "A B", "A:", "A\r\nB", " A", "A ", "a(b)", "a/b",
           "\xc3\xa9"}) {
    EXPECT_EQ(ghttp_headers_add(t.h, bad, "v"), GHTTP_ERR_INVALID) << bad;
  }
}

TEST(Headers, RejectsNullArguments) {
  Headers t;
  EXPECT_EQ(ghttp_headers_add(nullptr, "A", "v"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_headers_add(t.h, nullptr, "v"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_headers_add(t.h, "A", nullptr), GHTTP_ERR_INVALID);
  GHTTP_Field f;
  EXPECT_EQ(ghttp_headers_at(t.h, 0, &f), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_headers_at(t.h, 0, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_headers_create(nullptr, nullptr), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_headers_count(nullptr), 0u);
  ghttp_headers_destroy(nullptr);
  ghttp_headers_clear(nullptr);
}

TEST(Headers, ViewsSurviveUntilTheNextAddOnlyAndGrowthKeepsEarlierFields) {
  Headers t;
  std::vector<Field> expect;
  for (int i = 0; i < 500; i++) {
    std::string n = "N" + std::to_string(i);
    std::string v = std::string(i % 40, 'x') + std::to_string(i);
    ASSERT_EQ(ghttp_headers_add(t.h, n.c_str(), v.c_str()), GHTTP_OK);
    expect.push_back({n, v});
  }
  EXPECT_EQ(fields_of(t.h), expect);
  ghttp_headers_clear(t.h);
  EXPECT_EQ(ghttp_headers_count(t.h), 0u);
  ASSERT_EQ(ghttp_headers_add(t.h, "A", "v"), GHTTP_OK);
  EXPECT_EQ(ghttp_headers_count(t.h), 1u);
}

TEST(Headers, AnAllocationFailureLeavesTheListAsItWas) {
  for (size_t fail = 0; fail < 12; fail++) {
    FailingAllocator fa(fail, 0);
    GHTTP_Headers * h = nullptr;
    GHTTP_Result r = ghttp_headers_create(fa.get(), &h);
    if (r != GHTTP_OK) {
      EXPECT_EQ(r, GHTTP_ERR_OOM);
      EXPECT_EQ(fa.live(), 0u);
      continue;
    }
    GHTTP_Result a = ghttp_headers_add(h, "Name", "value");
    if (a != GHTTP_OK) {
      EXPECT_EQ(a, GHTTP_ERR_OOM);
      EXPECT_EQ(ghttp_headers_count(h), 0u) << "fail at " << fail;
    } else {
      EXPECT_EQ(ghttp_headers_count(h), 1u);
    }
    ghttp_headers_destroy(h);
    EXPECT_EQ(fa.live(), 0u) << "fail at " << fail;
  }
}

// ---------------------------------------------------------------------------

TEST(Request, StartsAsAGetOfSlashAtHttp11) {
  GHTTP_Request * r = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  EXPECT_STREQ(ghttp_request_method(r), "GET");
  EXPECT_STREQ(ghttp_request_target(r), "/");
  EXPECT_EQ(ghttp_request_version(r), 1);
  EXPECT_EQ(ghttp_headers_count(ghttp_request_headers_const(r)), 0u);
  ghttp_request_destroy(r);
}

TEST(Request, SettersCopyAndRefuseWhatTheParserWouldRefuse) {
  GHTTP_Request * r = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  std::string m = "POST";
  ASSERT_EQ(ghttp_request_set_method(r, m.c_str()), GHTTP_OK);
  m[0] = 'X';
  EXPECT_STREQ(ghttp_request_method(r), "POST");
  EXPECT_EQ(ghttp_request_set_method(r, "PO ST"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_method(r, ""), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_method(r, "G\r\nET"), GHTTP_ERR_INVALID);
  EXPECT_STREQ(ghttp_request_method(r), "POST");
  EXPECT_EQ(ghttp_request_set_target(r, ""), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_target(r, "/a b"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_target(r, "/a\r\nHost: evil"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_target(r, "/a\tb"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_target(r, "/caf\xc3\xa9"), GHTTP_ERR_INVALID);
  EXPECT_STREQ(ghttp_request_target(r), "/");
  EXPECT_EQ(ghttp_request_set_version(r, 2), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_version(r, -1), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_request_set_version(r, 0), GHTTP_OK);
  EXPECT_EQ(ghttp_request_version(r), 0);
  ghttp_request_destroy(r);
}

TEST(Request, TargetFormIsClassifiedForTheMethod) {
  GHTTP_Request * r = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  GHTTP_TargetForm f;
  struct Case { const char * method; const char * target; int form; };
  const Case ok[] = {
      {"GET", "/", GHTTP_TARGET_ORIGIN},
      {"GET", "/a/b?c=d", GHTTP_TARGET_ORIGIN},
      {"GET", "http://example.com/a", GHTTP_TARGET_ABSOLUTE},
      {"GET", "https://example.com", GHTTP_TARGET_ABSOLUTE},
      {"CONNECT", "example.com:443", GHTTP_TARGET_AUTHORITY},
      {"CONNECT", "[::1]:8080", GHTTP_TARGET_AUTHORITY},
      {"OPTIONS", "*", GHTTP_TARGET_ASTERISK},
  };
  for (const Case & c : ok) {
    ASSERT_EQ(ghttp_request_set_method(r, c.method), GHTTP_OK);
    ASSERT_EQ(ghttp_request_set_target(r, c.target), GHTTP_OK);
    ASSERT_EQ(ghttp_request_target_form(r, &f), GHTTP_OK)
        << c.method << ' ' << c.target;
    EXPECT_EQ(f, c.form) << c.method << ' ' << c.target;
  }
  const Case bad[] = {
      {"GET", "*", 0},               // asterisk belongs to OPTIONS
      {"GET", "example.com:443", 0}, // authority belongs to CONNECT
      {"CONNECT", "/path", 0},
      {"CONNECT", "example.com", 0}, // no port
      {"CONNECT", "example.com:", 0},
      {"CONNECT", ":443", 0},
      {"CONNECT", "a@b:443", 0},
      {"GET", "relative", 0},
      {"GET", "1http://x", 0},
      {"GET", "ht tp://x", 0},
  };
  for (const Case & c : bad) {
    ASSERT_EQ(ghttp_request_set_method(r, c.method), GHTTP_OK);
    if (ghttp_request_set_target(r, c.target) != GHTTP_OK) {
      continue; // refused earlier still
    }
    EXPECT_EQ(ghttp_request_target_form(r, &f), GHTTP_ERR_INVALID)
        << c.method << ' ' << c.target;
  }
  ghttp_request_destroy(r);
}

TEST(Request, OriginFormSplitsAtTheFirstQuestionMarkWithoutDecoding) {
  GHTTP_Request * r = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  const char * path;
  size_t plen;
  const char * q;
  size_t qlen;
  ASSERT_EQ(ghttp_request_set_target(r, "/a%2Fb/c?x=1?y=%20"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_target_split(r, &path, &plen, &q, &qlen), GHTTP_OK);
  EXPECT_EQ(std::string(path, plen), "/a%2Fb/c");
  EXPECT_EQ(std::string(q, qlen), "x=1?y=%20");
  ASSERT_EQ(ghttp_request_set_target(r, "/plain"), GHTTP_OK);
  ASSERT_EQ(ghttp_request_target_split(r, &path, &plen, &q, &qlen), GHTTP_OK);
  EXPECT_EQ(std::string(path, plen), "/plain");
  EXPECT_EQ(q, nullptr);
  EXPECT_EQ(qlen, 0u);
  ASSERT_EQ(ghttp_request_set_target(r, "http://h/x"), GHTTP_OK);
  EXPECT_EQ(ghttp_request_target_split(r, &path, &plen, &q, &qlen),
      GHTTP_ERR_INVALID);
  ghttp_request_destroy(r);
}

TEST(Request, GettersAcceptNull) {
  EXPECT_EQ(ghttp_request_method(nullptr), nullptr);
  EXPECT_EQ(ghttp_request_target(nullptr), nullptr);
  EXPECT_EQ(ghttp_request_version(nullptr), 0);
  EXPECT_EQ(ghttp_request_headers(nullptr), nullptr);
  EXPECT_EQ(ghttp_request_headers_const(nullptr), nullptr);
  EXPECT_EQ(ghttp_response_status(nullptr), 0);
  EXPECT_EQ(ghttp_response_reason(nullptr), nullptr);
  EXPECT_EQ(ghttp_response_version(nullptr), 0);
  EXPECT_EQ(ghttp_response_headers(nullptr), nullptr);
  EXPECT_EQ(ghttp_response_headers_const(nullptr), nullptr);
}

TEST(Request, ATargetWithDelWillNotBeSet) {
  GHTTP_Request * r = nullptr;
  ASSERT_EQ(ghttp_request_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_request_set_target(r, "/a\x7f"), GHTTP_ERR_INVALID);
  ghttp_request_destroy(r);
}

TEST(Response, StartsAs200OkAtHttp11) {
  GHTTP_Response * r = nullptr;
  ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_response_status(r), 200);
  EXPECT_STREQ(ghttp_response_reason(r), "OK");
  EXPECT_EQ(ghttp_response_version(r), 1);
  ghttp_response_destroy(r);
}

TEST(Response, StatusIsThreeDigitsAndTheReasonHasNoControls) {
  GHTTP_Response * r = nullptr;
  ASSERT_EQ(ghttp_response_create(nullptr, &r), GHTTP_OK);
  EXPECT_EQ(ghttp_response_set_status(r, 99, "x"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_response_set_status(r, 1000, "x"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_response_set_status(r, 200, "a\r\nb"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_response_set_status(r, 200, "a\x01"), GHTTP_ERR_INVALID);
  EXPECT_EQ(ghttp_response_status(r), 200);
  ASSERT_EQ(ghttp_response_set_status(r, 404, nullptr), GHTTP_OK);
  EXPECT_STREQ(ghttp_response_reason(r), "");
  ASSERT_EQ(ghttp_response_set_status(r, 599, "a\tb c"), GHTTP_OK);
  EXPECT_STREQ(ghttp_response_reason(r), "a\tb c");
  EXPECT_EQ(ghttp_response_set_version(r, 2), GHTTP_ERR_INVALID);
  ghttp_response_destroy(r);
}

TEST(Buffer, AppendsAndClearsAndRefusesNullWithLength) {
  GHTTP_Buffer * b = nullptr;
  ASSERT_EQ(ghttp_buffer_create(nullptr, &b), GHTTP_OK);
  EXPECT_EQ(ghttp_buffer_size(b), 0u);
  ASSERT_EQ(ghttp_buffer_append(b, "abc", 3), GHTTP_OK);
  ASSERT_EQ(ghttp_buffer_append(b, nullptr, 0), GHTTP_OK);
  ASSERT_EQ(ghttp_buffer_append(b, "def", 3), GHTTP_OK);
  EXPECT_EQ(std::string(static_cast<const char *>(ghttp_buffer_data(b)),
                ghttp_buffer_size(b)),
      "abcdef");
  EXPECT_EQ(ghttp_buffer_append(b, nullptr, 1), GHTTP_ERR_INVALID);
  ghttp_buffer_clear(b);
  EXPECT_EQ(ghttp_buffer_size(b), 0u);
  ghttp_buffer_destroy(b);
  ghttp_buffer_destroy(nullptr);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
