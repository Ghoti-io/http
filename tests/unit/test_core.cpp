/**
 * @file
 *
 * Result strings, limits defaults and the version macros.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <set>
#include <string>

#include "test_helpers.h"

TEST(Core, EveryResultHasItsOwnString) {
  std::set<std::string> seen;
  for (int i = 0; i < GHTTP_RESULT_COUNT; i++) {
    const char * s = ghttp_result_string(static_cast<GHTTP_Result>(i));
    ASSERT_NE(s, nullptr);
    EXPECT_STRNE(s, "Unknown error") << i;
    EXPECT_TRUE(seen.insert(s).second) << "duplicate string for " << i;
  }
  EXPECT_STREQ(ghttp_result_string(GHTTP_RESULT_COUNT), "Unknown error");
}

TEST(Core, ResultVocabularyKeepsTheSuiteValues) {
  // CONVENTIONS.md section 5: 0 is success, and the nine share their order.
  EXPECT_EQ(GHTTP_OK, 0);
  EXPECT_EQ(GHTTP_ERR_IO, 1);
  EXPECT_EQ(GHTTP_ERR_FORMAT, 2);
  EXPECT_EQ(GHTTP_ERR_UNSUPPORTED, 3);
  EXPECT_EQ(GHTTP_ERR_LIMIT, 4);
  EXPECT_EQ(GHTTP_ERR_CORRUPT, 5);
  EXPECT_EQ(GHTTP_ERR_OOM, 6);
  EXPECT_EQ(GHTTP_ERR_INVALID, 7);
  EXPECT_EQ(GHTTP_ERR_INTERNAL, 8);
  EXPECT_EQ(GHTTP_RESULT_COUNT, 9);
}

TEST(Core, LimitsDefaultFillsEveryField) {
  GHTTP_Limits l;
  std::memset(&l, 0xAB, sizeof(l));
  ghttp_limits_default(&l);
  EXPECT_EQ(l.max_head_bytes, GHTTP_DEFAULT_MAX_HEAD_BYTES);
  EXPECT_EQ(l.max_line_length, GHTTP_DEFAULT_MAX_LINE_LENGTH);
  EXPECT_EQ(l.max_header_count, GHTTP_DEFAULT_MAX_HEADER_COUNT);
  EXPECT_EQ(l.max_trailer_bytes, GHTTP_DEFAULT_MAX_TRAILER_BYTES);
  EXPECT_EQ(l.max_trailer_count, GHTTP_DEFAULT_MAX_TRAILER_COUNT);
  EXPECT_EQ(l.max_body_bytes, GHTTP_DEFAULT_MAX_BODY_BYTES);
  EXPECT_EQ(l.max_chunk_size, GHTTP_DEFAULT_MAX_CHUNK_SIZE);
  // The defaults are caps, so none of them is zero.
  EXPECT_GT(l.max_head_bytes, 0u);
  EXPECT_GT(l.max_line_length, 0u);
  EXPECT_GT(l.max_header_count, 0u);
  EXPECT_GT(l.max_body_bytes, 0u);
}

TEST(Core, LimitsDefaultIgnoresNull) {
  ghttp_limits_default(nullptr);
}

TEST(Core, ANullLimitsPointerMeansTheDefaults) {
  GHTTP_Parser * p = nullptr;
  ASSERT_EQ(ghttp_parser_create(GHTTP_PARSE_REQUEST, nullptr, nullptr, &p),
      GHTTP_OK);
  ghttp_parser_destroy(p);
}

TEST(Core, VersionMacrosAgree) {
  EXPECT_EQ(GHTTP_VERSION_NUMBER,
      GHTTP_MAKE_VERSION(GHTTP_VERSION_MAJOR, GHTTP_VERSION_MINOR,
          GHTTP_VERSION_PATCH));
  EXPECT_NE(std::string(GHTTP_VERSION_STRING), "");
}

TEST(Core, DefaultAllocatorIsCutils) {
  EXPECT_EQ(ghttp_allocator_default(), gcu_allocator_default());
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
