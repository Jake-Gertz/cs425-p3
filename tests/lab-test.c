#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))
#define SENTINEL_ADDR 0xDEADBEEFu

void setUp(void) {
}

void tearDown(void) {
}

/* Every malformed input listed in the assignment. Each must be rejected by
 * both ip_parse() and cidr_parse(). */
static const char *const pdf_malformed[] = {
  "1.2.3",       "1.2.3.4.5",   "1..2.3",      "256.1.1.1",   "010.0.0.1",
  "1.2.3.4x",    "1.2.3.4/33",  "1.2.3.4/024", "1.2.3.4/",    "1.2.3/24",
  "+1.2.3.4",    "1.2.3.4junk",
};

/* ------------------------------------------------------------------------
 * ip_parse
 * --------------------------------------------------------------------- */

void test_ip_parse_valid(void) {
  uint32_t addr = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010Au, addr);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(0x00000000u, addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, addr);
  TEST_ASSERT_TRUE(ip_parse("1.2.3.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(0x01020300u, addr);
  TEST_ASSERT_TRUE(ip_parse("132.178.227.11", &addr));
  TEST_ASSERT_EQUAL_HEX32(0x84B2E30Bu, addr);
  TEST_ASSERT_TRUE(ip_parse("10.0.200.99", &addr));
  TEST_ASSERT_EQUAL_HEX32(0x0A00C863u, addr);
}

void test_ip_parse_rejects_pdf_list(void) {
  for (size_t k = 0; k < COUNT_OF(pdf_malformed); k++) {
    uint32_t addr = SENTINEL_ADDR;
    TEST_ASSERT_FALSE_MESSAGE(ip_parse(pdf_malformed[k], &addr), pdf_malformed[k]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(SENTINEL_ADDR, addr, pdf_malformed[k]);
  }
}

void test_ip_parse_rejects_more_malformed(void) {
  static const char *const bad[] = {
    "",             " 1.2.3.4",     "1.2.3.4 ",     "1.2.3.4.",
    ".1.2.3.4",     "1.2.3.-4",     "1.2.3.4\n",    "1234.1.1.1",
    "1.2.3.1234",   "00.1.2.3",     "1.2.3.00",     "1.2.3.01",
    "1.2.3.256",    "999.1.1.1",    "-1.2.3.4",     "1,2,3,4",
    "0x1.2.3.4",    "1.2.3.4/24",   "1.2.3.",       "1.2..3.4",
    "...",          "1",            "a.b.c.d",      "1.2.3.4\t",
    "1. 2.3.4",     "1.2.3.0255",   "\n1.2.3.4",
  };
  for (size_t k = 0; k < COUNT_OF(bad); k++) {
    uint32_t addr = SENTINEL_ADDR;
    TEST_ASSERT_FALSE_MESSAGE(ip_parse(bad[k], &addr), bad[k]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(SENTINEL_ADDR, addr, bad[k]);
  }
}

void test_ip_parse_null(void) {
  uint32_t addr = SENTINEL_ADDR;
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_EQUAL_HEX32(SENTINEL_ADDR, addr);
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

/* ------------------------------------------------------------------------
 * ip_format
 * --------------------------------------------------------------------- */

void test_ip_format(void) {
  char out[IP_STR_LEN];
  ip_format(0u, out);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", out);
  ip_format(0xFFFFFFFFu, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", out);
  ip_format(0xC0A8010Au, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", out);
  ip_format(0x0A000001u, out);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1", out);
}

void test_ip_format_round_trip(void) {
  static const char *const texts[] = {
    "0.0.0.0", "255.255.255.255", "192.168.1.10", "132.178.227.127", "8.8.8.8",
  };
  for (size_t k = 0; k < COUNT_OF(texts); k++) {
    uint32_t addr = 0;
    char out[IP_STR_LEN];
    TEST_ASSERT_TRUE(ip_parse(texts[k], &addr));
    ip_format(addr, out);
    TEST_ASSERT_EQUAL_STRING(texts[k], out);
  }
}

/* ------------------------------------------------------------------------
 * cidr_parse
 * --------------------------------------------------------------------- */

void test_cidr_parse_valid(void) {
  cidr_t block = {0, 0};
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &block));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100u, block.addr);
  TEST_ASSERT_EQUAL_UINT8(24, block.prefix);
  /* host bits are allowed and kept */
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_HEX32(0x84B2E30Bu, block.addr);
  TEST_ASSERT_EQUAL_UINT8(25, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_HEX32(0u, block.addr);
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, block.addr);
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("10.0.0.1/31", &block));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, block.addr);
  TEST_ASSERT_EQUAL_UINT8(31, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("1.2.3.4/9", &block));
  TEST_ASSERT_EQUAL_UINT8(9, block.prefix);
}

void test_cidr_parse_rejects_pdf_list(void) {
  for (size_t k = 0; k < COUNT_OF(pdf_malformed); k++) {
    cidr_t block = {SENTINEL_ADDR, 77};
    TEST_ASSERT_FALSE_MESSAGE(cidr_parse(pdf_malformed[k], &block), pdf_malformed[k]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(SENTINEL_ADDR, block.addr, pdf_malformed[k]);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(77, block.prefix, pdf_malformed[k]);
  }
}

void test_cidr_parse_rejects_more_malformed(void) {
  static const char *const bad[] = {
    "",              "/24",            "1.2.3.4",        "1.2.3.4//24",
    "1.2.3.4/2a",    "1.2.3.4/-1",     "1.2.3.4/+1",     "1.2.3.4/00",
    "1.2.3.4/01",    "1.2.3.4/100",    "1.2.3.4/999",    "1.2.3.4/24 ",
    " 1.2.3.4/24",   "1.2.3.4/24\n",   "1.2.3.4/24/24",  "256.1.1.1/24",
    "010.0.0.1/8",   "1.2.3.4x/24",    "1.2.3.4 /24",    "1.2.3.4/ 24",
    "1.2.3.4.5/24",  "1..2.3/24",      "+1.2.3.4/24",    "1.2.3.4/24junk",
    "1.2.3.4/3 2",   "1.2.3.4\\24",    "1.2.3.4/0x10",   "1.2.3.4/32\r",
  };
  for (size_t k = 0; k < COUNT_OF(bad); k++) {
    cidr_t block = {SENTINEL_ADDR, 77};
    TEST_ASSERT_FALSE_MESSAGE(cidr_parse(bad[k], &block), bad[k]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(SENTINEL_ADDR, block.addr, bad[k]);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(77, block.prefix, bad[k]);
  }
}

void test_cidr_parse_null(void) {
  cidr_t block = {SENTINEL_ADDR, 77};
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_EQUAL_HEX32(SENTINEL_ADDR, block.addr);
  TEST_ASSERT_EQUAL_UINT8(77, block.prefix);
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.0/24", NULL));
}

/* ------------------------------------------------------------------------
 * cidr_format
 * --------------------------------------------------------------------- */

void test_cidr_format(void) {
  char out[CIDR_STR_LEN];
  cidr_t net = {0xC0A80100u, 24};
  cidr_format(net, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.0/24", out);

  cidr_t host_bits = {0x84B2E30Bu, 25}; /* address kept exactly as stored */
  cidr_format(host_bits, out);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", out);

  cidr_t all = {0u, 0};
  cidr_format(all, out);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", out);

  cidr_t longest = {0xFFFFFFFFu, 32}; /* needs all of CIDR_STR_LEN */
  cidr_format(longest, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", out);

  cidr_t too_long = {0x0A000001u, 40};
  cidr_format(too_long, out);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1/32", out);

  cidr_t max_prefix = {0x0A000001u, 255};
  cidr_format(max_prefix, out);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1/32", out);
}

void test_cidr_format_round_trip(void) {
  static const char *const texts[] = {
    "0.0.0.0/0", "255.255.255.255/32", "132.178.227.11/25", "10.1.2.128/25",
  };
  for (size_t k = 0; k < COUNT_OF(texts); k++) {
    cidr_t block = {0, 0};
    char out[CIDR_STR_LEN];
    TEST_ASSERT_TRUE(cidr_parse(texts[k], &block));
    cidr_format(block, out);
    TEST_ASSERT_EQUAL_STRING(texts[k], out);
  }
}

int main(void) {
  UNITY_BEGIN();
  /* Task 1 */
  RUN_TEST(test_ip_parse_valid);
  RUN_TEST(test_ip_parse_rejects_pdf_list);
  RUN_TEST(test_ip_parse_rejects_more_malformed);
  RUN_TEST(test_ip_parse_null);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_ip_format_round_trip);
  RUN_TEST(test_cidr_parse_valid);
  RUN_TEST(test_cidr_parse_rejects_pdf_list);
  RUN_TEST(test_cidr_parse_rejects_more_malformed);
  RUN_TEST(test_cidr_parse_null);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_format_round_trip);
  return UNITY_END();
}
