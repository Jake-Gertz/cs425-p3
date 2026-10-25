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

/* ------------------------------------------------------------------------
 * cidr_mask
 * --------------------------------------------------------------------- */

void test_cidr_mask_boundaries(void) {
  TEST_ASSERT_EQUAL_HEX32(0x00000000u, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0x80000000u, cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(0xFF000000u, cidr_mask(8));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00u, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF80u, cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFCu, cidr_mask(30));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFEu, cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_mask(255));
}

void test_cidr_mask_every_prefix(void) {
  for (unsigned p = 0; p <= 32; p++) {
    /* the same mask computed a different way: p ones then 32 - p zeros */
    uint32_t expected = (uint32_t)(((uint64_t)0xFFFFFFFFu << (32u - p)) & 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_HEX32(expected, cidr_mask((uint8_t)p));
  }
}

/* ------------------------------------------------------------------------
 * cidr_network / cidr_broadcast
 * --------------------------------------------------------------------- */

void test_cidr_network_broadcast_pdf_example(void) {
  cidr_t onyx = {0x84B2E30Bu, 25}; /* 132.178.227.11/25 */
  TEST_ASSERT_EQUAL_HEX32(0x84B2E300u, cidr_network(onyx));   /* .0 */
  TEST_ASSERT_EQUAL_HEX32(0x84B2E37Fu, cidr_broadcast(onyx)); /* .127 */
}

void test_cidr_network_broadcast_boundaries(void) {
  cidr_t all = {0x01020304u, 0};
  TEST_ASSERT_EQUAL_HEX32(0x00000000u, cidr_network(all));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_broadcast(all));

  cidr_t p2p = {0x0A000001u, 31}; /* 10.0.0.1/31 */
  TEST_ASSERT_EQUAL_HEX32(0x0A000000u, cidr_network(p2p));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_broadcast(p2p));

  cidr_t host = {0x0A000001u, 32};
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_network(host));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_broadcast(host));

  cidr_t top = {0xFFFFFFFFu, 32};
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_network(top));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_broadcast(top));

  cidr_t too_long = {0x0A000001u, 40}; /* treated as /32 */
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_network(too_long));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_broadcast(too_long));
}

/* ------------------------------------------------------------------------
 * cidr_first_host / cidr_last_host
 * --------------------------------------------------------------------- */

void test_cidr_host_range_pdf_example(void) {
  cidr_t onyx = {0x84B2E30Bu, 25};
  TEST_ASSERT_EQUAL_HEX32(0x84B2E301u, cidr_first_host(onyx)); /* .1 */
  TEST_ASSERT_EQUAL_HEX32(0x84B2E37Eu, cidr_last_host(onyx));  /* .126 */
}

void test_cidr_host_range_boundaries(void) {
  cidr_t all = {0u, 0};
  TEST_ASSERT_EQUAL_HEX32(0x00000001u, cidr_first_host(all)); /* 0.0.0.1 */
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFEu, cidr_last_host(all));  /* 255.255.255.254 */

  cidr_t p30 = {0x0A000000u, 30};
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_first_host(p30));
  TEST_ASSERT_EQUAL_HEX32(0x0A000002u, cidr_last_host(p30));

  cidr_t p2p = {0x0A000001u, 31}; /* RFC 3021: both addresses are hosts */
  TEST_ASSERT_EQUAL_HEX32(0x0A000000u, cidr_first_host(p2p));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_last_host(p2p));

  cidr_t host = {0x0A000001u, 32};
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_first_host(host));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_last_host(host));

  cidr_t bottom = {0u, 32};
  TEST_ASSERT_EQUAL_HEX32(0u, cidr_first_host(bottom));
  TEST_ASSERT_EQUAL_HEX32(0u, cidr_last_host(bottom));

  cidr_t top = {0xFFFFFFFFu, 32};
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_first_host(top));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_last_host(top));

  cidr_t top31 = {0xFFFFFFFEu, 31};
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFEu, cidr_first_host(top31));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, cidr_last_host(top31));

  cidr_t too_long = {0x0A000001u, 40}; /* treated as /32 */
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_first_host(too_long));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001u, cidr_last_host(too_long));
}

/* ------------------------------------------------------------------------
 * cidr_host_count
 * --------------------------------------------------------------------- */

void test_cidr_host_count(void) {
  cidr_t b = {0u, 0};
  TEST_ASSERT_EQUAL_UINT64(4294967294ull, cidr_host_count(b));
  b.prefix = 1;
  TEST_ASSERT_EQUAL_UINT64(2147483646ull, cidr_host_count(b));
  b.prefix = 8;
  TEST_ASSERT_EQUAL_UINT64(16777214ull, cidr_host_count(b));
  b.prefix = 24;
  TEST_ASSERT_EQUAL_UINT64(254ull, cidr_host_count(b));
  b.prefix = 25;
  TEST_ASSERT_EQUAL_UINT64(126ull, cidr_host_count(b));
  b.prefix = 30;
  TEST_ASSERT_EQUAL_UINT64(2ull, cidr_host_count(b));
  b.prefix = 31;
  TEST_ASSERT_EQUAL_UINT64(2ull, cidr_host_count(b));
  b.prefix = 32;
  TEST_ASSERT_EQUAL_UINT64(1ull, cidr_host_count(b));
  b.prefix = 33;
  TEST_ASSERT_EQUAL_UINT64(1ull, cidr_host_count(b));
  b.prefix = 255;
  TEST_ASSERT_EQUAL_UINT64(1ull, cidr_host_count(b));
}

void test_cidr_host_count_matches_range(void) {
  /* for /0 to /30 the count is exactly last - first + 1 */
  for (unsigned p = 0; p <= 30; p++) {
    cidr_t b = {0x0A000000u & cidr_mask((uint8_t)p), (uint8_t)p};
    uint64_t span = (uint64_t)cidr_last_host(b) - cidr_first_host(b) + 1u;
    TEST_ASSERT_EQUAL_UINT64(span, cidr_host_count(b));
  }
}

/* ------------------------------------------------------------------------
 * cidr_contains
 * --------------------------------------------------------------------- */

void test_cidr_contains_pdf_example(void) {
  cidr_t onyx = {0x84B2E30Bu, 25};
  TEST_ASSERT_TRUE(cidr_contains(onyx, 0x84B2E332u));  /* .50 */
  TEST_ASSERT_FALSE(cidr_contains(onyx, 0x84B2E3C8u)); /* .200 */
  TEST_ASSERT_TRUE(cidr_contains(onyx, 0x84B2E300u));  /* first address .0 */
  TEST_ASSERT_TRUE(cidr_contains(onyx, 0x84B2E37Fu));  /* last address .127 */
  TEST_ASSERT_FALSE(cidr_contains(onyx, 0x84B2E380u)); /* .128, just past */
  TEST_ASSERT_FALSE(cidr_contains(onyx, 0x84B2E2FFu)); /* 132.178.226.255, just before */
}

void test_cidr_contains_boundaries(void) {
  cidr_t all = {0u, 0};
  TEST_ASSERT_TRUE(cidr_contains(all, 0u));
  TEST_ASSERT_TRUE(cidr_contains(all, 0xFFFFFFFFu));
  TEST_ASSERT_TRUE(cidr_contains(all, 0x08080808u));

  cidr_t all_host_bits = {0x01020304u, 0}; /* /0 still contains everything */
  TEST_ASSERT_TRUE(cidr_contains(all_host_bits, 0u));
  TEST_ASSERT_TRUE(cidr_contains(all_host_bits, 0xFFFFFFFFu));

  cidr_t host = {0x0A000001u, 32};
  TEST_ASSERT_TRUE(cidr_contains(host, 0x0A000001u));
  TEST_ASSERT_FALSE(cidr_contains(host, 0x0A000000u));
  TEST_ASSERT_FALSE(cidr_contains(host, 0x0A000002u));

  cidr_t p2p = {0x0A000000u, 31};
  TEST_ASSERT_TRUE(cidr_contains(p2p, 0x0A000000u));
  TEST_ASSERT_TRUE(cidr_contains(p2p, 0x0A000001u));
  TEST_ASSERT_FALSE(cidr_contains(p2p, 0x0A000002u));

  cidr_t top = {0xFFFFFFFFu, 32};
  TEST_ASSERT_TRUE(cidr_contains(top, 0xFFFFFFFFu));
  TEST_ASSERT_FALSE(cidr_contains(top, 0xFFFFFFFEu));
}

/* ------------------------------------------------------------------------
 * cidr_is_network
 * --------------------------------------------------------------------- */

void test_cidr_is_network(void) {
  cidr_t net = {0xC0A80100u, 24};    /* 192.168.1.0/24 */
  cidr_t iface = {0xC0A80105u, 24};  /* 192.168.1.5/24 */
  cidr_t all = {0u, 0};
  cidr_t all_bad = {0x01000000u, 0};
  cidr_t p2p_net = {0x0A000000u, 31};
  cidr_t p2p_bad = {0x0A000001u, 31};
  cidr_t host = {0x0A000001u, 32};
  cidr_t top = {0xFFFFFFFFu, 32};
  cidr_t too_long = {0x0A000001u, 40};
  TEST_ASSERT_TRUE(cidr_is_network(net));
  TEST_ASSERT_FALSE(cidr_is_network(iface));
  TEST_ASSERT_TRUE(cidr_is_network(all));
  TEST_ASSERT_FALSE(cidr_is_network(all_bad));
  TEST_ASSERT_TRUE(cidr_is_network(p2p_net));
  TEST_ASSERT_FALSE(cidr_is_network(p2p_bad));
  TEST_ASSERT_TRUE(cidr_is_network(host)); /* a /32 is always a network */
  TEST_ASSERT_TRUE(cidr_is_network(top));
  TEST_ASSERT_TRUE(cidr_is_network(too_long));
}

/* ------------------------------------------------------------------------
 * cidr_subnet
 * --------------------------------------------------------------------- */

static void assert_subnet(cidr_t block, uint32_t n, uint32_t i, const char *expected) {
  cidr_t sub = {0, 0};
  char out[CIDR_STR_LEN];
  TEST_ASSERT_TRUE_MESSAGE(cidr_subnet(block, n, i, &sub), expected);
  cidr_format(sub, out);
  TEST_ASSERT_EQUAL_STRING(expected, out);
}

static void assert_no_subnet(cidr_t block, uint32_t n, uint32_t i) {
  cidr_t sub = {SENTINEL_ADDR, 77};
  TEST_ASSERT_FALSE(cidr_subnet(block, n, i, &sub));
  TEST_ASSERT_EQUAL_HEX32(SENTINEL_ADDR, sub.addr); /* untouched on failure */
  TEST_ASSERT_EQUAL_UINT8(77, sub.prefix);
}

void test_cidr_subnet_split_24_into_4(void) {
  cidr_t net = {0xC0A80100u, 24};
  assert_subnet(net, 4, 0, "192.168.1.0/26");
  assert_subnet(net, 4, 1, "192.168.1.64/26");
  assert_subnet(net, 4, 2, "192.168.1.128/26");
  assert_subnet(net, 4, 3, "192.168.1.192/26");
  assert_no_subnet(net, 4, 4);
  assert_no_subnet(net, 4, 0xFFFFFFFFu);
}

void test_cidr_subnet_one_piece_is_the_block(void) {
  cidr_t net = {0xC0A80100u, 24};
  assert_subnet(net, 1, 0, "192.168.1.0/24");
  assert_no_subnet(net, 1, 1);
  cidr_t all = {0u, 0};
  assert_subnet(all, 1, 0, "0.0.0.0/0");
  cidr_t host = {0x0A000001u, 32};
  assert_subnet(host, 1, 0, "10.0.0.1/32");
}

void test_cidr_subnet_rejects_bad_count(void) {
  cidr_t net = {0xC0A80100u, 24};
  assert_no_subnet(net, 0, 0);
  assert_no_subnet(net, 3, 0);
  assert_no_subnet(net, 6, 0);
  assert_no_subnet(net, 255, 0);
  assert_no_subnet(net, 0x80000001u, 0);
  assert_no_subnet(net, 0xFFFFFFFFu, 0);
}

void test_cidr_subnet_rejects_non_network(void) {
  cidr_t iface = {0xC0A80105u, 24}; /* 192.168.1.5/24 */
  assert_no_subnet(iface, 4, 0);
  assert_no_subnet(iface, 1, 0);
}

void test_cidr_subnet_prefix_limit(void) {
  cidr_t p30 = {0x0A000000u, 30};
  assert_subnet(p30, 4, 0, "10.0.0.0/32");
  assert_subnet(p30, 4, 3, "10.0.0.3/32");
  assert_no_subnet(p30, 8, 0); /* would need /33 */
  cidr_t host = {0x0A000001u, 32};
  assert_no_subnet(host, 2, 0);
  cidr_t net = {0xC0A80100u, 24};
  assert_subnet(net, 256, 255, "192.168.1.255/32");
  assert_no_subnet(net, 512, 0);
  assert_no_subnet(net, 0x80000000u, 0);
}

void test_cidr_subnet_null_out(void) {
  cidr_t net = {0xC0A80100u, 24};
  TEST_ASSERT_FALSE(cidr_subnet(net, 4, 0, NULL));
}

void test_cidr_subnet_whole_space(void) {
  cidr_t all = {0u, 0};
  assert_subnet(all, 2, 0, "0.0.0.0/1");
  assert_subnet(all, 2, 1, "128.0.0.0/1");
  /* 2^31 pieces is legal and gives /31s */
  assert_subnet(all, 0x80000000u, 0, "0.0.0.0/31");
  assert_subnet(all, 0x80000000u, 1, "0.0.0.2/31");
  assert_subnet(all, 0x80000000u, 0x7FFFFFFFu, "255.255.255.254/31");
  assert_no_subnet(all, 0x80000000u, 0x80000000u);
  assert_no_subnet(all, 0x80000000u, 0xFFFFFFFFu);
}

/* ------------------------------------------------------------------------
 * Task 3 helpers
 * --------------------------------------------------------------------- */

/* tables/example.txt from the assignment */
static const char example_table[] =
  "# destination      gateway          device\n"
  "default            132.178.227.1    eno1\n"
  "132.178.227.0/25   direct           eno1\n"
  "10.0.0.0/8         10.1.0.1         eth1\n"
  "10.1.0.0/16        direct           eth1\n"
  "10.1.2.0/24        direct           eth2\n"
  "10.1.2.128/25      10.1.2.1         eth2   # a router behind eth2\n"
  "192.168.0.0/16     10.1.0.1         eth1\n";

/* the same seven routes, one per string */
static const char *const example_routes[] = {
  "default            132.178.227.1    eno1",
  "132.178.227.0/25   direct           eno1",
  "10.0.0.0/8         10.1.0.1         eth1",
  "10.1.0.0/16        direct           eth1",
  "10.1.2.0/24        direct           eth2",
  "10.1.2.128/25      10.1.2.1         eth2",
  "192.168.0.0/16     10.1.0.1         eth1",
};

static uint32_t ip(const char *text) {
  uint32_t addr = 0;
  TEST_ASSERT_TRUE_MESSAGE(ip_parse(text, &addr), text);
  return addr;
}

static route_t route_of(const char *line) {
  route_t route;
  memset(&route, 0, sizeof route);
  TEST_ASSERT_TRUE_MESSAGE(route_parse(line, &route), line);
  return route;
}

/* A route built field by field, for cases route_parse() would refuse. */
static route_t raw_route(uint32_t addr, uint8_t prefix, uint32_t gateway, const char *dev) {
  route_t route;
  memset(&route, 0, sizeof route);
  route.dest.addr = addr;
  route.dest.prefix = prefix;
  route.gateway = gateway;
  strncpy(route.dev, dev, DEV_NAME_LEN - 1);
  return route;
}

static void assert_route(const route_t *route, const char *dest, const char *gateway,
                         const char *dev) {
  char text[CIDR_STR_LEN];
  char gw[IP_STR_LEN];
  TEST_ASSERT_NOT_NULL(route);
  cidr_format(route->dest, text);
  TEST_ASSERT_EQUAL_STRING(dest, text);
  ip_format(route->gateway, gw);
  TEST_ASSERT_EQUAL_STRING(gateway, gw);
  TEST_ASSERT_EQUAL_STRING(dev, route->dev);
}

/* Parse a route line and check every field of the result. */
static void assert_parsed(const char *line, const char *dest, const char *gateway,
                          const char *dev) {
  route_t route = route_of(line);
  assert_route(&route, dest, gateway, dev);
}

static FILE *file_with(const char *content) {
  FILE *file = tmpfile();
  TEST_ASSERT_NOT_NULL(file);
  fputs(content, file);
  rewind(file);
  return file;
}

static fwd_table_t *table_of(const char *const *lines, const size_t *order, size_t n) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  for (size_t k = 0; k < n; k++) {
    route_t route = route_of(lines[order[k]]);
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_size_t(n, table_count(table));
  return table;
}

/* Every lookup the example table must answer, as "dest gateway dev". */
static void assert_example_answers(const fwd_table_t *table) {
  assert_route(table_lookup(table, ip("132.178.227.50")), "132.178.227.0/25", "0.0.0.0", "eno1");
  assert_route(table_lookup(table, ip("8.8.8.8")), "0.0.0.0/0", "132.178.227.1", "eno1");
  assert_route(table_lookup(table, ip("10.1.2.5")), "10.1.2.0/24", "0.0.0.0", "eth2");
  assert_route(table_lookup(table, ip("10.1.2.200")), "10.1.2.128/25", "10.1.2.1", "eth2");
  assert_route(table_lookup(table, ip("192.168.5.5")), "192.168.0.0/16", "10.1.0.1", "eth1");
  assert_route(table_lookup(table, ip("10.200.0.1")), "10.0.0.0/8", "10.1.0.1", "eth1");
  assert_route(table_lookup(table, ip("10.1.99.1")), "10.1.0.0/16", "0.0.0.0", "eth1");
  assert_route(table_lookup(table, ip("132.178.227.200")), "0.0.0.0/0", "132.178.227.1", "eno1");
  assert_route(table_lookup(table, ip("0.0.0.0")), "0.0.0.0/0", "132.178.227.1", "eno1");
  assert_route(table_lookup(table, ip("255.255.255.255")), "0.0.0.0/0", "132.178.227.1", "eno1");
}

/* Rearrange order[] into the next lexicographic permutation; false after the last. */
static bool next_permutation(size_t *order, size_t n) {
  size_t i = n - 1;
  while (i > 0 && order[i - 1] >= order[i]) {
    i--;
  }
  if (i == 0) {
    return false;
  }
  size_t j = n - 1;
  while (order[j] <= order[i - 1]) {
    j--;
  }
  size_t tmp = order[i - 1];
  order[i - 1] = order[j];
  order[j] = tmp;
  for (size_t a = i, b = n - 1; a < b; a++, b--) {
    tmp = order[a];
    order[a] = order[b];
    order[b] = tmp;
  }
  return true;
}

/* ------------------------------------------------------------------------
 * route_parse
 * --------------------------------------------------------------------- */

void test_route_parse_example_lines(void) {
  assert_parsed(example_routes[0], "0.0.0.0/0", "132.178.227.1", "eno1");
  assert_parsed(example_routes[1], "132.178.227.0/25", "0.0.0.0", "eno1");
  assert_parsed(example_routes[2], "10.0.0.0/8", "10.1.0.1", "eth1");
  assert_parsed(example_routes[3], "10.1.0.0/16", "0.0.0.0", "eth1");
  assert_parsed(example_routes[4], "10.1.2.0/24", "0.0.0.0", "eth2");
  assert_parsed(example_routes[5], "10.1.2.128/25", "10.1.2.1", "eth2");
  assert_parsed(example_routes[6], "192.168.0.0/16", "10.1.0.1", "eth1");
}

void test_route_parse_keywords(void) {
  route_t route = route_of("default direct lo");
  TEST_ASSERT_EQUAL_HEX32(0u, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0u, route.gateway);
  TEST_ASSERT_EQUAL_STRING("lo", route.dev);
  /* the literal forms mean the same thing */
  assert_parsed("0.0.0.0/0 0.0.0.0 eth0", "0.0.0.0/0", "0.0.0.0", "eth0");
  assert_parsed("10.0.0.0/31 10.0.0.1 p2p", "10.0.0.0/31", "10.0.0.1", "p2p");
  assert_parsed("10.0.0.7/32 direct h", "10.0.0.7/32", "0.0.0.0", "h");
  assert_parsed("255.255.255.255/32 255.255.255.255 x",
                "255.255.255.255/32", "255.255.255.255", "x");
}

void test_route_parse_whitespace(void) {
  assert_parsed("10.0.0.0/8\t\t10.1.0.1  \t eth1", "10.0.0.0/8", "10.1.0.1", "eth1");
  assert_parsed("10.0.0.0/8 10.1.0.1 eth1\n", "10.0.0.0/8", "10.1.0.1", "eth1");
  assert_parsed("10.0.0.0/8 10.1.0.1 eth1\r\n", "10.0.0.0/8", "10.1.0.1", "eth1");
  assert_parsed("  \t10.0.0.0/8 10.1.0.1 eth1 \t ", "10.0.0.0/8", "10.1.0.1", "eth1");
  assert_parsed("\v\f\r\n10.0.0.0/8 direct eth1\f\v", "10.0.0.0/8", "0.0.0.0", "eth1");
}

void test_route_parse_device_length(void) {
  route_t route = route_of("default direct abcdefghijklmno"); /* 15 characters */
  TEST_ASSERT_EQUAL_STRING("abcdefghijklmno", route.dev);
  /* the unused part of dev is zero-filled */
  for (size_t k = 15; k < DEV_NAME_LEN; k++) {
    TEST_ASSERT_EQUAL_CHAR('\0', route.dev[k]);
  }
  route = route_of("default direct e");
  for (size_t k = 1; k < DEV_NAME_LEN; k++) {
    TEST_ASSERT_EQUAL_CHAR('\0', route.dev[k]);
  }
  route = route_of("default direct eno12399np0");
  TEST_ASSERT_EQUAL_STRING("eno12399np0", route.dev);
}

void test_route_parse_rejects(void) {
  static const char *const bad[] = {
    "",
    "   \t\r\n",
    "default",
    "default direct",
    "default direct eth0 extra",
    "10.0.0.0/8 direct eth1 # comment",
    "default direct abcdefghijklmnop",            /* 16 character device */
    "default direct abcdefghijklmnopqrstuvwxyz",  /* longer than any field */
    "10.1.2.5/24 direct eth2",                    /* host bits set */
    "0.0.0.1/0 direct eth2",                      /* host bits set in a /0 */
    "10.0.0.0 direct eth0",                       /* no prefix */
    "10.0.0.0/33 direct eth0",
    "1.2.3/24 direct eth0",
    "Default direct eth0",
    "DEFAULT direct eth0",
    "default Direct eth0",
    "default directly eth0",
    "default 1.2.3 eth0",
    "default 256.1.1.1 eth0",
    "default 010.0.0.1 eth0",
    "default 1.2.3.4/32 eth0",
    "default 1.2.3.4.5.6.7.8.9 eth0",
    "255.255.255.255/32255 direct eth0",          /* too long for a destination */
    "default\r1.2.3.4 eth0",                      /* only spaces and tabs separate */
    "default \v1.2.3.4 eth0",
    "default 1.2.3.4\n eth0",
    "default 1.2.3.4 \feth0",
  };
  for (size_t k = 0; k < COUNT_OF(bad); k++) {
    route_t route;
    route_t before;
    memset(&route, 0xAB, sizeof route);
    before = route;
    TEST_ASSERT_FALSE_MESSAGE(route_parse(bad[k], &route), bad[k]);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&before, &route, sizeof route, bad[k]);
  }
}

void test_route_parse_null(void) {
  route_t route;
  route_t before;
  memset(&route, 0xAB, sizeof route);
  before = route;
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_EQUAL_MEMORY(&before, &route, sizeof route);
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

/* ------------------------------------------------------------------------
 * table_create / table_destroy / table_count
 * --------------------------------------------------------------------- */

void test_table_create_destroy_count(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  TEST_ASSERT_NULL(table_lookup(table, ip("8.8.8.8")));
  table_destroy(table);
}

void test_table_null(void) {
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  table_destroy(NULL); /* allowed, does nothing */
  TEST_ASSERT_NULL(table_lookup(NULL, 0u));
}

/* ------------------------------------------------------------------------
 * table_add
 * --------------------------------------------------------------------- */

void test_table_add_null(void) {
  fwd_table_t *table = table_create();
  route_t route = route_of("default direct eth0");
  TEST_ASSERT_FALSE(table_add(NULL, &route));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  table_destroy(table);
}

void test_table_add_rejects_host_bits(void) {
  fwd_table_t *table = table_create();
  route_t route = raw_route(0x0A010205u, 24, 0u, "eth2"); /* 10.1.2.5/24 */
  TEST_ASSERT_FALSE(table_add(table, &route));
  route = raw_route(0x00000001u, 0, 0u, "eth0"); /* 0.0.0.1/0 */
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  table_destroy(table);
}

void test_table_add_rejects_long_prefix(void) {
  fwd_table_t *table = table_create();
  route_t route = raw_route(0x0A000001u, 33, 0u, "eth0");
  TEST_ASSERT_FALSE(table_add(table, &route));
  route = raw_route(0u, 255, 0u, "eth0");
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  table_destroy(table);
}

void test_table_add_rejects_duplicate(void) {
  fwd_table_t *table = table_create();
  route_t first = route_of("10.0.0.0/8 10.1.0.1 eth1");
  route_t again = route_of("10.0.0.0/8 10.9.9.9 eth9"); /* same block, other next hop */
  route_t other_prefix = route_of("10.0.0.0/16 direct eth2");
  TEST_ASSERT_TRUE(table_add(table, &first));
  TEST_ASSERT_FALSE(table_add(table, &again));
  TEST_ASSERT_FALSE(table_add(table, &first));
  TEST_ASSERT_EQUAL_size_t(1, table_count(table));
  /* the original route is still the one in the table */
  assert_route(table_lookup(table, ip("10.200.0.1")), "10.0.0.0/8", "10.1.0.1", "eth1");
  /* the same address with a different prefix is a different block */
  TEST_ASSERT_TRUE(table_add(table, &other_prefix));
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  /* a duplicate default route */
  route_t def = route_of("default direct eth0");
  route_t def2 = route_of("0.0.0.0/0 1.1.1.1 eth3");
  TEST_ASSERT_TRUE(table_add(table, &def));
  TEST_ASSERT_FALSE(table_add(table, &def2));
  TEST_ASSERT_EQUAL_size_t(3, table_count(table));
  table_destroy(table);
}

void test_table_add_copies_route(void) {
  fwd_table_t *table = table_create();
  route_t route = route_of("10.0.0.0/8 10.1.0.1 eth1");
  TEST_ASSERT_TRUE(table_add(table, &route));
  /* changing the caller's route afterwards does not change the table */
  route.gateway = 0u;
  strcpy(route.dev, "changed");
  assert_route(table_lookup(table, ip("10.0.0.1")), "10.0.0.0/8", "10.1.0.1", "eth1");
  table_destroy(table);
}

void test_table_add_terminates_device(void) {
  fwd_table_t *table = table_create();
  route_t route = raw_route(0x0A000000u, 8, 0u, "");
  memset(route.dev, 'X', DEV_NAME_LEN); /* no terminator at all */
  TEST_ASSERT_TRUE(table_add(table, &route));
  const route_t *found = table_lookup(table, ip("10.0.0.1"));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_size_t(DEV_NAME_LEN - 1, strlen(found->dev));
  /* an all-zero route (empty device name) is accepted */
  route_t zero;
  memset(&zero, 0, sizeof zero);
  TEST_ASSERT_TRUE(table_add(table, &zero));
  TEST_ASSERT_EQUAL_STRING("", table_lookup(table, ip("8.8.8.8"))->dev);
  table_destroy(table);
}

void test_table_add_grows(void) {
  fwd_table_t *table = table_create();
  /* 100 routes forces the array to grow several times (8, 16, 32, 64, 128) */
  for (uint32_t k = 0; k < 100; k++) {
    route_t route = raw_route(0x0A000000u | (k << 8), 24, 0x0A000001u + k, "eth0");
    TEST_ASSERT_TRUE(table_add(table, &route));
    TEST_ASSERT_EQUAL_size_t(k + 1, table_count(table));
  }
  for (uint32_t k = 0; k < 100; k++) {
    const route_t *found = table_lookup(table, 0x0A000063u | (k << 8));
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_HEX32(0x0A000000u | (k << 8), found->dest.addr);
    TEST_ASSERT_EQUAL_HEX32(0x0A000001u + k, found->gateway);
  }
  /* duplicates are still caught after the growth */
  route_t dup = raw_route(0x0A003100u, 24, 0u, "eth0");
  TEST_ASSERT_FALSE(table_add(table, &dup));
  TEST_ASSERT_EQUAL_size_t(100, table_count(table));
  table_destroy(table);
}

/* ------------------------------------------------------------------------
 * table_load
 * --------------------------------------------------------------------- */

void test_table_load_example(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with(example_table);
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(7, table_count(table));
  assert_example_answers(table);
  fclose(file);
  table_destroy(table);
}

void test_table_load_comments_and_blank_lines(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with("# only a comment\n"
                         "\n"
                         "   \t  \n"
                         "\r\n"
                         "#\n"
                         "   # indented comment\n"
                         "10.0.0.0/8 direct eth0 # trailing comment\n"
                         "10.1.0.0/16 direct eth1# no space before it\n"
                         "10.2.0.0/16 direct eth2#\n"
                         "# 10.3.0.0/16 direct eth3\n");
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(3, table_count(table));
  assert_route(table_lookup(table, ip("10.1.0.1")), "10.1.0.0/16", "0.0.0.0", "eth1");
  assert_route(table_lookup(table, ip("10.2.0.1")), "10.2.0.0/16", "0.0.0.0", "eth2");
  /* the commented out 10.3.0.0/16 was not loaded, so the /8 answers */
  assert_route(table_lookup(table, ip("10.3.0.1")), "10.0.0.0/8", "0.0.0.0", "eth0");
  fclose(file);
  table_destroy(table);
}

void test_table_load_bad_line_in_middle(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with("default 132.178.227.1 eno1\n"
                         "132.178.227.0/25 direct eno1\n"
                         "10.0.0.0/8 10.1.0.1 eth1\n"
                         "10.1.0.0/16 nowhere eth1\n"
                         "10.1.2.0/24 direct eth2\n");
  size_t bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(4, bad_line);
  /* the three routes before the bad line stay in the table */
  TEST_ASSERT_EQUAL_size_t(3, table_count(table));
  assert_route(table_lookup(table, ip("10.1.2.5")), "10.0.0.0/8", "10.1.0.1", "eth1");
  fclose(file);
  table_destroy(table);
}

void test_table_load_line_numbers_count_every_line(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with("# comment\n"
                         "\n"
                         "10.0.0.0/8 direct eth0\n"
                         "   \n"
                         "10.1.2.5/24 direct eth2   # host bits\n"
                         "10.2.0.0/16 direct eth2\n");
  size_t bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(5, bad_line);
  TEST_ASSERT_EQUAL_size_t(1, table_count(table));
  fclose(file);
  table_destroy(table);
}

void test_table_load_duplicate_line(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with("10.0.0.0/8 direct eth0\n"
                         "10.0.0.0/16 direct eth0\n"
                         "10.0.0.0/8 10.1.1.1 eth1\n");
  size_t bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(3, bad_line);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  fclose(file);
  table_destroy(table);
}

void test_table_load_duplicate_of_existing_route(void) {
  fwd_table_t *table = table_create();
  route_t route = route_of("default direct eth0");
  TEST_ASSERT_TRUE(table_add(table, &route));
  FILE *file = file_with("10.0.0.0/8 direct eth0\n"
                         "default 1.1.1.1 eth1\n");
  size_t bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(2, bad_line);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  fclose(file);
  table_destroy(table);
}

void test_table_load_first_line_bad(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with("not a route\n10.0.0.0/8 direct eth0\n");
  size_t bad_line = 0;
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(1, bad_line);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  fclose(file);
  table_destroy(table);
}

void test_table_load_null_arguments(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with(example_table);
  size_t bad_line = 99;
  TEST_ASSERT_FALSE(table_load(NULL, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_FALSE(table_load(NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  fclose(file);
  table_destroy(table);
}

void test_table_load_null_bad_line(void) {
  fwd_table_t *table = table_create();
  FILE *good = file_with(example_table);
  FILE *bad = file_with("10.9.0.0/16 direct eth0\nbogus\n");
  TEST_ASSERT_TRUE(table_load(table, good, NULL));
  TEST_ASSERT_EQUAL_size_t(7, table_count(table));
  TEST_ASSERT_FALSE(table_load(table, bad, NULL));
  TEST_ASSERT_EQUAL_size_t(8, table_count(table));
  fclose(good);
  fclose(bad);
  table_destroy(table);
}

void test_table_load_read_error(void) {
  fwd_table_t *table = table_create();
  /* a stream opened only for writing can not be read, so getline fails with ferror set */
  FILE *file = fopen("/dev/null", "w");
  TEST_ASSERT_NOT_NULL(file);
  size_t bad_line = 99;
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  fclose(file);
  table_destroy(table);
}

void test_table_load_empty_and_odd_files(void) {
  fwd_table_t *table = table_create();
  FILE *empty = file_with("");
  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, empty, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  fclose(empty);

  /* CRLF line endings and no newline at the end of the last line */
  FILE *crlf = file_with("# windows file\r\n"
                         "default 132.178.227.1 eno1\r\n"
                         "\r\n"
                         "10.0.0.0/8 10.1.0.1 eth1");
  TEST_ASSERT_TRUE(table_load(table, crlf, &bad_line));
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  assert_route(table_lookup(table, ip("10.0.0.1")), "10.0.0.0/8", "10.1.0.1", "eth1");
  fclose(crlf);

  /* a line far longer than getline's first buffer */
  char long_line[600];
  memset(long_line, ' ', sizeof long_line);
  strcpy(long_line + 500, "192.168.0.0/16 direct eth5\n");
  FILE *wide = file_with(long_line);
  TEST_ASSERT_TRUE(table_load(table, wide, &bad_line));
  TEST_ASSERT_EQUAL_size_t(3, table_count(table));
  fclose(wide);
  table_destroy(table);
}

/* ------------------------------------------------------------------------
 * table_lookup
 * --------------------------------------------------------------------- */

void test_table_lookup_longest_of_several(void) {
  /* 10.1.2.200 is inside all four blocks and the /25 wins */
  static const char *const nested[] = {
    "10.0.0.0/8 10.1.0.1 eth1",
    "10.1.0.0/16 direct eth1",
    "10.1.2.0/24 direct eth2",
    "10.1.2.128/25 10.1.2.1 eth2",
  };
  size_t order[] = {0, 1, 2, 3};
  fwd_table_t *table = table_of(nested, order, 4);
  assert_route(table_lookup(table, ip("10.1.2.200")), "10.1.2.128/25", "10.1.2.1", "eth2");
  assert_route(table_lookup(table, ip("10.1.2.127")), "10.1.2.0/24", "0.0.0.0", "eth2");
  assert_route(table_lookup(table, ip("10.1.3.1")), "10.1.0.0/16", "0.0.0.0", "eth1");
  assert_route(table_lookup(table, ip("10.2.0.0")), "10.0.0.0/8", "10.1.0.1", "eth1");
  /* no default route, so an address outside every block matches nothing */
  TEST_ASSERT_NULL(table_lookup(table, ip("11.0.0.0")));
  TEST_ASSERT_NULL(table_lookup(table, ip("9.255.255.255")));
  table_destroy(table);
}

void test_table_lookup_independent_of_order(void) {
  size_t order[COUNT_OF(example_routes)];
  size_t permutations = 0;
  for (size_t k = 0; k < COUNT_OF(order); k++) {
    order[k] = k;
  }
  /* every one of the 7! = 5040 orders gives the same answers */
  do {
    fwd_table_t *table = table_of(example_routes, order, COUNT_OF(order));
    assert_example_answers(table);
    table_destroy(table);
    permutations++;
  } while (next_permutation(order, COUNT_OF(order)));
  TEST_ASSERT_EQUAL_size_t(5040, permutations);
}

void test_table_lookup_reverse_and_shuffled(void) {
  size_t reverse[] = {6, 5, 4, 3, 2, 1, 0};
  size_t shuffled[] = {5, 0, 3, 6, 1, 4, 2};
  fwd_table_t *table = table_of(example_routes, reverse, 7);
  assert_example_answers(table);
  table_destroy(table);
  table = table_of(example_routes, shuffled, 7);
  assert_example_answers(table);
  table_destroy(table);
}

void test_table_lookup_no_default_route(void) {
  size_t order[] = {1, 2, 3, 4, 5, 6}; /* everything but the default */
  fwd_table_t *table = table_of(example_routes, order, 6);
  TEST_ASSERT_NULL(table_lookup(table, ip("8.8.8.8")));
  TEST_ASSERT_NULL(table_lookup(table, ip("132.178.227.200")));
  TEST_ASSERT_NULL(table_lookup(table, ip("0.0.0.0")));
  TEST_ASSERT_NULL(table_lookup(table, ip("255.255.255.255")));
  assert_route(table_lookup(table, ip("10.1.2.200")), "10.1.2.128/25", "10.1.2.1", "eth2");
  assert_route(table_lookup(table, ip("132.178.227.50")), "132.178.227.0/25", "0.0.0.0", "eno1");
  table_destroy(table);
}

void test_table_lookup_default_only_as_last_resort(void) {
  fwd_table_t *table = table_create();
  route_t def = route_of("default 132.178.227.1 eno1");
  TEST_ASSERT_TRUE(table_add(table, &def));
  /* alone, the default route matches everything */
  assert_route(table_lookup(table, 0u), "0.0.0.0/0", "132.178.227.1", "eno1");
  assert_route(table_lookup(table, 0xFFFFFFFFu), "0.0.0.0/0", "132.178.227.1", "eno1");
  assert_route(table_lookup(table, ip("10.1.2.3")), "0.0.0.0/0", "132.178.227.1", "eno1");
  /* once something more specific exists, it loses to that */
  route_t net = route_of("10.0.0.0/8 direct eth1");
  TEST_ASSERT_TRUE(table_add(table, &net));
  assert_route(table_lookup(table, ip("10.1.2.3")), "10.0.0.0/8", "0.0.0.0", "eth1");
  assert_route(table_lookup(table, ip("11.0.0.0")), "0.0.0.0/0", "132.178.227.1", "eno1");
  table_destroy(table);
}

void test_table_lookup_host_and_point_to_point_routes(void) {
  fwd_table_t *table = table_create();
  FILE *file = file_with(example_table);
  TEST_ASSERT_TRUE(table_load(table, file, NULL));
  fclose(file);
  route_t host = route_of("10.1.2.200/32 10.1.2.2 eth3");
  route_t p2p = route_of("10.1.2.250/31 direct ppp0");
  route_t top = route_of("255.255.255.255/32 direct bcast");
  TEST_ASSERT_TRUE(table_add(table, &host));
  TEST_ASSERT_TRUE(table_add(table, &p2p));
  TEST_ASSERT_TRUE(table_add(table, &top));
  assert_route(table_lookup(table, ip("10.1.2.200")), "10.1.2.200/32", "10.1.2.2", "eth3");
  assert_route(table_lookup(table, ip("10.1.2.201")), "10.1.2.128/25", "10.1.2.1", "eth2");
  assert_route(table_lookup(table, ip("10.1.2.250")), "10.1.2.250/31", "0.0.0.0", "ppp0");
  assert_route(table_lookup(table, ip("10.1.2.251")), "10.1.2.250/31", "0.0.0.0", "ppp0");
  assert_route(table_lookup(table, ip("10.1.2.252")), "10.1.2.128/25", "10.1.2.1", "eth2");
  assert_route(table_lookup(table, ip("255.255.255.255")), "255.255.255.255/32", "0.0.0.0", "bcast");
  assert_route(table_lookup(table, ip("255.255.255.254")), "0.0.0.0/0", "132.178.227.1", "eno1");
  table_destroy(table);
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
  /* Task 2 */
  RUN_TEST(test_cidr_mask_boundaries);
  RUN_TEST(test_cidr_mask_every_prefix);
  RUN_TEST(test_cidr_network_broadcast_pdf_example);
  RUN_TEST(test_cidr_network_broadcast_boundaries);
  RUN_TEST(test_cidr_host_range_pdf_example);
  RUN_TEST(test_cidr_host_range_boundaries);
  RUN_TEST(test_cidr_host_count);
  RUN_TEST(test_cidr_host_count_matches_range);
  RUN_TEST(test_cidr_contains_pdf_example);
  RUN_TEST(test_cidr_contains_boundaries);
  RUN_TEST(test_cidr_is_network);
  RUN_TEST(test_cidr_subnet_split_24_into_4);
  RUN_TEST(test_cidr_subnet_one_piece_is_the_block);
  RUN_TEST(test_cidr_subnet_rejects_bad_count);
  RUN_TEST(test_cidr_subnet_rejects_non_network);
  RUN_TEST(test_cidr_subnet_prefix_limit);
  RUN_TEST(test_cidr_subnet_null_out);
  RUN_TEST(test_cidr_subnet_whole_space);
  /* Task 3 */
  RUN_TEST(test_route_parse_example_lines);
  RUN_TEST(test_route_parse_keywords);
  RUN_TEST(test_route_parse_whitespace);
  RUN_TEST(test_route_parse_device_length);
  RUN_TEST(test_route_parse_rejects);
  RUN_TEST(test_route_parse_null);
  RUN_TEST(test_table_create_destroy_count);
  RUN_TEST(test_table_null);
  RUN_TEST(test_table_add_null);
  RUN_TEST(test_table_add_rejects_host_bits);
  RUN_TEST(test_table_add_rejects_long_prefix);
  RUN_TEST(test_table_add_rejects_duplicate);
  RUN_TEST(test_table_add_copies_route);
  RUN_TEST(test_table_add_terminates_device);
  RUN_TEST(test_table_add_grows);
  RUN_TEST(test_table_load_example);
  RUN_TEST(test_table_load_comments_and_blank_lines);
  RUN_TEST(test_table_load_bad_line_in_middle);
  RUN_TEST(test_table_load_line_numbers_count_every_line);
  RUN_TEST(test_table_load_duplicate_line);
  RUN_TEST(test_table_load_duplicate_of_existing_route);
  RUN_TEST(test_table_load_first_line_bad);
  RUN_TEST(test_table_load_null_arguments);
  RUN_TEST(test_table_load_null_bad_line);
  RUN_TEST(test_table_load_read_error);
  RUN_TEST(test_table_load_empty_and_odd_files);
  RUN_TEST(test_table_lookup_longest_of_several);
  RUN_TEST(test_table_lookup_independent_of_order);
  RUN_TEST(test_table_lookup_reverse_and_shuffled);
  RUN_TEST(test_table_lookup_no_default_route);
  RUN_TEST(test_table_lookup_default_only_as_last_resort);
  RUN_TEST(test_table_lookup_host_and_point_to_point_routes);
  return UNITY_END();
}
