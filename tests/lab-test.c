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
  return UNITY_END();
}
