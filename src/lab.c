#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <stdio.h>

/* ------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

static bool is_digit(char c)
{
  return c >= '0' && c <= '9';
}

/*
 * Parse a decimal number of 1 to max_digits digits starting at *pos. A leading
 * zero is only allowed when the number is exactly "0". On success *pos is moved
 * past the digits. Capping the digit count keeps the value from overflowing.
 */
static bool parse_decimal(const char **pos, unsigned max_digits, uint32_t *value)
{
  const char *s = *pos;
  uint32_t v = 0;
  unsigned n = 0;

  while (is_digit(s[n]))
  {
    if (n == max_digits)
    {
      return false;
    }
    v = v * 10u + (uint32_t)(s[n] - '0');
    n++;
  }
  if (n == 0 || (n > 1 && s[0] == '0'))
  {
    return false;
  }
  *pos = s + n;
  *value = v;
  return true;
}

/*
 * Parse four octets separated by single periods starting at *pos and stop
 * right after the last one, so the caller decides what may follow.
 */
static bool parse_quad(const char **pos, uint32_t *addr)
{
  const char *s = *pos;
  uint32_t result = 0;

  for (int k = 0; k < 4; k++)
  {
    uint32_t octet;
    if (k > 0)
    {
      if (*s != '.')
      {
        return false;
      }
      s++;
    }
    if (!parse_decimal(&s, 3, &octet) || octet > 255u)
    {
      return false;
    }
    result = (result << 8) | octet;
  }
  *pos = s;
  *addr = result;
  return true;
}

/* A prefix over 32 means 32 everywhere, the way cidr_mask() treats it. */
static unsigned clamp_prefix(uint8_t prefix)
{
  return prefix > 32 ? 32u : (unsigned)prefix;
}

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

bool ip_parse(const char *text, uint32_t *addr)
{
  uint32_t result;

  if (text == NULL || addr == NULL)
  {
    return false;
  }
  if (!parse_quad(&text, &result) || *text != '\0')
  {
    return false;
  }
  *addr = result;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
           (unsigned)((addr >> 24) & 0xFFu), (unsigned)((addr >> 16) & 0xFFu),
           (unsigned)((addr >> 8) & 0xFFu), (unsigned)(addr & 0xFFu));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  uint32_t addr;
  uint32_t prefix;

  if (text == NULL || block == NULL)
  {
    return false;
  }
  if (!parse_quad(&text, &addr) || *text != '/')
  {
    return false;
  }
  text++;
  if (!parse_decimal(&text, 2, &prefix) || prefix > 32u || *text != '\0')
  {
    return false;
  }
  block->addr = addr;
  block->prefix = (uint8_t)prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  uint32_t addr = block.addr;

  snprintf(out, CIDR_STR_LEN, "%u.%u.%u.%u/%u",
           (unsigned)((addr >> 24) & 0xFFu), (unsigned)((addr >> 16) & 0xFFu),
           (unsigned)((addr >> 8) & 0xFFu), (unsigned)(addr & 0xFFu),
           clamp_prefix(block.prefix));
}
