#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

uint32_t cidr_mask(uint8_t prefix)
{
  unsigned p = clamp_prefix(prefix);

  /* Shifting a 32 bit value by 32 is undefined, so /0 is its own case. */
  return p == 0 ? 0u : (uint32_t)(0xFFFFFFFFu << (32u - p));
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);

  /* /31 (RFC 3021) and /32 have no network address to skip. */
  return clamp_prefix(block.prefix) >= 31 ? network : network + 1u;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);

  /* /31 (RFC 3021) and /32 have no broadcast address to skip. */
  return clamp_prefix(block.prefix) >= 31 ? broadcast : broadcast - 1u;
}

uint64_t cidr_host_count(cidr_t block)
{
  unsigned p = clamp_prefix(block.prefix);

  if (p == 32)
  {
    return 1;
  }
  if (p == 31)
  {
    return 2;
  }
  /* 2^32 for a /0 needs 33 bits, so do the arithmetic in 64. */
  return ((uint64_t)1 << (32u - p)) - 2u;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);

  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return (block.addr & ~cidr_mask(block.prefix)) == 0;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  unsigned p = clamp_prefix(block.prefix);
  unsigned bits = 0;
  unsigned new_prefix;
  uint64_t size;

  if (out == NULL || !cidr_is_network(block) || n == 0 || (n & (n - 1u)) != 0 ||
      i >= n)
  {
    return false;
  }
  /* n is a power of two, so this finds log2(n): the bits borrowed from the host part. */
  while (((uint64_t)1 << bits) < n)
  {
    bits++;
  }
  if (p + bits > 32)
  {
    return false;
  }
  new_prefix = p + bits;
  /* A /0 subnet (n == 1 of a /0) holds 2^32 addresses, so the size is 64 bit. */
  size = (uint64_t)1 << (32u - new_prefix);
  out->addr = cidr_network(block) + (uint32_t)((uint64_t)i * size);
  out->prefix = (uint8_t)new_prefix;
  return true;
}

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

/*
 * The routes live in one array that doubles when it fills up. Lookups scan
 * all of it and keep the longest matching prefix, so the order the routes
 * were added in never matters.
 */
struct fwd_table
{
  route_t *routes;
  size_t count;
  size_t capacity;
};

/* The number of fields on a route line: destination, gateway and device. */
#define ROUTE_FIELDS 3

static bool is_space(char c)
{
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/* The characters that may separate the fields of a route line. */
static bool is_blank(char c)
{
  return c == ' ' || c == '\t';
}

static bool is_blank_line(const char *line)
{
  while (*line != '\0')
  {
    if (!is_space(*line))
    {
      return false;
    }
    line++;
  }
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  /* The longest valid field is a destination such as "255.255.255.255/32". */
  char field[ROUTE_FIELDS][CIDR_STR_LEN];
  size_t length[ROUTE_FIELDS];
  size_t count = 0;
  const char *end;
  route_t parsed;

  if (line == NULL || route == NULL)
  {
    return false;
  }
  while (is_space(*line))
  {
    line++;
  }
  end = line + strlen(line);
  while (end > line && is_space(end[-1]))
  {
    end--;
  }

  while (line < end)
  {
    const char *stop = line;
    while (stop < end && !is_space(*stop))
    {
      stop++;
    }
    /* stop == line means whitespace other than a space or tab between fields */
    if (stop == line || count == ROUTE_FIELDS ||
        (size_t)(stop - line) >= sizeof field[0])
    {
      return false;
    }
    length[count] = (size_t)(stop - line);
    memcpy(field[count], line, length[count]);
    field[count][length[count]] = '\0';
    count++;
    while (stop < end && is_blank(*stop))
    {
      stop++;
    }
    line = stop;
  }
  if (count != ROUTE_FIELDS)
  {
    return false;
  }

  memset(&parsed, 0, sizeof parsed);
  if (strcmp(field[0], "default") != 0 &&
      (!cidr_parse(field[0], &parsed.dest) || !cidr_is_network(parsed.dest)))
  {
    return false;
  }
  if (strcmp(field[1], "direct") != 0 && !ip_parse(field[1], &parsed.gateway))
  {
    return false;
  }
  if (length[2] >= DEV_NAME_LEN)
  {
    return false;
  }
  memcpy(parsed.dev, field[2], length[2]);
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  /* calloc leaves routes NULL and count and capacity 0. */
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table == NULL)
  {
    return;
  }
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  route_t copy;

  if (table == NULL || route == NULL || route->dest.prefix > 32 ||
      !cidr_is_network(route->dest))
  {
    return false;
  }
  for (size_t k = 0; k < table->count; k++)
  {
    const cidr_t *dest = &table->routes[k].dest;
    if (dest->addr == route->dest.addr && dest->prefix == route->dest.prefix)
    {
      return false;
    }
  }
  if (table->count == table->capacity)
  {
    size_t capacity = table->capacity == 0 ? 8 : table->capacity * 2;
    /* A temporary keeps the old array if realloc fails, so the table is unchanged. */
    route_t *grown = realloc(table->routes, capacity * sizeof(route_t));
    if (grown == NULL) // GCOVR_EXCL_START
    {
      return false;
    } // GCOVR_EXCL_STOP
    table->routes = grown;
    table->capacity = capacity;
  }
  copy = *route;
  copy.dev[DEV_NAME_LEN - 1] = '\0';
  table->routes[table->count] = copy;
  table->count++;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  bool ok = true;

  if (bad_line != NULL)
  {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL)
  {
    return false;
  }
  while (getline(&line, &capacity, in) != -1)
  {
    char *comment = strchr(line, '#');
    route_t route;

    line_number++;
    if (comment != NULL)
    {
      *comment = '\0';
    }
    if (is_blank_line(line))
    {
      continue;
    }
    if (!route_parse(line, &route) || !table_add(table, &route))
    {
      if (bad_line != NULL)
      {
        *bad_line = line_number;
      }
      ok = false;
      break;
    }
  }
  /* getline may allocate the buffer even when it reads nothing. */
  free(line);
  /* getline returns -1 for a read error as well as for the end of the file. */
  if (ok && ferror(in))
  {
    return false;
  }
  return ok;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  const route_t *best = NULL;

  if (table == NULL)
  {
    return NULL;
  }
  for (size_t k = 0; k < table->count; k++)
  {
    const route_t *candidate = &table->routes[k];
    /* Only a strictly longer prefix replaces the best so far; there are no
     * ties because table_add refuses a second route to the same block. */
    if (cidr_contains(candidate->dest, dest) &&
        (best == NULL || candidate->dest.prefix > best->dest.prefix))
    {
      best = candidate;
    }
  }
  return best;
}
