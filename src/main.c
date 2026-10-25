#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

/* The name used in messages; argv[0] differs between the builds. */
#define PROGRAM "myapp"

/* Exit codes */
#define EXIT_OK 0
#define EXIT_BAD_INPUT 1   /* bad command line or a malformed address */
#define EXIT_BAD_TABLE 2   /* the table file can not be opened or has a bad line */
#define EXIT_UNREACHABLE 3 /* an address matches no route */

static void print_usage(FILE *out)
{
  fputs("Usage: myapp info <address>/<prefix>\n"
        "       myapp split <network>/<prefix> <count>\n"
        "       myapp lookup <table-file> <address>...\n",
        out);
}

static int bad_usage(const char *message)
{
  fprintf(stderr, "%s: %s\n", PROGRAM, message);
  print_usage(stderr);
  return EXIT_BAD_INPUT;
}

/*
 * Parse a subnet count by hand: decimal digits only, no sign, no leading zero
 * (except "0" itself), and small enough for a uint32_t.
 */
static bool parse_count(const char *text, uint32_t *count)
{
  uint64_t value = 0;

  if (text[0] == '\0' || (text[0] == '0' && text[1] != '\0'))
  {
    return false;
  }
  for (const char *p = text; *p != '\0'; p++)
  {
    if (*p < '0' || *p > '9')
    {
      return false;
    }
    value = value * 10u + (uint64_t)(*p - '0');
    if (value > UINT32_MAX)
    {
      return false;
    }
  }
  *count = (uint32_t)value;
  return true;
}

static void print_field(const char *label, const char *value)
{
  printf("%-11s%s\n", label, value);
}

static int run_info(const char *text)
{
  cidr_t block;
  char value[CIDR_STR_LEN];

  if (!cidr_parse(text, &block))
  {
    fprintf(stderr, "%s: %s: not a valid CIDR block\n", PROGRAM, text);
    return EXIT_BAD_INPUT;
  }
  ip_format(block.addr, value);
  print_field("address", value);
  snprintf(value, sizeof value, "/%u", (unsigned)block.prefix);
  print_field("prefix", value);
  ip_format(cidr_mask(block.prefix), value);
  print_field("netmask", value);
  ip_format(cidr_network(block), value);
  print_field("network", value);
  ip_format(cidr_broadcast(block), value);
  print_field("broadcast", value);
  ip_format(cidr_first_host(block), value);
  print_field("first host", value);
  ip_format(cidr_last_host(block), value);
  print_field("last host", value);
  printf("%-11s%" PRIu64 "\n", "hosts", cidr_host_count(block));
  return EXIT_OK;
}

static int run_split(const char *block_text, const char *count_text)
{
  cidr_t block;
  cidr_t subnet;
  uint32_t count;

  /* Check everything before printing anything. */
  if (!cidr_parse(block_text, &block))
  {
    fprintf(stderr, "%s: %s: not a valid CIDR block\n", PROGRAM, block_text);
    return EXIT_BAD_INPUT;
  }
  if (!cidr_is_network(block))
  {
    fprintf(stderr, "%s: %s: host bits are set, not a network\n", PROGRAM, block_text);
    return EXIT_BAD_INPUT;
  }
  if (!parse_count(count_text, &count))
  {
    fprintf(stderr, "%s: %s: not a valid count\n", PROGRAM, count_text);
    return EXIT_BAD_INPUT;
  }
  if (count == 0 || (count & (count - 1u)) != 0)
  {
    fprintf(stderr, "%s: %s: count must be a power of two\n", PROGRAM, count_text);
    return EXIT_BAD_INPUT;
  }
  if (!cidr_subnet(block, count, 0, &subnet))
  {
    fprintf(stderr, "%s: %s can not be split into %s subnets (prefix would pass /32)\n",
            PROGRAM, block_text, count_text);
    return EXIT_BAD_INPUT;
  }
  /* A 64 bit counter, so count == 2^31 can not overflow it. */
  for (uint64_t i = 0; i < count; i++)
  {
    char text[CIDR_STR_LEN];
    cidr_subnet(block, count, (uint32_t)i, &subnet);
    cidr_format(subnet, text);
    puts(text);
  }
  return EXIT_OK;
}

/* Load the table file; on failure print why and return NULL. */
static fwd_table_t *load_table(const char *path)
{
  FILE *in = fopen(path, "r");
  fwd_table_t *table;
  size_t bad_line = 0;
  bool loaded;

  if (in == NULL)
  {
    fprintf(stderr, "%s: %s: %s\n", PROGRAM, path, strerror(errno));
    return NULL;
  }
  table = table_create();
  if (table == NULL)
  {
    fprintf(stderr, "%s: %s: out of memory\n", PROGRAM, path);
    fclose(in);
    return NULL;
  }
  loaded = table_load(table, in, &bad_line);
  fclose(in);
  if (!loaded)
  {
    if (bad_line > 0)
    {
      fprintf(stderr, "%s: %s:%zu: not a valid route\n", PROGRAM, path, bad_line);
    }
    else
    {
      fprintf(stderr, "%s: %s: read error\n", PROGRAM, path);
    }
    table_destroy(table);
    return NULL;
  }
  return table;
}

static int run_lookup(const char *path, int count, char *addresses[])
{
  fwd_table_t *table = load_table(path);
  bool malformed = false;
  bool unreachable = false;

  if (table == NULL)
  {
    return EXIT_BAD_TABLE;
  }
  for (int k = 0; k < count; k++)
  {
    uint32_t addr;
    const route_t *route;
    char text[IP_STR_LEN];
    char gateway[IP_STR_LEN];

    if (!ip_parse(addresses[k], &addr))
    {
      fprintf(stderr, "%s: %s: not a valid address\n", PROGRAM, addresses[k]);
      malformed = true;
      continue;
    }
    ip_format(addr, text);
    route = table_lookup(table, addr);
    if (route == NULL)
    {
      printf("%s unreachable\n", text);
      unreachable = true;
    }
    else if (route->gateway != 0)
    {
      ip_format(route->gateway, gateway);
      printf("%s via %s dev %s\n", text, gateway, route->dev);
    }
    else
    {
      printf("%s dev %s\n", text, route->dev);
    }
  }
  table_destroy(table);
  if (malformed)
  {
    return EXIT_BAD_INPUT;
  }
  return unreachable ? EXIT_UNREACHABLE : EXIT_OK;
}

int main(int argc, char *argv[])
{
  const char *command;

  if (argc < 2)
  {
    print_usage(stdout);
    return EXIT_OK;
  }
  command = argv[1];
  if (strcmp(command, "info") == 0)
  {
    if (argc != 3)
    {
      return bad_usage("info expects 1 argument");
    }
    return run_info(argv[2]);
  }
  if (strcmp(command, "split") == 0)
  {
    if (argc != 4)
    {
      return bad_usage("split expects 2 arguments");
    }
    return run_split(argv[2], argv[3]);
  }
  if (strcmp(command, "lookup") == 0)
  {
    if (argc < 4)
    {
      return bad_usage("lookup expects a table file and at least 1 address");
    }
    return run_lookup(argv[2], argc - 3, argv + 3);
  }
  fprintf(stderr, "%s: unknown command '%s'\n", PROGRAM, command);
  print_usage(stderr);
  return EXIT_BAD_INPUT;
}
