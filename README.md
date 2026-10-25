# P3 - Subnetting and Forwarding

- Name: Jake Dickinson
- Email: jakedickinson@u.boisestate.edu
- Class: CS425-001

## Known Bugs or Issues

None known. These are the places where the assignment left a choice open
and I picked one:

- **No matching route.** `lookup` prints `<address> unreachable` on stdout
  (for example `8.8.8.8 unreachable`), in the same position as the other
  answers, and exits 3. The assignment only says the line "prints
  `unreachable`", so the exact format is a judgment call.
- **Prefixes over 32.** `cidr_mask()` and every function built on it treat a
  prefix over 32 as 32, and `cidr_format()` prints it as `/32`, as `lab.h`
  says. `table_add()` refuses such a route instead, because a stored route
  should name a real block.
- **`info` accepts host bits** (`132.178.227.11/25` is an interface address),
  so it shows the address as given. `split` refuses host bits.
- **`split` counts** are decimal digits only, with no sign and no leading zero,
  and must fit in 32 bits. `0` is accepted as a number but is not a power of
  two, so it is refused.
- **`split 0.0.0.0/0 2147483648`** is legal and prints 2^31 lines.
- **Table files.** Line numbers in error messages count every line in the
  file, comments and blank lines included. The keywords `default` and `direct`
  are lowercase only. Fields are separated by spaces or tabs, and a device
  name is 1 to 15 characters with no whitespace. A line that contains a NUL
  byte is only read up to the NUL.
- **Errors.** Every error goes to stderr and names the input that caused it,
  for example `myapp: tables/bad.txt:4: not a valid route`. A bad command line
  also prints the usage text to stderr. Running with no arguments prints the
  usage text to stdout and exits 0.

## Experience

TODO (Jake): Describe your experience with the project (struggles, breakthroughs, etc.).

## Design

### Address representation

An address is a `uint32_t` in host byte order, so the first octet is the most
significant byte and `192.168.1.10` is `0xC0A8010A`. A block (`cidr_t`) is an
address plus a prefix length. Every value is a bit operation on the mask:
the network is `addr & mask`, the broadcast is `addr | ~mask`, and `x` is in
the block when `(x & mask) == (addr & mask)`.

The parser is written by hand: a small state machine reads four octets of 1
to 3 digits separated by single periods, then for CIDR a `/` and a prefix of 1
or 2 digits. It rejects leading zeros (`010`), signs, whitespace, empty or
extra octets, values over 255 or 32, and anything after the end. That is
stricter than the library functions on purpose. `inet_aton()` reads `010` as
octal (8), and `sscanf("%u.%u.%u.%u")` accepts `+1.2.3.4` and `1.2.3.4junk`.
A router should refuse input like that rather than guess what it means. The
output is written only on success, so a failed parse leaves the caller's
variable untouched. The formatting functions mask each octet to 0 to 255,
which lets the compiler prove the text always fits in `IP_STR_LEN` and
`CIDR_STR_LEN`.

### /0

The textbook mask, `0xFFFFFFFF << (32 - prefix)`, shifts by 32 when the
prefix is 0. That is undefined behavior in C, and on x86 it shifts by 0
instead, so the mask comes out all ones. With that bug the default route
would only match `0.0.0.0`. `cidr_mask()` returns 0 for `/0` without
shifting, and for every other prefix the shift is between 0 and 31.

The host count for a `/0` is 2^32 - 2. The result fits in 32 bits, but 2^32
does not, so `cidr_host_count()` does the arithmetic in `uint64_t`.
`cidr_subnet()` also computes subnet sizes and offsets in 64 bits, because
the single subnet of a `/0` (n = 1) holds 2^32 addresses. Splitting
`0.0.0.0/0` into 2^31 `/31`s works too.

The default route needs no special case anywhere. `default` in a table file
is stored as `0.0.0.0/0`, its mask is 0, so it contains every address. It has
the shortest possible prefix, so it wins only when nothing else matches.

### /31 and /32

The usual rule that the first address is the network and the last is the
broadcast does not apply to these two. A `/31` is a point-to-point link
between two routers (RFC 3021), so both addresses are hosts. A `/32` is a
single host. For both, `cidr_first_host()` returns the network address and
`cidr_last_host()` returns the broadcast address, instead of network + 1 and
broadcast - 1. `cidr_host_count()` returns 2 for a `/31` and 1 for a `/32`
instead of 2^(32 - prefix) - 2, which would give 0 and -1. `info` prints all
eight lines for these blocks too. `network` and `broadcast` show the computed
values, and the host lines follow the rules above.

### Longest prefix match

The private `struct fwd_table` holds a dynamic array of `route_t` with a
count and a capacity. `table_add()` doubles the capacity when the array is
full (8, 16, 32, ...). It calls `realloc()` into a temporary pointer, so if
the allocation fails the old array is still there and the table is
unchanged. Before adding anything, `table_add()` checks the route and refuses
it if the destination has host bits set, the prefix is over 32, or a route to
the same block (same address and prefix) is already in the table, the way
`ip route add` does. It stores a copy of the route and always terminates the
device name.

`table_lookup()` scans every route. A route is a candidate when its block
contains the address. The best candidate so far is replaced only by one with
a *strictly* longer prefix. Duplicate blocks are refused, so two candidates
can never have the same prefix (two different blocks with the same prefix
are disjoint). The result is therefore the longest match whatever order the
routes were added in. The unit tests check this by building the example
table in all 5040 possible orders. It never returns the first match.

A lookup costs O(n) for n routes. That is fine for tables of this size, and
the assignment allows a linear scan. A real router with about a million
prefixes would use a binary trie instead, walking one address bit per level,
so a lookup takes at most 32 steps whatever the table size.

`table_load()` reads the file with `getline()`. It removes everything from
the first `#`, skips lines that are then blank, and passes each other line
to `route_parse()` and then `table_add()`. It stops at the first line that
fails and reports its 1-based number, keeping the routes from earlier lines.
It frees the line buffer on every path. It also checks `ferror()` after the
loop, because `getline()` returns -1 both at the end of the file and on a
read error.

## Building and Testing

```bash
make all         # debug (ASan), release, test (gcov) and debug-test builds
make check       # run the Unity tests
make report      # tests plus a gcovr coverage report (build/report/)
make leak        # run the ASan build with no arguments (prints the usage)
make leak-test   # run the Unity tests under ASan with leak detection
```

`tests/lab-test.c` has Unity tests for every function in `src/lab.h`,
including the boundaries `/0`, `/31`, `/32`, `0.0.0.0` and
`255.255.255.255`. They also cover every malformed input from the
assignment, a lookup where several routes match, the same table added in
every order, a table with no default route, and table files with a bad line
in the middle, duplicate lines, comments, CRLF line endings and a read
error. They give 100% line and branch coverage of `src/lab.c`. The only
lines excluded are the `realloc()` failure branch in `table_add()`.

`tests/cli-test.sh` runs the program through every command line case from
the assignment and checks stdout byte for byte, stderr and the exit code:

```bash
tests/cli-test.sh                                                # release build
ASAN_OPTIONS=detect_leaks=1 tests/cli-test.sh build/debug/myapp_d  # also checks for leaks
```

Example:

```text
$ ./build/release/myapp lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
132.178.227.50 dev eno1
8.8.8.8 via 132.178.227.1 dev eno1
10.1.2.5 dev eth2
10.1.2.200 via 10.1.2.1 dev eth2
```
