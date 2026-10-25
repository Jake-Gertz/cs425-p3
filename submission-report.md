# Submission Report

- Submission generated at 10/25/2026 at 04:44:30

- Machine info: Linux runnervmtai0g 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux

## Note to Students

Please read this report carefully before submission.
Ensure that all sections are complete and accurate.
Look for any errors in the build or test outputs.
If you find any issues, correct them before submitting.
Post any questions on the class discussion board for help.


---

## README

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

I think that throughout this semester focusing on the AI first work flow for this class has really helped me understand the steps
required to make said workflow successful in a project like this! From the start I think my understanding of how to prompt my
agents and how to set up the tasks has improved leading to gains in both speed and effectiveness of my AI first work flows.
One funny bug I had was when I misspelled my name in my email when telling claude what to put in the header of things and it then assumed
that my email was correct and my normal name was not correct leading to a couple corrections having to be made to the plan. I also think that
I need to find a better way to manage the open shell windows I have while working in PowerShell on windows since I currently just have all the
seperate windows I use floating around my screen which causes then to be hidden behind other screen elements when I click around to do separate
work. I am sure there are plenty of solutions to this problem. I just need to spend the time to set one up. This task also showed me that there
are a lot of things I do before I get into sessions the exact same way every time, like giving the model context around what it will be building,
context on my system and how its set up, and some of the baseline rules I would like it to follow. I think that I should look into creating skills
to feed into my agents that give it a lot of the pre canned copy paste kind of instructions up front which will save me time and help me get a model
to give me more consistent results compared to what it was giving me before. Overall I thought this was a great project and as we continue to
develop things in this AI first way throughout this class I continue to find new and interesting side projects and tasks that I want to dive in
apart from classwork to make this approach as effective as possible at helping me learn and grow as a professional in important ways and at a speed
that would not have been possible before this technology existed.

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

---


## Build Output

This section was generated by running `make all` in the project root directory.

```bash
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/debug
cc -g -O0 -DDEBUG -fno-omit-frame-pointer -fsanitize=address -c src/lab.c -o build/debug/lab.c.o
mkdir -p build/debug
cc -g -O0 -DDEBUG -fno-omit-frame-pointer -fsanitize=address -c src/main.c -o build/debug/main.c.o
cc -g -O0 -DDEBUG -fno-omit-frame-pointer -fsanitize=address build/debug/lab.c.o build/debug/main.c.o -o build/debug/myapp_d -fsanitize=address
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/release
cc -Wall -Wextra -O2 -fPIE -MMD -MP -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -fstack-protector-strong -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion -c src/lab.c -o build/release/lab.c.o
mkdir -p build/release
cc -Wall -Wextra -O2 -fPIE -MMD -MP -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -fstack-protector-strong -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion -c src/main.c -o build/release/main.c.o
cc -Wall -Wextra -O2 -fPIE -MMD -MP -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -fstack-protector-strong -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion build/release/lab.c.o build/release/main.c.o -o build/release/myapp 
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/tests
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c src/lab.c -o build/tests/lab.c.o
mkdir -p build/tests
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c src/main.c -o build/tests/main.c.o
mkdir -p build/tests/
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c tests/lab-test.c -o build/tests/lab-test.c.o
mkdir -p build/tests/harness/
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c tests/harness/unity.c -o build/tests/harness/unity.c.o
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage build/tests/lab.c.o build/tests/main.c.o build/tests/lab-test.c.o build/tests/harness/unity.c.o -o build/tests/myapp_t -fprofile-arcs -ftest-coverage
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/debug-test
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c src/lab.c -o build/debug-test/lab.c.o
mkdir -p build/debug-test
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c src/main.c -o build/debug-test/main.c.o
mkdir -p build/debug-test/
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c tests/lab-test.c -o build/debug-test/lab-test.c.o
mkdir -p build/debug-test/harness/
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c tests/harness/unity.c -o build/debug-test/harness/unity.c.o
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address build/debug-test/lab.c.o build/debug-test/main.c.o build/debug-test/lab-test.c.o build/debug-test/harness/unity.c.o -o build/debug-test/myapp_td -fsanitize=address
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
Builds completed. You can run the application with: ./build/release/myapp
You can run the debug build with: ./build/debug/myapp_d
You can run the test build with: ./build/tests/myapp_t
You can run the debug-test build with: ./build/debug-test/myapp_td
```

---

## Coverage Report

This section was generated by running `make report` in the project root directory.

```bash
tests/lab-test.c:1130:test_ip_parse_valid:PASS
tests/lab-test.c:1131:test_ip_parse_rejects_pdf_list:PASS
tests/lab-test.c:1132:test_ip_parse_rejects_more_malformed:PASS
tests/lab-test.c:1133:test_ip_parse_null:PASS
tests/lab-test.c:1134:test_ip_format:PASS
tests/lab-test.c:1135:test_ip_format_round_trip:PASS
tests/lab-test.c:1136:test_cidr_parse_valid:PASS
tests/lab-test.c:1137:test_cidr_parse_rejects_pdf_list:PASS
tests/lab-test.c:1138:test_cidr_parse_rejects_more_malformed:PASS
tests/lab-test.c:1139:test_cidr_parse_null:PASS
tests/lab-test.c:1140:test_cidr_format:PASS
tests/lab-test.c:1141:test_cidr_format_round_trip:PASS
tests/lab-test.c:1143:test_cidr_mask_boundaries:PASS
tests/lab-test.c:1144:test_cidr_mask_every_prefix:PASS
tests/lab-test.c:1145:test_cidr_network_broadcast_pdf_example:PASS
tests/lab-test.c:1146:test_cidr_network_broadcast_boundaries:PASS
tests/lab-test.c:1147:test_cidr_host_range_pdf_example:PASS
tests/lab-test.c:1148:test_cidr_host_range_boundaries:PASS
tests/lab-test.c:1149:test_cidr_host_count:PASS
tests/lab-test.c:1150:test_cidr_host_count_matches_range:PASS
tests/lab-test.c:1151:test_cidr_contains_pdf_example:PASS
tests/lab-test.c:1152:test_cidr_contains_boundaries:PASS
tests/lab-test.c:1153:test_cidr_is_network:PASS
tests/lab-test.c:1154:test_cidr_subnet_split_24_into_4:PASS
tests/lab-test.c:1155:test_cidr_subnet_one_piece_is_the_block:PASS
tests/lab-test.c:1156:test_cidr_subnet_rejects_bad_count:PASS
tests/lab-test.c:1157:test_cidr_subnet_rejects_non_network:PASS
tests/lab-test.c:1158:test_cidr_subnet_prefix_limit:PASS
tests/lab-test.c:1159:test_cidr_subnet_null_out:PASS
tests/lab-test.c:1160:test_cidr_subnet_whole_space:PASS
tests/lab-test.c:1162:test_route_parse_example_lines:PASS
tests/lab-test.c:1163:test_route_parse_keywords:PASS
tests/lab-test.c:1164:test_route_parse_whitespace:PASS
tests/lab-test.c:1165:test_route_parse_device_length:PASS
tests/lab-test.c:1166:test_route_parse_rejects:PASS
tests/lab-test.c:1167:test_route_parse_null:PASS
tests/lab-test.c:1168:test_table_create_destroy_count:PASS
tests/lab-test.c:1169:test_table_null:PASS
tests/lab-test.c:1170:test_table_add_null:PASS
tests/lab-test.c:1171:test_table_add_rejects_host_bits:PASS
tests/lab-test.c:1172:test_table_add_rejects_long_prefix:PASS
tests/lab-test.c:1173:test_table_add_rejects_duplicate:PASS
tests/lab-test.c:1174:test_table_add_copies_route:PASS
tests/lab-test.c:1175:test_table_add_terminates_device:PASS
tests/lab-test.c:1176:test_table_add_grows:PASS
tests/lab-test.c:1177:test_table_load_example:PASS
tests/lab-test.c:1178:test_table_load_comments_and_blank_lines:PASS
tests/lab-test.c:1179:test_table_load_bad_line_in_middle:PASS
tests/lab-test.c:1180:test_table_load_line_numbers_count_every_line:PASS
tests/lab-test.c:1181:test_table_load_duplicate_line:PASS
tests/lab-test.c:1182:test_table_load_duplicate_of_existing_route:PASS
tests/lab-test.c:1183:test_table_load_first_line_bad:PASS
tests/lab-test.c:1184:test_table_load_null_arguments:PASS
tests/lab-test.c:1185:test_table_load_null_bad_line:PASS
tests/lab-test.c:1186:test_table_load_read_error:PASS
tests/lab-test.c:1187:test_table_load_empty_and_odd_files:PASS
tests/lab-test.c:1188:test_table_lookup_longest_of_several:PASS
tests/lab-test.c:1189:test_table_lookup_independent_of_order:PASS
tests/lab-test.c:1190:test_table_lookup_reverse_and_shuffled:PASS
tests/lab-test.c:1191:test_table_lookup_no_default_route:PASS
tests/lab-test.c:1192:test_table_lookup_default_only_as_last_resort:PASS
tests/lab-test.c:1193:test_table_lookup_host_and_point_to_point_routes:PASS

-----------------------
62 Tests 0 Failures 0 Ignored 
OK
./build/tests/myapp_t
tests/lab-test.c:1130:test_ip_parse_valid:PASS
tests/lab-test.c:1131:test_ip_parse_rejects_pdf_list:PASS
tests/lab-test.c:1132:test_ip_parse_rejects_more_malformed:PASS
tests/lab-test.c:1133:test_ip_parse_null:PASS
tests/lab-test.c:1134:test_ip_format:PASS
tests/lab-test.c:1135:test_ip_format_round_trip:PASS
tests/lab-test.c:1136:test_cidr_parse_valid:PASS
tests/lab-test.c:1137:test_cidr_parse_rejects_pdf_list:PASS
tests/lab-test.c:1138:test_cidr_parse_rejects_more_malformed:PASS
tests/lab-test.c:1139:test_cidr_parse_null:PASS
tests/lab-test.c:1140:test_cidr_format:PASS
tests/lab-test.c:1141:test_cidr_format_round_trip:PASS
tests/lab-test.c:1143:test_cidr_mask_boundaries:PASS
tests/lab-test.c:1144:test_cidr_mask_every_prefix:PASS
tests/lab-test.c:1145:test_cidr_network_broadcast_pdf_example:PASS
tests/lab-test.c:1146:test_cidr_network_broadcast_boundaries:PASS
tests/lab-test.c:1147:test_cidr_host_range_pdf_example:PASS
tests/lab-test.c:1148:test_cidr_host_range_boundaries:PASS
tests/lab-test.c:1149:test_cidr_host_count:PASS
tests/lab-test.c:1150:test_cidr_host_count_matches_range:PASS
tests/lab-test.c:1151:test_cidr_contains_pdf_example:PASS
tests/lab-test.c:1152:test_cidr_contains_boundaries:PASS
tests/lab-test.c:1153:test_cidr_is_network:PASS
tests/lab-test.c:1154:test_cidr_subnet_split_24_into_4:PASS
tests/lab-test.c:1155:test_cidr_subnet_one_piece_is_the_block:PASS
tests/lab-test.c:1156:test_cidr_subnet_rejects_bad_count:PASS
tests/lab-test.c:1157:test_cidr_subnet_rejects_non_network:PASS
tests/lab-test.c:1158:test_cidr_subnet_prefix_limit:PASS
tests/lab-test.c:1159:test_cidr_subnet_null_out:PASS
tests/lab-test.c:1160:test_cidr_subnet_whole_space:PASS
tests/lab-test.c:1162:test_route_parse_example_lines:PASS
tests/lab-test.c:1163:test_route_parse_keywords:PASS
tests/lab-test.c:1164:test_route_parse_whitespace:PASS
tests/lab-test.c:1165:test_route_parse_device_length:PASS
tests/lab-test.c:1166:test_route_parse_rejects:PASS
tests/lab-test.c:1167:test_route_parse_null:PASS
tests/lab-test.c:1168:test_table_create_destroy_count:PASS
tests/lab-test.c:1169:test_table_null:PASS
tests/lab-test.c:1170:test_table_add_null:PASS
tests/lab-test.c:1171:test_table_add_rejects_host_bits:PASS
tests/lab-test.c:1172:test_table_add_rejects_long_prefix:PASS
tests/lab-test.c:1173:test_table_add_rejects_duplicate:PASS
tests/lab-test.c:1174:test_table_add_copies_route:PASS
tests/lab-test.c:1175:test_table_add_terminates_device:PASS
tests/lab-test.c:1176:test_table_add_grows:PASS
tests/lab-test.c:1177:test_table_load_example:PASS
tests/lab-test.c:1178:test_table_load_comments_and_blank_lines:PASS
tests/lab-test.c:1179:test_table_load_bad_line_in_middle:PASS
tests/lab-test.c:1180:test_table_load_line_numbers_count_every_line:PASS
tests/lab-test.c:1181:test_table_load_duplicate_line:PASS
tests/lab-test.c:1182:test_table_load_duplicate_of_existing_route:PASS
tests/lab-test.c:1183:test_table_load_first_line_bad:PASS
tests/lab-test.c:1184:test_table_load_null_arguments:PASS
tests/lab-test.c:1185:test_table_load_null_bad_line:PASS
tests/lab-test.c:1186:test_table_load_read_error:PASS
tests/lab-test.c:1187:test_table_load_empty_and_odd_files:PASS
tests/lab-test.c:1188:test_table_lookup_longest_of_several:PASS
tests/lab-test.c:1189:test_table_lookup_independent_of_order:PASS
tests/lab-test.c:1190:test_table_lookup_reverse_and_shuffled:PASS
tests/lab-test.c:1191:test_table_lookup_no_default_route:PASS
tests/lab-test.c:1192:test_table_lookup_default_only_as_last_resort:PASS
tests/lab-test.c:1193:test_table_lookup_host_and_point_to_point_routes:PASS

-----------------------
62 Tests 0 Failures 0 Ignored 
OK
mkdir -p ./build/report/html
mkdir -p ./build/report/txt
gcovr -r . --html --html-details --exclude-directories build/tests/harness --exclude '.*main\.c$' --exclude '.*test\.c$' -o ./build/report/html/coverage_report.html
gcovr -r . --txt                 --exclude-directories build/tests/harness --exclude '.*main\.c$' --exclude '.*test\.c$'
------------------------------------------------------------------------------
                           GCC Code Coverage Report
Directory: .
------------------------------------------------------------------------------
File                                         Lines     Exec  Cover   Missing
------------------------------------------------------------------------------
src/lab.c                                      209      209   100%
------------------------------------------------------------------------------
TOTAL                                          209      209   100%
------------------------------------------------------------------------------
```

---

## Address Sanitizer Report

This section was generated by running `make leak-test` in the project root directory.

```bash
tests/lab-test.c:1130:test_ip_parse_valid:PASS
tests/lab-test.c:1131:test_ip_parse_rejects_pdf_list:PASS
tests/lab-test.c:1132:test_ip_parse_rejects_more_malformed:PASS
tests/lab-test.c:1133:test_ip_parse_null:PASS
tests/lab-test.c:1134:test_ip_format:PASS
tests/lab-test.c:1135:test_ip_format_round_trip:PASS
tests/lab-test.c:1136:test_cidr_parse_valid:PASS
tests/lab-test.c:1137:test_cidr_parse_rejects_pdf_list:PASS
tests/lab-test.c:1138:test_cidr_parse_rejects_more_malformed:PASS
tests/lab-test.c:1139:test_cidr_parse_null:PASS
tests/lab-test.c:1140:test_cidr_format:PASS
tests/lab-test.c:1141:test_cidr_format_round_trip:PASS
tests/lab-test.c:1143:test_cidr_mask_boundaries:PASS
tests/lab-test.c:1144:test_cidr_mask_every_prefix:PASS
tests/lab-test.c:1145:test_cidr_network_broadcast_pdf_example:PASS
tests/lab-test.c:1146:test_cidr_network_broadcast_boundaries:PASS
tests/lab-test.c:1147:test_cidr_host_range_pdf_example:PASS
tests/lab-test.c:1148:test_cidr_host_range_boundaries:PASS
tests/lab-test.c:1149:test_cidr_host_count:PASS
tests/lab-test.c:1150:test_cidr_host_count_matches_range:PASS
tests/lab-test.c:1151:test_cidr_contains_pdf_example:PASS
tests/lab-test.c:1152:test_cidr_contains_boundaries:PASS
tests/lab-test.c:1153:test_cidr_is_network:PASS
tests/lab-test.c:1154:test_cidr_subnet_split_24_into_4:PASS
tests/lab-test.c:1155:test_cidr_subnet_one_piece_is_the_block:PASS
tests/lab-test.c:1156:test_cidr_subnet_rejects_bad_count:PASS
tests/lab-test.c:1157:test_cidr_subnet_rejects_non_network:PASS
tests/lab-test.c:1158:test_cidr_subnet_prefix_limit:PASS
tests/lab-test.c:1159:test_cidr_subnet_null_out:PASS
tests/lab-test.c:1160:test_cidr_subnet_whole_space:PASS
tests/lab-test.c:1162:test_route_parse_example_lines:PASS
tests/lab-test.c:1163:test_route_parse_keywords:PASS
tests/lab-test.c:1164:test_route_parse_whitespace:PASS
tests/lab-test.c:1165:test_route_parse_device_length:PASS
tests/lab-test.c:1166:test_route_parse_rejects:PASS
tests/lab-test.c:1167:test_route_parse_null:PASS
tests/lab-test.c:1168:test_table_create_destroy_count:PASS
tests/lab-test.c:1169:test_table_null:PASS
tests/lab-test.c:1170:test_table_add_null:PASS
tests/lab-test.c:1171:test_table_add_rejects_host_bits:PASS
tests/lab-test.c:1172:test_table_add_rejects_long_prefix:PASS
tests/lab-test.c:1173:test_table_add_rejects_duplicate:PASS
tests/lab-test.c:1174:test_table_add_copies_route:PASS
tests/lab-test.c:1175:test_table_add_terminates_device:PASS
tests/lab-test.c:1176:test_table_add_grows:PASS
tests/lab-test.c:1177:test_table_load_example:PASS
tests/lab-test.c:1178:test_table_load_comments_and_blank_lines:PASS
tests/lab-test.c:1179:test_table_load_bad_line_in_middle:PASS
tests/lab-test.c:1180:test_table_load_line_numbers_count_every_line:PASS
tests/lab-test.c:1181:test_table_load_duplicate_line:PASS
tests/lab-test.c:1182:test_table_load_duplicate_of_existing_route:PASS
tests/lab-test.c:1183:test_table_load_first_line_bad:PASS
tests/lab-test.c:1184:test_table_load_null_arguments:PASS
tests/lab-test.c:1185:test_table_load_null_bad_line:PASS
tests/lab-test.c:1186:test_table_load_read_error:PASS
tests/lab-test.c:1187:test_table_load_empty_and_odd_files:PASS
tests/lab-test.c:1188:test_table_lookup_longest_of_several:PASS
tests/lab-test.c:1189:test_table_lookup_independent_of_order:PASS
tests/lab-test.c:1190:test_table_lookup_reverse_and_shuffled:PASS
tests/lab-test.c:1191:test_table_lookup_no_default_route:PASS
tests/lab-test.c:1192:test_table_lookup_default_only_as_last_resort:PASS
tests/lab-test.c:1193:test_table_lookup_host_and_point_to_point_routes:PASS

-----------------------
62 Tests 0 Failures 0 Ignored 
OK
```

---

## Src Files
### lab.c

```c

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

```

### lab.h

```c

#ifndef LAB_H
#define LAB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Every address in this file is a uint32_t in host byte order, so the first
 * octet of 192.168.1.10 is the most significant byte: 0xC0A8010A.
 */

/** Room for the longest dotted quad, "255.255.255.255", and its '\0'. */
#define IP_STR_LEN 16

/** Room for the longest CIDR string, "255.255.255.255/32", and its '\0'. */
#define CIDR_STR_LEN 19

/** Room for an interface name; IFNAMSIZ on Linux, including the '\0'. */
#define DEV_NAME_LEN 16

/** An address block in CIDR notation: an address and a prefix length. */
typedef struct {
  uint32_t addr;  /**< any address in the block, host byte order */
  uint8_t prefix; /**< 0 to 32 */
} cidr_t;

/** One entry in a forwarding table. */
typedef struct {
  cidr_t dest;            /**< destination block; host bits must be zero */
  uint32_t gateway;       /**< next hop, or 0 when the block is directly connected */
  char dev[DEV_NAME_LEN]; /**< outgoing interface, for example "eth0" */
} route_t;

/** A forwarding table. Its layout is private to lab.c. */
typedef struct fwd_table fwd_table_t;

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

/**
 * @brief Parse a dotted quad such as "192.168.1.10".
 *
 * Exactly four decimal octets from 0 to 255 separated by single periods, with
 * nothing before, between or after them. An octet with a leading zero ("010")
 * is rejected, because inet_aton() reads it as octal and that is never what a
 * person typing it meant.
 *
 * @param text The string to parse.
 * @param addr Where the address is stored on success; untouched on failure.
 * @return true if text is a valid dotted quad, false otherwise (including NULL).
 */
bool ip_parse(const char *text, uint32_t *addr);

/**
 * @brief Format an address as a dotted quad.
 * @param addr The address, host byte order.
 * @param out A buffer of at least IP_STR_LEN bytes.
 */
void ip_format(uint32_t addr, char out[IP_STR_LEN]);

/**
 * @brief Parse a block in CIDR notation such as "192.168.1.0/24".
 *
 * The address follows the rules of ip_parse() and the prefix is a decimal
 * number from 0 to 32 with no leading zero. The slash and the prefix are
 * required. Host bits may be set ("132.178.227.11/25" is an interface
 * address), so use cidr_is_network() when they must not be.
 *
 * @param text The string to parse.
 * @param block Where the block is stored on success; untouched on failure.
 * @return true if text is valid CIDR notation, false otherwise (including NULL).
 */
bool cidr_parse(const char *text, cidr_t *block);

/**
 * @brief Format a block as "a.b.c.d/p", using the address exactly as stored.
 *
 * A prefix over 32 is written as 32, the way cidr_mask() treats it.
 *
 * @param block The block.
 * @param out A buffer of at least CIDR_STR_LEN bytes.
 */
void cidr_format(cidr_t block, char out[CIDR_STR_LEN]);

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

/**
 * @brief The subnet mask for a prefix length: /24 is 255.255.255.0.
 *
 * Careful with /0. Shifting a 32 bit value by 32 is undefined behavior in C.
 *
 * @param prefix 0 to 32; anything larger is treated as 32.
 * @return The mask, host byte order.
 */
uint32_t cidr_mask(uint8_t prefix);

/** @brief The lowest address in the block: the address with the host bits cleared. */
uint32_t cidr_network(cidr_t block);

/** @brief The highest address in the block: the address with the host bits set. */
uint32_t cidr_broadcast(cidr_t block);

/**
 * @brief The first address that can be given to a host.
 *
 * For /0 to /30 that is the network address plus one. A /31 is a point to
 * point link (RFC 3021) where both addresses are usable, and a /32 is a single
 * host, so for those two the first host is the network address.
 */
uint32_t cidr_first_host(cidr_t block);

/**
 * @brief The last address that can be given to a host.
 *
 * The broadcast address minus one for /0 to /30, and the broadcast address
 * itself for /31 and /32 (see cidr_first_host()).
 */
uint32_t cidr_last_host(cidr_t block);

/**
 * @brief How many addresses in the block can be given to hosts.
 *
 * 2^(32 - prefix) - 2 for /0 to /30, 2 for /31, and 1 for /32. For a /0 the
 * 2^32 in that formula needs 33 bits, more than a uint32_t holds, which is why
 * this returns a uint64_t.
 */
uint64_t cidr_host_count(cidr_t block);

/** @brief true if addr falls inside the block. */
bool cidr_contains(cidr_t block, uint32_t addr);

/** @brief true if the block's host bits are all zero, so it names a network. */
bool cidr_is_network(cidr_t block);

/**
 * @brief The i-th of n equally sized subnets of a block.
 *
 * Splitting a /24 into 4 gives four /26 blocks, and subnet 0 is the lowest.
 * Equal sizes are only possible when n is a power of two, and the new prefix
 * can not pass 32.
 *
 * @param block The block to split; it must be a network (cidr_is_network()).
 * @param n How many subnets, a power of two from 1 up.
 * @param i Which subnet, 0 to n - 1.
 * @param out Where the subnet is stored on success; untouched on failure.
 * @return false if out is NULL, the block is not a network, n is not a power
 *         of two, the split would need a prefix longer than 32, or i is out of
 *         range.
 */
bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out);

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

/**
 * @brief Parse one line of a forwarding table file.
 *
 * A line is three fields separated by spaces or tabs:
 *
 *     <destination> <gateway> <device>
 *
 * The destination is a block in CIDR notation with no host bits set, or the
 * word "default" for 0.0.0.0/0. The gateway is a dotted quad, or the word
 * "direct" for a directly connected block (stored as 0). The device is 1 to
 * DEV_NAME_LEN - 1 characters. Leading and trailing whitespace, including a
 * trailing newline, is ignored. Comments are not handled here.
 *
 * @param line The line.
 * @param route Where the route is stored on success; untouched on failure.
 * @return true if the line is a valid route, false otherwise (including NULL).
 */
bool route_parse(const char *line, route_t *route);

/**
 * @brief Create an empty forwarding table.
 * @return The table, which the caller frees with table_destroy(), or NULL if
 *         memory could not be allocated.
 */
fwd_table_t *table_create(void);

/** @brief Free a table and everything in it. NULL is allowed and does nothing. */
void table_destroy(fwd_table_t *table);

/** @brief The number of routes in the table; 0 for NULL. */
size_t table_count(const fwd_table_t *table);

/**
 * @brief Add a copy of a route to the table, growing it as needed.
 * @return false if either argument is NULL, the destination has host bits
 *         set, the table already holds a route to the same block, or memory
 *         could not be allocated. The table is unchanged on failure.
 */
bool table_add(fwd_table_t *table, const route_t *route);

/**
 * @brief Read a forwarding table file and add every route in it.
 *
 * Everything from a '#' to the end of a line is a comment, and a line that is
 * blank once the comment is removed is skipped. Every other line must be a
 * valid route (route_parse()) that table_add() accepts.
 *
 * @param table The table to add to.
 * @param in The open file to read.
 * @param bad_line If not NULL, set to the 1-based number of the first line
 *        that failed, or 0 if the arguments were NULL or the file could not
 *        be read.
 * @return true if every line loaded. On false, routes from the lines before
 *         the bad one stay in the table.
 */
bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line);

/**
 * @brief Longest prefix match: the route whose block contains dest and has the
 *        longest prefix.
 *
 * A default route (0.0.0.0/0) matches everything, so it is chosen only when
 * nothing more specific does. The order the routes were added in does not
 * matter.
 *
 * @return The matching route, which stays owned by the table, or NULL if no
 *         route matches (or table is NULL).
 */
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest);

#endif // LAB_H

```

### main.c

```c

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

```

## Tests Files
### cli-test.sh

```c

#!/bin/bash
# Run myapp through every command line case from the assignment and check its
# stdout (byte for byte), its exit code, and its stderr.
#
#   tests/cli-test.sh                          # tests ./build/release/myapp
#   ASAN_OPTIONS=detect_leaks=1 tests/cli-test.sh build/debug/myapp_d
#
# With the ASan build any leak or memory error is reported on stderr and
# changes the exit code, so the same cases also check every error path.
# Exits 0 only when every case passes.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
APP="${1:-./build/release/myapp}"
if [[ ! -x "$APP" ]]; then
  echo "cli-test: $APP not found; run 'make all' first" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pass=0
fail=0

USAGE='Usage: myapp info <address>/<prefix>
       myapp split <network>/<prefix> <count>
       myapp lookup <table-file> <address>...
'

# check NAME EXIT STDOUT STDERR ARGS...
#   STDOUT is compared exactly. STDERR is "" (must be empty), "+" (must not be
#   empty), or anything else (compared exactly).
check() {
  local name="$1" want_code="$2" want_out="$3" want_err="$4"
  shift 4
  "$APP" "$@" >"$TMP/out" 2>"$TMP/err"
  local code=$?
  printf '%s' "$want_out" >"$TMP/want_out"
  local problems=""
  [[ "$code" -eq "$want_code" ]] || problems+=" exit=$code(want $want_code)"
  cmp -s "$TMP/out" "$TMP/want_out" || problems+=" stdout"
  case "$want_err" in
    "") [[ -s "$TMP/err" ]] && problems+=" stderr(want empty)" ;;
    "+") [[ -s "$TMP/err" ]] || problems+=" stderr(want a message)" ;;
    *)
      printf '%s' "$want_err" >"$TMP/want_err"
      cmp -s "$TMP/err" "$TMP/want_err" || problems+=" stderr"
      ;;
  esac
  if [[ -z "$problems" ]]; then
    pass=$((pass + 1))
    echo "PASS  $name"
  else
    fail=$((fail + 1))
    echo "FAIL  $name:$problems"
    if [[ "$problems" == *stdout* ]]; then
      diff "$TMP/want_out" "$TMP/out" | sed 's/^/        /'
    fi
    if [[ "$problems" == *stderr* ]]; then
      sed 's/^/        stderr: /' "$TMP/err"
    fi
  fi
}

# Scratch tables
NO_DEFAULT="$TMP/no-default.txt"
grep -v '^default' tables/example.txt >"$NO_DEFAULT"
BAD="$TMP/bad.txt"
printf '%s\n' "default 132.178.227.1 eno1" "132.178.227.0/25 direct eno1" \
  "10.0.0.0/8 10.1.0.1 eth1" "10.1.0.0/16 nowhere eth1" "10.1.2.0/24 direct eth2" >"$BAD"
CRLF="$TMP/crlf.txt"
sed 's/$/\r/' tables/example.txt >"$CRLF"

echo "== usage and bad command lines"
check "no arguments prints usage" 0 "$USAGE" ""
check "unknown command" 1 "" "myapp: unknown command 'bogus'
$USAGE" bogus
check "info with no argument" 1 "" "myapp: info expects 1 argument
$USAGE" info
check "info with two arguments" 1 "" "+" info 10.0.0.0/8 10.0.0.0/8
check "split with one argument" 1 "" "myapp: split expects 2 arguments
$USAGE" split 192.168.1.0/24
check "split with three arguments" 1 "" "+" split 192.168.1.0/24 4 4
check "lookup with no arguments" 1 "" "+" lookup
check "lookup with no addresses" 1 "" "myapp: lookup expects a table file and at least 1 address
$USAGE" lookup tables/example.txt

echo "== info"
check "info PDF example" 0 'address    132.178.227.11
prefix     /25
netmask    255.255.255.128
network    132.178.227.0
broadcast  132.178.227.127
first host 132.178.227.1
last host  132.178.227.126
hosts      126
' "" info 132.178.227.11/25
check "info /0" 0 'address    0.0.0.0
prefix     /0
netmask    0.0.0.0
network    0.0.0.0
broadcast  255.255.255.255
first host 0.0.0.1
last host  255.255.255.254
hosts      4294967294
' "" info 0.0.0.0/0
check "info /31" 0 'address    10.0.0.1
prefix     /31
netmask    255.255.255.254
network    10.0.0.0
broadcast  10.0.0.1
first host 10.0.0.0
last host  10.0.0.1
hosts      2
' "" info 10.0.0.1/31
check "info /32" 0 'address    10.0.0.1
prefix     /32
netmask    255.255.255.255
network    10.0.0.1
broadcast  10.0.0.1
first host 10.0.0.1
last host  10.0.0.1
hosts      1
' "" info 10.0.0.1/32
check "info 255.255.255.255/32" 0 'address    255.255.255.255
prefix     /32
netmask    255.255.255.255
network    255.255.255.255
broadcast  255.255.255.255
first host 255.255.255.255
last host  255.255.255.255
hosts      1
' "" info 255.255.255.255/32
check "info /24" 0 'address    192.168.1.0
prefix     /24
netmask    255.255.255.0
network    192.168.1.0
broadcast  192.168.1.255
first host 192.168.1.1
last host  192.168.1.254
hosts      254
' "" info 192.168.1.0/24
check "info address without prefix" 1 "" "myapp: 1.2.3.4: not a valid CIDR block
" info 1.2.3.4
check "info malformed block" 1 "" "myapp: 1.2.3/24: not a valid CIDR block
" info 1.2.3/24
for bad in 1.2.3.4/33 1.2.3.4/024 1.2.3.4/ 010.0.0.1/8 +1.2.3.4/8 ""; do
  check "info rejects '$bad'" 1 "" "+" info "$bad"
done

echo "== split"
check "split PDF example" 0 '192.168.1.0/26
192.168.1.64/26
192.168.1.128/26
192.168.1.192/26
' "" split 192.168.1.0/24 4
check "split /30 into /32s" 0 '10.0.0.0/32
10.0.0.1/32
10.0.0.2/32
10.0.0.3/32
' "" split 10.0.0.0/30 4
check "split /0 into 1" 0 '0.0.0.0/0
' "" split 0.0.0.0/0 1
check "split /0 into 2" 0 '0.0.0.0/1
128.0.0.0/1
' "" split 0.0.0.0/0 2
check "split /32 into 1" 0 '10.0.0.1/32
' "" split 10.0.0.1/32 1
check "split /24 into 256" 0 "$(for i in $(seq 0 255); do echo "10.0.0.$i/32"; done)
" "" split 10.0.0.0/24 256
check "split past /32" 1 "" "myapp: 10.0.0.0/30 can not be split into 8 subnets (prefix would pass /32)
" split 10.0.0.0/30 8
check "split /24 into 512" 1 "" "myapp: 192.168.1.0/24 can not be split into 512 subnets (prefix would pass /32)
" split 192.168.1.0/24 512
check "split host bits set" 1 "" "myapp: 192.168.1.5/24: host bits are set, not a network
" split 192.168.1.5/24 4
check "split malformed block" 1 "" "myapp: 1.2.3/24: not a valid CIDR block
" split 1.2.3/24 4
check "split count 3" 1 "" "myapp: 3: count must be a power of two
" split 192.168.1.0/24 3
check "split count 0" 1 "" "myapp: 0: count must be a power of two
" split 192.168.1.0/24 0
check "split count 04" 1 "" "myapp: 04: not a valid count
" split 192.168.1.0/24 04
check "split count -4" 1 "" "myapp: -4: not a valid count
" split 192.168.1.0/24 -4
for bad in +4 " 4" "4 " 4x "" 0x4 4294967296 99999999999999999999; do
  check "split rejects count '$bad'" 1 "" "+" split 192.168.1.0/24 "$bad"
done
check "split count 4294967295 (fits, not a power of two)" 1 "" "+" split 0.0.0.0/0 4294967295

echo "== lookup"
check "lookup PDF example" 0 '132.178.227.50 dev eno1
8.8.8.8 via 132.178.227.1 dev eno1
10.1.2.5 dev eth2
10.1.2.200 via 10.1.2.1 dev eth2
' "" lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
check "lookup 192.168.5.5" 0 '192.168.5.5 via 10.1.0.1 dev eth1
' "" lookup tables/example.txt 192.168.5.5
check "lookup 10.200.0.1" 0 '10.200.0.1 via 10.1.0.1 dev eth1
' "" lookup tables/example.txt 10.200.0.1
check "lookup 10.1.99.1" 0 '10.1.99.1 dev eth1
' "" lookup tables/example.txt 10.1.99.1
check "lookup 132.178.227.200" 0 '132.178.227.200 via 132.178.227.1 dev eno1
' "" lookup tables/example.txt 132.178.227.200
check "lookup 0.0.0.0 and 255.255.255.255" 0 '0.0.0.0 via 132.178.227.1 dev eno1
255.255.255.255 via 132.178.227.1 dev eno1
' "" lookup tables/example.txt 0.0.0.0 255.255.255.255
check "lookup malformed and good" 1 '8.8.8.8 via 132.178.227.1 dev eno1
' "myapp: 1.2.3: not a valid address
" lookup tables/example.txt 1.2.3 8.8.8.8
check "lookup only malformed" 1 "" "myapp: 010.0.0.1: not a valid address
" lookup tables/example.txt 010.0.0.1
check "lookup no default, unreachable" 3 '8.8.8.8 unreachable
' "" lookup "$NO_DEFAULT" 8.8.8.8
check "lookup no default, malformed and unreachable" 1 '8.8.8.8 unreachable
' "myapp: 1.2.3: not a valid address
" lookup "$NO_DEFAULT" 1.2.3 8.8.8.8
check "lookup no default, reachable and unreachable" 3 '10.1.2.200 via 10.1.2.1 dev eth2
8.8.8.8 unreachable
132.178.227.1 dev eno1
' "" lookup "$NO_DEFAULT" 10.1.2.200 8.8.8.8 132.178.227.1
check "lookup missing table" 2 "" "myapp: tables/missing.txt: No such file or directory
" lookup tables/missing.txt 8.8.8.8
check "lookup bad line 4" 2 "" "myapp: $BAD:4: not a valid route
" lookup "$BAD" 8.8.8.8
check "lookup bad line 4 with a malformed address" 2 "" "myapp: $BAD:4: not a valid route
" lookup "$BAD" 1.2.3
check "lookup table that is a directory" 2 "" "myapp: $TMP: read error
" lookup "$TMP" 8.8.8.8
check "lookup CRLF table" 0 '10.1.2.200 via 10.1.2.1 dev eth2
' "" lookup "$CRLF" 10.1.2.200

echo
echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]

```

### lab-test.c

```c

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

```

## Scripts Files
Report generated on 10/25/2026 at 04:44:32


---

## End of Report

SHA-256 Hash of the report: 424c8baf3e235e25b8e252f2d418173ccb83c5525f09fcaed3a7611ebce67d3a

Do not edit the generated report. Any changes will be reported as academic dishonesty

---
## GitHub Info
- GitHub repo name: Jake-Gertz/cs425-p3
- The repository visibility is public.
- The workflow was triggered by Jake-Gertz
