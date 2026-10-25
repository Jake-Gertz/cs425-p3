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
