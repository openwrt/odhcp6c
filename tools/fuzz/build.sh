#!/bin/sh
# Build the script_req_decode() libFuzzer target as a self-contained binary.
#
# The codec is pure (no sockets, no fork/exec, no daemon globals), so this needs
# nothing from odhcp6c's dependency tree -- no libubox/ubus/json-c, and no full
# CMake configure. It compiles exactly two files: the pure codec and the harness.
# That is also why CI can fuzz without provisioning the daemon's dependencies.
#
# Usage:
#   CC=clang tools/fuzz/build.sh [output-binary]
#
# Env:
#   CC                compiler (default: clang; must support -fsanitize=fuzzer)
#   FUZZ_SANITIZERS   sanitizer set (default: fuzzer,address,undefined)
set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
root=$(CDPATH= cd "$here/../.." && pwd)

cc="${CC:-clang}"
out="${1:-$root/script_req_fuzz}"
san="${FUZZ_SANITIZERS:-fuzzer,address,undefined}"

set -x
"$cc" -I"$root/src" -std=gnu11 -D_GNU_SOURCE -g -O1 \
	-fsanitize="$san" \
	-o "$out" \
	"$root/src/script_codec.c" "$here/script_req_fuzz.c"
