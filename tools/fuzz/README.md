# Fuzzing the privsep request codec

`script_req_decode()` (in `src/script_codec.c`) is the **root-side** parser for
the privilege-separation IPC datagram: the unprivileged, network-facing worker
serializes a request and the privileged monitor decodes it before running the
status script. A bug here is reachable from attacker-influenced DHCPv6/RA input,
so the parser must never crash, over-read, or accept a malformed datagram.

The codec is intentionally **pure** — no sockets, no `fork`/`exec`, no globals,
no client state — so it can be fuzzed in isolation. The fuzz target links only
`src/script_codec.c` plus `tools/fuzz/script_req_fuzz.c`.

## Build & run

Requires a libFuzzer-capable compiler (Clang):

```sh
CC=clang cmake -S . -B build-fuzz -DFUZZING=ON
cmake --build build-fuzz --target script_req_fuzz

# Seed corpus (optional but recommended):
tools/fuzz/gen_seed_corpus.sh

# Fuzz:
./build-fuzz/script_req_fuzz tools/fuzz/corpus
```

The target is built with `-fsanitize=fuzzer,address,undefined`, so memory and
UB bugs abort immediately with a reproducer written to `crash-*`.

To replay a single input:

```sh
./build-fuzz/script_req_fuzz crash-<hash>
```

## What it exercises

`LLVMFuzzerTestOneInput` copies the input into a writable buffer (decode
re-sanitizes env entries in place) and calls `script_req_decode()` with the same
caps the monitor uses. Every datagram is checked for: magic, zero padding, the
`resume` boolean, per-field hard caps, exact size match, the action allow-list,
per-entry NUL-termination, full consumption of the declared env bytes, and
per-entry re-sanitization. The fuzzer's job is to prove none of those paths can
be driven into a crash or an out-of-bounds access.

## Corpus

`gen_seed_corpus.sh` writes a handful of valid/near-valid datagrams into
`tools/fuzz/corpus/`. The directory is otherwise empty (and git-ignored), so the
corpus is fully regenerable.
