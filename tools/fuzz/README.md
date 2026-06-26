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

Requires a libFuzzer-capable compiler (Clang).

The codec is pure, so the simplest build compiles just the two files it needs
(no libubox/ubus/json-c, no full project configure):

```sh
# Self-contained build (recommended):
CC=clang tools/fuzz/build.sh /tmp/script_req_fuzz

# Seed corpus (optional but recommended):
tools/fuzz/gen_seed_corpus.sh

# Fuzz:
/tmp/script_req_fuzz tools/fuzz/corpus
```

Alternatively, the CMake `FUZZING` option builds the same target — but note it
configures the whole project, so it needs odhcp6c's normal build dependencies
present:

```sh
CC=clang cmake -S . -B build-fuzz -DFUZZING=ON
cmake --build build-fuzz --target script_req_fuzz
```

The target is built with `-fsanitize=fuzzer,address,undefined`, so memory and
UB bugs abort immediately with a reproducer written to `crash-*`.

To replay a single input:

```sh
/tmp/script_req_fuzz crash-<hash>
```

## Continuous integration

`.github/workflows/fuzz.yml` runs two jobs off this directory:

- **Per PR** (when the codec or this tooling changes): builds with
  `build.sh`, replays the seed corpus and every file under `regressions/`, then
  does a short bounded run. Deterministic, so it gates the PR.
- **Nightly / on demand**: a longer campaign with the corpus persisted across
  runs; best-effort, never blocks a PR.

When a crash is found, commit its `crash-*` reproducer into `regressions/` so it
is replayed on every future PR (see `regressions/README.md`).


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
