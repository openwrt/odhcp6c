# odhcp6c Integration Harness — Improvement Tasks

Instructions for an AI coding agent (GitHub Copilot / Claude) to strengthen the
`tools/harness` integration suite and its CI wiring
(`.github/workflows/integration.yml`).

Tasks are ordered **highest impact first**. Each is self-contained: do them in
order, open one focused PR per task (or per tier), and do not start a task until
the previous one is green.

## Ground rules for every task

- The harness is high quality and deliberately POSIX-`sh` (it runs under Alpine
  BusyBox `ash` and OpenWrt). **Do not introduce bashisms** into `tools/harness/lib/*.sh`,
  `run-scenario.sh`, or `stub-script.sh`. `seccomp-syscall-report.sh` is `bash` and may stay so.
- Preserve existing behavior and comments unless a task says to change them.
- A test failure you uncover is a **finding to triage, not a thing to silence**.
  Never make a scenario pass by weakening an assertion or adding a skip without
  an explicit, documented reason.
- When you change assertion or capture semantics, update the affected
  `scenarios/*/expect.txt` and the header docs in `lib/assert.sh`.
- Validate locally where possible: `tools/harness/run-scenario.sh --list` and
  `tools/harness/run-scenario.sh <name>` (needs root/`sudo` for netns).

---

## Tier 0 — Run the tests that already exist (do first)

### Task 1. Stop the CI scenario list from drifting; run the orphaned scenarios

**Problem.** `.github/workflows/integration.yml` hard-codes the `SCENARIOS` env
list, and it has silently drifted from `tools/harness/scenarios/`. Five authored
scenarios never run in CI: `entry-formatting`, `info-options`, `malformed-dhcpv6`,
`prefix-renumber`, `ra-holdoff`. The most important is **`malformed-dhcpv6`** — it
sends a DHCPv6 REPLY with a TLV whose declared length (`0xffff`) exceeds the
datagram and asserts odhcp6c neither crashes nor binds (the out-of-bounds-read
defense in the option parser). The scapy backend already supports the
`--reply-raw-trailer` flag it needs. For a C daemon parsing hostile input, this
is the highest-value test in the repo and it currently produces **zero** signal.

**Change.**
1. Make the scenario set the single source of truth. Either:
   - **Preferred:** generate the list at job runtime from the harness itself, e.g.
     add a step that runs `tools/harness/run-scenario.sh --list` inside the built
     image and feeds the result into the matrix / loop; **or**
   - keep the static `SCENARIOS` env but add a **drift-guard step** that fails the
     job when the static list and `run-scenario.sh --list` disagree:
     ```sh
     diff <(printf '%s\n' $SCENARIOS | sort) \
          <(tools/harness/run-scenario.sh --list | sort) \
       || { echo "::error::SCENARIOS is out of sync with scenarios/ (see diff)"; exit 1; }
     ```
2. Add the five orphaned scenarios to the run set.
3. Run them across the existing matrix and **triage every failure**. A genuine
   failure here is likely a real bug or a real harness gap — capture it as an
   issue, do not park the scenario again. If a scenario is legitimately
   environment-gated (e.g. needs egress the cell does not have), gate it
   explicitly and document why, rather than dropping it from the list.

**Acceptance criteria.**
- `malformed-dhcpv6` runs in the per-PR `scenarios` job in every matrix cell.
- A scenario added to `scenarios/` but not to CI (or vice-versa) **fails CI**.
- No scenario is excluded without an inline comment stating the reason.

---

## Tier 1 — Make a passing test mean what a reader assumes

### Task 2. Add a sanitizer (ASan + UBSan) build/run cell

**Problem.** `malformed-dhcpv6` asserts "didn't crash, didn't bind" — a behavioral
proxy. An out-of-bounds **read** in the TLV walker that doesn't segfault passes
both checks. There is no memory-safety detector in the integration suite (the
separate `fuzz.yml` is different signal).

**Change.**
- Add a build path that compiles odhcp6c with `-fsanitize=address,undefined`
  `-fno-sanitize-recover=all -fno-omit-frame-pointer` (a CMake option/build-arg,
  e.g. `SANITIZE=ON`, threaded through the harness `Dockerfile`).
- Add one matrix cell (glibc/amd64 is sufficient — ASan support is best there)
  that runs the **full scenario set** against the sanitized binary.
- Export `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1` and
  `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1` so a finding aborts the
  worker (the harness already treats an unexpected exit as failure). Upload the
  sanitizer logs as artifacts.
- The privsep worker drops privileges and installs seccomp; ASan needs a few
  syscalls/mmap behavior. Run the sanitizer cell with `SECCOMP=OFF` (and note it),
  so ASan is the confinement under test, mirroring how the trace job already
  builds seccomp-off for visibility.

**Acceptance criteria.**
- A deliberately introduced 1-byte over-read in the option parser is caught by
  the sanitizer cell (verify once on a throwaway commit, then revert).
- Sanitizer logs are uploaded on failure.

### Task 3. Make absence assertions crash-safe harness-wide

**Problem.** In `lib/assert.sh`, a negative-polarity check on the wildcard action
(`harness_assert_one '*' ADDRESSES empty`) returns **PASS when zero records
exist**, because nothing violated the forbidden condition. Today only
`malformed-dhcpv6` guards this, via a per-scenario liveness pre-check. Any
negative-op scenario that forgets the guard mis-passes if odhcp6c died early.

**Change.**
- In `harness_assert_one`, when the op is negative **and** no records were
  captured at all (`_seen_action == 0`, including the `'*'` case), treat it as a
  **failure**: an absence claim is only meaningful if the binary produced
  evidence of life. Add a clear message ("no records captured; cannot assert
  absence — did odhcp6c start?").
- Alternatively/additionally, add a reusable `harness_require_liveness` helper
  (assert at least one record OR `harness_odhcp6c_running`) and call it from
  `scenario_assert`'s default path before negative checks.
- Keep the existing intended semantics for the case where records **do** exist.

**Acceptance criteria.**
- A scenario whose binary exits before writing any record **fails** its `empty` /
  `no_action` assertions instead of passing.
- `malformed-dhcpv6` still passes for the right reason (binary stays alive, emits
  `stopped`, never binds).

### Task 4. Let expect-files assert final state and counts

**Problem.** The default `expect.txt` path routes through `harness_assert_one`,
which for positive ops passes if **any** record matches ("X happened at some
point"). `harness_assert_last` exists but is unreachable from `expect.txt`. So
most scenarios cannot express "the **final** `bound` record must contain X" or
"there must be exactly N `ra-updated` records," and a regression that is correct
transiently but wrong in steady state passes.

**Change.**
- Extend the expect grammar in `harness_assert_expect` with a per-line modifier
  selecting evaluation scope. Suggested syntax (keep it POSIX-parseable):
  - `last:<action> <key> <op> [value]` → routes to `harness_assert_last`.
  - leave bare `<action> ...` as today (at-least-one).
- Add a count op, e.g. `count <action> <eq|ge|le> <n>`, backed by a new
  `harness_assert_count` helper that counts records with that ACTION.
- Update `lib/assert.sh`'s header grammar docs and convert at least the
  final-state-sensitive existing scenarios (e.g. `pd-exclude`, `prefix-renumber`,
  `renew-rebind`) to use `last:` where the final state is the property under test.

**Acceptance criteria.**
- `last:` and `count` work from `expect.txt` and are documented in the grammar.
- A regression that appends a spurious wrong final record is now caught by a
  `last:` assertion in at least one scenario.

---

## Tier 2 — Close the CI confidence gaps from the workflow review

### Task 5. Turn the seccomp allow-list reconciliation into a gate

**Problem.** The `trace` job runs `seccomp-syscall-report.sh` **without
`--strict`**, so a syscall the worker issues that is missing from
`src/seccomp.c` is only printed to the job summary — it never fails CI. The
`libcapng-seccomp` cell disables Docker's seccomp so the in-process filter is the
sole confinement, but it only catches a gap if a scenario happens to exercise the
missing syscall. So allow-list drift can ship green.

**Change.**
- Add a **strict** reconciliation that fails the job on a newly-missing syscall
  or ioctl command. To avoid false positives from environment noise, compare
  against a checked-in baseline/allow-delta file (e.g.
  `tools/harness/seccomp-known-gaps.txt`) and fail only on entries **not** in the
  baseline; require a PR to update the baseline deliberately.
- Keep the existing human-readable summary output.

**Acceptance criteria.**
- Removing a required `SCMP_SYS(...)` entry from `src/seccomp.c` fails the trace
  job (verify once, then revert).
- Expected, already-known gaps do not fail the job.

### Task 6. Make the OpenWrt-rootfs cell trustworthy

**Problem.** `openwrt-rootfs` is the "authoritative musl environment" but is
`continue-on-error: true` and points at a hard-coded **example** rootfs URL. The
most deployment-representative cell can never fail the build.

**Change.**
- Pin the rootfs to a specific OpenWrt release via a workflow input/`env`
  (document the chosen release), with the URL and an expected SHA256 checksum;
  verify the checksum after download.
- Once the image provisions reliably, **remove `continue-on-error: true`** so the
  cell gates (keep it on the nightly/dispatch triggers — it need not block every
  PR, but it must be able to go red).
- Add a retry around the `curl` download to absorb transient network failures.

**Acceptance criteria.**
- The cell downloads a checksum-verified, pinned rootfs and a real scenario
  failure inside it turns the run red.

### Task 7. Add code-coverage reporting

**Problem.** Nothing reports which parts of the odhcp6c source the scenarios
exercise, so "what isn't tested" is invisible.

**Change.**
- Add a coverage build (`--coverage` / `-fprofile-arcs -ftest-coverage`, or
  `-fprofile-instr-generate -fcoverage-mapping` for clang) in one glibc/amd64
  cell, run the full scenario set, and aggregate with `gcovr`/`llvm-cov`.
- Publish a coverage summary to `$GITHUB_STEP_SUMMARY` and upload the HTML/XML
  report as an artifact. Focus the report on `src/` (parsing/state machine).
- Do **not** gate on a coverage threshold yet — establish the baseline first.

**Acceptance criteria.**
- Each run publishes per-file line/branch coverage for `src/` and uploads the
  report.

### Task 8. Add architecture diversity that catches real bugs

**Problem.** The per-PR gate is amd64-only; all four nightly QEMU targets are
little-endian. odhcp6c does heavy byte-order work and OpenWrt's historical core
targets are big-endian MIPS — `htons`/`ntohl` mistakes have no cell to surface in.

**Change.**
- Add a **big-endian** target to the nightly `multiarch` matrix
  (`linux/mips64le` is still LE — use a genuinely big-endian QEMU platform such as
  `linux/s390x`, or a MIPS BE rootfs cell, whichever buildx/QEMU supports
  reliably here).
- Add the cheap 32-bit `linux/386` cell to the **per-PR** gate (not just nightly)
  so 32-bit/`time_t`/alignment regressions are caught before merge.

**Acceptance criteria.**
- Nightly runs include at least one big-endian execution of the scenario set.
- `linux/386` runs on pull requests.

---

## Tier 3 — Correctness and hygiene of the harness itself

### Task 9. Implement or remove `harness_assert_action_order`

**Problem.** `lib/assert.sh`'s header advertises `harness_assert_action_order`,
but the function is defined nowhere — a scenario calling it would error out.
Ordering properties (e.g. SOLICIT→ADVERTISE→REQUEST→`bound`, or renew before
rebind) currently cannot be asserted.

**Change.**
- Implement `harness_assert_action_order <action1> <action2> ...`: confirm the
  first capture of each listed ACTION appears in the given order (records sort by
  filename = timestamp.pid — see Task 11 for the resolution caveat). Then add an
  ordering assertion to a scenario where order is meaningful (e.g. `renew-rebind`).
- If you choose not to implement it, **delete the reference** from the header so
  the docs match the code.

**Acceptance criteria.**
- The helper either exists and is exercised by a scenario, or no longer appears in
  the docs.

### Task 10. Make negative-path backends fail hard

**Problem.** `servers/scapy_server.py` logs and continues on an invalid
`--reply-raw-trailer` (or `--raw-trailer`) hex string. A typo would send a
**valid** packet; odhcp6c would correctly bind; and the negative scenario would
mis-pass while believing it proved defensive parsing.

**Change.**
- When a malformation flag is supplied but cannot be constructed (bad hex, etc.),
  **exit non-zero** with a clear error rather than logging and continuing. The
  harness already treats a dead backend as a setup failure.

**Acceptance criteria.**
- A malformed `--reply-raw-trailer` value aborts the backend and fails the
  scenario instead of silently sending a valid packet.

### Task 11. Fix record-ordering resolution on the musl/BusyBox path

**Problem.** `harness_assert_last` (and any future ordering helper) determines
"most recent" by sorting record filenames `rec.<date+%s%N>.<pid>`. `stub-script.sh`
falls back to `date +%s` (1-second resolution) where `%N` is unavailable; under
that fallback, records in the same second sort by **PID**, not time — so "last"
can be wrong. This is exactly the Alpine/OpenWrt environment the harness targets.

**Change.**
- Make ordering robust to coarse timestamps: have the stub write a monotonic
  per-capture sequence number into the record filename (e.g. an atomically
  incremented counter file in the capture dir, or `date +%s%N` with a verified
  fallback that still preserves order), and sort on that sequence. Ensure it works
  when the script is exec'd by the unprivileged privsep worker (the capture dir is
  already mode 0777).

**Acceptance criteria.**
- With `date +%N` unavailable, multiple records emitted within the same second
  still sort in true emission order, and `harness_assert_last` is correct.

### Task 12. Build-config coverage: exercise `UBUS=OFF`

**Problem.** Images always build **with** ubus; the `UBUS=OFF` configuration is
never compiled or run in this workflow, even though `ubus-reconnect` self-skips on
it. A compile break or behavior change under `UBUS=OFF` is invisible here.

**Change.**
- Add a small matrix axis or a dedicated cell that builds with `--build-arg UBUS=OFF`
  and runs the scenario set (the ubus broker autostart is a no-op there, and
  `ubus-reconnect` self-skips — confirm the skip is reported, not silently passed,
  per Task 1's triage rule).

**Acceptance criteria.**
- A `UBUS=OFF` build is compiled and runs the suite in CI.

### Task 13. Remove leftover debug scaffolding

**Problem.** `harness_dump_privsep_state` in `lib/common.sh` is marked "Remove
once confirmed" and is called on every `privsep-signals` run, emitting
`[privsep-debug]` noise — a sign of an investigation never closed out.

**Change.**
- Resolve the underlying single-process-under-privsep question if still open, then
  remove the `[privsep-debug]` dump calls from the scenarios and either delete the
  helper or gate it behind an explicit `HARNESS_DEBUG=1`.

**Acceptance criteria.**
- Normal runs no longer emit `[privsep-debug]` output; the helper, if kept, is
  opt-in.

### Task 14. Pipeline hygiene

**Problem.** Standard CI hardening/efficiency items are missing.

**Change.**
- **Pin actions to commit SHAs** (`actions/checkout`, `actions/upload-artifact`,
  `docker/setup-qemu-action`, `docker/setup-buildx-action`) instead of mutable
  tags.
- Add **`timeout-minutes`** to every job (the per-scenario `--timeout` does not
  bound a hung `docker build` or QEMU step).
- Add a **`concurrency`** group keyed on workflow + ref to cancel superseded PR
  runs.
- Add **Docker layer caching** (buildx `--cache-from`/`--cache-to` with the GHA
  cache backend) so the wide matrix rebuilds less and broader coverage stays
  affordable.
- Add a **per-scenario result table** to `$GITHUB_STEP_SUMMARY` in the
  `scenarios` job (the `trace` job already writes a summary), and consider
  emitting JUnit XML for the Checks UI.

**Acceptance criteria.**
- Actions are SHA-pinned, jobs have timeouts, superseded PR runs cancel, builds
  use a layer cache, and the gate job prints a scenario × cell result table.

---

## Suggested PR sequencing

| Order | Tasks | Theme |
|------:|-------|-------|
| 1 | 1 | Run the orphaned scenarios + drift guard |
| 2 | 2, 3, 4 | Real teeth: sanitizer + crash-safe absence + final-state assertions |
| 3 | 5, 6, 7, 8 | CI confidence: seccomp gate, OpenWrt gate, coverage, arch diversity |
| 4 | 9–14 | Harness correctness + hygiene |

Tier 0 and Tier 1 deliver the great majority of the confidence improvement;
do not let the later tiers delay them.
