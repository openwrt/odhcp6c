# odhcp6c privsep — `script.c` refactoring guide for GitHub Copilot

This document is a set of **implementation instructions** for completing the
architectural cleanup of the privilege-separation code in `src/script.c` before
it is submitted upstream. It is written to be handed to GitHub Copilot (coding
agent or interactive) one **Group** at a time — each Group is sized to become a
single reviewable PR.

The review that produced this list identified 8 dimensions. They are grouped
below so that changes touching the same code or sharing the same rationale land
together. **Do the groups in order**: later groups assume the structure created
by earlier ones.

---

## 0. Shared context (read before every group)

### Build & verification
- A full native build currently needs `libubox` (not always installed) and trips
  pre-existing `-Werror=discarded-qualifiers` warnings in `config.c`. Those are
  **unrelated** to this work — do not "fix" them as part of these PRs.
- `src/script.c` compiles **standalone** under the project's strict flags. Use
  this as the fast inner-loop check after every change:
  ```sh
  gcc -c -Isrc -std=gnu11 -Wall -Wextra -Werror \
      -Werror=implicit-function-declaration -Werror=format-security \
      -Werror=format-nonliteral -Wno-shadow=compatible-local \
      -Wno-unused-parameter -o /tmp/script.o src/script.c
  ```
  New translation units (e.g. a split monitor file) must compile clean under the
  same flags. Where ubus is available, also run a full
  `cmake -S . -B build && cmake --build build`.

### Hard invariants — DO NOT REGRESS
These are load-bearing security and correctness properties. Preserve them
exactly; if a refactor makes one harder to see, add a comment, do not remove it.
1. **Trust boundary.** The monitor runs as **root** and must never trust the
   worker. It owns the script path and `argv`; it re-validates every length, the
   exact datagram size, the action allow-list, and re-sanitizes every
   `NAME=value` entry before `execv`. Keep all of that monitor-side.
2. **SIGCHLD discipline.** SIGCHLD is blocked across `fork()` so the handler
   cannot reap a child before `running` is recorded; `running` is snapshotted
   before any `kill()` so a cleared value never signals the whole process group.
3. **Notification ordering.** A still-delayed script is superseded (SIGTERM +
   delay inheritance = state batching); an already-executing one is drained so
   its notification (e.g. the terminal `unbound -> stopped`) is not lost.
4. **Bounded waits.** Every drain/wait loop stays bounded
   (`SCRIPT_DRAIN_TIMEOUT_MS`) and escalates SIGTERM -> SIGKILL on shutdown.
5. **No behavioral change unless a group explicitly calls for one.** These are
   structural refactors. The emitted environment, action set, wire format, and
   exit-status propagation must be observably identical.

### Commit / PR conventions
- Commit subject style (match existing history): `script: <imperative summary>`.
  Keep the body explaining *why*, and explicitly state "No behavioral change"
  when true.
- Include the trailer:
  `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
- One group = one focused commit/PR. Do not bundle groups.

---

## Group 0 — Item 2: De-duplicate the child-launch path

**Do this first. It is the foundation** for the rest: every later group assumes
a single shared spawn path. Once implemented, treat `script_spawn()`'s signature
as stable and keep it the one place that forks a script child.

### Problem
`script_call()` (single-process worker) and `monitor_run_script()` (privileged
monitor) carry a near-verbatim copy of the script-child bookkeeping:
supersede-or-drain a still-running script, adjust the delay, latch the action
into `action[]`, block SIGCHLD across `fork()`, record the child in `running`,
and in the child reset SIGTERM + sleep out the delay before `execv`. The **only**
real difference is what the child does to prepare its environment immediately
before `execv`:
- worker: if a delay was waited out, `odhcp6c_expire(false)`, then
  `script_build_env()` (reads live client state and `putenv`s it);
- monitor: `putenv()` each already-re-validated `NAME=value` entry from the
  request (no client state consulted).

Two copies of subtle fork/signal logic is the highest-risk maintenance hazard in
the file — the copies can drift, and a fix applied to one path can be missed in
the other.

### Change
Extract the common path into one helper, parameterized by a callback that
supplies the differing in-child env step:

```c
static void script_spawn(const char *act, int delay, bool resume,
        void (*child_setup)(int delay, void *ctx), void *ctx);
```

Then reduce each caller to: handle its own preconditions, then delegate.

1. **Add `script_spawn()`** containing the shared bookkeeping verbatim from the
   existing functions:
   - snapshot `now`; if a previous child is still in its pre-exec delay window,
     `kill(prev, SIGTERM)`, inherit/adjust the remaining delay, set
     `running_script = true`; else `script_drain_running()`;
   - latch the action: `if (resume || !running_script || !action[0])` then
     `strncpy(action, act, sizeof(action) - 1)` **and** explicitly
     `action[sizeof(action) - 1] = '\0'`;
   - `script_block_sigchld(&omask)`, then `fork()`;
   - on `fork()` failure: log, **leave `running` unchanged** (a prior child may
     still be in-flight), restore the mask, return;
   - in the parent: set `running`/`started`/`started_delay`, clear `action[0]`
     when not resuming, restore the mask;
   - in the child: restore the mask, `signal(SIGTERM, SIG_DFL)`,
     `if (delay > 0) sleep(delay);`, call `child_setup(delay, ctx)`, then
     `execv(argv[0], argv)` / `_exit(128)`.
2. **Add the worker callback** `script_call_child(int delay, void *ctx)`:
   `(void)ctx; if (delay > 0) odhcp6c_expire(false); script_build_env();`
3. **Add the monitor callback** `monitor_run_script_child(int delay, void *ctx)`
   with a context struct:
   ```c
   struct monitor_env_ctx { char *const *envp; size_t envc; };
   ```
   `(void)delay;` then `putenv()` each `envp[i]`.
4. **Reduce `script_call()`** to its unique preconditions plus the delegation:
   ```c
   if (!argv[0]) return;
   if (script_channel >= 0) { script_send_request(status, delay, resume); return; }
   script_spawn(status, delay, resume, script_call_child, NULL);
   ```
5. **Reduce `monitor_run_script()`** to:
   ```c
   struct monitor_env_ctx ctx = { .envp = envp, .envc = envc };
   script_spawn(act, delay, resume, monitor_run_script_child, &ctx);
   ```
6. Update the surrounding comments so the rationale (state batching, SIGCHLD
   race, drain-vs-supersede) now lives on `script_spawn()`, and
   `monitor_run_script()`'s comment notes it reuses the shared bookkeeping.

### Watch-outs
- **Preserve the worker-only `odhcp6c_expire(false)`.** It must run *only* in the
  worker child and *only* when a delay was actually waited out. The monitor must
  **not** call it (it consults no client state). Routing it through the callback
  keeps this correct — do not hoist expiry into `script_spawn()`.
- **Keep the NUL-termination.** The original `script_call()` did a bare
  `strncpy` without an explicit terminator (safe only because `action` is a
  zero-initialized static buffer). Unifying on the monitor's explicit
  `action[sizeof(action) - 1] = '\0'` is the intended, safe behavior — keep it.
- **Do not change the `fork()`-failure handling.** Leaving `running` untouched on
  failure is deliberate (invariant #2 / shutdown drain). Preserve it exactly.

### Acceptance criteria
- `script_spawn()` is the **only** function in the file that calls `fork()` for a
  script child; `script_call()` and `monitor_run_script()` no longer duplicate
  the bookkeeping (expect roughly −70 net lines).
- Strict standalone compile passes (see the §0 Shared context build flags).
- No behavioral change: emitted environment, action latching, delay batching,
  drain/supersede ordering, and exit handling are observably identical. State
  this in the commit body.

---

## Group A — Items 1 + 3: Split worker/monitor + encapsulate global state

**Why together:** you cannot cleanly split the file along the trust boundary
without first deciding who owns the mutable globals (`running`, `started`,
`started_delay`, `action[]`, `argv[]`, the env collector). Encapsulating that
state into structs *is* the act that makes the split tractable, so do both in
one PR. This is the single highest-value change for upstream review because it
shrinks the trusted (root) surface a maintainer must audit.

### A1. Encapsulate the shared child-launch state
- Introduce a struct (file-local) bundling the launch bookkeeping currently held
  in separate globals:
  ```c
  struct script_child {
      volatile pid_t running;
      time_t  started;
      int     started_delay;
      char    action[16];
      char   *argv[4];   /* argv[0]=path, argv[1]=ifname, argv[2]=action, argv[3]=NULL */
  };
  ```
  Note `argv[2]` aliases `action` today — make that relationship explicit (a
  comment plus an init helper that wires `argv[2] = state->action`). Do not
  break the alias; the child relies on it.
- Replace the scattered globals with a single instance. Keep it file-scope
  (there is exactly one script child at a time per process), but route all
  access through the struct so ownership is unambiguous.
- Keep `script_spawn()` operating on this struct (pass a pointer, or keep the
  single instance file-local and have `script_spawn` use it). Preserve the
  `volatile`/`sig_atomic_t` qualifiers used by the SIGCHLD handler — do not
  weaken them.

### A2. Encapsulate the env collector
- Bundle the worker-side collector globals (`env_collecting`, `env_list`,
  `env_cnt`, `env_cap`, `env_bytes`) into:
  ```c
  struct env_collector {
      bool    collecting;
      char  **list;
      size_t  cnt, cap, bytes;
  };
  ```
- `script_putenv()` and the `*_to_env()` helpers take/use this collector. (Group
  B revisits the dual-mode design; here just mechanically encapsulate.)

### A3. Split into worker and monitor translation units
Carve `script.c` along the trust boundary into (suggested names; match the
project's existing file/Make conventions):

- **`script_worker.c`** — the unprivileged, network-facing presentation +
  request side:
    - the `*_to_env()` family (`ipv6_to_env`, `fqdn_to_env`, `string_to_env`,
    `bin_to_env`, `entry_to_env`, `search_to_env`, `int_to_env`, `s46_to_env*`),
    `script_build_env`, `script_putenv`, the env collector,
    - `script_hexlify` / `script_unhexlify`,
    - `script_call`, `script_call_child`, `script_send_request`,
    `script_set_channel`.
- **`script_monitor.c`** — the privileged (root) TCB:
    - `script_monitor_loop`, `monitor_handle_request`, `monitor_run_script`,
    `monitor_run_script_child`, `monitor_sighandle`, `script_action_allowed`,
    the `script_actions[]` allow-list.
- **Shared, used by both:** `script_spawn`, `script_drain_running`,
  `script_block_sigchld`, `script_sleep_ms`, `script_sighandle`,
  `script_sanitize_env`, `script_init`, and the `struct script_child` instance.
  Put these in a third unit (e.g. `script_common.c`) **or** keep them in a
  retained `script.c` that both include-link against. Choose whichever yields the
  fewest non-static exports.
- Promote only the minimum set of symbols from `static` to externally linked
  (declared in a small internal header, e.g. `script_internal.h`). Everything
  that can stay `static` must stay `static`.
- `script.h`'s public IPC contract (the `struct script_req`, the `SCRIPT_*`
  caps, `script_set_channel`, `script_monitor_loop`) is the only cross-domain
  surface and stays as-is.

### A4. Build wiring
- Add the new sources to `CMakeLists.txt` (and any other build file). Keep them
  unconditional — the monitor code already compiles without ubus/seccomp.

### Acceptance criteria
- `script_monitor.c` contains **no** call into worker env-building and reads
  **no** client state; a reviewer can audit the root TCB without reading the
  presentation layer.
- No global mutable launch/env state remains at file scope outside its struct.
- Strict standalone compile passes for every new TU; full build passes where
  ubus is present.

---

## Group B — Items 4 + 5: Make the env pipeline explicit and always-sanitized

**Why together:** both items are about the same data path — how a `NAME=value`
string travels from an `*_to_env()` builder to either `putenv()` (single
process) or the wire (privsep). #4 removes the hidden mode flag; #5 removes the
per-call-site "is this safe?" judgement. Doing them together lets you design one
clean emit step that always validates.

### B1. Remove the dual-mode side channel (Item 4)
- Today `script_putenv()` branches on `collector->collecting`: same callers
  either `putenv` into a forked child or append to a global list. Replace the
  implicit mode with an explicit pipeline:
    - `*_to_env()` helpers **always** append fully-formed entries to a collector
    (no `putenv` from inside the builders).
    - A single explicit **emit** step consumes the collector and chooses the sink:
        - worker single-process child: `putenv` each entry, then `execv`;
        - worker privsep: serialize each entry into the datagram;
        - (monitor already receives a list and `putenv`s it — unchanged).
- Net effect: data flow is visible at one call site instead of being decided by
  a global flag read deep in `script_putenv`.

### B2. Always sanitize; centralize the decision (Item 5)
- Currently each `*_to_env()` site decides by comment whether to call
  `script_sanitize_env()` ("charset is safe" vs sanitize). A field mislabeled
  "safe" would silently bypass sanitization in the single-process path (the
  monitor backstops privsep, but single-process has no second gate).
- `script_sanitize_env()` is **idempotent on already-safe input** (it only
  rewrites bytes outside the allowed set and validates the NAME). Therefore run
  it unconditionally as part of the single emit step in B1, for **every** entry,
  regardless of origin. Remove the per-site "safe, skip sanitize" decisions.
- Keep the monitor's independent re-sanitization on receive — defense in depth
  across the trust boundary is intentional, not redundant. Do **not** drop it.
- Preserve current semantics: an entry whose NAME is invalid is **rejected**
  (dropped), not rewritten; rejection must never abort the process.

### Acceptance criteria
- No `env_collecting`-style global mode flag remains; the sink is chosen at one
  explicit emit site.
- Every emitted environment entry passes through `script_sanitize_env()` exactly
  once on the producing side, plus the monitor's re-check on the privileged
  side. No call site opts out.
- Output for known-safe inputs is unchanged (idempotency), so existing scripts
  see identical variables. Document this in the commit body.

---

## Group C — Items 6 + 7: Testable IPC codec + observable drops

**Why together:** both require turning the request path into pure,
side-effect-free functions. Once parsing/serialization are pure, (6) you can
fuzz them and (7) you have clean call sites to emit diagnostics when something
is dropped or rejected.

### C1. Extract a pure wire codec (Item 6)
- Refactor the serialize half of `script_send_request()` and the
  parse/validate half of `monitor_handle_request()` into **pure functions** that
  operate only on buffers — no sockets, no `fork`, no globals, no `putenv`:
  ```c
  /* returns bytes written, or -1; never sends */
  ssize_t script_req_encode(uint8_t *out, size_t outcap,
          const char *action, int delay, bool resume,
          char *const *env, size_t envc);

  /* validates layout/caps/action/env; fills caller arrays; never execs.
     Returns 0 on accept, negative reason code on reject. */
  int script_req_decode(const uint8_t *buf, size_t len,
          struct script_req *out_hdr, char action[SCRIPT_ACTION_MAX + 1],
          char **env_out, size_t env_cap, size_t *env_count_out);
  ```
  The existing `script_send_request` / `monitor_handle_request` become thin
  wrappers: build args -> call codec -> do I/O / spawn.
- `script_req_decode` must enforce exactly today's checks: magic, zero padding,
  per-field caps (`SCRIPT_ACTION_MAX`, `SCRIPT_ENV_MAX_COUNT`,
  `SCRIPT_ENV_MAX_TOTAL`), exact size match
  (`sizeof(req) + action_len + env_total`), action allow-list, per-entry
  NUL-termination, full consumption of declared bytes, and per-entry
  re-sanitization. Do not relax any check.

### C2. Add a fuzz harness (Item 6)
- Add a libFuzzer/AFL target (build it only under an opt-in CMake flag, e.g.
  `FUZZING`, so normal builds are unaffected) that feeds arbitrary bytes to
  `script_req_decode`:
  ```c
  int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      struct script_req hdr; char action[SCRIPT_ACTION_MAX + 1];
      char *env[SCRIPT_ENV_MAX_COUNT]; size_t n;
      (void)script_req_decode(data, size, &hdr, action, env,
                              SCRIPT_ENV_MAX_COUNT, &n);
      return 0;
  }
  ```
  Goal: the privileged parser must never crash, over-read, or accept a malformed
  datagram. Document how to run it in a short note (`tools/` or the PR body).
  This is a strong artifact to show maintainers reviewing a root-side parser.

### C3. Make silent drops observable (Item 7)
- Today several paths silently `return`/`free` on `malloc` failure or when an
  env entry exceeds caps (`script_putenv`, the `*_to_env` allocators,
  `script_send_request`'s budget loop, decode rejections). A script can thus
  receive a **partial** environment with no trace.
- Add a `debug()`/`notice()` log at each drop/reject point: which variable or
  entry was dropped and why (allocation failure vs over-cap vs invalid NAME vs
  decode reason code). Keep messages non-sensitive (log the NAME and reason, not
  attacker-controlled values). Do not change control flow — still fail-soft;
  just make it diagnosable.

### Acceptance criteria
- `script_req_encode`/`script_req_decode` are pure (unit-testable with no I/O)
  and the wire format is byte-for-byte unchanged (encode old input -> identical
  datagram; decode accepts exactly the same set as before).
- Fuzz target builds under the opt-in flag and runs; a short corpus is included
  or generatable.
- Every previously-silent drop now emits a log line with a reason; behavior
  (which requests succeed/fail) is otherwise unchanged.

---

## Group D — Item 8: Tighten the seccomp `ioctl` allow-rule

**Standalone** — touches `seccomp.c`, not `script.c`; ship independently.

- The worker filter currently allows `ioctl` unconditionally. It is used only
  for `SIOCGIFFLAGS` / `SIOCGIFINDEX` / `SIOCGIFHWADDR` during socket setup and
  EUI-64 generation.
- Add an argument filter so only those request numbers are permitted, e.g. three
  `seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, SIOCGIFFLAGS))`
  rules (one per command), and drop the blanket `ioctl` allow.
- Keep the existing `-EDOM` "skip syscalls not defined on this arch" handling and
  the fail-closed / `WITH_SECCOMP_FAIL_OPEN` behavior intact.
- **Caution:** some libc versions issue additional `ioctl`s (e.g. terminal/stdio
  probes). Validate on both glibc and musl across the full DHCPv6 lifecycle
  (solicit -> bound -> renew -> rebind -> reset -> release) before tightening;
  if a needed command surfaces, add it explicitly with a comment. If validation
  is impractical in this PR, leave `ioctl` broad and instead add a precise
  TODO/comment enumerating the required commands — do not guess.

### Acceptance criteria
- With `SECCOMP=ON`, the worker completes a full lifecycle on both glibc and
  musl with the narrowed `ioctl` filter and no seccomp kills.
- Default builds (`SECCOMP=OFF`) are unaffected.

---

## Suggested PR sequence

| PR | Group | Items | Risk | Notes |
|----|-------|-------|------|-------|
| 1  | 0 | 2 | low | Foundation: extract shared `script_spawn()` |
| 2  | A | 1, 3 | medium | Biggest review win: split TCB + encapsulate state |
| 3  | B | 4, 5 | low | Explicit emit + always-sanitize |
| 4  | C | 6, 7 | medium | Pure codec + fuzz harness + drop diagnostics |
| 5  | D | 8 | low | seccomp `ioctl` arg filter (independent) |

````
