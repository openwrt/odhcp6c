# odhcp6c DHCPv6/RA integration harness

A self-contained, reproducible network harness that stands up `odhcp6c` on one
side of a virtual link and a controllable DHCPv6 server + RA sender on the
other, drives it through its full lifecycle, and asserts on observable
behaviour — primarily the **environment and arguments passed to the status
script**, plus exit status and log output.

It runs **hermetically** inside a single container using a Linux network
namespace + `veth` pair: no host networking, no external server, no root beyond
a container with `NET_ADMIN` + `SYS_ADMIN` (the latter is needed for `ip netns
add`, which performs a `mount --make-shared /run/netns`).

The harness is the reusable foundation for integration/regression testing, the
N-2 seccomp syscall reconciliation (via the trace modes), and fuzz-style RA/
reply injection for the parser-hardening work (H-1/H-2/H-3/N-4/N-5).

> **No `src/` changes.** Everything here lives under `tools/harness/` and
> `.github/workflows/integration.yml`.

---

## Layout

```
tools/harness/
├── run-scenario.sh        # entry point / orchestrator
├── stub-script.sh         # odhcp6c -s status script: the assertion surface
├── lib/
│   ├── common.sh          # netns/veth, bounded waits, odhcp6c lifecycle
│   ├── assert.sh          # record parsing + expect.txt engine
│   ├── trace.sh           # strace / seccomp-log post-processing
│   ├── backend_scapy.sh   # crafted-packet backend launcher
│   └── backend_odhcpd.sh  # real-server (odhcpd) backend launcher
├── servers/
│   └── scapy_server.py    # RA sender/injector + DHCPv6 server (scapy)
├── scenarios/
│   └── <name>/
│       ├── scenario.sh    # backend + odhcp6c args + drive + (optional) assert
│       └── expect.txt     # declarative assertions (optional)
├── Dockerfile             # Alpine/musl image (default)
└── Dockerfile.debian      # Debian/glibc variant
```

---

## Prerequisites

Running directly on a host (Linux only):

- `ip` (iproute2) and permission to create network namespaces (root or
  `CAP_NET_ADMIN`).
- `python3` with [`scapy`](https://scapy.net/) for the crafted-packet backend.
- An `odhcp6c` binary to test. Point the harness at it with `ODHCP6C_BIN=...`
  or `--odhcp6c <path>`; otherwise it autodetects `./odhcp6c`, `build/odhcp6c`,
  or one on `$PATH`.
- Optional: `odhcpd` for the real-server backend; `strace` and a seccomp build
  for the trace modes.

The supported, reproducible way to get all of this is the container image
(below) — that is also exactly what CI uses.

---

## Running a scenario

```sh
# List scenarios
tools/harness/run-scenario.sh --list

# Run one (autodetect binary)
sudo tools/harness/run-scenario.sh stateful-basic

# Point at a specific binary, raise the per-wait timeout, keep artifacts
sudo ODHCP6C_BIN=/path/to/odhcp6c \
    tools/harness/run-scenario.sh --timeout 30 --keep --outdir /tmp/out ra-slaac
```

In the container:

```sh
docker build -f tools/harness/Dockerfile -t odhcp6c-harness .
docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
    --security-opt apparmor=unconfined odhcp6c-harness \
    tools/harness/run-scenario.sh stateful-basic
```

Exit status is `0` only if the scenario completed **and** every assertion
passed. Every wait is bounded by `--timeout` (default 30s) so the harness never
hangs CI; failures print a clear message naming the unmet condition.

### Options

| Option | Meaning |
| --- | --- |
| `--odhcp6c <path>` | binary under test (default: `$ODHCP6C_BIN` / autodetect) |
| `--trace <mode>` | `none` (default), `strace`, or `seccomp-log` |
| `--timeout <s>` | per-wait timeout (default 30) |
| `--outdir <dir>` | keep artifacts here instead of a temp dir |
| `--keep` | do not delete the work dir on exit |
| `--list` | list scenarios and exit |

---

## Scenarios

| Scenario | Backend | What it proves |
| --- | --- | --- |
| `stateful-basic` | scapy serve | IA_NA + IA_PD → `bound`; `ADDRESSES`/`PREFIXES`/`RDNSS`/`DOMAINS` exported |
| `stateless-info` | scapy serve | INFORMATION-REQUEST → `informed`; DNS/domains, no address/prefix |
| `renew-rebind` | scapy serve | `bound` → renew (`SIGUSR1`) → server loss → **`DHCPV6_RESET` + socket re-create** |
| `ra-slaac` | scapy ra | SLAAC RA path; `RA_ADDRESSES`/`RA_ROUTES`/`RA_DNS`/`RA_MTU` |
| `ra-options-edge` | scapy ra | MTU boundary, route-info `len==0`, odd RDNSS, bad hop-limit / non-link-local source are survived and dropped |
| `captive-portal` | scapy ra | **H-3**: a metacharacter/control-byte URI yields a *sanitized* `CAPTIVE_PORTAL_URI` |
| `release-on-stop` | scapy serve | terminal `stopped`/`unbound`; RELEASE on stop (and suppression with `-k`) |
| `s46-mape` *(optional)* | scapy serve | OPTION_S46_CONT_MAPE parsed into a formatted `MAPE=` env value |

### The status script (assertion surface)

`stub-script.sh` is passed to odhcp6c via `-s`. On every invocation it writes a
per-invocation `KEY=VALUE` record to `$ODHCP6C_HARNESS_CAPTURE` capturing the
action (`$2`), interface (`$1`), and the full set of exported variables
(`PREFIXES`, `ADDRESSES`, `RDNSS`, `DOMAINS`, `SIP_*`, `NTP_*`, `AFTR`,
`MAPE`/`MAPT`/`LW4O6`, `CAPTIVE_PORTAL_URI`, `RA_ADDRESSES`, `RA_ROUTES`,
`RA_DNS`, `RA_DOMAINS`, `RA_HOPLIMIT`, `RA_MTU`, `RA_REACHABLE`,
`RA_RETRANSMIT`, `PASSTHRU`, `OPTION_<n>`). Tests assert against these records.

Under privilege separation the script is exec'd by the monitor, so the stub
additionally validates that the monitor builds the environment correctly across
the privilege boundary. Scenarios run odhcp6c with privsep **enabled** (the
production default).

---

## Adding a scenario

1. Create `tools/harness/scenarios/<name>/scenario.sh` overriding any of these
   shell functions (all optional except `scenario_drive`):

   - `scenario_backend` — echo the backend + args, e.g.
     `scapy ra --prefix 2001:db8:1:: --mtu 1480` or
     `scapy serve --respond-rs --address 2001:db8:1::1000 ...`. Echo nothing for
     RA-injection-only scenarios. Words are split unquoted, so values containing
     spaces must be injected with `harness_inject` instead (see below).
   - `scenario_odhcp6c` — echo the odhcp6c argument list **ending in the
     interface** (use `$HARNESS_VETH_CLIENT`). Default: `--no-privsep <iface>`.
   - `scenario_drive` — perform the lifecycle: `wait_for_action <action>
     [timeout]`, `wait_for_log <regex> [timeout] [min-count]`,
     `harness_odhcp6c_signal <USR1|TERM|…>`, and one-shot crafted injections via
     `harness_inject <scapy-subcommand-and-args…>` (use a finite `--count`).
   - `scenario_assert` — custom assertions. Defaults to evaluating `expect.txt`.

2. Add a declarative `expect.txt` (optional). Each non-comment line is:

   ```
   <action>  <KEY>  <op>  [value]
   ```

   `<action>` matches the record's `ACTION` (or `*` for any). Ops:

   | op | meaning |
   | --- | --- |
   | `eq` / `ne` | exact match / mismatch |
   | `contains` / `not_contains` | substring presence / absence |
   | `regex` | extended-regex match |
   | `empty` / `nonempty` | value is empty / non-empty |
   | `sanitized` | value contains no shell metacharacters/control bytes (H-3) |

   **Polarity matters.** Positive ops (`eq`, `contains`, `regex`, `nonempty`,
   `sanitized`) pass if *at least one* matching record satisfies them — tolerant
   of the multiple invocations a real lifecycle produces. Negative ops (`ne`,
   `not_contains`, `empty`) pass only if *no* matching record violates them — the
   correct semantics for absence / leak checks.

3. Run it: `sudo tools/harness/run-scenario.sh <name>`.

---

## Trace mode (for N-2 syscall reconciliation)

```sh
# Readable cross-check: follow BOTH privsep processes with strace.
docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    odhcp6c-harness \
    tools/harness/run-scenario.sh --trace=strace --outdir /out renew-rebind

# Authoritative: a SCMP_ACT_LOG build logs disallowed syscalls to the kernel.
docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    odhcp6c-harness \
    tools/harness/run-scenario.sh --trace=seccomp-log --outdir /out stateful-basic
```

Artifacts under `<outdir>/trace/`:

- `syscalls.<pid>.txt` — per-process sorted-unique syscall names (strace), one
  file per followed process (monitor, worker, and any script subprocess).
- `syscalls.union.txt` — union across all processes (strace).
- `syscalls.seccomp.txt` — observed syscalls (seccomp-log).

These are machine-readable so N-2's reconciliation job can diff them against the
checked-in allow-list.

- **`strace`** wraps odhcp6c with `strace -f -ff -qq -e
  trace=%network,%desc,%memory,%signal,%process`, so both privsep processes are
  followed. Faithful for a readable cross-check; QEMU-user strace semantics can
  be quirky, so prefer seccomp-log for authoritative capture.
- **`seccomp-log`** requires an odhcp6c built with the filter default action set
  to `SCMP_ACT_LOG`; it scrapes new `SECCOMP` records from `dmesg` and maps
  numbers→names (via `ausyscall` when present). If no seccomp build / `dmesg`
  access is available it degrades gracefully with a warning rather than failing.

---

## Backends

- **`scapy`** (default for most scenarios) — a Python sender that emits exactly
  the RA/reply packets a scenario needs, including deliberate malformations for
  edge-branch coverage. It also serves a minimal DHCPv6 exchange
  (`scapy serve` / `scapy dhcpv6`). Because it sends fully-formed L2 frames it is
  ideal both for realistic flows and for the injection-fuzzer seed cases.
- **`odhcpd`** (real-server) — the OpenWrt counterpart, configured to advertise
  RAs and serve IA_NA + IA_PD with RDNSS/DNSSL. Selected with a
  `scenario_backend` of `odhcpd …`; requires `odhcpd` in the image.

---

## Image variants

- **Alpine / musl (default, `Dockerfile`)** — fast proxy for the OpenWrt musl
  target; used for the per-PR gate.
- **Debian / glibc (`Dockerfile.debian`)** — catches glibc-vs-musl differences.
  Debian packages neither `libubox` nor `odhcpd`: `libubox` is built from the
  upstream source in the image, and the optional `odhcpd` real-server backend is
  omitted (scapy is the default backend for every scenario).
- **OpenWrt x86-64 rootfs** — the authoritative musl environment (important for
  the N-2 syscall list, since Alpine musl ≠ OpenWrt musl exactly). Build it by
  importing the published rootfs and running the same scenarios:

  ```sh
  curl -L -o rootfs.tar.gz <openwrt-x86-64-generic-rootfs.tar.gz-url>
  docker import rootfs.tar.gz openwrt-rootfs:latest
  # then build odhcp6c inside / mount the harness and run run-scenario.sh
  ```

  This cell runs in the nightly/dispatch job, alongside QEMU-emulated
  `linux/arm/v7`, `linux/arm64`, and `linux/386` (via
  `docker/setup-qemu-action`) which exercise 32-bit `socketcall`/`*_time64`
  syscall numbers relevant to N-2.

---

## Privileges

| Mode | Required container capabilities |
| --- | --- |
| normal scenarios | `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` |
| `--trace=strace` | `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --security-opt apparmor=unconfined` |
| `--trace=seccomp-log` | `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined` (+ `dmesg` access) |

`SYS_ADMIN` and an unconfined AppArmor profile are required because `ip netns
add` performs a `mount --make-shared /run/netns`, which the default Docker
capability set and AppArmor profile both block.

---

## Determinism & pitfalls

- The driver waits on **observable conditions** (stub records, log lines) rather
  than fixed sleeps wherever possible, and caps every wait with a timeout.
- **Client egress:** the stateful scenarios (`stateful-basic`, `stateless-info`,
  `renew-rebind`, `s46-mape`, and the RELEASE assertion of `release-on-stop`)
  require odhcp6c to be able to *send* DHCPv6 packets. Some sandboxed
  environments block datagram egress with a cgroup/eBPF firewall; there those
  scenarios cannot reach `bound`. The CI container imposes no such restriction.
  The RA-driven scenarios (`ra-slaac`, `ra-options-edge`, `captive-portal`) are
  receive-driven and work even where egress is blocked.
- **ubus:** the harness builds with `-DUBUS=OFF` to avoid needing `ubusd`.
- **musl ≠ OpenWrt musl exactly:** Alpine is a fast proxy; the OpenWrt-rootfs
  cell is the authoritative environment for the N-2 syscall list.
