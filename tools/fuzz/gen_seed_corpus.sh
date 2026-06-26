#!/bin/sh
# Generate a small seed corpus for the script_req_decode() fuzz target.
#
# The seeds are valid (and near-valid) request datagrams so libFuzzer starts
# from meaningful coverage of the privileged parser instead of random noise.
# Re-run any time; it only writes into tools/fuzz/corpus/.
#
# Usage: tools/fuzz/gen_seed_corpus.sh [output-dir]
set -eu

out="${1:-$(dirname "$0")/corpus}"
mkdir -p "$out"

python3 - "$out" <<'PY'
import os, struct, sys

out = sys.argv[1]

# struct script_req: magic, action_len, delay, resume, pad[3], env_count, env_total
MAGIC = 0x6f366970

def req(action, delay, resume, envs):
    env_blob = b"".join(e.encode() + b"\0" for e in envs)
    # struct script_req is sent as a raw memcpy() of the native C struct, so it
    # uses host byte order. Pack with "=" (native endianness, standard sizes)
    # and an explicit 3-byte pad so the seeds are valid on any target.
    hdr = struct.pack("=IIiB3xII", MAGIC, len(action), delay,
                      resume, len(envs), len(env_blob))
    return hdr + action.encode() + env_blob

seeds = {
    "bound_no_env":      req("bound", 0, 0, []),
    "bound_two_env":     req("bound", 0, 0, ["SERVER=2001:db8::1", "RA_MTU=1500"]),
    "started_resume":    req("started", 5, 1, ["PREFIXES=2001:db8::/64,3600,7200,1800,3600"]),
    "unbound_no_env":    req("unbound", 0, 0, []),
}

for name, blob in seeds.items():
    with open(os.path.join(out, name), "wb") as f:
        f.write(blob)
    print("wrote", name, len(blob), "bytes")
PY
