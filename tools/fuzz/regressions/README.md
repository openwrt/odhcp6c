# Crash regressions for the script_req_decode() fuzz target.
#
# Drop any libFuzzer reproducer (the `crash-*` file it writes on a finding) into
# this directory and commit it. The `fuzz` CI workflow replays every file here on
# each pull request, so a fixed crash stays fixed -- this is the deterministic,
# blocking part of the fuzzing setup (the timed campaign is best-effort).
#
# Replay locally with:
#   CC=clang tools/fuzz/build.sh /tmp/script_req_fuzz
#   /tmp/script_req_fuzz tools/fuzz/regressions
