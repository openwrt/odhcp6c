#!/bin/sh
# shellcheck shell=sh
#
# assert.sh - record parsing and fixture comparison for the harness.
#
# The stub script writes one KEY=VALUE record file per odhcp6c invocation into
# the capture directory. A scenario asserts on those records using an "expect"
# file: a small line-oriented spec evaluated by harness_assert_expect().
#
# Expect-file grammar (one assertion per line; '#' comments and blank lines are
# ignored):
#
#     <action> <key> <op> [value]
#
#   <action>  the ACTION the record must have (e.g. bound, ra-updated). Use
#             '*' to match a record with ANY action that satisfies the check.
#   <key>     an environment key from the record (e.g. RA_MTU, CAPTIVE_PORTAL_URI).
#   <op>      one of:
#               eq            value equals exactly
#               ne            value does not equal
#               contains      value contains the substring
#               not_contains  value does not contain the substring
#               regex         value matches the extended regex
#               empty         value is empty (no <value> argument)
#               nonempty      value is non-empty (no <value> argument)
#               sanitized     value contains NONE of the shell-dangerous bytes
#                             (` $ \ " ' and whitespace other than space, and no
#                             non-printable bytes). Proves H-3 sanitization.
#
# The polarity of the op decides how multiple records are combined:
#   * Positive ops (eq, contains, regex, nonempty, sanitized) pass if AT LEAST
#     ONE matching record satisfies the check -- this tolerates the multiple
#     invocations a real lifecycle produces (e.g. several ra-updated records)
#     while still proving the asserted condition occurred.
#   * Negative ops (ne, not_contains, empty) pass only if NO matching record
#     violates the check -- the correct semantics for absence / leak assertions.
#
# A scenario can also assert on ordering and presence of actions with
# harness_assert_action_seen / harness_assert_action_order.

ASSERT_FAILURES=0

assert_fail() { ASSERT_FAILURES=$(( ASSERT_FAILURES + 1 )); printf '[assert][FAIL] %s\n' "$*" >&2; }
assert_pass() { printf '[assert][ok]   %s\n' "$*" >&2; }

# Extract the value of KEY from a single record file. Prints the raw value.
_record_get() {
	# Only the first '=' separates key from value; values may contain '='.
	sed -n "s/^$2=//p" "$1" | head -1
}

_record_action() {
	sed -n 's/^ACTION=//p' "$1" | head -1
}

# Does a value contain any shell-dangerous / non-printable byte?
# Returns 0 (true) if the value is DIRTY, 1 if clean.
_value_is_dirty() {
	# Dangerous: backtick, $, backslash, double/single quote.
	case "$1" in
	*'`'*|*'$'*|*'\'*|*'"'*|*"'"*) return 0 ;;
	esac
	# Any non-printable byte or whitespace other than a plain space.
	printf '%s' "$1" | LC_ALL=C grep -q '[^[:print:]]' && return 0
	printf '%s' "$1" | LC_ALL=C grep -q '[	]' && return 0
	return 1
}

# Evaluate one op against a concrete value. Returns 0 on success.
_eval_op() {
	_op="$1"; _val="$2"; _want="$3"
	case "$_op" in
	eq)           [ "$_val" = "$_want" ] ;;
	ne)           [ "$_val" != "$_want" ] ;;
	contains)     case "$_val" in *"$_want"*) true ;; *) false ;; esac ;;
	not_contains) case "$_val" in *"$_want"*) false ;; *) true ;; esac ;;
	regex)        printf '%s' "$_val" | grep -Eq "$_want" ;;
	empty)        [ -z "$_val" ] ;;
	nonempty)     [ -n "$_val" ] ;;
	sanitized)    ! _value_is_dirty "$_val" ;;
	*)            warn "unknown assertion op: $_op"; false ;;
	esac
}

# harness_assert_one <action> <key> <op> [value]
# Semantics depend on the op's polarity:
#   * Positive ops (eq, contains, regex, nonempty, sanitized): succeed if AT
#     LEAST ONE matching record satisfies the op (the asserted condition
#     occurred at some point in the lifecycle).
#   * Negative ops (ne, not_contains, empty): succeed only if NO matching record
#     violates the op (the forbidden condition never occurred). This is the
#     correct semantics for absence/leak checks.
harness_assert_one() {
	_a="$1"; _k="$2"; _op="$3"; _want="${4:-}"
	_desc="$_a $_k $_op${_want:+ $_want}"

	case "$_op" in
	ne|not_contains|empty) _polarity="negative" ;;
	*)                     _polarity="positive" ;;
	esac

	_seen_action=0
	_violation=""
	for rec in "$HARNESS_CAPTURE"/rec.*; do
		[ -e "$rec" ] || continue
		_ract="$(_record_action "$rec")"
		if [ "$_a" != "*" ] && [ "$_ract" != "$_a" ]; then
			continue
		fi
		_seen_action=1
		_val="$(_record_get "$rec" "$_k")"
		if _eval_op "$_op" "$_val" "$_want"; then
			if [ "$_polarity" = positive ]; then
				assert_pass "$_desc  (record: $(basename "$rec"), value='$_val')"
				return 0
			fi
		else
			if [ "$_polarity" = negative ]; then
				assert_fail "$_desc  (violated by $(basename "$rec"), value='$_val')"
				return 1
			fi
		fi
	done

	if [ "$_seen_action" = 0 ] && [ "$_a" != "*" ]; then
		assert_fail "$_desc  (no record with ACTION=$_a captured)"
		return 1
	fi

	if [ "$_polarity" = negative ]; then
		# No record violated the forbidden condition.
		assert_pass "$_desc  (no matching record violated the check)"
		return 0
	fi

	assert_fail "$_desc  (no matching record satisfied the check)"
	return 1
}

# harness_assert_expect <expect-file>
harness_assert_expect() {
	_file="$1"
	[ -f "$_file" ] || fatal "expect file not found: $_file"
	while IFS= read -r line || [ -n "$line" ]; do
		# Strip comments and skip blanks.
		case "$line" in
		''|'#'*) continue ;;
		esac
		# Split into at most 4 fields; value may contain spaces. awk handles
		# arbitrary whitespace between the first three fields; the value is
		# everything after the third field with leading whitespace stripped so
		# column-aligned expect files work.
		_a=$(printf '%s' "$line" | awk '{print $1}')
		_k=$(printf '%s' "$line" | awk '{print $2}')
		_op=$(printf '%s' "$line" | awk '{print $3}')
		_val=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*//')
		harness_assert_one "$_a" "$_k" "$_op" "$_val"
	done < "$_file"
}

# harness_assert_action_seen <action>
harness_assert_action_seen() {
	if harness_has_action "$1"; then
		assert_pass "action seen: $1"
	else
		assert_fail "action never seen: $1"
	fi
}

# harness_assert_no_action <action>
harness_assert_no_action() {
	if harness_has_action "$1"; then
		assert_fail "unexpected action seen: $1"
	else
		assert_pass "action correctly absent: $1"
	fi
}

# harness_assert_log <extended-regex> <human description>
harness_assert_log() {
	if grep -Eq "$1" "$HARNESS_WORKDIR/odhcp6c.log"; then
		assert_pass "log matches: $2"
	else
		assert_fail "log missing: $2 (/$1/)"
	fi
}

# Final verdict. Returns non-zero if any assertion failed.
harness_assert_summary() {
	if [ "$ASSERT_FAILURES" -eq 0 ]; then
		info "all assertions passed"
		return 0
	fi
	warn "$ASSERT_FAILURES assertion(s) failed"
	return 1
}
