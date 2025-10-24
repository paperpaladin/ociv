#!/bin/sh
# ociv test suite.
#
# Every assertion here compares ociv against something ociv did not produce:
# skopeo, GNU tar, sha256sum, or a second implementation in Python. An
# assertion that compares ociv to ociv is not an assertion.
#
# Final line is exactly "N passed, M failed", which the collection's tooling
# parses.
set -u
cd "$(dirname "$0")/.." || exit 2
OCIV=./ociv
[ -x "$OCIV" ] || { echo "ociv binary missing: run make" >&2; exit 2; }

# The binary must be newer than its sources. Running the suite directly after
# an edit otherwise tests whatever was lying around, which is how three
# mutations elsewhere in this collection were each recorded as surviving.
for f in *.go go.mod; do
	if [ "$f" -nt "$OCIV" ]; then
		echo "$f is newer than $OCIV: run make, not t/run.sh" >&2
		exit 2
	fi
done

W=$(mktemp -d "${TMPDIR:-/tmp}/ociv.XXXXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "ok   $*"; }
bad()  { fail=$((fail+1)); echo "FAIL $*"; }

# eq NAME EXPECTED ACTUAL -- the workhorse. Prints both sides on a mismatch,
# because a failure that does not say what it saw costs a reproduction run.
eq() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1"
		echo "       expected: $2"
		echo "       actual:   $3"
	fi
}

# status NAME WANT CMD... -- assert the exit status, which is how a REFUSAL is
# told apart from a wrong answer.
status() {
	name=$1; want=$2; shift 2
	"$@" >/dev/null 2>&1
	got=$?
	eq "$name" "$want" "$got"
}

echo "--- cli surface ---"
status "no args is a usage error"      2 $OCIV
status "unknown command is usage"      2 $OCIV frobnicate x
status "help exits clean"              0 $OCIV --help
status "info with no image is usage"   2 $OCIV info

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
