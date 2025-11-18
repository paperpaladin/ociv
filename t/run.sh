#!/bin/sh
# ociv test suite.
#
# Every assertion compares ociv against something ociv did not produce:
# skopeo, GNU tar, sha256sum, or a second implementation in Python. An
# assertion that compares ociv to ociv is not an assertion.
#
# Final line is exactly "N passed, M failed", which this collection's
# tooling parses.
set -u
cd "$(dirname "$0")/.." || exit 2
OCIV=$PWD/ociv
[ -x "$OCIV" ] || { echo "ociv binary missing: run make" >&2; exit 2; }

# The binary must be newer than its sources. Running the suite directly
# after an edit otherwise tests whatever was lying around, which is how
# three mutations elsewhere in this collection were each recorded as
# surviving.
for f in *.go go.mod; do
	if [ "$f" -nt "$OCIV" ]; then
		echo "$f is newer than $OCIV: run make, not t/run.sh" >&2
		exit 2
	fi
done

# A missing oracle is a refusal, not a quiet skip. skopeo, GNU tar and
# python are each the only authority for a whole section of this suite; a
# run without one of them would report a smaller number having checked
# less, and a smaller number that still says "0 failed" is the shape of a
# suite that proves nothing.
missing=
for tool in skopeo tar sha256sum python3; do
	command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
	echo "ociv: every oracle here is external and these are not installed:$missing" >&2
	exit 2
fi

W=$(mktemp -d "${TMPDIR:-/tmp}/ociv.XXXXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

pass=0
fail=0
ok()  { pass=$((pass+1)); echo "ok   $*"; }
bad() { fail=$((fail+1)); echo "FAIL $*"; }

eq() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1"
		echo "       expected: $2"
		echo "       actual:   $3"
	fi
}

# diffeq NAME FILE_A FILE_B -- compare two fact listings line for line.
# Per entry, never per image: "the images differ" is not a finding.
diffeq() {
	if diff -u "$2" "$3" > "$W/d.$$" 2>&1; then
		ok "$1"
	else
		bad "$1"
		sed -n '3,22p' "$W/d.$$" | sed 's/^/       /'
		n=$(grep -c '^[-+]' "$W/d.$$")
		echo "       ($n differing lines in total)"
	fi
	rm -f "$W/d.$$"
}

status() {
	name=$1; want=$2; shift 2
	"$@" >/dev/null 2>&1
	eq "$name" "$want" "$?"
}

echo "--- cli surface ---"
status "no args is a usage error"       2 "$OCIV"
status "unknown command is usage"       2 "$OCIV" frobnicate x
status "help exits clean"               0 "$OCIV" --help
status "info with no image is usage"    2 "$OCIV" info
status "nonexistent path is usage"      2 "$OCIV" info "$W/no/such/path"

echo
echo "--- corpus ---"
if ! ./t/corpus.sh "$W" > "$W/corpus.log" 2>&1; then
	echo "corpus build failed:" >&2
	cat "$W/corpus.log" >&2
	exit 2
fi
IMG=$W/img
L=$W/l

# Which layer tarballs make up which image. The suite needs this to point
# the Python second implementation at the same bytes ociv is reading.
layers_of() {
	case $1 in
	single)  echo "$L/s0.tar" ;;
	multi|multigz) echo "$L/m0.tar $L/m1.tar $L/m2.tar $L/m3.tar" ;;
	longgnu) echo "$L/lpgnu.tar" ;;
	longpax) echo "$L/lppax.tar" ;;
	dup)     echo "$L/dup.tar" ;;
	xattr)   echo "$L/xa.tar $L/caps.tar" ;;
	escape)  echo "$L/escape.tar" ;;
	esac
}
GOOD="single multi multigz longgnu longpax dup xattr escape"

# The census, from the Python reader, summed over every image. Printed
# because a reader has to be able to see that the corpus contains what the
# tests below claim to exercise, and asserted because a whiteout test over
# a corpus with no whiteouts passes while checking nothing.
: > "$W/census.raw"
for img in $GOOD; do
	# multigz shares its layers with multi; counting both would double
	# every construct and make the floors look twice as comfortable.
	[ "$img" = multigz ] && continue
	python3 ./t/oracle.py census $(layers_of "$img") >> "$W/census.raw"
done
awk '{s[$1]+=$2} END {for (k in s) print k, s[k]}' "$W/census.raw" | sort > "$W/census"
sed 's/^/     /' "$W/census"

floor() {
	have=$(awk -v k="$1" '$1==k {print $2}' "$W/census")
	[ -n "$have" ] || have=0
	if [ "$have" -ge "$2" ]; then
		ok "corpus has $have $1 (floor $2)"
	else
		bad "corpus has $have $1, the tests below need at least $2"
	fi
}
floor layers 10
floor entries 90
floor whiteout-file 2
floor whiteout-opaque 1
floor hardlink 2
floor symlink 3
floor chardev 1
floor setuid 1
floor setgid 1
floor sticky 1
floor world-writable 4
floor xattr 4
floor capability 2
floor escape 3
floor longname 2
floor dup-in-layer 1
floor path-in-many-layers 5
floor deleted 7
floor shadowed 3

echo
echo "--- oracle: skopeo and sha256sum agree on the manifest digest ---"
# Three independent computations of one number: ours, skopeo's over the
# same bytes, and coreutils' over the same bytes. skopeo is an independent
# Go implementation of the spec; sha256sum is a third implementation of
# SHA-256 so the claim does not rest on crypto/sha256 alone.
for img in $GOOD; do
	skopeo inspect --raw "oci:$IMG/$img:latest" > "$W/raw.json" 2>"$W/e" || {
		bad "skopeo cannot read $img: $(tail -1 "$W/e")"; continue; }
	sk=$(skopeo manifest-digest "$W/raw.json")
	cs="sha256:$(sha256sum < "$W/raw.json" | cut -d' ' -f1)"
	ours=$("$OCIV" info "$IMG/$img" | awk '$1=="manifest" {print $2}')
	eq "$img manifest digest: ociv vs skopeo" "$sk" "$ours"
	eq "$img manifest digest: ociv vs sha256sum" "$cs" "$ours"
	# The bytes themselves, not just their digest. skopeo serialises the
	# manifest it read; if it had re-encoded, the digest check above
	# would be comparing two different documents and still pass.
	"$OCIV" info "$IMG/$img" >/dev/null
done

echo
echo "--- oracle: sha256sum and wc agree on every blob ---"
for img in $GOOD; do
	n=0
	"$OCIV" info "$IMG/$img" | awk '$1=="layer" {print $3, $4}' | while read -r dg sz; do
		p="$IMG/$img/blobs/${dg%%:*}/${dg#*:}"
		real="sha256:$(sha256sum < "$p" | cut -d' ' -f1)"
		[ "$real" = "$dg" ] || echo "MISMATCH $img $dg $real"
		[ "$(wc -c < "$p")" = "$sz" ] || echo "SIZEMISMATCH $img $dg $sz"
	done > "$W/blobcheck.$img"
	n=$(wc -l < "$W/blobcheck.$img")
	eq "$img every blob matches sha256sum and wc -c" "0" "$n"
done

echo
echo "--- oracle: GNU tar, entry for entry ---"
# The comparison is over (type, mode, uid, gid, size, name, link) for every
# member of every layer, with names in hex because the corpus contains a
# filename with a newline in it. Not "the same number of entries": a reader
# that gets the size right and the mode wrong passes any comparison that
# only counts.
for f in "$L"/*.tar; do
	base=$(basename "$f" .tar)
	python3 ./t/tarfacts.py gnu --sanitise-links "$f" > "$W/gnu.$base" 2>"$W/e" || {
		bad "GNU tar listing of $base could not be parsed: $(tail -1 "$W/e")"; continue; }
	python3 ./t/tarfacts.py py "$f" > "$W/py.$base"
	lines=$(wc -l < "$W/gnu.$base")
	if [ "$lines" -lt 1 ]; then
		bad "$base: GNU tar listed no entries, the comparison would be vacuous"
		continue
	fi
	ok "$base: GNU tar lists $lines entries"
done

for img in $GOOD; do
	i=0
	for f in $(layers_of "$img"); do
		base=$(basename "$f" .tar)
		"$OCIV" layers "$IMG/$img" | python3 ./t/tarfacts.py ociv --sanitise-links - "$i" > "$W/ociv.$img.$i"
		diffeq "$img layer $i entries: ociv vs GNU tar" "$W/gnu.$base" "$W/ociv.$img.$i"
		# python's tarfile strips a trailing slash from a directory
		# name and GNU tar does not, so that one comparison is run
		# with both sides normalised.
		python3 ./t/tarfacts.py py --strip "$f" > "$W/pys.$base"
		"$OCIV" layers "$IMG/$img" | python3 ./t/tarfacts.py ociv --strip - "$i" > "$W/ocivs.$img.$i"
		diffeq "$img layer $i entries: ociv vs python tarfile" "$W/pys.$base" "$W/ocivs.$img.$i"
		i=$((i+1))
	done
done

# The one place GNU tar and ociv genuinely disagree, pinned so that a
# change on either side is a failure rather than a silent renormalisation.
# GNU tar sanitises an escaping hard link target in its own listing; ociv
# and python's tarfile both report the bytes in the header. ociv's answer
# is the one a security tool needs: the archive really does say "..".
gnuraw=$(python3 ./t/tarfacts.py gnu "$L/escape.tar" | awk '$1=="hardlink" {print $7}')
pyraw=$(python3 ./t/tarfacts.py py "$L/escape.tar" | awk '$1=="hardlink" {print $7}')
ocivraw=$("$OCIV" layers "$IMG/escape" | python3 ./t/tarfacts.py ociv - 0 | awk '$1=="hardlink" {print $7}')
eq "escaping hard link target: ociv agrees with python tarfile" "$pyraw" "$ocivraw"
if [ "$gnuraw" != "$ocivraw" ]; then
	ok "escaping hard link target: GNU tar still sanitises it ($gnuraw) and we do not ($ocivraw)"
else
	bad "GNU tar no longer sanitises the hard link target; the normalisation in tarfacts.py is now hiding nothing and should go"
fi

echo
echo "--- oracle: the Python second implementation of the merge ---"
# No tool on this machine applies whiteouts, so the authority here is a
# second implementation written from the spec text in another language.
# Weaker than skopeo and labelled as such in the README.
for img in $GOOD; do
	for cmd in tree audit; do
		"$OCIV" "$cmd" "$IMG/$img" > "$W/o.$img.$cmd"
		python3 ./t/oracle.py "$cmd" $(layers_of "$img") > "$W/p.$img.$cmd"
		diffeq "$img $cmd: ociv vs the Python implementation" "$W/p.$img.$cmd" "$W/o.$img.$cmd"
	done
	"$OCIV" stats "$IMG/$img" > "$W/o.$img.stats"
	python3 ./t/oracle.py census $(layers_of "$img") > "$W/p.$img.stats"
	diffeq "$img stats: ociv vs the Python implementation" "$W/p.$img.stats" "$W/o.$img.stats"
done

echo
echo "--- gzip: the descriptor digest and the diff_id are different numbers ---"
# An uncompressed image cannot tell a reader that conflates the two apart
# from a correct one, because there they are equal.
ngz=$("$OCIV" info "$IMG/multigz" | awk '$1=="layer" && $3!=$7' | wc -l)
eq "multigz: all 4 layers have digest != diff_id" "4" "$ngz"
nplain=$("$OCIV" info "$IMG/multi" | awk '$1=="layer" && $3==$7' | wc -l)
eq "multi: all 4 layers have digest == diff_id" "4" "$nplain"
# And the compressed image's merged tree is the uncompressed one's.
diffeq "multigz tree equals the Python merge of the uncompressed layers" \
	"$W/p.multi.tree" "$W/o.multigz.tree"

echo
echo "--- verify: clean images ---"
for img in $GOOD; do
	status "$img verifies clean" 0 "$OCIV" verify "$IMG/$img"
done

echo
echo "--- verify: one named defect each, and what skopeo says about the same bytes ---"
# A refusal needs an outside authority too. For every image skopeo
# rejects, ociv must also reject: ociv accepting what skopeo rejects would
# be a hole. The reverse is not required, and the cases where ociv is
# stricter than skopeo are named below rather than waved through.
check_bad() {
	name=$1; want_rc=$2; want_code=$3
	out=$("$OCIV" verify "$IMG/bad-$name" 2>&1); rc=$?
	eq "bad-$name exit status" "$want_rc" "$rc"
	if [ -n "$want_code" ]; then
		if echo "$out" | grep -q "$want_code"; then
			ok "bad-$name reports $want_code"
		else
			bad "bad-$name did not report $want_code"
			echo "$out" | sed 's/^/       /' | head -5
		fi
	fi
}
check_bad corrupt-layer            1 "V012"
check_bad corrupt-config           1 ""
check_bad wrong-size               1 "V011"
check_bad missing-blob             1 "V010"
check_bad bad-digest-string        1 "V008"
check_bad no-oci-layout            1 "V001"
check_bad bad-layout-version       1 "V002"
check_bad bad-schema-version       1 "V004"
check_bad empty-index              1 ""
check_bad diffid-mismatch          1 "V019"
check_bad diffid-count             1 "V018"
check_bad bad-rootfs-type          1 "V017"
check_bad index-digest-mismatch    1 ""
check_bad index-size-mismatch      1 "V011"
check_bad config-as-layer-mediatype 1 "V015"

echo
echo "--- refusal is not a wrong answer ---"
# Exit 3 and the word REFUSE. These are cases the spec permits and ociv
# does not implement, which is a different claim from "your image is
# broken" and leaves by a different door.
for name in unknown-algorithm zstd-layer; do
	out=$("$OCIV" verify "$IMG/bad-$name" 2>&1); rc=$?
	eq "bad-$name exits 3 (refusal)" "3" "$rc"
	if echo "$out" | grep -q "REFUSE"; then
		ok "bad-$name says REFUSE"
	else
		bad "bad-$name exited 3 without saying REFUSE: $out"
	fi
done

echo
echo "--- the digest grammar, against skopeo ---"
# Twelve spellings of one digest, each in an otherwise valid image with a
# copy of the manifest blob at the path that spelling names. Without that
# copy every case would die at "no such file" and the grammar would never
# be reached: a test that passes for a reason unrelated to what it claims.
#
# Two assertions per case. The first is skopeo's verdict against ours,
# which is the external authority. The second is the finding CODE, and it
# is the one that matters: a malformed digest string must be reported as
# V008, not as V012. Every one of these images also fails the content
# comparison -- the blob at the alternate path hashes to the canonical
# spelling -- so a reader with no grammar at all still exits 1, and three
# separate mutations of the grammar survived a suite that only checked the
# exit status.
dgcase() {
	name=$1; wantrc=$2; wantcode=$3
	rm -rf "$W/sk"
	if skopeo copy "oci:$IMG/dg-$name:latest" "dir:$W/sk" >/dev/null 2>&1; then sk=accept; else sk=reject; fi
	out=$("$OCIV" verify "$IMG/dg-$name" 2>&1); rc=$?
	eq "digest $name: exit status" "$wantrc" "$rc"
	if [ "$sk" = reject ] && [ "$rc" = 0 ]; then
		bad "digest $name: skopeo rejects it and ociv accepts it"
	else
		ok "digest $name: skopeo says $sk, ociv exits $rc"
	fi
	if [ -n "$wantcode" ]; then
		if echo "$out" | grep -q "$wantcode"; then
			ok "digest $name reports $wantcode"
		else
			bad "digest $name did not report $wantcode"
			echo "$out" | sed "s/^/       /" | head -3
		fi
	fi
}
dgcase upper        1 V008
dgcase short        1 V008
dgcase long         1 V008
dgcase trailsep     1 V008
dgcase leadsep      1 V008
dgcase dblsep       1 V008
dgcase nocolon      1 V008
dgcase emptyalg     1 V008
dgcase emptyenc     1 V008
dgcase badchar      1 V008
# Grammatically valid, algorithm we cannot compute. A refusal, not an
# accusation: the image may be perfectly good and we cannot tell.
dgcase unregistered 3 ""
dgcase sha512       3 ""

echo
echo "--- what skopeo thinks of the same bytes ---"
# Recorded as a measurement, not as an assertion that the two agree: they
# do not, and the divergences are the interesting part. The assertion is
# one-directional -- every image skopeo rejects, ociv must also reject.
: > "$W/skdiverge"
for d in "$IMG"/bad-*; do
	name=$(basename "$d")
	rm -rf "$W/sk"
	if skopeo copy "oci:$d:latest" "dir:$W/sk" >/dev/null 2>&1; then sk=accept; else sk=reject; fi
	"$OCIV" verify "$d" >/dev/null 2>&1; orc=$?
	case $orc in 0) ov=accept ;; 3) ov=refuse ;; *) ov=reject ;; esac
	echo "$name skopeo=$sk ociv=$ov" >> "$W/skdiverge"
done
sed 's/^/     /' "$W/skdiverge"
holes=$(awk '$2=="skopeo=reject" && $3=="ociv=accept"' "$W/skdiverge" | wc -l)
eq "no image skopeo rejects is accepted by ociv" "0" "$holes"
nrej=$(grep -c 'skopeo=reject' "$W/skdiverge")
if [ "$nrej" -ge 5 ]; then
	ok "skopeo rejected $nrej of the broken images, so the check above is not vacuous"
else
	bad "skopeo rejected only $nrej broken images: the one-directional check proves little"
fi
# And every good image: both must accept.
for img in $GOOD; do
	rm -rf "$W/sk"
	if skopeo copy "oci:$IMG/$img:latest" "dir:$W/sk" >/dev/null 2>&1; then sk=0; else sk=1; fi
	eq "$img: skopeo accepts it too" "0" "$sk"
done

echo
echo "--- docker-archive: the other container format ---"
# skopeo writes it, so the conversion is not ours and the thing being
# tested is whether we can read what another implementation wrote.
skopeo copy "oci:$IMG/multi:latest" "docker-archive:$W/multi.tar:ex/multi:latest" >/dev/null 2>&1
if [ -f "$W/multi.tar" ]; then
	ok "skopeo wrote a docker-archive"
	status "docker-archive verifies clean" 0 "$OCIV" verify "$W/multi.tar"
	"$OCIV" tree "$W/multi.tar" > "$W/o.da.tree"
	diffeq "docker-archive tree equals the Python merge of the same layers" \
		"$W/p.multi.tree" "$W/o.da.tree"
	"$OCIV" audit "$W/multi.tar" > "$W/o.da.audit"
	diffeq "docker-archive audit equals the Python audit of the same layers" \
		"$W/p.multi.audit" "$W/o.da.audit"
else
	bad "skopeo did not produce a docker-archive"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
