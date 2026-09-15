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

# TALLY carries the per-entry totals: one line of "KEY compared differ
# refused" per comparison, summed at the end of the run. The assertions
# below are one per layer or one per image, and "ok multi layer 0 entries"
# does not say whether that was four tuples or four hundred. The number
# the README quotes should be the suite's own, not one counted by hand
# into a file nobody re-counts.
TALLY=$W/tally
: > "$TALLY"
tallied() { echo "$1 $2 $3 $4" >> "$TALLY"; }

# diffeq NAME FILE_A FILE_B [TALLYKEY] -- compare two fact listings line
# for line. Per entry, never per image: "the images differ" is not a
# finding.
diffeq() {
	if diff -u "$2" "$3" > "$W/d.$$" 2>&1; then
		ok "$1"
		if [ -n "${4:-}" ]; then tallied "$4" "$(wc -l < "$2")" 0 0; fi
	else
		bad "$1"
		sed -n '3,22p' "$W/d.$$" | sed 's/^/       /'
		n=$(grep -c '^[-+]' "$W/d.$$")
		echo "       ($n differing lines in total)"
		if [ -n "${4:-}" ]; then tallied "$4" "$(wc -l < "$2")" "$n" 0; fi
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
	opq)     echo "$L/opqbase.tar $L/opqmark.tar" ;;
	samelayer) echo "$L/whbase.tar $L/whsame.tar" ;;
	symparent) echo "$L/symbase.tar $L/symwrite.tar" ;;
	symdir)  echo "$L/symbase.tar $L/symdirwrite.tar" ;;
	symsame) echo "$L/symsame.tar" ;;
	symwh)   echo "$L/symbase.tar $L/symwh.tar" ;;
	symout)  echo "$L/symoutbase.tar $L/symoutwrite.tar" ;;
	symescape) echo "$L/symescbase.tar $L/symescwrite.tar" ;;
	esac
}
GOOD="single multi multigz longgnu longpax dup xattr escape opq samelayer symparent symdir symsame symwh symout symescape"

# blobfacts IMAGE -- "DIGEST:COMPRESSION" per layer, comma separated.
#
# The leak findings name the blob a leaked file is still inside, and the
# Python second implementation is handed layer tarballs rather than an
# image, so it cannot derive that for itself and is told. The digest
# comes from sha256sum over the blob file, not from ociv, so the digest
# in the finding is checked against coreutils. Which file is layer i,
# and what its media type is, comes out of the manifest skopeo serves.
blobfacts() {
	skopeo inspect --raw "oci:$IMG/$1:latest" > "$W/bf.raw" 2>/dev/null || return 1
	python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
for l in m["layers"]:
    mt = l["mediaType"]
    comp = "gzip" if mt.endswith("+gzip") else "zstd" if mt.endswith("+zstd") else "none"
    print(l["digest"], comp)
' "$W/bf.raw" | while read -r dg comp; do
		f=$IMG/$1/blobs/$(echo "$dg" | tr : /)
		real=sha256:$(sha256sum "$f" | cut -d" " -f1)
		printf "%s:%s," "$real" "$comp"
	done | sed 's/,$//'
}

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
floor whiteout-file 3
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
floor escape 4
floor longname 2
floor dup-in-layer 1
floor path-in-many-layers 5
floor deleted 8
floor shadowed 3
floor symlink-parent 3
floor symlink-escape 2
floor whiteout-hit-nothing 2
floor hardlink-dangling 1

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
		diffeq "$img layer $i entries: ociv vs GNU tar" "$W/gnu.$base" "$W/ociv.$img.$i" entries-gnu
		# python's tarfile strips a trailing slash from a directory
		# name and GNU tar does not, so that one comparison is run
		# with both sides normalised.
		python3 ./t/tarfacts.py py --strip "$f" > "$W/pys.$base"
		"$OCIV" layers "$IMG/$img" | python3 ./t/tarfacts.py ociv --strip - "$i" > "$W/ocivs.$img.$i"
		diffeq "$img layer $i entries: ociv vs python tarfile" "$W/pys.$base" "$W/ocivs.$img.$i" entries-py
		i=$((i+1))
	done
done

# The refused column, measured rather than declared. bad-zstd-layer is
# multi with layer 0's media type relabelled as tar+zstd and the bytes
# left alone, so GNU tar lists every member of it and ociv declines to
# read any of them. A refusal is not a disagreement and the totals at the
# end of this run keep the two apart; without an image in this state the
# "0 refused" column would come from a branch nothing can reach, which is
# decoration rather than a result.
"$OCIV" layers "$IMG/bad-zstd-layer" >/dev/null 2>&1
zrc=$?
nz=$(wc -l < "$W/gnu.m0")
eq "a layer relabelled tar+zstd is refused, not read" "3" "$zrc"
if [ "$zrc" = 3 ] && [ "$nz" -gt 0 ]; then
	tallied entries-gnu 0 0 "$nz"
	ok "GNU tar lists $nz members of that layer, so the refused column is a measurement"
else
	bad "no layer was refused while GNU tar could list it: the refused column counts nothing"
fi

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
echo "--- where each file's bytes are: the offset, and the bytes at it ---"
# ociv reports off=N for every member: where that member's data starts in
# the UNCOMPRESSED layer stream. The leak report is what wants it, since
# "layer 0 still holds etc/secrets.txt" is a sentence and "offset 1536,
# 41 bytes" is something a reader can check with dd.
#
# The number rests on an assumption about somebody else's code: that
# archive/tar hands its underlying reader exactly the bytes it consumes,
# so a counter wrapped around that reader is sitting on the first data
# byte when Next() returns. Two comparisons, because they fail
# differently. python tarfile's offset_data is a second implementation of
# the same calculation. The sha256 of size bytes read FROM that offset in
# the archive file is the archive itself answering, and it is the one
# that still fails when both implementations are wrong the same way.
for img in $GOOD; do
	i=0
	for f in $(layers_of "$img"); do
		python3 ./t/tarfacts.py offsets "$f" > "$W/off.$img.$i"
		"$OCIV" layers "$IMG/$img" | awk -v L="$i" '
			$1=="entry" && $2==L && $4=="file" {
				o=""; c=""; n="";
				for (j=1; j<=NF; j++) {
					if ($j ~ /^off=/)     o = substr($j,5);
					if ($j ~ /^content=/) c = substr($j,9);
					if ($j ~ /^nhex=/)    n = substr($j,6); }
				print o, $8, c, n }' > "$W/ocivoff.$img.$i"
		diffeq "$img layer $i data offsets: ociv vs python tarfile, and the bytes at them" \
			"$W/off.$img.$i" "$W/ocivoff.$img.$i" offsets
		i=$((i+1))
	done
done
# Non-vacuity: a corpus of empty files would make every offset comparison
# pass while hashing nothing. Count the file members that actually have
# bytes.
nby=$(cat "$W"/off.*.* | awk '$2 > 0' | wc -l)
if [ "$nby" -ge 20 ]; then
	ok "$nby file members with a nonzero length were read at their offset"
else
	bad "only $nby nonempty file members: the offset comparison is near-vacuous"
fi

echo
echo "--- cat: one member's bytes, against tar writing the same member ---"
# GNU tar can write a single member to stdout by name, which is an
# external authority for the whole path from "the audit says phex=X in
# layer N" to the bytes themselves. t/catcmp.py drives both sides,
# because the member names and the bytes both have to survive intact and
# a shell argument does not survive a newline.
ncat=0 ncatbad=0 ncatdup=0
for img in $GOOD; do
	[ "$img" = multigz ] && continue   # same uncompressed members as multi
	python3 ./t/catcmp.py "$OCIV" "$IMG/$img" $(layers_of "$img") > "$W/cat.$img" 2>&1
	line=$(grep '^catcmp:' "$W/cat.$img")
	n=$(echo "$line"  | awk '{print $2}')
	d=$(echo "$line"  | awk '{print $4}')
	k=$(echo "$line"  | awk '{print $6}')
	ncat=$((ncat + n)); ncatbad=$((ncatbad + d)); ncatdup=$((ncatdup + k))
	[ "$d" = 0 ] || sed -n '/^  layer/p' "$W/cat.$img" | sed 's/^/     /'
done
eq "every member GNU tar writes to stdout comes back the same from ociv cat" "0" "$ncatbad"
if [ "$ncat" -ge 40 ]; then
	ok "$ncat members compared byte for byte against tar -xOf"
else
	bad "only $ncat members went through tar -xOf: the comparison is near-vacuous"
fi
# The one place the two differ on purpose. dup names ./etc/dup twice;
# extraction leaves the second and so does ociv, while tar -xOf by name
# writes both members one after the other. catcmp.py leaves such paths
# out, so the difference is asserted here instead of being averaged into
# a mismatch count.
eq "catcmp left both members of the duplicated path out, rather than calling them mismatches" "2" "$ncatdup"
# Why catcmp runs tar with -P, measured rather than assumed. GNU tar
# rewrites the member name it was GIVEN before matching, so a member
# whose name leaves the root cannot be asked for by its real name and
# cannot be asked for by the sanitised one either, because the archive
# holds the unsanitised spelling. Three members of the escape layer are
# in that position. ociv has no such rule: it reports and serves what
# the header says, which is what a tool looking for a supply-chain
# attack needs.
printf '../etc/shadow\0' | tar -xOf "$L/escape.tar" --null -T - >/dev/null 2>"$W/tarp.err"
eq "GNU tar without -P refuses to name a member containing dot-dot" "2" "$?"
if grep -q "Member name contains" "$W/tarp.err"; then
	ok "and says so: $(grep -o "Member name contains .*" "$W/tarp.err" | head -1)"
else
	bad "GNU tar refused for some other reason: $(head -1 "$W/tarp.err")"
fi
printf 'etc/shadow\0' | tar -xOf "$L/escape.tar" --null -T - >/dev/null 2>"$W/tarp2.err"
if grep -q "Not found in archive" "$W/tarp2.err"; then
	ok "and the sanitised spelling is not in the archive either"
else
	bad "tar found etc/shadow in an archive that does not contain it"
fi
ndd=$("$OCIV" cat "$IMG/escape" 0 "$(printf -- '../etc/shadow' | od -An -tx1 | tr -d ' \n')" | wc -c)
eq "ociv cat serves the member by the name the header holds" "16" "$ndd"
dboth=$(printf './etc/dup\0' | tar -xOf "$L/dup.tar" --null -T - | wc -c)
dlast=$("$OCIV" cat "$IMG/dup" 0 "$(printf 'etc/dup' | od -An -tx1 | tr -d ' \n')" | wc -c)
eq "tar -xOf writes both members of a duplicated path" "21" "$dboth"
eq "ociv cat gives the last one, which is what extraction leaves" "15" "$dlast"
status "cat on a path the layer does not hold is a usage error" \
	2 "$OCIV" cat "$IMG/single" 0 6e6f742d686572652e747874
status "cat with a layer number past the end is a usage error" \
	2 "$OCIV" cat "$IMG/single" 9 6574632f6d6f7464
status "cat with an odd-length hex path is a usage error" \
	2 "$OCIV" cat "$IMG/single" 0 abc
status "cat on a zstd layer is a refusal, not a wrong answer" \
	3 "$OCIV" cat "$IMG/bad-zstd-layer" 0 6574632f6d6f7464

echo
echo "--- oracle: the Python second implementation of the merge ---"
# No tool on this machine applies whiteouts, so the authority here is a
# second implementation written from the spec text in another language.
# Weaker than skopeo and labelled as such in the README.
for img in $GOOD; do
	for cmd in tree audit; do
		"$OCIV" "$cmd" "$IMG/$img" > "$W/o.$img.$cmd"
		if [ "$cmd" = audit ]; then
			python3 ./t/oracle.py audit $(layers_of "$img") \
				--blobs "$(blobfacts "$img")" > "$W/p.$img.$cmd"
		else
			python3 ./t/oracle.py "$cmd" $(layers_of "$img") > "$W/p.$img.$cmd"
		fi
		diffeq "$img $cmd: ociv vs the Python implementation" "$W/p.$img.$cmd" "$W/o.$img.$cmd" "$cmd-py"
	done
	"$OCIV" stats "$IMG/$img" > "$W/o.$img.stats"
	python3 ./t/oracle.py census $(layers_of "$img") > "$W/p.$img.stats"
	diffeq "$img stats: ociv vs the Python implementation" "$W/p.$img.stats" "$W/o.$img.stats" stats-py
done

echo
echo "--- oracle: GNU tar actually extracting the layers ---"
# The strongest oracle for the merge, because nothing here argues about
# what the spec means: tar unpacks the layers in order onto a real
# filesystem and the result is read back with lstat. The only part that is
# not tar is four lines of rm -rf driven by the whiteout markers tar just
# extracted.
#
# Three things it cannot see, each handled rather than hidden. uid and gid
# are the invoking user's, because extraction is unprivileged; ownership is
# covered by the per-entry GNU tar listing comparison instead. Device nodes
# need mknod and are dropped from both sides. A symlink's permission bits
# are not stored by Linux at all, so the mode of a symlink is compared as
# "-" on both sides; the header's value is still checked against GNU tar's
# listing, where it is a real fact.
ocivfs() {   # ociv tree -> the same shape the extraction prints
	awk '{t=$2; m=$3; sz=$6; c="-"; l="-"; p="";
	      for (i=7; i<=NF; i++) {
	        if ($i ~ /^content=/) c = substr($i,9);
	        if ($i ~ /^link=/)    l = substr($i,6);
	        if ($i ~ /^phex=/)    p = substr($i,6); }
	      ty = "?";
	      if (t=="file" || t=="hardlink") ty = "f";
	      if (t=="dir")      ty = "d";
	      if (t=="symlink")  ty = "l";
	      if (t=="chardev")  ty = "c";
	      if (t=="blockdev") ty = "b";
	      if (t=="fifo")     ty = "p";
	      if (ty=="c" || ty=="b") next;
	      if (ty=="l") m = "-";
	      if (t=="hardlink") l = "-";
	      printf "fnode %s %s %s %s %s %s\n", ty, m, sz, c, l, p }' | sort -k7
}
extractfs() {  # extract.sh -> the same, with nlink dropped
	awk '{ if ($2=="c" || $2=="b") next;
	       m = ($2=="l") ? "-" : $3;
	       printf "fnode %s %s %s %s %s %s\n", $2, m, $4, $6, $7, $8 }' | sort -k7
}
# escape used to be excluded, on the argument that tar's sanitisation
# would be what was measured rather than ociv. That was the wrong call:
# measuring exactly that is the point. tar strips a leading slash and
# writes the member inside the root, refuses a name still containing
# dot-dot, and then cannot make a hard link whose target it refused.
# ociv now does all three, so the two trees can simply be compared, and
# the sanitisation is the thing under test rather than the excuse.
#
# symparent and symescape are excluded too, for a reason that belongs to
# extract.sh rather than to tar: it unpacks each layer into a FRESH
# staging directory and copies the result over, which is what makes "this
# layer's own whiteouts" distinguishable from "what is below". A layer
# written into an empty stage cannot meet a symlink an earlier layer left
# behind, so the redirection this corpus exists to test never happens
# there. They get their own comparison below, against tar extracting the
# layers one after another into one directory.
for img in single multi multigz longgnu longpax dup xattr escape opq samelayer symwh; do
	rm -rf "$W/ex.$img"; mkdir -p "$W/ex.$img"
	# tar creates intermediate directories no member names: the dup
	# archive's only member is ./etc/dup and extracting it leaves an
	# "etc" directory behind. ociv reports what the image contains, not
	# what unpacking it would create, so the extracted tree is filtered
	# down to the paths GNU tar says the archives actually name.
	python3 ./t/tarfacts.py names $(layers_of "$img") > "$W/named.$img"
	./t/extract.sh "$W/ex.$img" $(layers_of "$img") | extractfs \
		| awk -v NF2="$W/named.$img" '
		    BEGIN { while ((getline l < NF2) > 0) seen[l] = 1 }
		    $2 == "d" && !($7 in seen) { next }
		    { print }' > "$W/ex.$img.facts"
	"$OCIV" tree "$IMG/$img" | ocivfs > "$W/tr.$img.facts"
	n=$(wc -l < "$W/ex.$img.facts")
	if [ "$n" -lt 1 ]; then
		bad "$img: GNU tar extracted nothing, the comparison would be vacuous"
		continue
	fi
	diffeq "$img merged tree ($n paths): ociv vs GNU tar extracting the layers" \
		"$W/ex.$img.facts" "$W/tr.$img.facts" tree-tar
done
# The filter above is not free: assert that it is doing something, and
# that what it drops is exactly the implicit parent directory.
impl=$(./t/extract.sh "$W/ex.dup" $(layers_of dup) | extractfs | wc -l)
kept=$(wc -l < "$W/ex.dup.facts")
eq "GNU tar invented one directory extracting dup that the archive does not name" "1" "$((impl-kept))"

# The hard link really is a hard link on disk, which is the fact that
# makes resolving it the right answer: a hardlink member carries size 0
# and no content, and tar gives the path the target's bytes.
nl=$(./t/extract.sh "$W/ex.multi" $(layers_of multi) | awk '$8=="'"$(printf 'usr/bin/app2' | od -An -tx1 | tr -d ' \n')"'" {print $5}')
eq "GNU tar made usr/bin/app2 a hard link (nlink)" "2" "$nl"
hl=$("$OCIV" tree "$IMG/multi" | awk '/phex='"$(printf 'usr/bin/app2' | od -An -tx1 | tr -d ' \n')"'$/ {print $6}')
eq "ociv reports the hard link with the target's size, not the header's 0" "32" "$hl"

echo
echo "--- the three whiteout rules, stated as facts about named paths ---"
# These are the rules implementations get wrong, each asserted against a
# path that exists for the purpose. The Python comparison above covers
# them too, but a line-for-line diff of two tree listings says "they
# differ" and these say which rule broke.
has() {  # has NAME IMAGE PATH -- the merged tree contains this path
	h=$(printf '%s' "$3" | od -An -tx1 | tr -d ' \n')
	if "$OCIV" tree "$IMG/$2" | grep -q "phex=$h\$"; then ok "$1"; else bad "$1 ($3 missing from $2)"; fi
}
hasnt() {
	h=$(printf '%s' "$3" | od -An -tx1 | tr -d ' \n')
	if "$OCIV" tree "$IMG/$2" | grep -q "phex=$h\$"; then bad "$1 ($3 still present in $2)"; else ok "$1"; fi
}
hasnt "a plain whiteout removes its target"            multi etc/secrets.txt
hasnt "a directory whiteout takes the subtree with it" multi var/log/app.log
hasnt "and the directory itself"                       multi var/log
has   "but not a sibling sharing its prefix"           multi var/logrotate.conf
hasnt "an opaque marker empties the directory"         multi opt/data/a
has   "and leaves the directory"                       multi opt/data
has   "and the current layer entries under it"         multi opt/data/new
has   "and a sibling sharing its prefix"               multi opt/database
hasnt "an opaque marker in a layer with no directory entries still empties it" opq opt/data/a
has   "and the directory survives from the lower layer"                        opq opt/data
has   "and so does the prefix sibling"                                         opq opt/database
has   "a whiteout does not remove a file from its OWN layer"   samelayer etc/keepme
hasnt "but does remove the same name from a lower layer"       samelayer etc/gone
# And the surviving file is the new version, not the old one resurrected.
newsha="sha256:$(printf 'the new version\n' | sha256sum | cut -d" " -f1)"
gotsha=$("$OCIV" tree "$IMG/samelayer" | awk -v h="$(printf 'etc/keepme' | od -An -tx1 | tr -d " \n")" '$0 ~ ("phex=" h "$") {for(i=1;i<=NF;i++) if ($i ~ /^content=/) print substr($i,9)}')
eq "the survivor is this layer's version of the file" "$newsha" "$gotsha"

# A marker that removed nothing. Legal, and the reader's question is
# usually whether the marker did what the Dockerfile meant, so a marker
# that hit nothing is an answer rather than silence. Two shapes,
# because they take different code paths: a plain marker for a name no
# lower layer has, and an opaque marker in a directory no lower layer
# has at all.
nn=$("$OCIV" audit "$IMG/samelayer" | grep -c '^audit whiteout-nothing ')
eq "the two markers that removed nothing are reported" "2" "$nn"
nnf=$("$OCIV" audit "$IMG/samelayer" | grep -c '^audit whiteout-nothing layer=1 kind=file ')
eq "one of them as a plain marker" "1" "$nnf"
nno=$("$OCIV" audit "$IMG/samelayer" | grep -c '^audit whiteout-nothing layer=1 kind=opaque ')
eq "and one as an opaque marker over a directory that is not there" "1" "$nno"
# And they are not counted as deletions, which is the failure that
# would make the leak report lie in the safe direction.
nd=$("$OCIV" audit "$IMG/samelayer" | grep -c '^audit deleted ')
eq "and neither is counted as a deletion" "2" "$nd"
hasnt "the opaque marker did not invent the directory it is in" samelayer srv/nosuchdir

echo
echo "--- writing through a symlink an earlier layer left in the way ---"
# These name the specific paths, so a failure says which rule broke
# rather than that two listings differ. The external authority for the
# relative case is the sequential tar extraction further down; what is
# here is the per-path statement of the same facts.
hasnt "a file written through a symlink is not at its literal path" symparent bin/newfile
has   "it is where the symlink points"                              symparent usr/bin/existing
has   "and so is the one that went through two symlinks"            symparent usr/bin/twohops
# GNU tar doing it for real, into one directory, layer after layer. This
# is the external authority for the relative case and the only part of
# the suite that can see it: neither python's tarfile nor the staged
# extraction follows a symlinked parent.
for sp in symparent symdir symsame; do
	rm -rf "$W/ex.$sp"; mkdir -p "$W/ex.$sp"
	python3 ./t/tarfacts.py names $(layers_of "$sp") > "$W/named.$sp"
	./t/extract.sh --direct "$W/ex.$sp" $(layers_of "$sp") | extractfs \
		| awk -v NF2="$W/named.$sp" '
		    BEGIN { while ((getline l < NF2) > 0) seen[l] = 1 }
		    $2 == "d" && !($7 in seen) { next }
		    { print }' > "$W/ex.$sp.facts"
	"$OCIV" tree "$IMG/$sp" | ocivfs > "$W/tr.$sp.facts"
	nex=$(wc -l < "$W/ex.$sp.facts")
	if [ "$nex" -lt 1 ]; then
		bad "$sp: sequential GNU tar extraction produced nothing"
	else
		diffeq "$sp merged tree ($nex paths): ociv vs sequential GNU tar extraction" \
			"$W/ex.$sp.facts" "$W/tr.$sp.facts" tree-tar
	fi
done
nex=$(wc -l < "$W/ex.symparent.facts")
# The same base layer, and a second layer that names ./bin/ as a
# directory member before writing through it. GNU tar then replaces the
# symlink with a real directory and the file lands literally, which is
# the opposite answer from symparent and is decided by one member being
# present. The comment on the symparent fixture has said so since it
# was written and nothing checked it.
has   "naming the parent directory puts the file at its literal path" symdir bin/newfile
hasnt "and not where the symlink used to point"                       symdir usr/bin/newfile
if [ -L "$W/ex.symdir/root/bin" ]; then
	bad "GNU tar left bin a symlink even though the layer named it a directory"
else
	ok "GNU tar replaced the symlink with a real directory on disk"
fi
nsd=$("$OCIV" audit "$IMG/symdir" | grep -c '^audit symlink-parent ')
eq "and ociv reports no redirected write for that image" "0" "$nsd"
nsp=$("$OCIV" audit "$IMG/symparent" | grep -c '^audit symlink-parent ')
eq "where the image without the directory member reports two" "2" "$nsp"

# The third shape: one layer that creates the symlink and writes
# through it, which is all a single-layer image can do. Same answer as
# the cross-layer case, and worth having because the rule is about tar
# ORDER inside one archive rather than about layering.
hasnt "a symlink made and written through in one layer still redirects" symsame bin/newfile
has   "the file is where the symlink points"                            symsame usr/bin/newfile
if [ -L "$W/ex.symsame/root/bin" ]; then
	ok "and GNU tar left the symlink alone writing through it in one pass"
else
	bad "GNU tar replaced the symlink even though no directory member named it"
fi

# And the fact that makes the comparison above worth running at all: the
# redirected path is present on disk and the literal one is not. Without
# this, a tar that stopped following symlinked parents would agree with
# an ociv that stopped resolving them, and the pair would pass.
redir=$(awk '$7=="'"$(printf 'usr/bin/newfile' | od -An -tx1 | tr -d ' \n')"'"' "$W/ex.symparent.facts" | wc -l)
eq "GNU tar put ./bin/newfile at usr/bin/newfile on disk" "1" "$redir"
lit=$(awk '$7=="'"$(printf 'bin/newfile' | od -An -tx1 | tr -d ' \n')"'"' "$W/ex.symparent.facts" | wc -l)
eq "and nothing at the literal path bin/newfile" "0" "$lit"

nred=$("$OCIV" audit "$IMG/symparent" | grep -c '^audit symlink-parent ')
eq "symparent reports two redirected writes" "2" "$nred"

# A whiteout marker underneath a symlinked directory. The marker is
# bin/.wh.existing and bin is a symlink to usr/bin, so usr/bin/existing
# is what goes. The staged extraction oracle agrees for a reason worth
# stating: it runs rm -rf on the path the marker names, the kernel
# resolves bin through the symlink, and the file disappears. That is the
# filesystem's own rule, not a rule anyone here wrote.
hasnt "a whiteout under a symlinked directory removes the resolved path" symwh usr/bin/existing
has   "and leaves the directory the symlink points at"                   symwh usr/bin
has   "and the ordinary file in the same layer"                          symwh usr/lib/note
nwhd=$("$OCIV" audit "$IMG/symwh" | grep -c "^audit deleted .*phex=$(printf 'usr/bin/existing' | od -An -tx1 | tr -d ' \n')\$")
eq "the deletion is reported at the resolved path, not the literal one" "1" "$nwhd"
nnone=$("$OCIV" stats "$IMG/symwh" | awk '$1=="whiteout-hit-nothing" {print $2}')
eq "and the marker is not recorded as having hit nothing" "0" "$nnone"


echo
echo "--- the leak, confirmed by pulling the bytes back out of the layer ---"
# The finding this program exists for. RUN rm /secrets removes the file
# from the merged view and publishes it anyway, because a layer is an
# append-only changeset and a whiteout is an instruction to the reader,
# not an edit to the bytes below.
#
# Up to here that claim rests on ociv and on the Python implementation
# agreeing, and they are both ours. This reads the reported offset and
# length straight out of the layer archive with dd and hashes what comes
# back. If the bytes were not there, or were somewhere else, the digest
# would not match: no part of this goes through either reader.
# The blob the finding NAMES is the file this opens, not a tarball the
# harness happened to keep: blob= has to be load-bearing or it is
# decoration. For comp=gzip the blob is inflated first, because off=
# counts bytes in the uncompressed stream, which is the distinction the
# comp field exists for and the reason multigz is no longer skipped.
nleak=0 nleakgz=0
for img in $GOOD; do
	"$OCIV" audit "$IMG/$img" | awk '$2=="deleted" || $2=="shadowed"' |
	while read -r _a kind rest; do
		fld() { echo "$rest" | tr ' ' '\n' | sed -n "s/^$1=//p"; }
		sz=$(fld size); off=$(fld off); want=$(fld content); ph=$(fld phex)
		bl=$(fld blob); cp=$(fld comp)
		bf=$IMG/$img/blobs/$(echo "$bl" | tr : /)
		if [ ! -f "$bf" ]; then
			echo "NO $img $kind $ph no blob file at $bf"
			continue
		fi
		case $cp in
		gzip) gzip -dc "$bf" > "$W/inflated" && src=$W/inflated ;;
		none) src=$bf ;;
		*)    echo "NO $img $kind $ph unexpected comp=$cp"; continue ;;
		esac
		got="sha256:$(dd if="$src" bs=1 skip="$off" count="$sz" \
			2>/dev/null | sha256sum | cut -d' ' -f1)"
		if [ "$got" = "$want" ]; then
			echo "OK $img $kind $cp $ph"
		else
			echo "NO $img $kind $ph want=$want got=$got off=$off size=$sz comp=$cp"
		fi
	done > "$W/leak.$img"
	n=$(grep -c '^NO ' "$W/leak.$img")
	eq "$img: every leaked file's bytes are at the offset reported" "0" "$n"
	[ "$n" = 0 ] || sed -n '/^NO /p' "$W/leak.$img" | sed 's/^/       /' | head -5
	nleak=$((nleak + $(grep -c '^OK ' "$W/leak.$img")))
	nleakgz=$((nleakgz + $(grep -c '^OK .* gzip ' "$W/leak.$img")))
done
if [ "$nleak" -ge 10 ]; then
	ok "$nleak leaked files were pulled back out of the blobs the findings name"
else
	bad "only $nleak leaks were confirmed against the blob bytes"
fi
# Without a compressed image in that count, the comp field would never
# have been read and the gzip branch above would never have run.
if [ "$nleakgz" -ge 5 ]; then
	ok "$nleakgz of them came out of a gzip blob, inflated first because comp said so"
else
	bad "only $nleakgz leaks went through a compressed blob: comp= is untested"
fi
# The whole point, said as a fact about one named path. multi's layer 1
# writes etc/secrets.txt and layer 2 whiteouts it: the merged tree does
# not have it and the published layer still does.
hasnt "etc/secrets.txt is not in the merged tree"    multi etc/secrets.txt
sec=$(printf 'etc/secrets.txt' | od -An -tx1 | tr -d ' \n')
grep -q " $sec\$" "$W/leak.multi" || bad "etc/secrets.txt was not among the confirmed leaks"
grep -q "^OK multi deleted none $sec\$" "$W/leak.multi" \
	&& ok "and its bytes came back out of layer 1 with dd" \
	|| bad "etc/secrets.txt: dd did not reproduce the reported digest"

# The deleted half of the finding, with a credential shape behind it.
# multi's layer 0 writes a private key and layer 2 whiteouts it, which
# is RUN rm /secrets exactly. The bytes are fetched with ociv cat using
# the phex off the finding, so what is read is what a reader following
# the report would read, and the PEM header is looked for in them
# rather than the digest being compared to a constant.
key=$(printf 'home/user/.ssh/id_rsa' | od -An -tx1 | tr -d ' \n')
hasnt "the private key is not in the merged tree" multi home/user/.ssh/id_rsa
keyline=$("$OCIV" audit "$IMG/multi" | grep "^audit deleted .*phex=$key\$")
if [ -n "$keyline" ]; then
	ok "but it is reported as deleted, with the layer that still holds it"
else
	bad "the deleted private key produced no finding"
fi
keylay=$(echo "$keyline" | tr ' ' '\n' | sed -n 's/^layer=//p')
keybody=$("$OCIV" cat "$IMG/multi" "${keylay:-0}" "$key")
# Split so this file does not itself contain the header it looks for:
# a detector must not contain what it detects, and this repository's
# own secret scan reads every blob in it.
if echo "$keybody" | grep -q -- "-----BEGIN .*PRIVATE"' KEY-----'; then
	ok "and its header comes back out of layer $keylay with ociv cat"
else
	bad "the deleted key did not come back with a PEM header in it"
fi
if echo "$keybody" | grep -q notarealkey; then
	ok "the fixture is the provably fake one, not something that looks real"
else
	bad "the deleted key fixture is not the notarealkey one any more"
fi

# The loud line. One per layer that is still publishing content the
# merged filesystem does not show, with both shapes of the leak counted
# separately: deleted is RUN rm, shadowed is a later layer writing over
# the path and leaving the earlier version in the blob.
# What changed, not only that something did. A chmod of an unchanged
# file leaks nothing new; different bytes mean the earlier version is a
# separate document still being published. A report that cannot tell
# those apart calls every layer rebuild a credential leak.
: > "$W/deltas"
for i in $GOOD; do
	"$OCIV" audit "$IMG/$i" | sed -n 's/^audit shadowed .*delta=\([a-z+]*\) .*/\1/p' >> "$W/deltas"
done
for d in content mode content+mode; do
	n=$(grep -cx "$d" "$W/deltas")
	if [ "$n" -ge 1 ]; then
		ok "the corpus produces $n shadowed findings with delta=$d"
	else
		bad "no shadowed finding with delta=$d: that branch is never reached"
	fi
done
n=$(grep -cx none "$W/deltas")
eq "and none that changed nothing, which would not be a finding at all" "0" "$n"
# The claim behind delta=mode: same bytes, so there is one document and
# not two. Checked against the archive, not against the field.
app=$(printf 'usr/bin/app' | od -An -tx1 | tr -d ' \n')
line=$("$OCIV" audit "$IMG/multi" | grep "^audit shadowed .*phex=$app\$")
oldc=$(echo "$line" | tr ' ' '\n' | sed -n 's/^content=//p')
newc=$(echo "$line" | tr ' ' '\n' | sed -n 's/^new=//p')
eq "delta=mode means the two versions really are the same bytes" "$oldc" "$newc"
cfgp=$(printf 'etc/config.ini' | od -An -tx1 | tr -d ' \n')
cfgl=$("$OCIV" audit "$IMG/multi" | grep "^audit shadowed .*phex=$cfgp\$")
oldc=$(echo "$cfgl" | tr ' ' '\n' | sed -n 's/^content=//p')
newc=$(echo "$cfgl" | tr ' ' '\n' | sed -n 's/^new=//p')
if [ "$oldc" != "$newc" ]; then
	ok "and delta=content means they are not"
else
	bad "etc/config.ini is reported as content-changed with equal digests"
fi

summ=$("$OCIV" audit "$IMG/multi" | grep '^audit leak ')
# The expected blob digest is sha256sum over the file in blobs/, so this
# line is also coreutils confirming the digest the finding names.
m0blob=$(echo "$(blobfacts multi)" | cut -d, -f1 | rev | cut -d: -f2- | rev)
eq "multi's leak summary names layer 0, its blob, and both counts" \
	"audit leak layer=0 blob=$m0blob comp=none deleted=7 shadowed=4 bytes=291" "$summ"
# And the same finding on the gzipped copy of the same layers names a
# DIFFERENT blob with comp=gzip, which is the distinction a reader needs
# before taking off= to the file: the offset counts bytes in the
# uncompressed stream and the blob on disk is deflated.
gzsumm=$("$OCIV" audit "$IMG/multigz" | grep '^audit leak layer=0 ')
gzblob=$(echo "$(blobfacts multigz)" | cut -d, -f1 | rev | cut -d: -f2- | rev)
eq "multigz's leak summary names the compressed blob and says so" \
	"audit leak layer=0 blob=$gzblob comp=gzip deleted=7 shadowed=4 bytes=291" "$gzsumm"
if [ "$m0blob" != "$gzblob" ]; then
	ok "the two blobs really are different files, so the comparison is not vacuous"
else
	bad "the gzipped layer has the same blob digest as the plain one"
fi
# The bytes figure is a sum, so it can be right with the parts wrong.
# Check it against the per-finding sizes rather than against a constant
# written here, which would be ociv checked against ociv.
sumsz=$("$OCIV" audit "$IMG/multi" | awk '$2=="deleted" || $2=="shadowed" {
		for (i=1;i<=NF;i++) if ($i ~ /^size=/) s += substr($i,6) } END {print s+0}')
eq "and the byte total is the sum of the findings' sizes" "291" "$sumsz"
nleaklines=$(for i in $GOOD; do "$OCIV" audit "$IMG/$i"; done | grep -c '^audit leak ')
if [ "$nleaklines" -ge 5 ]; then
	ok "$nleaklines layers across the corpus are publishing removed content"
else
	bad "only $nleaklines leak summary lines: the corpus barely exercises this"
fi

# The leak shown as the thing it is. multi's layer 1 replaces
# etc/config.ini, and layer 0's version carries a token. Pull layer 0's
# bytes out at the reported offset and look at them: the token is in
# the published image, under a path whose current contents do not have
# it. A digest comparison says the bytes are there; this says what they
# are, which is the sentence a reader needs.
set -- $(layers_of multi)
cfg=$(printf 'etc/config.ini' | od -An -tx1 | tr -d ' \n')
line=$("$OCIV" audit "$IMG/multi" | grep "^audit shadowed .*phex=$cfg\$")
coff=$(echo "$line" | tr ' ' '\n' | sed -n 's/^off=//p')
csz=$(echo "$line"  | tr ' ' '\n' | sed -n 's/^size=//p')
clay=$(echo "$line" | tr ' ' '\n' | sed -n 's/^layer=//p')
eval "ctar=\${$((clay+1))}"
body=$(dd if="$ctar" bs=1 skip="$coff" count="$csz" 2>/dev/null)
if echo "$body" | grep -q '^token=gh'; then
	ok "the overwritten etc/config.ini still has its token in layer $clay's blob"
else
	bad "the shadowed config.ini did not come back with a token in it"
	echo "$body" | sed 's/^/       /' | head -3
fi
nowtok=$("$OCIV" tree "$IMG/multi" | grep -c "phex=$cfg\$")
eq "while the merged tree's copy of that path is layer 1's" "1" "$nowtok"

# Every credential-shaped string in this repository has to be one of the
# two shapes that cannot be a real credential: a token whose body is all
# zeros, or a PEM header over material saying it is not a key. The
# collection's audit asserts this across every object of every repo and
# would catch a third shape eventually; catching it here is catching it
# in the commit that introduced it. The pattern is deliberately a
# superset of what a fixture here would use.
python3 - "$PWD" <<'GUARD' > "$W/credguard" 2>&1
import pathlib, re, subprocess, sys
pat = re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}"
                 r"|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                 r"|xox[baprs]-[A-Za-z0-9-]{10,}")
# Objects AND the working tree. Objects alone is the stronger scan,
# because a secret committed and then deleted is still in the object
# database and not in any file; the working tree alone is the only one
# available where there is no .git, which is where t/mutate.py runs the
# suite -- it copies the sources into a scratch directory, so the first
# version of this guard reported zero matches there and failed the
# non-vacuity check in every mutant run. Both, unioned, so neither
# situation is silently scanning nothing.
root = pathlib.Path(sys.argv[1])
out = subprocess.run(["git", "-C", sys.argv[1], "cat-file",
                      "--batch-all-objects", "--batch"],
                     capture_output=True).stdout.decode("utf-8", "replace")
for f in sorted(root.rglob("*")):
    if f.is_file() and ".git/" not in str(f):
        out += f.read_bytes().decode("utf-8", "replace")
n = bad = 0
for m in pat.finditer(out):
    n += 1
    body = m.group(0).split("_", 1)[-1]
    if body and set(body) == {"0"}:
        continue
    if m.group(0).startswith("-----BEGIN") and "notarealkey" in out[m.end():m.end() + 40]:
        continue
    bad += 1
    print("REAL-SHAPED", m.group(0)[:20])
print("COUNT", n, "BAD", bad)
GUARD
cn=$(awk '$1=="COUNT" {print $2}' "$W/credguard")
cb=$(awk '$1=="COUNT" {print $4}' "$W/credguard")
eq "no credential-shaped string in this repo is anything but provably fake" "0" "${cb:-1}"
[ "${cb:-1}" = 0 ] || grep REAL-SHAPED "$W/credguard" | sed 's/^/       /'
if [ "${cn:-0}" -ge 2 ]; then
	ok "${cn} credential-shaped strings are present, so the guard above is not vacuous"
else
	bad "only ${cn:-0} credential-shaped strings in the repo: the leak fixtures have gone"
fi

echo
echo "--- what GNU tar does when the symlinked parent leaves the root ---"
# Measured, not assumed. The symout layers hold a symlink out -> .. and a
# member ./out/escaped, which is the shape of a layer that writes outside
# whatever directory it is unpacked into. The question a verifier has to
# answer is whether tar stops it, and the answer is that it does not.
#
# Contained on purpose: one level out, inside this run's own scratch
# directory. symescape's /etc and ../../.. are the realistic spellings
# and are never extracted here, because doing so would have tar writing
# at the host's /etc or at the filesystem root.
mkdir -p "$W/box/root"
: > "$W/box/tar.err"
for f in $(layers_of symout); do
	tar -xpf "$f" -C "$W/box/root" 2>>"$W/box/tar.err"
	echo "$?" >> "$W/box/tar.rc"
done
nz=$(grep -cv '^0$' "$W/box/tar.rc")
eq "GNU tar extracted the escaping layer without an error status" "0" "$nz"
nerr=$(wc -c < "$W/box/tar.err")
eq "and without a diagnostic"                                     "0" "$nerr"
if [ -f "$W/box/escaped" ]; then
	ok "GNU tar wrote the file OUTSIDE the extraction root, at box/escaped"
else
	bad "GNU tar did not write outside the root; the hazard this image records has changed"
	find "$W/box" | sed 's/^/       /' | head -10
fi
# "is root/out/escaped absent" is NOT the way to ask this: root/out is
# the symlink, so that path resolves to the file tar just wrote outside
# and a -f test on it succeeds. It did, and the first version of this
# assertion was red for that reason. The question is whether tar left
# the symlink alone, which is a statement about root/out itself.
if [ -L "$W/box/root/out" ]; then
	ok "the symlink is still a symlink: tar wrote through it, not over it"
else
	bad "tar replaced the symlink with a directory; the redirection no longer happens"
fi
# What ociv does about it: reports it, and leaves it out of the tree.
# Reporting without dropping would put a path in the merged filesystem
# that is not in this image's filesystem at all; dropping without
# reporting would make the image look clean.
nout=$("$OCIV" audit "$IMG/symout" | grep -c '^audit symlink-escape ')
eq "ociv reports one symlink-escape for the same bytes" "1" "$nout"
hasnt "and the escaping path is not in the merged tree" symout out/escaped
has   "while the file that stayed inside it is"         symout keep
status "an escaping symlink is a finding, not a refusal: verify still exits 0" \
	0 "$OCIV" verify "$IMG/symout"

nesc=$("$OCIV" audit "$IMG/symescape" | grep -c '^audit symlink-escape ')
eq "symescape reports the dot-dot symlink as an escape" "1" "$nesc"
nabs=$("$OCIV" audit "$IMG/symescape" | grep -c '^audit symlink-parent-absolute ')
eq "symescape reports the absolute symlink separately" "1" "$nabs"
hasnt "nothing written through the escaping symlink is in the tree" symescape up/pwned
has   "the absolute symlink lands inside the image root"            symescape etc/passwd

echo
echo "--- what GNU tar does with a member name that leaves the root ---"
# Three spellings in one layer, extracted for real into a scratch
# directory and read back, because the whole escape finding rests on a
# claim about what an unpacker would do and that claim was never
# measured. The answers are not the same for all three, which is the
# reason for measuring rather than arguing.
rm -rf "$W/esc"; mkdir -p "$W/esc"
tar -xpf "$L/escape.tar" -C "$W/esc" 2>"$W/esc.err"
erc=$?
if [ "$erc" != 0 ]; then
	ok "GNU tar exits $erc on the escape layer: some members were not written"
else
	bad "GNU tar extracted the escape layer cleanly; the hazard has changed"
fi
# A leading slash: stripped, and the member lands INSIDE the root.
if [ -f "$W/esc/absolute/path" ]; then
	ok "a leading slash is stripped and /absolute/path lands at absolute/path"
else
	bad "GNU tar did not write the absolute member inside the root"
fi
# Dot-dot: refused by name, after being sanitised, so nothing is written.
for m in "etc/shadow" "root/.ssh/authorized_keys" "etc/leaked"; do
	if [ -e "$W/esc/$m" ]; then
		bad "GNU tar wrote $m from a dot-dot member name"
	else
		ok "nothing was written at $m: the dot-dot member was dropped"
	fi
done
if grep -q "Member name contains" "$W/esc.err"; then
	ok "and tar says why: $(grep -c "Member name contains" "$W/esc.err") members contain dot-dot"
else
	bad "tar dropped them without saying why; the diagnostic has changed"
fi
# And the knock-on: a hard link whose target was one of the dropped
# members cannot be made, so that path is missing too.
if [ -e "$W/esc/hard-out" ]; then
	bad "GNU tar created hard-out, whose target it refused to extract"
else
	ok "hard-out is absent too: its target was dropped, so the link could not be made"
fi
if grep -q "Cannot hard link" "$W/esc.err"; then
	ok "and tar says so rather than creating an empty file"
else
	bad "tar did not report the failed hard link"
fi
# ociv follows tar on all three. The absolute member is in the tree at
# the path the slash-stripping produces; the two dot-dot members are
# not in the tree at all, because no unpacker writes them. Both are
# still reported by the audit: a path kept out of the tree and out of
# the report is an image that looks clean.
has   "ociv puts the absolute member inside the root too" escape absolute/path
hasnt "and keeps the dot-dot member out of the tree"      escape etc/shadow
hasnt "and the one that climbs out through a subdirectory" escape root/.ssh/authorized_keys
nesc=$("$OCIV" audit "$IMG/escape" | grep -c '^audit escape ')
eq "all four are still in the audit, which is where they belong" "4" "$nesc"
hasnt "and the one that is absolute AND climbing is out of the tree too" escape etc/leaked

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
# The config and the manifest corrupted so that they still parse. Only the
# digest comparison can see these, and without them a mutation that
# deleted that comparison outright survived the whole suite: every other
# corruption in the corpus also broke the JSON.
check_bad corrupt-config-valid     1 "V012"
check_bad corrupt-manifest-valid   1 "V012"
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
	"$OCIV" verify "$d" > "$W/ovout" 2>&1; orc=$?
	case $orc in 0) ov=accept ;; 3) ov=refuse ;; *) ov=reject ;; esac
	# The reason, from ociv's own first diagnostic. Without it the
	# table says eleven images are accepted by skopeo and rejected
	# here and leaves the reader to go and find out why each, which
	# is how the README ended up carrying a hand-written column
	# that nothing kept in step with the code.
	why=$(sed -n 's/^BAD \([A-Z0-9]*\) \(.*\)$/\1 \2/p' "$W/ovout" | head -1)
	[ -n "$why" ] || why=$(sed -n 's/^ociv: REFUSE: //p' "$W/ovout" | head -1)
	[ -n "$why" ] || why=$(sed -n 's/^ociv: //p' "$W/ovout" | head -1)
	[ -n "$why" ] || why="-"
	echo "$name skopeo=$sk ociv=$ov $why" >> "$W/skdiverge"
done
cut -c1-118 "$W/skdiverge" | sed 's/^/     /'
# The reason column has to be a measurement too: a table whose third
# field is empty on every row says nothing and looks like it says
# something.
nowhy=$(awk '$4=="-"' "$W/skdiverge" | wc -l)
eq "every image in the table has a reason beside its verdict" "0" "$nowhy"
# And every rejection names a code, not only the ones that reach the
# findings list. bad-empty-index used to be the exception: it failed
# while opening the image, printed a bare sentence and exited 1, so
# there was nothing to grep for and nothing to put in the table.
nocode=$(awk '$3=="ociv=reject" && $4 !~ /^V[0-9][0-9][0-9]$/' "$W/skdiverge" | wc -l)
eq "every rejection names a Vnnn code" "0" "$nocode"
eq "and an empty index is V003 rather than a sentence" "V003" \
	"$(awk '$1=="bad-empty-index" {print $4}' "$W/skdiverge")"
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
echo "--- multi-platform index: one tag, three architectures ---"
# What a published image is. The failure to rule out is a reader that
# takes index.json's first entry: it then verifies somebody else's
# architecture and reports the image fine.
MA=$IMG/multiarch
status "no selector over a 3-platform index is a refusal"       3 "$OCIV" verify "$MA"
status "and so is :latest, which all three entries carry"       3 "$OCIV" verify "$MA:latest"
out=$("$OCIV" verify "$MA:latest" 2>&1)
if echo "$out" | grep -q 'matching "latest"'; then
	ok "the refusal says the tag matched three, not that no tag was given"
else
	bad "the :latest refusal still claims no selector was given: $out"
fi
if echo "$out" | grep -q "linux/arm/v7"; then
	ok "and it lists the platforms, which is what distinguishes them"
else
	bad "the refusal does not name the platforms: $out"
fi
# The three manifests must actually differ, or every comparison below
# would pass against a single-manifest index.
nd=$(awk '{print $2}' "$IMG/multiarch.platforms" | sort -u | wc -l)
eq "the three manifest digests are distinct" "3" "$nd"
nplat=0
while read -r plat dg; do
	nplat=$((nplat+1))
	ours=$("$OCIV" info "$MA" --platform "$plat" | awk '$1=="manifest" {print $2}')
	eq "multiarch $plat: ociv picks the manifest the corpus wrote" "$dg" "$ours"
	# Not only the digest. Each layer holds one file naming its own
	# architecture, so a right digest over the wrong image is visible.
	arch=${plat#linux/}
	arch=$(echo "$arch" | tr -d /)
	want="sha256:$(printf '%s\n' "$arch" | sha256sum | cut -d' ' -f1)"
	got=$("$OCIV" tree "$MA" --platform "$plat" |
		awk '/phex='"$(printf 'usr/bin/arch' | od -An -tx1 | tr -d ' \n')"'$/ {
			for (i=1;i<=NF;i++) if ($i ~ /^content=/) print substr($i,9) }')
	eq "multiarch $plat: usr/bin/arch in the selected layer says $arch" "$want" "$got"
done < "$IMG/multiarch.platforms"
eq "all three platforms were checked" "3" "$nplat"
status "a platform the index does not hold is invalid, not a refusal" \
	1 "$OCIV" verify "$MA" --platform linux/riscv64
status "a malformed --platform is a usage error" 2 "$OCIV" verify "$MA" --platform amd64
# Where the flag sits on the line. parsePlatform takes it out of the
# argument list and hands back the rest, and run() read os.Args[1:]
# again instead of that, so the leading spelling took "--platform" as
# the command and "linux/arm64" as the image: "stat linux/arm64: no such
# file or directory", exit 2, which reads like a typo in the path. Every
# test above puts the flag last, which is why it survived.
lead=$("$OCIV" --platform linux/arm64 info "$MA" | awk '$1=="manifest" {print $2}')
trail=$("$OCIV" info "$MA" --platform linux/arm64 | awk '$1=="manifest" {print $2}')
eq "--platform before the command selects the same manifest as after it" "$trail" "$lead"
[ -n "$trail" ] || bad "neither spelling selected anything, so the comparison above is vacuous"
# @DIGEST still works and still narrows to one, which is the escape hatch
# for an index whose entries carry no platform field at all.
dg=$(awk '$1=="linux/arm64" {print $2}' "$IMG/multiarch.platforms")
status "selecting the same manifest by digest verifies clean" 0 "$OCIV" verify "$MA@$dg"

# Where skopeo and ociv disagree, measured rather than asserted away.
# skopeo's oci-layout transport resolves a reference by the ref.name
# annotation and returns the FIRST entry that carries it; the platform
# field of an entry sitting directly in index.json is not consulted. So
# skopeo reports amd64 for all three --override-arch values here, which
# is the "first entry wins" behaviour this image was built to catch.
#
# ociv follows the image-index document, which says an entry SHOULD
# carry platform and a consumer selects on it. We are stricter, we say
# so here and in the README, and the assertion below is on skopeo's
# behaviour so that a change in it is a failure rather than silence.
: > "$W/skplat"
for a in amd64 arm64; do
	skopeo --override-os linux --override-arch "$a" inspect "oci:$MA:latest" \
		2>/dev/null | sed -n 's/.*"Architecture": *"\([^"]*\)".*/\1/p' >> "$W/skplat"
done
got=$(tr '\n' ' ' < "$W/skplat")
eq "skopeo reads a flat multi-platform index by ref.name alone (first entry wins)" \
	"amd64 amd64 " "$got"

echo
echo "--- nested index: the shape a registry actually serves ---"
# index.json holding ONE entry that points at an image index, with the
# per-platform manifests below it. That is what skopeo copy --all writes
# and what a registry returns, and ociv refused every one of them until
# now.
#
# skopeo IS the oracle here, unlike the flat case: its oci-layout
# transport does resolve a nested index by platform. skopeo copy writes
# the selected image manifest to dir:, and that file's digest is the
# answer to compare against.
NE=$IMG/nested
status "a nested index with no selector is still a refusal" 3 "$OCIV" verify "$NE"
nn=0
while read -r plat dg; do
	nn=$((nn+1))
	arch=${plat#linux/}
	var=""
	case $arch in */*) var=${arch#*/}; arch=${arch%%/*} ;; esac
	ours=$("$OCIV" info "$NE" --platform "$plat" | awk '$1=="manifest" {print $2}')
	eq "nested $plat: ociv reaches the same manifest as the flat index" "$dg" "$ours"
	rm -rf "$W/sknest"
	if skopeo --override-os linux --override-arch "$arch" \
		${var:+--override-variant "$var"} \
		copy "oci:$NE:latest" "dir:$W/sknest" >/dev/null 2>"$W/e"; then
		sk="sha256:$(sha256sum < "$W/sknest/manifest.json" | cut -d' ' -f1)"
		eq "nested $plat: ociv agrees with skopeo copy --override-arch" "$dg" "$sk"
	else
		bad "skopeo could not copy $NE for $plat: $(tail -1 "$W/e")"
	fi
done < "$IMG/multiarch.platforms"
eq "all three nested platforms were checked" "3" "$nn"
# With the tag spelled out as well. The tag selects the index out of
# index.json and must NOT be carried down into it: the entries there
# have platforms and no ref.name, so a reader that keeps matching on the
# tag finds nothing and calls a valid image broken. Without this case
# the mutation that does exactly that survived the whole suite, because
# every other nested assertion here omits the tag.
dg64=$(awk '$1=="linux/arm64" {print $2}' "$IMG/multiarch.platforms")
withtag=$("$OCIV" info "$NE:latest" --platform linux/arm64 | awk '$1=="manifest" {print $2}')
eq "nested: :latest selects the index and does not follow it down" "$dg64" "$withtag"
status "and verifies clean that way" 0 "$OCIV" verify "$NE:latest" --platform linux/arm64
# info says which level it traversed, and only when it traversed one.
ni=$("$OCIV" info "$NE" --platform linux/arm64 | grep -c '^nested-index ')
eq "info names the index it went through" "1" "$ni"
ni=$("$OCIV" info "$IMG/single" | grep -c '^nested-index ')
eq "and says nothing about nesting when there was none" "0" "$ni"
# One level, not a loop. Deeper is refused by name rather than followed.
status "an index inside an index inside index.json is refused" \
	3 "$OCIV" verify "$IMG/nested2" --platform linux/arm64
out=$("$OCIV" verify "$IMG/nested2" --platform linux/arm64 2>&1)
if echo "$out" | grep -q "one level of nesting"; then
	ok "and the refusal says how deep it goes"
else
	bad "the two-level refusal does not say why: $out"
fi
# The tree, not only the digest: each layer names its own architecture.
got=$("$OCIV" tree "$NE" --platform linux/arm/v7 |
	awk '/phex='"$(printf 'usr/bin/arch' | od -An -tx1 | tr -d ' \n')"'$/ {
		for (i=1;i<=NF;i++) if ($i ~ /^content=/) print substr($i,9) }')
eq "nested linux/arm/v7: the layer that came out says armv7" \
	"sha256:$(printf 'armv7\n' | sha256sum | cut -d' ' -f1)" "$got"

echo
echo "--- malformed input: truncation and corruption at every stride ---"
# An image is attacker-controlled data in any tool that reads one from a
# stranger, and the failure mode to rule out here is not a wrong answer,
# it is a panic, an unbounded allocation or a hang. Every length in an OCI
# image comes out of the image.
#
# Before believing the sweep, check that it can report a failure. Two
# stand-ins are run through the same harness: one that always exits 86,
# which is the status ociv gives a recovered panic, and one that hangs.
# A sweep whose crash detector is broken reports a clean score over
# whatever it likes.
cat > "$W/stub-panic" <<'STUB'
#!/bin/sh
exit 86
STUB
cat > "$W/stub-hang" <<'STUB'
#!/bin/sh
sleep 30
STUB
chmod +x "$W/stub-panic" "$W/stub-hang"
out=$(python3 ./t/sweep.py "$W/stub-panic" "$IMG/single" --stride 100000 --timeout 3 --max-runs 1 2>&1)
if echo "$out" | grep -q "SWEEPFAIL.*panic"; then
	ok "the sweep reports a panic when the program panics"
else
	bad "the sweep did not notice a program that always exits 86"
	echo "$out" | sed 's/^/       /' | head -5
fi
out=$(python3 ./t/sweep.py "$W/stub-hang" "$IMG/single" --stride 100000 --timeout 2 --max-runs 1 2>&1)
if echo "$out" | grep -q "SWEEPFAIL.*timeout"; then
	ok "the sweep reports a timeout when the program hangs"
else
	bad "the sweep did not notice a program that hangs"
	echo "$out" | sed 's/^/       /' | head -5
fi
# And a sweep in which nothing is rejected must call itself vacuous: a
# clean score over inputs that all produced exit 0 has checked nothing.
cat > "$W/stub-ok" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$W/stub-ok"
out=$(python3 ./t/sweep.py "$W/stub-ok" "$IMG/single" --stride 100000 --timeout 3 2>&1)
if echo "$out" | grep -q "VACUOUS"; then
	ok "the sweep calls itself vacuous when nothing is rejected"
else
	bad "a sweep that rejected nothing reported success"
fi

# The stride is tunable because t/mutate.py reruns this whole suite once
# per planted defect, and a sweep dense enough to be worth running once is
# too slow to run thirty-four times. The mutation harness sets it coarse;
# a direct "make test" uses 251. "make sweep" runs a dense one at 7.
SWEEP_STRIDE=${OCIV_SWEEP_STRIDE:-251}
for img in multi multigz xattr; do
	if python3 ./t/sweep.py "$OCIV" "$IMG/$img" --stride "$SWEEP_STRIDE" --timeout 20 > "$W/sweep.$img" 2>&1; then
		ok "$img sweep: $(tail -1 "$W/sweep.$img")"
	else
		bad "$img sweep"
		sed 's/^/       /' "$W/sweep.$img" | head -14
	fi
	sed 's/^/     /' "$W/sweep.$img" | head -4
done

# Inputs that are not images at all.
printf 'not an image\n' > "$W/notanimage"
mkdir -p "$W/emptydir"
printf 'x' > "$W/emptydir/index.json"
for cmd in verify info layers tree audit stats; do
	status "$cmd on a text file is usage or invalid, never a crash" 2 "$OCIV" "$cmd" "$W/notanimage"
done
status "a directory with a one-byte index.json is invalid" 1 "$OCIV" verify "$W/emptydir"
status "/dev/null is not an image"                         2 "$OCIV" verify /dev/null

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
echo "--- what the per-entry comparisons actually compared ---"
# Every assertion above is one per layer or one per image. This is the
# number of facts behind them, which is the figure the README quotes and
# the figure that falls to nothing first if a comparison stops finding
# its input. Refusals are a separate column because they need different
# work: a disagreement is a bug and a refusal is a feature that is not
# written.
awk '{c[$1]+=$2; d[$1]+=$3; r[$1]+=$4}
     END {for (k in c) printf "%s %d %d %d\n", k, c[k], d[k], r[k]}' \
	"$TALLY" | sort > "$W/tallysum"
tsum() {  # tsum KEY FLOOR WHAT
	tk=$1 tf=$2 tw=$3
	tc=$(awk -v k="$tk" '$1==k {print $2}' "$W/tallysum"); tc=${tc:-0}
	td=$(awk -v k="$tk" '$1==k {print $3}' "$W/tallysum"); td=${td:-0}
	tx=$(awk -v k="$tk" '$1==k {print $4}' "$W/tallysum"); tx=${tx:-0}
	if [ "$tc" -lt "$tf" ]; then
		bad "$tw: $tc compared, below the floor of $tf; something stopped producing input"
	elif [ "$td" -ne 0 ]; then
		bad "$tw: $tc compared, $td differ, $tx refused"
	else
		ok "$tw: $tc compared, $tc same, 0 differ, $tx refused"
	fi
}
tsum entries-gnu 150 "member tuples against GNU tar"
tsum entries-py  150 "member tuples against python tarfile"
tsum offsets      60 "member data offsets against python tarfile and the bytes there"
tsum tree-py     100 "merged tree nodes against the Python merge"
tsum tree-tar     80 "merged tree nodes against GNU tar extracting the layers"
tsum audit-py     40 "audit findings against the Python audit"
tsum stats-py    300 "construct counts against the Python census"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
