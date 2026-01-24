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
	opq)     echo "$L/opqbase.tar $L/opqmark.tar" ;;
	samelayer) echo "$L/whbase.tar $L/whsame.tar" ;;
	symparent) echo "$L/symbase.tar $L/symwrite.tar" ;;
	symwh)   echo "$L/symbase.tar $L/symwh.tar" ;;
	symout)  echo "$L/symoutbase.tar $L/symoutwrite.tar" ;;
	symescape) echo "$L/symescbase.tar $L/symescwrite.tar" ;;
	esac
}
GOOD="single multi multigz longgnu longpax dup xattr escape opq samelayer symparent symwh symout symescape"

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
floor symlink-parent 3
floor symlink-escape 2

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
			"$W/off.$img.$i" "$W/ocivoff.$img.$i"
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
# escape is excluded: GNU tar strips "../" and a leading "/" when it
# extracts, so the paths on disk are not the paths in the archive and the
# comparison would be measuring tar's sanitisation. ociv's handling of
# those names is checked against the listing instead, where tar reports
# them unchanged.
#
# symparent and symescape are excluded too, for a reason that belongs to
# extract.sh rather than to tar: it unpacks each layer into a FRESH
# staging directory and copies the result over, which is what makes "this
# layer's own whiteouts" distinguishable from "what is below". A layer
# written into an empty stage cannot meet a symlink an earlier layer left
# behind, so the redirection this corpus exists to test never happens
# there. They get their own comparison below, against tar extracting the
# layers one after another into one directory.
for img in single multi multigz longgnu longpax dup xattr opq samelayer symwh; do
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
		"$W/ex.$img.facts" "$W/tr.$img.facts"
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
rm -rf "$W/ex.symparent"; mkdir -p "$W/ex.symparent"
python3 ./t/tarfacts.py names $(layers_of symparent) > "$W/named.symparent"
./t/extract.sh --direct "$W/ex.symparent" $(layers_of symparent) | extractfs \
	| awk -v NF2="$W/named.symparent" '
	    BEGIN { while ((getline l < NF2) > 0) seen[l] = 1 }
	    $2 == "d" && !($7 in seen) { next }
	    { print }' > "$W/ex.symparent.facts"
"$OCIV" tree "$IMG/symparent" | ocivfs > "$W/tr.symparent.facts"
nex=$(wc -l < "$W/ex.symparent.facts")
if [ "$nex" -lt 1 ]; then
	bad "symparent: sequential GNU tar extraction produced nothing"
else
	diffeq "symparent merged tree ($nex paths): ociv vs sequential GNU tar extraction" \
		"$W/ex.symparent.facts" "$W/tr.symparent.facts"
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
nleak=0
for img in $GOOD; do
	[ "$img" = multigz ] && continue   # same uncompressed layers as multi
	set -- $(layers_of "$img")
	"$OCIV" audit "$IMG/$img" | awk '$2=="deleted" || $2=="shadowed"' |
	while read -r _a kind rest; do
		lay=${rest#layer=}; lay=${lay%% *}
		sz=$(echo "$rest"  | tr ' ' '\n' | sed -n 's/^size=//p')
		off=$(echo "$rest" | tr ' ' '\n' | sed -n 's/^off=//p')
		want=$(echo "$rest" | tr ' ' '\n' | sed -n 's/^content=//p')
		ph=$(echo "$rest"  | tr ' ' '\n' | sed -n 's/^phex=//p')
		eval "tarf=\${$((lay+1))}"
		got="sha256:$(dd if="$tarf" bs=1 skip="$off" count="$sz" \
			2>/dev/null | sha256sum | cut -d' ' -f1)"
		if [ "$got" = "$want" ]; then
			echo "OK $img $kind $ph"
		else
			echo "NO $img $kind $ph want=$want got=$got off=$off size=$sz"
		fi
	done > "$W/leak.$img"
	n=$(grep -c '^NO ' "$W/leak.$img")
	eq "$img: every leaked file's bytes are at the offset reported" "0" "$n"
	[ "$n" = 0 ] || sed -n '/^NO /p' "$W/leak.$img" | sed 's/^/       /' | head -5
	nleak=$((nleak + $(grep -c '^OK ' "$W/leak.$img")))
done
if [ "$nleak" -ge 10 ]; then
	ok "$nleak leaked files were pulled back out of the layers with dd"
else
	bad "only $nleak leaks were confirmed against the archive bytes"
fi
# The whole point, said as a fact about one named path. multi's layer 1
# writes etc/secrets.txt and layer 2 whiteouts it: the merged tree does
# not have it and the published layer still does.
hasnt "etc/secrets.txt is not in the merged tree"    multi etc/secrets.txt
sec=$(printf 'etc/secrets.txt' | od -An -tx1 | tr -d ' \n')
grep -q " $sec\$" "$W/leak.multi" || bad "etc/secrets.txt was not among the confirmed leaks"
grep -q "^OK multi deleted $sec\$" "$W/leak.multi" \
	&& ok "and its bytes came back out of layer 1 with dd" \
	|| bad "etc/secrets.txt: dd did not reproduce the reported digest"

# The loud line. One per layer that is still publishing content the
# merged filesystem does not show, with both shapes of the leak counted
# separately: deleted is RUN rm, shadowed is a later layer writing over
# the path and leaving the earlier version in the blob.
summ=$("$OCIV" audit "$IMG/multi" | grep '^audit leak ')
eq "multi's leak summary names layer 0 with both counts" \
	"audit leak layer=0 deleted=6 shadowed=3 bytes=215" "$summ"
# The bytes figure is a sum, so it can be right with the parts wrong.
# Check it against the per-finding sizes rather than against a constant
# written here, which would be ociv checked against ociv.
sumsz=$("$OCIV" audit "$IMG/multi" | awk '$2=="deleted" || $2=="shadowed" {
		for (i=1;i<=NF;i++) if ($i ~ /^size=/) s += substr($i,6) } END {print s+0}')
eq "and the byte total is the sum of the findings' sizes" "215" "$sumsz"
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
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
