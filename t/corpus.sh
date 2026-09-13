#!/bin/sh
# Build the test corpus: layer tarballs with GNU tar, assembled into OCI
# image layouts by t/oci.py.
#
# Nothing is downloaded. Every layer here is built on this machine out of a
# directory tree, by GNU tar, which is also the oracle that says what the
# resulting tar contains. The constructs are deliberate and t/run.sh asserts
# a nonzero count of each one before running the test that depends on it.
#
#   usage: corpus.sh WORKDIR
#
# Produces WORKDIR/l/*.tar (layers) and WORKDIR/img/<name>/ (images).
set -eu
W=${1:?usage: corpus.sh WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$W/l" "$W/img" "$W/r"
R=$W/r
L=$W/l

# Determinism: a corpus whose digests change between two runs cannot be
# compared against a recorded number, and the harness does record some.
# --mtime fixes the timestamps; --sort=name fixes the entry order;
# --owner/--group fix the ownership, which a non-root tar would otherwise
# take from whoever is running the suite.
TARBASE="--mtime=@1700000000 --sort=name --numeric-owner"

mk() {  # mk NAME FORMAT OWNER GROUP SRCDIR -- one layer tarball
	name=$1 fmt=$2 own=$3 grp=$4 src=$5
	tar --format="$fmt" $TARBASE --owner="$own" --group="$grp" \
	    -cf "$L/$name.tar" -C "$src" .
}

# ---------------------------------------------------------------------------
# multi: the main image. Four layers, each adding a different construct.
# ---------------------------------------------------------------------------

# L0: a plausible base. Includes two files that look like credentials,
# because the whole point of this program is what happens to them in L2.
rm -rf "$R/m0"; mkdir -p "$R/m0/etc" "$R/m0/usr/bin" "$R/m0/usr/lib" \
	"$R/m0/var/log" "$R/m0/opt/data" "$R/m0/home/user/.ssh"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$R/m0/etc/passwd"
printf 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n' > "$R/m0/etc/secrets.txt"
# The token goes in the layer that gets OVERWRITTEN, not the one that
# survives. That is the shape of the real mistake: a credential committed
# into a config file, noticed, and replaced in a later build step. The
# merged image is clean and the published layer still has it, which is
# exactly the finding a reader of the merged tree alone cannot make. The
# body is all zeros so that it is provably not a credential; the
# collection's audit exempts that shape by content and nothing else.
printf 'verbose=0\ntoken=ghp_0000000000000000000000000000000000\n' > "$R/m0/etc/config.ini"
printf '\177ELF\002\001\001 placeholder application\n' > "$R/m0/usr/bin/app"
printf '\177ELF\002\001\001 placeholder library\n' > "$R/m0/usr/lib/libx.so"
printf 'boot ok\n' > "$R/m0/var/log/app.log"
# A sibling whose name shares a prefix with a directory a later layer
# whiteouts. "var/log" must go and "var/logrotate.conf" must stay; a
# descendant test that forgets the slash removes both.
printf 'weekly\n' > "$R/m0/var/logrotate.conf"
printf 'rotated\n' > "$R/m0/var/log/old.log"
for f in a b c; do printf 'data %s\n' "$f" > "$R/m0/opt/data/$f"; done
printf 'a sibling of the opaque directory\n' > "$R/m0/opt/database"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nnotarealkey\n' > "$R/m0/home/user/.ssh/id_rsa"
chmod 0600 "$R/m0/etc/secrets.txt" "$R/m0/home/user/.ssh/id_rsa"
chmod 0755 "$R/m0/usr/bin/app"
chmod 0644 "$R/m0/usr/lib/libx.so"
mk m0 gnu 0 0 "$R/m0"

# L1: setuid, setgid, a hard link, a symlink, and a file overwritten.
rm -rf "$R/m1"; mkdir -p "$R/m1/usr/bin" "$R/m1/usr/sbin" "$R/m1/etc"
printf '#!/bin/sh\nexec /usr/bin/app "$@"\n' > "$R/m1/usr/bin/helper"
printf '#!/bin/sh\necho tool\n' > "$R/m1/usr/sbin/tool"
printf '\177ELF\002\001\001 placeholder application\n' > "$R/m1/usr/bin/app"
ln "$R/m1/usr/bin/app" "$R/m1/usr/bin/app2"
ln -s usr/bin "$R/m1/bin"
printf 'verbose=1\n' > "$R/m1/etc/config.ini"
chmod 4755 "$R/m1/usr/bin/helper"
chmod 2755 "$R/m1/usr/sbin/tool"
# uid 1000 and gid 100, not 1000 and 1000. Every other layer here is 0:0,
# and with uid equal to gid everywhere a reader that swapped the two
# fields would agree with GNU tar on every entry in the corpus.
mk m1 gnu 1000 100 "$R/m1"

# L2: the deletions. A plain whiteout over the credential file, an opaque
# directory, and one more overwrite.
rm -rf "$R/m2"; mkdir -p "$R/m2/etc" "$R/m2/opt/data" "$R/m2/home/user/.ssh"
: > "$R/m2/etc/.wh.secrets.txt"
# The deleted half of the leak finding, with something credential
# shaped behind it. etc/secrets.txt is an AWS example key, which looks
# like a credential to a person and matches nothing a scanner greps
# for; the PEM header does, and until now the only PEM in the corpus
# was in a file no layer removed. So the finding this program exists
# for had a token behind its OVERWRITTEN half and nothing behind its
# DELETED half. The body is the word notarealkey, which is the shape
# the collection's secret audit exempts, and the audit exempts it by
# content rather than by path.
: > "$R/m2/home/user/.ssh/.wh.id_rsa"
: > "$R/m2/opt/data/.wh..wh..opq"
printf 'replaced\n' > "$R/m2/opt/data/new"
printf 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/:/sbin/nologin\n' > "$R/m2/etc/passwd"
# Different bytes AND a different mode on one path. Without this the
# audit's delta field never reports content+mode and the branch that
# produces it is never reached; the corpus had content-only and
# mode-only and nothing that was both.
mkdir -p "$R/m2/usr/lib"
printf '\177ELF\002\001\001 placeholder library, rebuilt\n' > "$R/m2/usr/lib/libx.so"
chmod 0755 "$R/m2/usr/lib/libx.so"
mk m2 pax 0 0 "$R/m2"

# L3: a directory whiteout that must take a subtree with it, a sticky
# world-writable directory, a world-writable directory without the sticky
# bit, and a character device.
rm -rf "$R/m3"; mkdir -p "$R/m3/var" "$R/m3/tmp" "$R/m3/srv/open" "$R/m3/dev"
: > "$R/m3/var/.wh.log"
printf 'scratch\n' > "$R/m3/srv/open/scratch"
chmod 1777 "$R/m3/tmp"
chmod 0777 "$R/m3/srv/open"
chmod 0666 "$R/m3/srv/open/scratch"
tar --format=gnu $TARBASE --owner=0 --group=0 -cf "$L/m3.tar" -C "$R/m3" .
# A character device cannot be created without privilege, so the entry is
# taken from the one every machine has. GNU tar records it as typeflag 3
# with the right major and minor; --transform renames it into place.
tar --format=gnu $TARBASE --owner=0 --group=0 -cf "$L/m3dev.tar" \
    --transform='s|^dev/null$|./dev/null|' -C / dev/null
tar -Af "$L/m3.tar" "$L/m3dev.tar"
rm -f "$L/m3dev.tar"

python3 "$HERE/oci.py" assemble "$W/img/multi" \
	"$L/m0.tar" "$L/m1.tar" "$L/m2.tar" "$L/m3.tar" > "$W/img/multi.digest"

# Same four layers, gzipped. The descriptor digest is then over the
# compressed bytes and the diff_id over the uncompressed ones; an image
# where the two are equal cannot tell a reader that conflates them apart
# from a correct one.
python3 "$HERE/oci.py" assemble "$W/img/multigz" --gzip \
	"$L/m0.tar" "$L/m1.tar" "$L/m2.tar" "$L/m3.tar" > "$W/img/multigz.digest"

# ---------------------------------------------------------------------------
# single: one uncompressed ustar layer. The smallest thing skopeo will copy,
# used where a test wants an image with no interesting constructs at all.
# ---------------------------------------------------------------------------
rm -rf "$R/s0"; mkdir -p "$R/s0/etc"
printf 'hello\n' > "$R/s0/etc/motd"
mk s0 ustar 0 0 "$R/s0"
python3 "$HERE/oci.py" assemble "$W/img/single" "$L/s0.tar" > "$W/img/single.digest"

# ---------------------------------------------------------------------------
# longpath: names past the 100-byte ustar limit, in both encodings that
# exist for them. GNU tar writes a 'L' typeflag entry; pax writes a type 'x'
# extended header with a path record. A reader that handles one and not the
# other is correct on roughly half of all real images.
# ---------------------------------------------------------------------------
rm -rf "$R/lp"
deep=$R/lp
seg=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa      # 36 bytes
mkdir -p "$deep/$seg/$seg/$seg/$seg"
printf 'deep\n' > "$deep/$seg/$seg/$seg/$seg/leaf.txt"
# A single component longer than 100 bytes, which the prefix field cannot
# split: ustar genuinely cannot represent this and both long-name formats
# must.
mkdir -p "$deep/short"
printf 'wide\n' > "$deep/short/$seg$seg$seg.txt"
mk lpgnu gnu 0 0 "$deep"
mk lppax pax 0 0 "$deep"
python3 "$HERE/oci.py" assemble "$W/img/longgnu" "$L/lpgnu.tar" > "$W/img/longgnu.digest"
python3 "$HERE/oci.py" assemble "$W/img/longpax" "$L/lppax.tar" > "$W/img/longpax.digest"

# ---------------------------------------------------------------------------
# dup: the same path twice in one layer, with different contents. tar allows
# it and extraction takes the last. A reader keyed by a map gets this right
# by accident; a reader that appends to a list does not.
# ---------------------------------------------------------------------------
rm -rf "$R/d1" "$R/d2"; mkdir -p "$R/d1/etc" "$R/d2/etc"
printf 'first\n' > "$R/d1/etc/dup"
printf 'second version\n' > "$R/d2/etc/dup"
tar --format=gnu $TARBASE --owner=0 --group=0 -cf "$L/dup.tar" -C "$R/d1" ./etc/dup
tar --format=gnu $TARBASE --owner=0 --group=0 -cf "$L/dup2.tar" -C "$R/d2" ./etc/dup
tar -Af "$L/dup.tar" "$L/dup2.tar"
rm -f "$L/dup2.tar"
python3 "$HERE/oci.py" assemble "$W/img/dup" "$L/dup.tar" > "$W/img/dup.digest"

# ---------------------------------------------------------------------------
# xattr: user.* attributes, set with os.setxattr and archived by GNU tar as
# SCHILY.xattr.* pax records. This machine has no setfattr, no setcap and no
# privilege to set security.capability on a real file, so the capability
# case is built separately as raw pax records -- see t/mkcaps.py, and see
# the README, which says plainly that the capability half has python's
# tarfile as its only reader-oracle and not a kernel.
# ---------------------------------------------------------------------------
rm -rf "$R/xa"; mkdir -p "$R/xa/usr/bin"
printf 'binary with attributes\n' > "$R/xa/usr/bin/xbin"
chmod 0755 "$R/xa/usr/bin/xbin"
python3 - "$R/xa/usr/bin/xbin" <<'PY'
import os, sys
os.setxattr(sys.argv[1], "user.ociv.test", b"present")
os.setxattr(sys.argv[1], "user.ociv.second", b"\x00\x01\xfe\xff")
PY
tar --format=pax $TARBASE --owner=0 --group=0 \
    --xattrs --xattrs-include='user.*' -cf "$L/xa.tar" -C "$R/xa" .
python3 "$HERE/mktar.py" caps "$L/caps.tar"
python3 "$HERE/oci.py" assemble "$W/img/xattr" "$L/xa.tar" "$L/caps.tar" > "$W/img/xattr.digest"

# ---------------------------------------------------------------------------
# escape: entries whose names leave the root. These cannot be produced by
# GNU tar from a directory tree, because tar strips leading slashes and
# refuses to store "..", so they are written as raw headers. That is exactly
# why they are interesting: an image containing one was built by something
# that was not tar, on purpose.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" escape "$L/escape.tar"
python3 "$HERE/oci.py" assemble "$W/img/escape" "$L/escape.tar" > "$W/img/escape.digest"

# ---------------------------------------------------------------------------
# opq: an opaque marker in a layer that re-adds no directory entries, so
# that "the marker empties the directory" and "the marker deletes the
# directory" produce different answers. Every tar built from a directory
# tree carries its parents, which makes the two indistinguishable.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" opq-base "$L/opqbase.tar"
python3 "$HERE/mktar.py" opq-mark "$L/opqmark.tar"
python3 "$HERE/oci.py" assemble "$W/img/opq" "$L/opqbase.tar" "$L/opqmark.tar" > "$W/img/opq.digest"

# ---------------------------------------------------------------------------
# samelayer: a whiteout AFTER a file of the same name inside one layer.
# The spec says a whiteout applies only to the layers below it, so the
# file survives. A reader that walks the archive once in tar order deletes
# it. ".wh.keepme" sorts before "keepme", so this order cannot come out of
# tar --sort=name and the archive is written by hand.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" wh-base "$L/whbase.tar"
python3 "$HERE/mktar.py" wh-same "$L/whsame.tar"
python3 "$HERE/oci.py" assemble "$W/img/samelayer" "$L/whbase.tar" "$L/whsame.tar" > "$W/img/samelayer.digest"

# ---------------------------------------------------------------------------
# symparent: a layer writing through a symlink an earlier layer left in
# place. GNU tar extracting ./bin/newfile where bin is a symlink to
# usr/bin writes usr/bin/newfile, so the file is not where its name says.
# The second layer carries no directory entries at all, because a ./bin/
# entry would replace the symlink with a real directory and the
# redirection would not happen.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" sym-base  "$L/symbase.tar"
python3 "$HERE/mktar.py" sym-write "$L/symwrite.tar"
python3 "$HERE/oci.py" assemble "$W/img/symparent" "$L/symbase.tar" "$L/symwrite.tar" > "$W/img/symparent.digest"

# ---------------------------------------------------------------------------
# symdir: the same base layer, and a second layer that writes through the
# symlink AND names ./bin/ as a directory member. Measured: GNU tar then
# REPLACES the symlink with a real directory and the file lands at
# bin/newfile, not usr/bin/newfile. The comment on symparent has said so
# since it was written and nothing in the corpus checked it, so the two
# images are here together and differ only in that one member.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" symdir-write "$L/symdirwrite.tar"
python3 "$HERE/oci.py" assemble "$W/img/symdir" "$L/symbase.tar" "$L/symdirwrite.tar" > "$W/img/symdir.digest"

# symsame: one layer that creates the symlink and then writes through
# it. The third shape, and the only one a single-layer image can have.
python3 "$HERE/mktar.py" symsame "$L/symsame.tar"
python3 "$HERE/oci.py" assemble "$W/img/symsame" "$L/symsame.tar" > "$W/img/symsame.digest"

# ---------------------------------------------------------------------------
# symwh: a whiteout marker under a symlinked directory. ./bin/.wh.existing
# where bin is a symlink to usr/bin deletes usr/bin/existing, and the
# staged extraction oracle agrees because rm -rf through a symlink is the
# kernel resolving the path, not a rule anyone here wrote.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" sym-whiteout "$L/symwh.tar"
python3 "$HERE/oci.py" assemble "$W/img/symwh" "$L/symbase.tar" "$L/symwh.tar" > "$W/img/symwh.digest"

# ---------------------------------------------------------------------------
# symout: the same escape, one level only, so GNU tar can be turned loose
# on it for real. The suite extracts this pair and looks at where the
# bytes landed; symescape's /etc and ../../.. cannot be extracted without
# writing somewhere this machine's owner did not ask for.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" symout-base  "$L/symoutbase.tar"
python3 "$HERE/mktar.py" symout-write "$L/symoutwrite.tar"
python3 "$HERE/oci.py" assemble "$W/img/symout" "$L/symoutbase.tar" "$L/symoutwrite.tar" > "$W/img/symout.digest"

# ---------------------------------------------------------------------------
# symescape: the same trick with symlinks that leave the image, one
# absolute and one climbing out with dot-dot. GNU tar extracting this into
# an ordinary directory resolves the absolute target against the HOST root
# and tries to write there, which is why this image is excluded from the
# extraction comparison and compared only against the Python
# implementation. See the README.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" symesc-base  "$L/symescbase.tar"
python3 "$HERE/mktar.py" symesc-write "$L/symescwrite.tar"
python3 "$HERE/oci.py" assemble "$W/img/symescape" "$L/symescbase.tar" "$L/symescwrite.tar" > "$W/img/symescape.digest"

# ---------------------------------------------------------------------------
# multiarch: one tag, three platforms. This is what every published image
# on a registry actually looks like, and the failure it exists to catch is
# a reader that takes index.json's first entry: that verifies somebody
# else's architecture and says the image is fine. Each manifest's config
# carries the matching os and architecture, because skopeo cross-checks
# them.
# ---------------------------------------------------------------------------
python3 "$HERE/mktar.py" plat-amd64 "$L/plamd64.tar"
python3 "$HERE/mktar.py" plat-arm64 "$L/plarm64.tar"
python3 "$HERE/mktar.py" plat-armv7 "$L/plarmv7.tar"
python3 "$HERE/oci.py" assemble-platforms "$W/img/multiarch" \
	"linux/amd64=$L/plamd64.tar" \
	"linux/arm64=$L/plarm64.tar" \
	"linux/arm/v7=$L/plarmv7.tar" > "$W/img/multiarch.platforms"

# nested: the same three platforms behind one index entry, which is the
# shape a registry serves and skopeo copy --all writes. nested2 wraps it
# once more, which the spec allows and nothing publishes, so that the
# refusal for deeper nesting is tested against an image rather than
# asserted about.
python3 "$HERE/oci.py" nest "$W/img/multiarch" "$W/img/nested"  1 > "$W/img/nested.digest"
python3 "$HERE/oci.py" nest "$W/img/multiarch" "$W/img/nested2" 2 > "$W/img/nested2.digest"

# ---------------------------------------------------------------------------
# Broken images. One named defect each.
# ---------------------------------------------------------------------------
for defect in corrupt-layer corrupt-config corrupt-config-valid \
	      corrupt-manifest-valid wrong-size missing-blob \
	      bad-digest-string unknown-algorithm no-oci-layout \
	      bad-layout-version bad-schema-version empty-index \
	      diffid-mismatch diffid-count bad-rootfs-type \
	      index-digest-mismatch index-size-mismatch \
	      config-as-layer-mediatype zstd-layer; do
	python3 "$HERE/oci.py" break "$W/img/multi" "$W/img/bad-$defect" "$defect"
done

# Digest grammar cases, built off the smallest image so the only variable
# is the spelling of one string.
python3 "$HERE/oci.py" digestcases "$W/img/single" "$W/img" > /dev/null

echo "corpus built in $W" >&2
