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
printf 'verbose=0\n' > "$R/m0/etc/config.ini"
printf '\177ELF\002\001\001 placeholder application\n' > "$R/m0/usr/bin/app"
printf '\177ELF\002\001\001 placeholder library\n' > "$R/m0/usr/lib/libx.so"
printf 'boot ok\n' > "$R/m0/var/log/app.log"
printf 'rotated\n' > "$R/m0/var/log/old.log"
for f in a b c; do printf 'data %s\n' "$f" > "$R/m0/opt/data/$f"; done
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
printf 'verbose=1\ntoken=ghp_0000000000000000000000000000000000\n' > "$R/m1/etc/config.ini"
chmod 4755 "$R/m1/usr/bin/helper"
chmod 2755 "$R/m1/usr/sbin/tool"
mk m1 gnu 1000 1000 "$R/m1"

# L2: the deletions. A plain whiteout over the credential file, an opaque
# directory, and one more overwrite.
rm -rf "$R/m2"; mkdir -p "$R/m2/etc" "$R/m2/opt/data"
: > "$R/m2/etc/.wh.secrets.txt"
: > "$R/m2/opt/data/.wh..wh..opq"
printf 'replaced\n' > "$R/m2/opt/data/new"
printf 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/:/sbin/nologin\n' > "$R/m2/etc/passwd"
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
# Broken images. One named defect each.
# ---------------------------------------------------------------------------
for defect in corrupt-layer corrupt-config wrong-size missing-blob \
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
