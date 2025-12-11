#!/bin/sh
# A third implementation of layer merging, in shell, using GNU tar and the
# real filesystem.
#
#   usage: extract.sh WORKDIR LAYER.tar...
#
# Prints one line per path in the resulting tree:
#
#   fnode TYPE MODE SIZE CONTENTSHA LINKHEX PATHHEX
#
# Why this exists. The Python oracle beside it is a second opinion written
# in the same project; this is GNU tar actually doing the extraction, and
# "layer N overwrites layer N-1" is then not an argument about the spec
# but a statement about what tar did. The only logic here that is not tar
# is four lines of rm -rf driven by the whiteout markers tar just
# extracted, which is as close to the OCI spec's own prose as a shell
# script gets:
#
#   .wh.NAME          delete NAME from what is below
#   .wh..wh..opq      delete everything in this directory from what is below
#
# Each layer is unpacked into a staging directory FIRST, so that "what this
# layer contributes" and "what is below" are still distinguishable when the
# whiteouts are applied. Unpacking straight into the result loses that and
# makes the same-layer rule untestable.
#
# What this oracle cannot see, and why:
#   - uid and gid. Extraction runs unprivileged, so every file comes out
#     owned by the invoking user. The GNU tar listing comparison in
#     t/run.sh covers ownership instead, per entry, from the headers.
#   - device nodes. mknod needs privilege. tar prints a diagnostic and
#     carries on; such paths are absent here and the comparison drops them.
#   - which of a set of hard links was the "original". The inode is shared
#     and the distinction is gone. nlink is reported so the suite can
#     still assert that a link was made.
set -u
W=${1:?usage: extract.sh WORKDIR LAYER.tar...}
shift
R=$W/root
S=$W/stage
rm -rf "$R" "$S"
mkdir -p "$R"

for layer in "$@"; do
	rm -rf "$S"
	mkdir -p "$S"
	# -p keeps the setuid, setgid and sticky bits, which the umask would
	# otherwise take off and which are the whole point of the audit.
	tar -xpf "$layer" -C "$S" 2>>"$W/extract.err" || true

	# Whiteouts, against what is already in R. Markers are found in the
	# staging tree, so they are this layer's and only this layer's.
	( cd "$S" && find . -name '.wh.*' -printf '%P\n' ) | while read -r mk; do
		base=${mk##*/}
		dir=${mk%/*}
		[ "$dir" = "$mk" ] && dir=.
		if [ "$base" = ".wh..wh..opq" ]; then
			[ -d "$R/$dir" ] && find "$R/$dir" -mindepth 1 -maxdepth 1 \
				-exec rm -rf {} + 2>/dev/null
		else
			rm -rf "$R/$dir/${base#.wh.}"
		fi
	done

	# The markers themselves are never part of the result.
	find "$S" -name '.wh.*' -exec rm -f {} + 2>/dev/null
	cp -a "$S/." "$R/" 2>>"$W/extract.err" || true
done

# The listing is done by python's os.lstat rather than by find -printf,
# because find's output has to be split on something and a tar member name
# may contain a tab, a newline or a space -- the corpus has all three on
# purpose. The extraction above is GNU tar and rm; this only reads back
# what they produced.
python3 - "$R" <<'PYLIST'
import hashlib, os, stat, sys

root = sys.argv[1]
rows = []
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    for n in sorted(dirnames) + sorted(filenames):
        p = os.path.join(dirpath, n)
        rel = os.path.relpath(p, root)
        st = os.lstat(p)
        m = st.st_mode
        if stat.S_ISDIR(m):
            y, size, link, sha = "d", 0, "", "-"
        elif stat.S_ISLNK(m):
            y, size, link, sha = "l", 0, os.readlink(p), "-"
        elif stat.S_ISREG(m):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for b in iter(lambda: f.read(1 << 16), b""):
                    h.update(b)
            y, size, link, sha = "f", st.st_size, "", "sha256:" + h.hexdigest()
        elif stat.S_ISCHR(m):
            y, size, link, sha = "c", 0, "", "-"
        elif stat.S_ISBLK(m):
            y, size, link, sha = "b", 0, "", "-"
        elif stat.S_ISFIFO(m):
            y, size, link, sha = "p", 0, "", "-"
        else:
            y, size, link, sha = "?", 0, "", "-"
        rows.append("fnode %s %04o %d %d %s %s %s" % (
            y, stat.S_IMODE(m), size, st.st_nlink, sha,
            link.encode("utf-8", "surrogateescape").hex() or "-",
            rel.encode("utf-8", "surrogateescape").hex()))
for r in sorted(rows, key=lambda s: s.split()[-1]):
    print(r)
PYLIST
