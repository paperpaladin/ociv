#!/usr/bin/env python3
"""Write tar archives GNU tar will not produce from a directory tree.

Two cases need this and nothing else does.

Capabilities. A file capability lives in the security.capability extended
attribute, and setting one needs CAP_SETFCAP. This machine has no setcap,
no setfattr and no privilege, so there is no way to put a real capability on
a real file and let GNU tar archive it. The record is therefore written
directly, in the same SCHILY.xattr.* pax form GNU tar itself uses -- which
is verifiable, because GNU tar reads these archives back and says what it
found, and python's tarfile decodes the same records independently.

Escapes. tar strips a leading slash and refuses to store "..", by design,
so an archive containing either was not made by tar. That is the whole
reason such an archive is interesting: it is what a hostile image looks
like. Writing the headers by hand is the only way to get one.

The writer below is about seventy lines of ustar and pax header
construction, written from POSIX.1-2001 section 20.1 (ustar) and the pax
extended header format. It is not a general tar writer and is not used
outside the corpus.

    mktar.py caps     OUT.tar
    mktar.py escape   OUT.tar
    mktar.py opq-base OUT.tar
    mktar.py opq-mark OUT.tar
    mktar.py wh-base  OUT.tar
    mktar.py wh-same  OUT.tar
    mktar.py sym-base OUT.tar
    mktar.py sym-write OUT.tar
    mktar.py sym-whiteout OUT.tar
    mktar.py plat-amd64 OUT.tar
    mktar.py plat-arm64 OUT.tar
    mktar.py plat-armv7 OUT.tar
    mktar.py symout-base OUT.tar
    mktar.py symout-write OUT.tar
    mktar.py symesc-base OUT.tar
    mktar.py symesc-write OUT.tar
"""
import sys

BLOCK = 512
MTIME = 1700000000


def octal(n, width):
    """ustar numeric field: octal, NUL-terminated, right-aligned, zero-padded."""
    return ("%0*o" % (width - 1, n)).encode() + b"\0"


def ustar_header(name, size=0, mode=0o644, uid=0, gid=0, typeflag=b"0",
                 linkname="", uname="root", gname="root",
                 devmajor=0, devminor=0, mtime=MTIME, prefix=""):
    h = bytearray(BLOCK)

    def put(off, b, n):
        b = b if isinstance(b, bytes) else b.encode()
        if len(b) > n:
            raise ValueError("field at %d overflows: %r" % (off, b))
        h[off:off + len(b)] = b

    put(0, name, 100)
    put(100, octal(mode, 8), 8)
    put(108, octal(uid, 8), 8)
    put(116, octal(gid, 8), 8)
    put(124, octal(size, 12), 12)
    put(136, octal(mtime, 12), 12)
    h[148:156] = b" " * 8          # checksum field is spaces while summing
    put(156, typeflag, 1)
    put(157, linkname, 100)
    put(257, b"ustar\0", 6)
    put(263, b"00", 2)
    put(265, uname, 32)
    put(297, gname, 32)
    put(329, octal(devmajor, 8), 8)
    put(337, octal(devminor, 8), 8)
    put(345, prefix, 155)
    chk = sum(h)
    h[148:156] = ("%06o\0 " % chk).encode()
    return bytes(h)


def pad(b):
    r = len(b) % BLOCK
    return b + b"\0" * (BLOCK - r) if r else b


def pax_record(key, value):
    """A pax record is 'LEN KEY=VALUE\\n' where LEN counts itself. The
    self-reference means the length has to be solved for, which is the one
    fiddly part of the format and the one a hand-rolled writer gets wrong."""
    if isinstance(value, str):
        value = value.encode()
    body = key.encode() + b"=" + value + b"\n"
    n = len(body) + 2
    while True:
        cand = str(n).encode() + b" " + body
        if len(cand) == n:
            return cand
        n = len(cand)


def pax_entry(name, records, size=0, mode=0o644, typeflag=b"0", content=b"",
              linkname="", uid=0, gid=0):
    """An 'x' typeflag block carrying the records, then the real entry."""
    blob = b"".join(pax_record(k, v) for k, v in records)
    out = ustar_header("PaxHeaders/" + name.lstrip("./")[:80], size=len(blob),
                       typeflag=b"x", mode=0o644)
    out += pad(blob)
    out += ustar_header(name, size=len(content), mode=mode, typeflag=typeflag,
                        linkname=linkname, uid=uid, gid=gid)
    out += pad(content)
    return out


def plain_entry(name, content=b"", mode=0o644, typeflag=b"0", linkname="",
                uid=0, gid=0, devmajor=0, devminor=0):
    return ustar_header(name, size=len(content), mode=mode, typeflag=typeflag,
                        linkname=linkname, uid=uid, gid=gid,
                        devmajor=devmajor, devminor=devminor) + pad(content)


def finish(parts):
    return b"".join(parts) + b"\0" * (BLOCK * 2)


# Linux VFS capability, revision 2: a 20-byte little-endian struct of
# magic_etc, then permitted/inheritable low words, then the high words.
VFS_CAP_REVISION_2 = 0x02000000
VFS_CAP_FLAGS_EFFECTIVE = 0x000001
CAP_NET_RAW = 13
CAP_SETUID = 7
CAP_DAC_OVERRIDE = 1


def vfs_cap(permitted_bits, effective=True):
    magic = VFS_CAP_REVISION_2 | (VFS_CAP_FLAGS_EFFECTIVE if effective else 0)
    lo = 0
    hi = 0
    for b in permitted_bits:
        if b < 32:
            lo |= 1 << b
        else:
            hi |= 1 << (b - 32)
    out = magic.to_bytes(4, "little")
    out += lo.to_bytes(4, "little") + (0).to_bytes(4, "little")
    out += hi.to_bytes(4, "little") + (0).to_bytes(4, "little")
    assert len(out) == 20
    return out


def build_caps(path):
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./usr/", mode=0o755, typeflag=b"5"),
        plain_entry("./usr/bin/", mode=0o755, typeflag=b"5"),
        # ping with cap_net_raw: the canonical real-world example, and the
        # reason a tool that only looks at the setuid bit misses half the
        # privileged binaries in a modern image.
        pax_entry("./usr/bin/ping",
                  [("SCHILY.xattr.security.capability",
                    vfs_cap([CAP_NET_RAW])),
                   ("mtime", str(MTIME))],
                  mode=0o755, content=b"#!/bin/sh\necho ping\n"),
        # Two capabilities at once, and no effective bit: the file still
        # grants them to a program that knows how to ask.
        pax_entry("./usr/bin/multi",
                  [("SCHILY.xattr.security.capability",
                    vfs_cap([CAP_SETUID, CAP_DAC_OVERRIDE], effective=False)),
                   ("mtime", str(MTIME))],
                  mode=0o755, content=b"#!/bin/sh\necho multi\n"),
        # A plain user.* attribute on an otherwise ordinary file, so the
        # capability test cannot pass by reporting every xattr as a
        # capability.
        pax_entry("./usr/bin/plainxattr",
                  [("SCHILY.xattr.user.note", b"not a capability"),
                   ("mtime", str(MTIME))],
                  mode=0o755, content=b"#!/bin/sh\necho plain\n"),
        plain_entry("./usr/bin/nocap", content=b"#!/bin/sh\necho nocap\n",
                    mode=0o755),
    ]
    open(path, "wb").write(finish(parts))


def build_escape(path):
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./etc/", mode=0o755, typeflag=b"5"),
        plain_entry("./etc/ok", content=b"this one is fine\n"),
        # Five shapes of escape. They are not the same bug: the first
        # is obvious, the second hides inside a path that starts
        # legitimately, the third is an absolute name, the fourth is
        # absolute and climbing at once, and the fifth is an absolute
        # symlink target that only escapes when something follows it.
        plain_entry("../etc/shadow", content=b"root:!:0:0:::::\n"),
        plain_entry("etc/../../root/.ssh/authorized_keys",
                    content=b"ssh-rsa AAAA notarealkey\n"),
        plain_entry("/absolute/path", content=b"absolute\n"),
        # Absolute AND climbing. GNU tar takes the slash off and then
        # refuses what is left, because it still contains "..", so this
        # one lands nowhere where /absolute/path lands inside the root.
        # The two have to be in the corpus together or the rule that
        # separates them is never exercised: a climb test that gives the
        # leading empty component one level of credit gets this wrong
        # and nothing else notices.
        plain_entry("/../etc/leaked", content=b"climbed out\n"),
        plain_entry("./link-out", typeflag=b"2", linkname="/etc/passwd"),
        plain_entry("./link-up", typeflag=b"2", linkname="../../../etc/passwd"),
        plain_entry("./hard-out", typeflag=b"1", linkname="../etc/shadow"),
        # A newline inside a filename. Legal in a tar member name and legal
        # on Linux, and it destroys any line-oriented report that does not
        # quote. Put here deliberately so that ociv's own output format has
        # to survive its own corpus.
        plain_entry("./etc/new\nline", content=b"newline in the name\n"),
        plain_entry("./etc/tab\there", content=b"tab in the name\n"),
        plain_entry('./etc/quote"and\\back', content=b"quoting\n"),
    ]
    open(path, "wb").write(finish(parts))


def build_opq_base(path):
    """A directory with contents, and a SIBLING whose name shares its
    prefix. Whiteouting "opt/data" must not touch "opt/database"; a
    descendant test that forgets the slash removes both and nothing in a
    corpus without such a sibling would notice."""
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./opt/", mode=0o755, typeflag=b"5"),
        plain_entry("./opt/data/", mode=0o755, typeflag=b"5"),
        plain_entry("./opt/data/a", content=b"alpha\n"),
        plain_entry("./opt/data/b", content=b"bravo\n"),
        plain_entry("./opt/database", content=b"a sibling, not a child\n"),
    ]
    open(path, "wb").write(finish(parts))


def build_opq_mark(path):
    """A layer holding ONLY the opaque marker: no directory entries at all.

    Every layer GNU tar builds from a directory tree carries the parent
    directories, so in such a corpus an implementation that lets the
    opaque marker delete the directory ITSELF is indistinguishable from a
    correct one -- the directory is immediately re-added by the same
    layer. This layer re-adds nothing, so the two behaviours differ."""
    parts = [plain_entry("./opt/data/" + WH_OPAQUE)]
    open(path, "wb").write(finish(parts))


def build_wh_base(path):
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./etc/", mode=0o755, typeflag=b"5"),
        plain_entry("./etc/keepme", content=b"the old version\n"),
        plain_entry("./etc/gone", content=b"PRIVATE KEY MATERIAL\n", mode=0o600),
    ]
    open(path, "wb").write(finish(parts))


def build_wh_same(path):
    """A whiteout AFTER a file of the same name, in one layer.

    The spec is explicit: a whiteout applies to the layers below it and
    never to the layer it appears in. So etc/keepme must survive with this
    layer's contents even though etc/.wh.keepme follows it in the archive.
    An implementation that walks the archive once in order deletes it.

    The order matters and cannot be produced by "tar --sort=name", because
    ".wh.keepme" sorts before "keepme" and a one-pass reader then gets the
    right answer by accident."""
    parts = [
        plain_entry("./etc/keepme", content=b"the new version\n"),
        plain_entry("./etc/" + WH_PREFIX + "keepme"),
        plain_entry("./etc/" + WH_PREFIX + "gone"),
    ]
    open(path, "wb").write(finish(parts))


WH_PREFIX = ".wh."
WH_OPAQUE = ".wh..wh..opq"

def build_sym_base(path):
    """A real directory, and a symlink standing in front of it. This is
    the /bin -> usr/bin arrangement every modern distribution image has."""
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./usr/", mode=0o755, typeflag=b"5"),
        plain_entry("./usr/bin/", mode=0o755, typeflag=b"5"),
        plain_entry("./usr/bin/existing", content=b"was here first\n", mode=0o755),
        plain_entry("./bin", typeflag=b"2", linkname="usr/bin", mode=0o777),
        plain_entry("./usr/lib/", mode=0o755, typeflag=b"5"),
        plain_entry("./deep", typeflag=b"2", linkname="bin", mode=0o777),
    ]
    open(path, "wb").write(finish(parts))


def build_sym_write(path):
    """A layer that writes THROUGH the symlink, with no directory entry of
    its own to replace it.

    GNU tar extracting ./bin/newfile into a tree where bin is already a
    symlink to usr/bin writes usr/bin/newfile. Checked, not assumed. So a
    layer can put a file somewhere other than where its name says. The
    absence of a ./bin/ directory entry is the whole point: when the
    layer carries one, tar replaces the symlink with a real directory and
    the redirection does not happen."""
    parts = [
        plain_entry("./bin/newfile", content=b"written through a symlink\n"),
        plain_entry("./deep/twohops", content=b"through two symlinks\n"),
    ]
    open(path, "wb").write(finish(parts))


def build_sym_whiteout(path):
    """A whiteout marker underneath a symlinked directory.

    The marker is ./bin/.wh.existing and bin is a symlink to usr/bin in
    the layer below, so what gets deleted is usr/bin/existing. A reader
    that treats the marker's directory as a literal path deletes nothing
    and reports nothing, and the file stays in the merged tree while an
    unpacker removes it. That is a disagreement about what the image
    contains, in the direction that matters least on a laptop and most
    in a scanner.

    An ordinary file beside it, so the layer is not only a marker: a
    layer whose single member is a whiteout is a special case in several
    readers and this is not meant to be testing that."""
    parts = [
        plain_entry("./bin/.wh.existing"),
        plain_entry("./usr/lib/note", content=b"not a whiteout\n"),
    ]
    open(path, "wb").write(finish(parts))


def build_plat(arch):
    """A one-file layer naming its own architecture, so that picking the
    wrong manifest out of a multi-platform index is visible in the merged
    tree rather than only in a digest."""
    def build(path):
        parts = [
            plain_entry("./", mode=0o755, typeflag=b"5"),
            plain_entry("./usr/", mode=0o755, typeflag=b"5"),
            plain_entry("./usr/bin/", mode=0o755, typeflag=b"5"),
            plain_entry("./usr/bin/arch", content=("%s\n" % arch).encode(),
                        mode=0o755),
        ]
        open(path, "wb").write(finish(parts))
    return build


def build_symout_base(path):
    """One level out, and only one.

    symesc-base escapes with an absolute /etc and a three-deep dot-dot,
    which is the realistic shape and is also untestable against real
    extraction: letting GNU tar loose on either would have it writing at
    the host's /etc or at the filesystem root. This pair escapes exactly
    one directory, so the suite can extract it for real into a scratch
    tree and look at where the bytes landed without touching anything it
    does not own."""
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./keep", content=b"inside\n"),
        plain_entry("./out", typeflag=b"2", linkname="..", mode=0o777),
    ]
    open(path, "wb").write(finish(parts))


def build_symout_write(path):
    parts = [
        plain_entry("./out/escaped", content=b"one level above the root\n"),
    ]
    open(path, "wb").write(finish(parts))


def build_symesc_base(path):
    """Symlinks that leave the image: one absolute, one climbing out with
    dot-dot. Both are legal tar members and both are what a layer-based
    escape looks like."""
    parts = [
        plain_entry("./", mode=0o755, typeflag=b"5"),
        plain_entry("./etc/", mode=0o755, typeflag=b"5"),
        plain_entry("./abs", typeflag=b"2", linkname="/etc", mode=0o777),
        plain_entry("./up", typeflag=b"2", linkname="../../..", mode=0o777),
    ]
    open(path, "wb").write(finish(parts))


def build_symesc_write(path):
    parts = [
        plain_entry("./abs/passwd", content=b"root::0:0:::\n"),
        plain_entry("./up/pwned", content=b"outside the image\n"),
    ]
    open(path, "wb").write(finish(parts))


BUILDERS = {"caps": build_caps, "escape": build_escape,
            "sym-base": build_sym_base, "sym-write": build_sym_write,
            "sym-whiteout": build_sym_whiteout,
            "plat-amd64": build_plat("amd64"),
            "plat-arm64": build_plat("arm64"),
            "plat-armv7": build_plat("armv7"),
            "symout-base": build_symout_base,
            "symout-write": build_symout_write,
            "symesc-base": build_symesc_base, "symesc-write": build_symesc_write,
            "opq-base": build_opq_base, "opq-mark": build_opq_mark,
            "wh-base": build_wh_base, "wh-same": build_wh_same}


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    BUILDERS[argv[1]](argv[2])


if __name__ == "__main__":
    main(sys.argv)
