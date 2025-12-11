#!/usr/bin/env python3
"""Emit normalised per-entry facts about a tar archive, from one of three
sources, in one format, so they can be compared line for line.

    tarfacts.py gnu  FILE.tar     parse GNU tar's own -tv listing
    tarfacts.py py   FILE.tar     read it with python's tarfile module
    tarfacts.py ociv FILE         re-normalise ociv's "entry" lines from stdin
    tarfacts.py names FILE...     the normalised paths the archives NAME

Format, one line per entry, fields separated by single spaces:

    TYPE MODE UID GID SIZE NAMEHEX LINKHEX

MODE is four octal digits including setuid, setgid and sticky. SIZE for a
device entry is "MAJOR,MINOR", which is what GNU tar prints in that column
and is the only place the numbers appear in its output at all. Names are
hex because the corpus deliberately contains a filename with a newline in
it and another with a backslash and a quote, and two tools' ideas of how to
escape those will differ somewhere. Hex has no corners.

The point of three sources is that GNU tar and python's tarfile were
written by different people from the same specification, and ociv is the
one being judged. Agreement with one of them is weaker evidence than
agreement with both, and a disagreement between the two of them is a fact
about tar worth knowing before it is blamed on ociv.
"""
import re
import subprocess
import sys
import tarfile

# GNU tar's first column. The mapping to a typeflag is from tar's own
# source order and from POSIX: regular, directory, symlink, hard link,
# character device, block device, fifo, socket.
TYPECHAR = {"-": "file", "d": "dir", "l": "symlink", "h": "hardlink",
            "c": "chardev", "b": "blockdev", "p": "fifo", "s": "socket"}

# Permission string to octal. The interesting part is columns 2, 5 and 8,
# where s/S and t/T carry the setuid, setgid and sticky bits -- lowercase
# meaning the execute bit is also set, uppercase meaning it is not. A
# parser that only reads rwx silently drops every bit this program exists
# to report.
def perms_to_octal(p):
    assert len(p) == 9, p
    bits = 0
    for i, (ch, val) in enumerate(zip(p, [0o400, 0o200, 0o100,
                                          0o40, 0o20, 0o10,
                                          0o4, 0o2, 0o1])):
        if ch in "rwx":
            bits |= val
        elif ch in "sSb":          # 'b' never appears; guard anyway
            pass
        elif ch in "tT":
            pass
        elif ch == "-":
            pass
        else:
            raise ValueError("unknown permission character %r in %r" % (ch, p))
    if p[2] in "sS":
        bits |= 0o4000
        if p[2] == "s":
            bits |= 0o100
    elif p[2] == "x":
        bits |= 0o100
    if p[5] in "sS":
        bits |= 0o2000
        if p[5] == "s":
            bits |= 0o10
    elif p[5] == "x":
        bits |= 0o10
    if p[8] in "tT":
        bits |= 0o1000
        if p[8] == "t":
            bits |= 0o1
    elif p[8] == "x":
        bits |= 0o1
    return bits


# GNU tar --quoting-style=c escapes. Undo them to get the real bytes.
C_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
             "\\": 92, '"': 34, "'": 39, "?": 63}


def c_unescape(s):
    out = bytearray()
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
            continue
        nxt = s[i + 1]
        if nxt in C_ESCAPES:
            out.append(C_ESCAPES[nxt])
            i += 2
        elif nxt.isdigit():
            out.append(int(s[i + 1:i + 4], 8))
            i += 4
        else:
            raise ValueError("unknown escape \\%s in %r" % (nxt, s))
    return bytes(out)


LINE = re.compile(
    r'^(?P<perm>[-dlhcbps])(?P<rest>[rwxsStT-]{9})\s+'
    r'(?P<uid>\d+)/(?P<gid>\d+)\s+'
    r'(?P<size>[\d,]+)\s+'
    r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?\s+'
    r'(?P<tail>".*)$')


def from_gnu(path):
    out = subprocess.run(
        ["tar", "--numeric-owner", "--quoting-style=c", "-tvf", path],
        capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            raise SystemExit("tarfacts: cannot parse GNU tar line: %r" % line)
        tail = m.group("tail")
        # tail is '"name"', '"name" -> "target"', or '"name" link to "target"'
        if " -> " in tail:
            n, l = tail.split(" -> ", 1)
        elif " link to " in tail:
            n, l = tail.split(" link to ", 1)
        else:
            n, l = tail, '""'
        name = c_unescape(n[1:-1])
        link = c_unescape(l[1:-1])
        rows.append((TYPECHAR[m.group("perm")],
                     perms_to_octal(m.group("rest")),
                     int(m.group("uid")), int(m.group("gid")),
                     m.group("size"), name, link))
    return rows


PYTYPE = {tarfile.REGTYPE: "file", tarfile.AREGTYPE: "file",
          tarfile.DIRTYPE: "dir", tarfile.SYMTYPE: "symlink",
          tarfile.LNKTYPE: "hardlink", tarfile.CHRTYPE: "chardev",
          tarfile.BLKTYPE: "blockdev", tarfile.FIFOTYPE: "fifo"}


def from_py(path):
    rows = []
    with tarfile.open(path, "r:*") as t:
        for m in t.getmembers():
            typ = PYTYPE[m.type]
            size = "%d,%d" % (m.devmajor, m.devminor) if typ in ("chardev", "blockdev") else str(m.size)
            rows.append((typ, m.mode, m.uid, m.gid, size,
                         m.name.encode("utf-8", "surrogateescape"),
                         m.linkname.encode("utf-8", "surrogateescape")))
    return rows


OCIV = re.compile(r"^entry (\d+) (\d+) (\S+) (\d+) (\d+) (\d+) (\d+) ")


def from_ociv(stream, layer):
    rows = []
    for line in stream:
        m = OCIV.match(line)
        if not m or int(m.group(1)) != layer:
            continue
        typ, mode, uid, gid, size = (m.group(3), int(m.group(4), 8),
                                     int(m.group(5)), int(m.group(6)),
                                     m.group(7))
        kv = dict(p.split("=", 1) for p in line.split() if "=" in p and
                  p.split("=", 1)[0] in ("nhex", "lhex", "dev"))
        if typ in ("chardev", "blockdev"):
            size = kv.get("dev", "0,0").replace(",", ",")
        rows.append((typ, mode, uid, gid, size,
                     bytes.fromhex(kv["nhex"]),
                     bytes.fromhex(kv.get("lhex", ""))))
    return rows


def sanitise_link(t, link):
    """GNU tar, when LISTING an archive, removes a leading "../" from a
    hard link target and says so on stderr. python's tarfile and ociv both
    report the bytes that are actually in the header. The difference is
    real and is recorded in the README; this undoes it on both sides so the
    rest of the comparison is not drowned by it. The suite also asserts
    the divergence is still there, so a change in GNU tar's behaviour
    shows up as a failure rather than as silence."""
    if t != "hardlink":
        return link
    while link.startswith(b"../"):
        link = link[3:]
    return link


def emit(rows, strip=False, sanlinks=False):
    """strip removes a trailing slash from a directory name. python's
    tarfile does that normalisation itself and GNU tar does not, so a
    comparison between those two has to choose one spelling. The
    ociv-against-GNU-tar comparison runs WITHOUT it, because there the
    claim is about the bytes in the header."""
    for t, mode, uid, gid, size, name, link in rows:
        if strip and t == "dir" and name.endswith(b"/") and name != b"/":
            name = name.rstrip(b"/") or b"."
        if sanlinks:
            link = sanitise_link(t, link)
        print("%s %04o %d %d %s %s %s" %
              (t, mode, uid, gid, size, name.hex(), link.hex()))


def names(paths):
    """The set of paths the archives actually NAME, normalised, one hex
    per line. Needed because tar creates intermediate directories that no
    member mentions: extracting an archive whose only member is
    "./etc/dup" leaves an "etc" directory behind, and ociv reports what
    the image contains rather than what unpacking it would create."""
    out = set()
    for p in paths:
        for row in from_gnu(p):
            n = row[5]
            if n.startswith(b"./"):
                n = n[2:]
            n = n.rstrip(b"/")
            if n:
                out.add(n.hex())
    for h in sorted(out):
        print(h)


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    strip = "--strip" in argv
    sanlinks = "--sanitise-links" in argv
    argv = [a for a in argv if a not in ("--strip", "--sanitise-links")]
    mode, path = argv[1], argv[2]
    if mode == "names":
        names(argv[2:])
        return
    if mode == "gnu":
        emit(from_gnu(path), strip, sanlinks)
    elif mode == "py":
        emit(from_py(path), strip, sanlinks)
    elif mode == "ociv":
        emit(from_ociv(sys.stdin, int(argv[3])), strip, sanlinks)
    else:
        sys.exit("tarfacts: unknown mode %r" % mode)


if __name__ == "__main__":
    main(sys.argv)
