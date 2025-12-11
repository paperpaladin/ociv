#!/usr/bin/env python3
"""A second implementation of layer merging and the security report.

Written in Python from the OCI image-spec "Applying Changesets" section and
the Linux mode bits, against the specification text rather than against
ociv's source. It reads the layer tarballs directly with python's tarfile,
which is a different tar parser by different authors, so a disagreement is
either a bug in ociv or a bug here and both are worth finding.

It is honestly weaker than skopeo or GNU tar: those are external
authorities, and this is a second opinion written in the same project. The
README says so. It exists because no tool on this machine applies
whiteouts, and the alternative to a second opinion is no opinion.

    oracle.py census LAYER.tar...   construct counts, one per line
    oracle.py tree   LAYER.tar...   the merged root filesystem
    oracle.py audit  LAYER.tar...   the security-relevant findings

Standard library only.
"""
import hashlib
import sys
import tarfile

WH_PREFIX = ".wh."
WH_OPAQUE = ".wh..wh..opq"

TYPE = {tarfile.REGTYPE: "file", tarfile.AREGTYPE: "file",
        tarfile.DIRTYPE: "dir", tarfile.SYMTYPE: "symlink",
        tarfile.LNKTYPE: "hardlink", tarfile.CHRTYPE: "chardev",
        tarfile.BLKTYPE: "blockdev", tarfile.FIFOTYPE: "fifo"}


def clean(name):
    """Normalise a member name to the path it occupies in the root, and say
    whether it would occupy one at all. A leading slash is an absolute path
    an unpacker must not honour; a '..' that pops past the root escapes.
    Collapsing 'a/../b' to 'b' is correct, so the walk tracks depth rather
    than matching text."""
    escapes = False
    why = ""
    s = name
    if s.startswith("/"):
        escapes, why = True, "absolute path"
        s = s.lstrip("/")
    out = []
    for p in s.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if out:
                out.pop()
            else:
                escapes = True
                why = why or "parent reference above the root"
        else:
            out.append(p)
    return "/".join(out), escapes, why


def whiteout(path):
    """Classify a normalised path as a whiteout marker. The opaque marker is
    tested first because it also starts with '.wh.'; testing the prefix
    first deletes a lower-layer file literally named '.wh..wh..opq'
    instead of emptying the directory."""
    dirp, _, base = path.rpartition("/")
    if base == WH_OPAQUE:
        return "opaque", dirp
    if base.startswith(WH_PREFIX):
        t = base[len(WH_PREFIX):]
        return "file", (dirp + "/" + t if dirp else t)
    return "", ""


class Node:
    __slots__ = ("layer", "index", "type", "mode", "uid", "gid", "size",
                 "link", "xattrs", "content")


    def __init__(self, layer, index, m, content):
        self.layer = layer
        self.index = index
        self.type = TYPE.get(m.type, "type" + m.type.decode())
        self.mode = m.mode
        self.uid = m.uid
        self.gid = m.gid
        self.size = m.size
        self.link = m.linkname
        self.xattrs = {k[len("SCHILY.xattr."):]: v
                       for k, v in m.pax_headers.items()
                       if k.startswith("SCHILY.xattr.")}
        if not self.xattrs and getattr(m, "pax_headers", None) is None:
            self.xattrs = {}
        self.content = content
        if self.type in ("chardev", "blockdev"):
            self.size = 0
            self.link = "%d,%d" % (m.devmajor, m.devminor)


def read_layer(path, idx):
    """Every member of one layer, in tar order, with regular-file contents
    hashed. Duplicates are kept: a tar may name the same path twice and the
    second one wins on extraction, which a reader keyed by a dict gets
    right only by accident."""
    out = []
    with tarfile.open(path, "r:*") as t:
        for n, m in enumerate(t.getmembers()):
            content = "-"
            if m.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                f = t.extractfile(m)
                h = hashlib.sha256()
                while True:
                    b = f.read(1 << 16)
                    if not b:
                        break
                    h.update(b)
                content = "sha256:" + h.hexdigest()
            out.append((n, m, content))
    return out


def descendants(state, d):
    """Every path strictly below directory d. The slash is part of the test:
    without it, whiteouting 'var/log' would also remove 'var/logrotate'."""
    pre = d + "/" if d else ""
    return [p for p in state if p.startswith(pre) and p != d]


def merge(layers):
    """Apply the layers in order. Returns the merged state, the list of
    paths a whiteout removed, and the list of paths a later layer replaced.

    The ordering rule is the one implementations get wrong: a whiteout
    applies to the layers BELOW it and never to the layer it appears in.
    So each layer is applied in two passes, whiteouts first against the
    accumulated lower state, then this layer's own entries."""
    state = {}
    deleted = []    # (path, layer_still_holding_it, whiteout_layer, node)
    shadowed = []   # (path, old_layer, new_layer, old_node, new_node)
    nowhere = []    # whiteouts that removed nothing
    dangling = []   # hard links whose target is in no layer at or below
    all_entries = []

    for i, lp in enumerate(layers):
        entries = read_layer(lp, i)
        all_entries.append(entries)

        # Pass one: the whiteouts of this layer, against the lower state.
        for n, m, _ in entries:
            path, esc, _why = clean(m.name)
            kind, target = whiteout(path)
            if kind == "opaque":
                victims = descendants(state, target)
                if not victims:
                    nowhere.append(("opaque", target, i))
                for p in victims:
                    deleted.append((p, state[p].layer, i, state[p]))
                    del state[p]
            elif kind == "file":
                victims = ([target] if target in state else []) + descendants(state, target)
                if not victims:
                    nowhere.append(("file", target, i))
                for p in victims:
                    deleted.append((p, state[p].layer, i, state[p]))
                    del state[p]

        # Pass two: this layer's real entries, in tar order.
        for n, m, content in entries:
            path, esc, _why = clean(m.name)
            kind, _ = whiteout(path)
            if kind:
                continue            # markers are never in the result
            if path == "":
                continue            # the root entry itself
            node = Node(i, n, m, content)
            # A hard link's header carries size 0 and no content: the
            # bytes are at the target. Resolve against the state as it
            # stands, which is the lower layers plus this layer's earlier
            # entries -- what an unpacker has when it reaches this member.
            if node.type == "hardlink":
                t, _e, _w = clean(m.linkname)
                tgt = state.get(t)
                if tgt is not None:
                    node.size = tgt.size
                    node.content = tgt.content
                else:
                    dangling.append(node)
            old = state.get(path)
            if old is not None and (old.layer != i or old.index != n):
                if old.content != node.content or old.mode != node.mode:
                    shadowed.append((path, old.layer, i, old, node))
            state[path] = node
    return state, deleted, shadowed, nowhere, all_entries, dangling


# ---------------------------------------------------------------------------

def hx(s):
    return s.encode("utf-8", "surrogateescape").hex()


def cmd_tree(layers):
    state, _, _, _, _, _ = merge(layers)
    for p in sorted(state, key=lambda s: s.encode("utf-8", "surrogateescape")):
        n = state[p]
        print("node %s %04o %d %d %d layer=%d content=%s link=%s phex=%s" %
              (n.type, n.mode, n.uid, n.gid, n.size, n.layer, n.content,
               hx(n.link) if n.link else "-", hx(p)))


def is_cap(name):
    return name == "security.capability"


def cmd_audit(layers):
    state, deleted, shadowed, nowhere, all_entries, dangling = merge(layers)
    out = []
    for i, entries in enumerate(all_entries):
        for n, m, content in entries:
            path, esc, why = clean(m.name)
            kind, _ = whiteout(path)
            typ = TYPE.get(m.type, "?")
            if esc:
                out.append("audit escape layer=%d why=%s phex=%s" %
                           (i, why.replace(" ", "_"), hx(m.name)))
            if kind:
                continue
            if m.mode & 0o4000:
                out.append("audit setuid layer=%d mode=%04o phex=%s" % (i, m.mode, hx(path)))
            if m.mode & 0o2000:
                out.append("audit setgid layer=%d mode=%04o phex=%s" % (i, m.mode, hx(path)))
            if typ != "symlink" and m.mode & 0o2:
                if typ == "dir" and not (m.mode & 0o1000):
                    out.append("audit world-writable-dir-nosticky layer=%d mode=%04o phex=%s" % (i, m.mode, hx(path)))
                elif typ != "dir":
                    out.append("audit world-writable layer=%d mode=%04o phex=%s" % (i, m.mode, hx(path)))
            for k, v in sorted(m.pax_headers.items()):
                if not k.startswith("SCHILY.xattr."):
                    continue
                name = k[len("SCHILY.xattr."):]
                if is_cap(name):
                    raw = v.encode("utf-8", "surrogateescape")
                    out.append("audit capability layer=%d value=%s phex=%s" % (i, raw.hex(), hx(path)))
            if typ in ("chardev", "blockdev"):
                out.append("audit devnode layer=%d type=%s dev=%d,%d phex=%s" %
                           (i, typ, m.devmajor, m.devminor, hx(path)))
            if typ == "hardlink":
                _lp, lesc, _lw = clean(m.linkname)
                if lesc:
                    out.append("audit linkescape layer=%d target=%s phex=%s" %
                               (i, hx(m.linkname), hx(path)))
    for p, held, whl, node in deleted:
        if node.type != "file":
            continue
        out.append("audit deleted layer=%d by=%d size=%d content=%s phex=%s" %
                   (held, whl, node.size, node.content, hx(p)))
    for p, oldl, newl, old, new in shadowed:
        if old.type != "file":
            continue
        out.append("audit shadowed layer=%d by=%d size=%d content=%s phex=%s" %
                   (oldl, newl, old.size, old.content, hx(p)))
    for s in sorted(out):
        print(s)


def cmd_census(layers):
    state, deleted, shadowed, nowhere, all_entries, dangling = merge(layers)
    c = {k: 0 for k in (
        "layers", "entries", "whiteout-file", "whiteout-opaque", "hardlink",
        "symlink", "chardev", "dir", "file", "setuid", "setgid", "sticky",
        "world-writable", "xattr", "capability", "escape", "longname",
        "dup-in-layer", "path-in-many-layers", "deleted", "shadowed",
        "whiteout-hit-nothing", "merged-paths", "hardlink-dangling")}
    c["layers"] = len(all_entries)
    seen_layers = {}
    for i, entries in enumerate(all_entries):
        seen = set()
        for n, m, content in entries:
            c["entries"] += 1
            path, esc, _ = clean(m.name)
            kind, _ = whiteout(path)
            if kind == "file":
                c["whiteout-file"] += 1
            elif kind == "opaque":
                c["whiteout-opaque"] += 1
            typ = TYPE.get(m.type, "?")
            if typ in c:
                c[typ] += 1
            if m.mode & 0o4000:
                c["setuid"] += 1
            if m.mode & 0o2000:
                c["setgid"] += 1
            if m.mode & 0o1000:
                c["sticky"] += 1
            if typ != "symlink" and m.mode & 0o2:
                c["world-writable"] += 1
            xs = [k for k in m.pax_headers if k.startswith("SCHILY.xattr.")]
            if xs:
                c["xattr"] += 1
            if any(k.endswith(".security.capability") for k in xs):
                c["capability"] += 1
            if esc:
                c["escape"] += 1
            if len(m.name.encode("utf-8", "surrogateescape")) > 100:
                c["longname"] += 1
            if path in seen:
                c["dup-in-layer"] += 1
            seen.add(path)
            if not kind and path:
                seen_layers.setdefault(path, set()).add(i)
    c["path-in-many-layers"] = sum(1 for v in seen_layers.values() if len(v) > 1)
    c["deleted"] = len(deleted)
    c["shadowed"] = len(shadowed)
    c["whiteout-hit-nothing"] = len(nowhere)
    c["merged-paths"] = len(state)
    c["hardlink-dangling"] = len(dangling)
    for k in sorted(c):
        print("%s %d" % (k, c[k]))


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    {"tree": cmd_tree, "audit": cmd_audit, "census": cmd_census}[argv[1]](argv[2:])


if __name__ == "__main__":
    main(sys.argv)
