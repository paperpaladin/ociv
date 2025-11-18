#!/usr/bin/env python3
"""Plant a deliberate defect in ociv, rebuild, and require the suite to go red.

A test that has never been watched to fail is not evidence. Each mutant
below is a single literal edit to one line of Go, chosen to break exactly
one claim the suite makes. The run reports, for each one:

    CAUGHT   name   N passed, M failed   first failing assertion
    SURVIVED name   N passed, 0 failed

A survivor is either a hole in the suite or a mutant that is genuinely
equivalent on this corpus, and the two are not the same thing. Both are
printed and the README records which is which, with the argument.

Two traps this harness is built to avoid.

A mutation that does not apply. A sed that matches nothing produces an
unmodified binary, a green suite, and a line saying SURVIVED. Every
replacement here is a literal string and the count is asserted to be
exactly one, so a mutant whose target has been edited away fails loudly
instead of lying.

A mutation that does not compile. That is not a survivor either; it is a
mutant that was never run. It is reported as BUILDFAIL and counted apart.

    mutate.py            run them all
    mutate.py NAME...    run only these
    mutate.py --list     print the table

Standard library only.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, file, old, new, what it is meant to break)
MUTANTS = [
    # --- digest.go: the grammar -------------------------------------------
    ("digest-uppercase", "digest.go",
     'if !((c >= \'0\' && c <= \'9\') || (c >= \'a\' && c <= \'f\')) {',
     'if !((c >= \'0\' && c <= \'9\') || (c >= \'a\' && c <= \'f\') || (c >= \'A\' && c <= \'F\')) {',
     "accept uppercase hex, which makes one blob have two spellings"),
    ("digest-length", "digest.go",
     'if len(enc) != n {',
     'if false {',
     "stop checking that sha256 has 64 characters"),
    ("digest-leading-sep", "digest.go",
     '\t\t\tif prevSep {\n\t\t\t\treturn Digest{}, fmt.Errorf("digest %q: algorithm separator',
     '\t\t\tif false {\n\t\t\t\treturn Digest{}, fmt.Errorf("digest %q: algorithm separator',
     "allow a separator where the grammar requires a component"),

    # --- image.go: the structural checks ----------------------------------
    ("layout-version", "image.go",
     '} else if *lay.V != "1.0.0" {',
     '} else if false {',
     "stop requiring imageLayoutVersion 1.0.0"),
    ("index-schema", "image.go",
     '} else if *im.Index.SchemaVersion != 2 {',
     '} else if false {',
     "stop requiring schemaVersion 2 in index.json"),
    ("blob-size", "image.go",
     'if d.Size != nil && *d.Size != int64(len(b)) {',
     'if false {',
     "stop comparing a descriptor's stated size against the blob"),
    ("blob-digest", "image.go",
     'if got := SHA256Hex(b); got != dg.S {',
     'if got := SHA256Hex(b); false {',
     "stop verifying the config and manifest blob digests"),
    ("rootfs-type", "image.go",
     'if im.Config.RootFS.Type != "layers" {\n\t\tim.note("V017", "config.rootfs", "type is %q, spec requires \\"layers\\"", im.Config.RootFS.Type)\n\t}\n\tif n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {',
     'if false {\n\t\tim.note("V017", "config.rootfs", "type is %q, spec requires \\"layers\\"", im.Config.RootFS.Type)\n\t}\n\tif n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {',
     "stop requiring rootfs.type to be layers"),
    ("diffid-count", "image.go",
     'if n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {',
     'if n := len(im.Config.RootFS.DiffIDs); false {',
     "stop checking there is one diff_id per layer"),

    # --- layer.go: the tar reader and the path rules ----------------------
    ("path-dotdot", "layer.go",
     '\t\tcase "..":\n\t\t\tif len(out) == 0 {',
     '\t\tcase "..":\n\t\t\tif false {',
     "stop treating a leading .. as an escape"),
    ("path-absolute", "layer.go",
     '\tif strings.HasPrefix(s, "/") {\n\t\tescapes = true',
     '\tif strings.HasPrefix(s, "/") {\n\t\tescapes = false',
     "stop treating an absolute member name as an escape"),
    ("whiteout-order", "layer.go",
     '\tif base == whOpaque {\n\t\treturn "opaque", dir\n\t}\n\tif strings.HasPrefix(base, whPrefix) {',
     '\tif false {\n\t\treturn "opaque", dir\n\t}\n\tif strings.HasPrefix(base, whPrefix) {',
     "test the .wh. prefix before the opaque marker, so an opaque directory deletes a file named .wh..wh..opq instead"),
    ("whiteout-dir", "layer.go",
     '\t\tt := strings.TrimPrefix(base, whPrefix)\n\t\tif dir != "" {\n\t\t\tt = dir + "/" + t\n\t\t}',
     '\t\tt := strings.TrimPrefix(base, whPrefix)\n\t\tif false {\n\t\t\tt = dir + "/" + t\n\t\t}',
     "resolve a whiteout target without its directory, so etc/.wh.secrets.txt deletes secrets.txt at the root"),
    ("mode-mask", "layer.go",
     'Name: h.Name, Type: h.Typeflag, Mode: h.Mode,',
     'Name: h.Name, Type: h.Typeflag, Mode: h.Mode & 0777,',
     "drop the setuid, setgid and sticky bits while reading the header"),
    ("xattr-skip", "layer.go",
     'if strings.HasPrefix(k, "SCHILY.xattr.") {',
     'if false {',
     "stop reading extended attributes out of pax records"),
    ("diffid-undrained", "layer.go",
     '\tif _, err := io.Copy(io.Discard, r); err != nil {\n\t\treturn out, "", err\n\t}',
     '\tif false {\n\t\treturn out, "", nil\n\t}',
     "compute the diff_id without draining the trailing zero blocks"),

    # --- merge.go: the whiteout semantics ---------------------------------
    ("merge-onepass", "merge.go",
     '\t\t// Pass two: this layer\'s real entries, in tar order, so a path',
     '\t\tif false { _ = ents }\n\t\t// Pass two: this layer\'s real entries, in tar order, so a path',
     "no-op control: proves the harness is not reporting CAUGHT for an edit that changes nothing"),
    ("descend-prefix", "merge.go",
     '\tpre := d + "/"\n\tif d == "" {',
     '\tpre := d\n\tif d == "" {',
     "drop the slash from the descendant prefix, so whiteouting var/log also removes var/logrotate"),
    ("opaque-removes-dir", "merge.go",
     'if p != d && strings.HasPrefix(p, pre) {',
     'if strings.HasPrefix(p, pre) {',
     "let an opaque marker remove the directory it is in, not only its contents"),
    ("whiteout-no-subtree", "merge.go",
     '\t\t\t\tsub := descendants(m.State, e.WhTarget)\n\t\t\t\tvictims = append(victims, sub...)',
     '\t\t\t\tsub := descendants(m.State, e.WhTarget)\n\t\t\t\t_ = sub',
     "whiteout a directory and leave its children behind as orphans"),
    ("shadow-content-only", "merge.go",
     'if old.ContentSHA != e.ContentSHA || old.Mode != e.Mode {',
     'if old.ContentSHA != e.ContentSHA {',
     "miss a layer that republishes the same bytes with different permissions"),
    ("dup-first-wins", "merge.go",
     '\t\t\tm.State[e.Path] = e\n\t\t}\n\t}\n\treturn m, nil',
     '\t\t\tif _, dup := m.State[e.Path]; !dup || old2(m, e) {\n\t\t\t\tm.State[e.Path] = e\n\t\t\t}\n\t\t}\n\t}\n\treturn m, nil',
     "let the FIRST of two entries with the same name in one layer win, where extraction takes the last"),

    # --- audit.go: the findings -------------------------------------------
    ("setgid-bit", "audit.go",
     'if e.Mode&02000 != 0 {\n\t\t\t\tadd("setgid',
     'if e.Mode&04000 != 0 {\n\t\t\t\tadd("setgid',
     "report the setuid bit as setgid"),
    ("ww-symlink", "audit.go",
     'if t != "symlink" && e.Mode&02 != 0 {',
     'if e.Mode&02 != 0 {',
     "report world-writable symlinks, whose mode bits Linux does not honour"),
    ("ww-sticky", "audit.go",
     'if e.Mode&01000 == 0 {\n\t\t\t\t\t\tadd("world-writable-dir-nosticky',
     'if true {\n\t\t\t\t\t\tadd("world-writable-dir-nosticky',
     "report /tmp at 1777 as a finding"),
    ("deleted-layers-swapped", "audit.go",
     'add("deleted layer=%d by=%d size=%d content=%s phex=%s",\n\t\t\tr.Held, r.By,',
     'add("deleted layer=%d by=%d size=%d content=%s phex=%s",\n\t\t\tr.By, r.Held,',
     "name the layer that deleted the file as the layer that still holds it"),
    ("cap-any-xattr", "audit.go",
     'if v, ok := e.Xattrs["security.capability"]; ok {',
     'if v, ok := anyXattr(e.Xattrs); ok {',
     "report every extended attribute as a file capability"),
    ("deleted-dirs-too", "audit.go",
     'for _, r := range m.Deleted {\n\t\tif typeName(r.E.Type) != "file" {',
     'for _, r := range m.Deleted {\n\t\tif false {',
     "report deleted directories as leaked file contents"),

    # --- cmd.go: the rendering --------------------------------------------
    ("mode-print", "cmd.go",
     'fmt.Printf("entry %d %d %s %04o',
     'fmt.Printf("entry %d %d %s %03o',
     "print a mode without room for the setuid digit"),
    ("no-quote", "cmd.go",
     'func q(s string) string { return strconv.Quote(s) }',
     'func q(s string) string { return "\\"" + s + "\\"" }',
     "stop quoting a path, so a filename with a newline in it becomes two lines"),
]

# Helpers some mutants need in order to compile. Appended to the mutated
# file, never present in the real source.
HELPERS = {
    "dup-first-wins": ("merge.go", "\nfunc old2(m *Merged, e Entry) bool { return false }\n"),
    "cap-any-xattr": ("audit.go", "\nfunc anyXattr(x map[string]string) (string, bool) {\n\tfor _, v := range x {\n\t\treturn v, true\n\t}\n\treturn \"\", false\n}\n"),
}


def apply(work, name):
    for n, f, old, new, _why in MUTANTS:
        if n != name:
            continue
        p = os.path.join(work, f)
        s = open(p).read()
        c = s.count(old)
        if c != 1:
            raise SystemExit(
                "mutate: %s: its target appears %d times in %s, not once.\n"
                "A mutation that does not apply produces an unmodified binary "
                "and reports SURVIVED." % (name, c, f))
        open(p, "w").write(s.replace(old, new))
        if name in HELPERS:
            hf, text = HELPERS[name]
            with open(os.path.join(work, hf), "a") as fh:
                fh.write(text)
        return
    raise SystemExit("mutate: no mutant called %r" % name)


def run_one(name, keep_log=None):
    work = tempfile.mkdtemp(prefix="ocivmut.")
    try:
        for f in os.listdir(ROOT):
            if f.endswith(".go") or f in ("go.mod", "Makefile"):
                shutil.copy(os.path.join(ROOT, f), work)
        shutil.copytree(os.path.join(ROOT, "t"), os.path.join(work, "t"))
        apply(work, name)
        env = dict(os.environ, GOPROXY="off", GOFLAGS="", GOCACHE=os.environ.get(
            "GOCACHE", os.path.expanduser("~/.cache/go-build")))
        b = subprocess.run(["go", "build", "-o", "ociv", "."], cwd=work,
                           capture_output=True, text=True, env=env)
        if b.returncode != 0:
            return "BUILDFAIL", 0, 0, b.stderr.strip().splitlines()[:2]
        r = subprocess.run(["./t/run.sh"], cwd=work, capture_output=True, text=True)
        if keep_log:
            open(keep_log, "w").write(r.stdout + r.stderr)
        m = re.search(r"^(\d+) passed, (\d+) failed$", r.stdout, re.M)
        if not m:
            return "NOSUMMARY", 0, 0, (r.stdout + r.stderr).splitlines()[-3:]
        p, f = int(m.group(1)), int(m.group(2))
        firsts = [l[5:] for l in r.stdout.splitlines() if l.startswith("FAIL ")]
        if f == 0:
            return "SURVIVED", p, f, []
        return "CAUGHT", p, f, firsts[:3]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv):
    if "--list" in argv:
        for n, f, _o, _nw, why in MUTANTS:
            print("%-24s %-10s %s" % (n, f, why))
        return 0
    names = [a for a in argv[1:] if not a.startswith("-")]
    if not names:
        names = [m[0] for m in MUTANTS]
    caught = survived = broken = 0
    for n in names:
        kind, p, f, detail = run_one(n)
        if kind == "CAUGHT":
            caught += 1
            print("CAUGHT   %-24s %3d passed %2d failed   %s" % (n, p, f, detail[0]))
            for d in detail[1:]:
                print("%41s %s" % ("", d))
        elif kind == "SURVIVED":
            survived += 1
            why = next(w for nm, _f, _o, _nw, w in MUTANTS if nm == n)
            print("SURVIVED %-24s %3d passed  0 failed   (%s)" % (n, p, why))
        else:
            broken += 1
            print("%-8s %-24s %s" % (kind, n, " / ".join(detail)))
    print()
    print("mutants: %d caught, %d survived, %d did not build or did not report" %
          (caught, survived, broken))
    return 1 if survived or broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
