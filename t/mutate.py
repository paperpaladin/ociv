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
    mutate.py --check    every target still matches its source, in a second

Standard library only.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, file, [(old, new), ...], what it is meant to break)
#
# A mutant may need more than one edit: making the merge single-pass means
# switching one loop off and giving the other the deleted behaviour, and
# doing only half of that is a different mutant from the one described.
MUTANTS = [
    ('digest-uppercase', 'digest.go',
     [("if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {",
       "if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {")],
     'accept uppercase hex, which makes one blob have two spellings'),
    ('digest-length', 'digest.go',
     [('if len(enc) != n {',
       'if false {')],
     'stop checking that sha256 has 64 characters'),
    ('digest-leading-sep', 'digest.go',
     [('\t\t\tif prevSep {\n\t\t\t\treturn Digest{}, fmt.Errorf("digest %q: algorithm separator',
       '\t\t\tif false {\n\t\t\t\treturn Digest{}, fmt.Errorf("digest %q: algorithm separator')],
     'allow a separator where the grammar requires a component'),
    ('nested-no-traverse', 'image.go',
     [('\t\tif im.nested {', '\t\tif true {')],
     'refuse every nested index instead of following one level, which is what ociv did before and which refuses every multi-arch image a registry serves'),
    ('nested-keeps-tag', 'image.go',
     [('\t\touter := im.Selector\n\t\tim.Selector = ""',
       '\t\touter := im.Selector')],
     'carry the tag down into the nested index, where the entries have platforms and no ref.name, so nothing matches and a valid image reports as broken'),
    ('nested-depth-unbounded', 'image.go',
     [('\t\tim.nested = true\n\t\tim.NestedIndexDigest = im.ManifestDigest',
       '\t\tim.NestedIndexDigest = im.ManifestDigest')],
     'follow nesting to any depth, so the one-level claim becomes untrue and nothing says so'),
    ('platform-filter-always', 'image.go',
     [('\t\tif anyPlatform && wantPlatform != "" && d.Platform.String() != wantPlatform {',
       '\t\t_ = anyPlatform\n\t\tif wantPlatform != "" && d.Platform.String() != wantPlatform {')],
     "apply the platform filter at a level whose entries carry no platform, which removes index.json's only entry and reports a nested image as not holding the platform"),
    ('platform-ignored', 'image.go',
     [('\t\tif anyPlatform && wantPlatform != "" && d.Platform.String() != wantPlatform {',
       '\t\t_ = anyPlatform\n\t\tif false && wantPlatform != "" && d.Platform.String() != wantPlatform {')],
     'ignore --platform and take the first index entry, which is what skopeo does with a flat index and what verifies the wrong architecture'),
    ('args-from-os', 'main.go',
     [('\tcmdArgs = parsePlatform(os.Args[1:])\n\targs := cmdArgs',
       '\tcmdArgs = os.Args[1:]\n\targs := parsePlatform(os.Args[1:])')],
     'hand run() the raw argument list rather than the one parsePlatform returned, which is the bug that made --platform work only when it came after the command'),
    ('platform-variant-dropped', 'image.go',
     [('\ts := p.OS + "/" + p.Architecture\n\tif p.Variant != "" {',
       '\ts := p.OS + "/" + p.Architecture\n\tif false {')],
     'leave the variant off the platform string, so linux/arm/v7 and a hypothetical linux/arm/v6 become one platform'),
    ('layout-version', 'image.go',
     [('} else if *lay.V != "1.0.0" {',
       '} else if false {')],
     'stop requiring imageLayoutVersion 1.0.0'),
    ('index-schema', 'image.go',
     [('} else if *im.Index.SchemaVersion != 2 {',
       '} else if false {')],
     'stop requiring schemaVersion 2 in index.json'),
    ('blob-size', 'image.go',
     [('if d.Size != nil && *d.Size != int64(len(b)) {',
       'if false {')],
     "stop comparing a descriptor's stated size against the blob"),
    ('blob-digest', 'image.go',
     [('if got := SHA256Hex(b); got != dg.S {',
       'if got := SHA256Hex(b); false {')],
     'stop verifying the config and manifest blob digests'),
    ('rootfs-type', 'image.go',
     [('if im.Config.RootFS.Type != "layers" {\n\t\tim.note("V017", "config.rootfs", "type is %q, spec requires \\"layers\\"", im.Config.RootFS.Type)\n\t}\n\tif n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {',
       'if false {\n\t\tim.note("V017", "config.rootfs", "type is %q, spec requires \\"layers\\"", im.Config.RootFS.Type)\n\t}\n\tif n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {')],
     'stop requiring rootfs.type to be layers'),
    ('diffid-count', 'image.go',
     [('if n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {',
       'if n := len(im.Config.RootFS.DiffIDs); false {')],
     'stop checking there is one diff_id per layer'),
    ('path-dotdot', 'layer.go',
     [('\t\tcase "..":\n\t\t\tif len(out) == 0 {',
       '\t\tcase "..":\n\t\t\tif false {')],
     'stop treating a leading .. as an escape'),
    ('path-absolute', 'layer.go',
     [('\tif strings.HasPrefix(s, "/") {\n\t\tescapes = true',
       '\tif strings.HasPrefix(s, "/") {\n\t\tescapes = false')],
     'stop treating an absolute member name as an escape'),
    ('above-root-ignored', 'merge.go',
     [('\t\t\tif aboveRoot(e.Name) {', '\t\t\tif false && aboveRoot(e.Name) {')],
     'put a member whose name climbs above the root into the merged tree, at the path the dot-dot resolves to, which is a path GNU tar refuses to write'),
    ('above-root-empty-counts', 'layer.go',
     [('\t\tcase "", ".":\n\t\tcase "..":', '\t\tcase ".":\n\t\tcase "..":')],
     'count an empty component as a directory, so a leading slash gives the climb test one level of credit and /../etc/x reads as inside the root'),
    ('whiteout-order', 'layer.go',
     [('\tif base == whOpaque {\n\t\treturn "opaque", dir\n\t}\n\tif strings.HasPrefix(base, whPrefix) {',
       '\tif false {\n\t\treturn "opaque", dir\n\t}\n\tif strings.HasPrefix(base, whPrefix) {')],
     'test the .wh. prefix before the opaque marker, so an opaque directory deletes a file named .wh..wh..opq instead'),
    ('whiteout-dir', 'layer.go',
     [('\t\tt := strings.TrimPrefix(base, whPrefix)\n\t\tif dir != "" {\n\t\t\tt = dir + "/" + t\n\t\t}',
       '\t\tt := strings.TrimPrefix(base, whPrefix)\n\t\tif false {\n\t\t\tt = dir + "/" + t\n\t\t}')],
     'resolve a whiteout target without its directory, so etc/.wh.secrets.txt deletes secrets.txt at the root'),
    ('mode-mask', 'layer.go',
     [('Name: h.Name, Type: h.Typeflag, Mode: h.Mode,',
       'Name: h.Name, Type: h.Typeflag, Mode: h.Mode & 0777,')],
     'drop the setuid, setgid and sticky bits while reading the header'),
    ('xattr-skip', 'layer.go',
     [('if strings.HasPrefix(k, "SCHILY.xattr.") {',
       'if false {')],
     'stop reading extended attributes out of pax records'),
    ('entry-offset-zero', 'layer.go',
     [('Layer: i, Index: n, Offset: cr.n,',
       'Layer: i, Index: n, Offset: 0,')],
     'report every member as starting at offset 0'),
    ('entry-offset-header', 'layer.go',
     [('Layer: i, Index: n, Offset: cr.n,',
       'Layer: i, Index: n, Offset: cr.n - 512,')],
     "point at the member's header block instead of its data, which is one block out and the mistake a hand-written tar reader actually makes"),
    ('diffid-undrained', 'layer.go',
     [('\tif _, err := io.Copy(io.Discard, r); err != nil {\n\t\treturn out, "", err\n\t}',
       '\tif false {\n\t\treturn out, "", nil\n\t}')],
     'compute the diff_id without draining the trailing zero blocks'),
    ('noop-control', 'merge.go',
     [("\t\t// Pass two: this layer's real entries, in tar order, so a path",
       "\t\tif false {\n\t\t\t_ = ents\n\t\t}\n\t\t// Pass two: this layer's real entries, in tar order, so a path")],
     'EQUIVALENT BY CONSTRUCTION: a dead branch. It must survive. If it is ever reported as CAUGHT the harness is reporting failures that are not caused by the mutation'),
    ('plant-panic', 'layer.go',
     [('\t\t\treturn out, "", fmt.Errorf("layer %d entry %d: %w", i, n, err)',
       '\t\t\tpanic(fmt.Sprintf("layer %d entry %d: %v", i, n, err))')],
     'panic instead of returning an error on a malformed tar. Reachable only from a corrupted image, so ONLY the truncation and corruption sweep can see it: it is the end-to-end check that a real panic inside ociv becomes exit 86 and is reported'),
    ('merge-onepass', 'merge.go',
     [("\t\tfor _, e := range ents {\n\t\t\tif e.Whiteout == \"\" {",
       "\t\tfor _, e := range []Entry(nil) {\n\t\t\tif e.Whiteout == \"\" {"),
      ("\t\t\tif e.Whiteout != \"\" || e.Path == \"\" {\n\t\t\t\tcontinue\n\t\t\t}",
       "\t\t\tif e.Whiteout != \"\" {\n\t\t\t\tonepass(m, e, i)\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tif e.Path == \"\" {\n\t\t\t\tcontinue\n\t\t\t}")],
     'apply whiteouts in one pass in tar order, so a whiteout deletes a file of the same name in its OWN layer'),
    ('symparent-literal', 'merge.go',
     [('\t\t\tres, via, abs, esc := resolveParents(m.State, e.Path)',
       '\t\t\tres, via, abs, esc := e.Path, false, false, false\n\t\t\t_ = resolveParents')],
     'take a member name as the literal path, ignoring a symlinked ancestor, which is what tar does not do'),
    ('symparent-whiteout', 'merge.go',
     [('\t\t\ttarget, _, _, tesc := resolveParents(m.State, e.WhTarget)',
       '\t\t\ttarget, tesc := e.WhTarget, false\n\t\t\t_ = resolveParents')],
     'resolve a whiteout target literally, so a marker under a symlinked directory deletes nothing'),
    ('symlink-abs-escape', 'merge.go',
     [('\t\t\t\tt = strings.TrimLeft(t, "/")',
       '')],
     'treat an absolute symlink target as an escape, which is the defect this corpus was built after finding'),
    ('symlink-chain-stops', 'merge.go',
     [('\t\tfor hops := 0; hops < 40; hops++ {',
       '\t\tfor hops := 0; hops < 1; hops++ {')],
     'follow one symlink and stop, so a chain of two resolves half way'),
    ('descend-prefix', 'merge.go',
     [('\tpre := d + "/"\n\tif d == "" {',
       '\tpre := d\n\tif d == "" {')],
     'drop the slash from the descendant prefix, so whiteouting var/log also removes var/logrotate'),
    ('opaque-removes-dir', 'merge.go',
     [('\t\t\tcase "opaque":\n\t\t\t\tvictims := descendants(m.State, e.WhTarget)',
       '\t\t\tcase "opaque":\n\t\t\t\tvictims := append(descendants(m.State, e.WhTarget), e.WhTarget)')],
     'let an opaque marker remove the directory it is in, not only its contents'),
    ('whiteout-no-subtree', 'merge.go',
     [('\t\t\t\tsub := descendants(m.State, e.WhTarget)\n\t\t\t\tvictims = append(victims, sub...)',
       '\t\t\t\tsub := descendants(m.State, e.WhTarget)\n\t\t\t\t_ = sub')],
     'whiteout a directory and leave its children behind as orphans'),
    ('shadow-content-only', 'merge.go',
     [('if old.ContentSHA != e.ContentSHA || old.Mode != e.Mode {',
       'if old.ContentSHA != e.ContentSHA {')],
     'miss a layer that republishes the same bytes with different permissions'),
    ('dup-first-wins', 'merge.go',
     [('\t\t\tm.State[e.Path] = e\n\t\t}\n\t}\n\treturn m, nil',
       '\t\t\tif _, dup := m.State[e.Path]; !dup || old2(m, e) {\n\t\t\t\tm.State[e.Path] = e\n\t\t\t}\n\t\t}\n\t}\n\treturn m, nil')],
     'let the FIRST of two entries with the same name in one layer win, where extraction takes the last'),
    ('setgid-bit', 'audit.go',
     [('if e.Mode&02000 != 0 {\n\t\t\t\tadd("setgid',
       'if e.Mode&04000 != 0 {\n\t\t\t\tadd("setgid')],
     'report the setuid bit as setgid'),
    ('ww-symlink', 'audit.go',
     [('if t != "symlink" && e.Mode&02 != 0 {\n\t\t\t\tif t == "dir" {',
       'if e.Mode&02 != 0 {\n\t\t\t\tif t == "dir" {')],
     'report world-writable symlinks, whose mode bits Linux does not honour'),
    ('ww-sticky', 'audit.go',
     [('if e.Mode&01000 == 0 {\n\t\t\t\t\t\tadd("world-writable-dir-nosticky',
       'if true {\n\t\t\t\t\t\tadd("world-writable-dir-nosticky')],
     'report /tmp at 1777 as a finding'),
    ('shadow-delta-always-content', 'audit.go',
     [('\t\tcase s.Old.Mode != s.New.Mode:\n\t\t\tdelta = "mode"',
       '\t\tcase s.Old.Mode != s.New.Mode:\n\t\t\tdelta = "content"')],
     'call a chmod of unchanged bytes a content change, so every layer rebuild reads as a second copy of the document'),
    ('shadow-new-is-old', 'audit.go',
     [('s.Old.ContentSHA, s.New.ContentSHA, s.New.Mode, hx(s.Path))',
       's.Old.ContentSHA, s.Old.ContentSHA, s.New.Mode, hx(s.Path))')],
     'print the old digest twice, so the two versions always look identical to anyone comparing them'),
    ('deleted-layers-swapped', 'audit.go',
     [('\t\t\tr.Held, r.By, m.blob(r.Held), m.comp(r.Held),',
       '\t\t\tr.By, r.Held, m.blob(r.Held), m.comp(r.Held),')],
     'name the layer that deleted the file as the layer that still holds it'),
    ('leak-offset-zero', 'audit.go',
     [('\t\t\tr.E.Size, r.E.Offset, r.E.ContentSHA, hx(r.Path))',
       '\t\t\tr.E.Size, 0, r.E.ContentSHA, hx(r.Path))')],
     "report a leaked file's bytes as starting at offset 0, so a reader following the report pulls out the first tar header instead"),
    ('leak-blob-is-diffid', 'audit.go',
     [('\treturn m.LayerBlob[i]', '\treturn m.DiffIDs[i]')],
     "name the leaked bytes' blob by its diff_id instead of its descriptor digest, which is the same number on an uncompressed layer and the wrong file on a gzip one"),
    ('leak-comp-always-none', 'audit.go',
     [('\treturn m.LayerComp[i]', '\treturn "none"')],
     'say every layer is uncompressed, so a reader following off= into a gzip blob reads deflate output'),
    ('leak-summary-deleted-only', 'audit.go',
     [('\t\tk := at(s.OldL)\n\t\tk.shadow++\n\t\tk.bytes += s.Old.Size',
       '\t\tk := at(s.OldL)\n\t\t_ = k')],
     'leave overwritten files out of the per-layer leak count, so a layer that republishes a credential under the same name reports clean'),
    ('cap-any-xattr', 'audit.go',
     [('if v, ok := e.Xattrs["security.capability"]; ok {',
       'if v, ok := anyXattr(e.Xattrs); ok {')],
     'report every extended attribute as a file capability'),
    ('deleted-dirs-too', 'audit.go',
     [('for _, r := range m.Deleted {\n\t\tif typeName(r.E.Type) != "file" {\n\t\t\tcontinue\n\t\t}\n\t\tadd("deleted',
       'for _, r := range m.Deleted {\n\t\tif false {\n\t\t\tcontinue\n\t\t}\n\t\tadd("deleted')],
     'report deleted directories as leaked file contents'),
    ('mode-print', 'cmd.go',
     [('q(e.Name), q(e.Linkname), strings.Join(extra, " "))',
       'q(e.Name), q(e.Linkname), strings.Join(extra, " "))\n\t_ = e.Mode & 0777')],
     'EQUIVALENT BY CONSTRUCTION: appends a dead expression. Replaced the original %03o mutant, which was equivalent for a reason worth writing down: in Go a width in a verb is a MINIMUM, so %03o renders 04755 as 4755 exactly as %04o does'),
    ('mode-print-mask', 'cmd.go',
     [('e.Layer, e.Index, typeName(e.Type), e.Mode, e.UID, e.GID, e.Size,',
       'e.Layer, e.Index, typeName(e.Type), e.Mode&0777, e.UID, e.GID, e.Size,')],
     'drop the setuid digit when rendering an entry, with the header read correctly'),
    ('uidgid-swap', 'cmd.go',
     [('e.Layer, e.Index, typeName(e.Type), e.Mode, e.UID, e.GID, e.Size,',
       'e.Layer, e.Index, typeName(e.Type), e.Mode, e.GID, e.UID, e.Size,')],
     'swap uid and gid when rendering an entry'),
    ('cat-first-wins', 'cmd.go',
     [('\t\tfound = b\n\t}', '\t\tif found == nil {\n\t\t\tfound = b\n\t\t}\n\t}')],
     'let the FIRST member with a duplicated path win in cat, where extraction leaves the last'),
    ('cat-name-only', 'cmd.go',
     [('if p, _, _ := cleanPath(h.Name); p != target && h.Name != target {',
       'if p, _, _ := cleanPath(h.Name); p != target {')],
     'match only the normalised path in cat, so a member whose name leaves the root cannot be fetched at all'),
    ('no-quote', 'cmd.go',
     [('func q(s string) string { return strconv.Quote(s) }',
       'func q(s string) string { _ = strconv.Quote; return "\\"" + s + "\\"" }')],
     'stop quoting a path, so a filename with a newline in it becomes two lines'),
]

# The mutants that are expected to SURVIVE, with the argument for each
# written next to them in the table above. A survivor is not automatically
# a hole, and an equivalent mutant is not automatically fine: both have to
# be named, and the run fails if reality disagrees with this set in either
# direction. A mutant that moves from caught to equivalent without anyone
# editing this line is a test that stopped working.
EQUIVALENT = {"noop-control", "mode-print"}

# The smoke subset, run by "make test". The full sweep takes minutes and so
# would never be part of the gate; three mutants take half a minute and
# answer the only question the gate needs answered, which is whether this
# harness is capable of reporting a failure at all. One must survive and
# two must be caught, so a harness that always says CAUGHT and a harness
# that always says SURVIVED both fail it.
SMOKE = ["noop-control", "whiteout-order", "blob-digest"]

# Helpers some mutants need in order to compile. Appended to the mutated
# file, never present in the real source.
HELPERS = {
    "merge-onepass": ("merge.go", """
func onepass(m *Merged, e Entry, i int) {
	switch e.Whiteout {
	case "opaque":
		for _, p := range descendants(m.State, e.WhTarget) {
			m.Deleted = append(m.Deleted, Removal{Path: p, Held: m.State[p].Layer, By: i, E: m.State[p], Opaque: true})
			delete(m.State, p)
		}
	case "file":
		var v []string
		if _, ok := m.State[e.WhTarget]; ok {
			v = append(v, e.WhTarget)
		}
		v = append(v, descendants(m.State, e.WhTarget)...)
		for _, p := range v {
			m.Deleted = append(m.Deleted, Removal{Path: p, Held: m.State[p].Layer, By: i, E: m.State[p]})
			delete(m.State, p)
		}
	}
}
"""),
    "dup-first-wins": ("merge.go", "\nfunc old2(m *Merged, e Entry) bool { return false }\n"),
    "cap-any-xattr": ("audit.go", "\nfunc anyXattr(x map[string]string) (string, bool) {\n\tfor _, v := range x {\n\t\treturn v, true\n\t}\n\treturn \"\", false\n}\n"),
}


def apply(work, name):
    for n, f, edits, _why in MUTANTS:
        if n != name:
            continue
        p = os.path.join(work, f)
        s = open(p).read()
        for old, new in edits:
            c = s.count(old)
            if c != 1:
                raise SystemExit(
                    "mutate: %s: its target appears %d times in %s, not once.\n"
                    "A mutation that does not apply produces an unmodified binary "
                    "and reports SURVIVED.\ntarget was: %r" % (name, c, f, old[:70]))
            s = s.replace(old, new)
        open(p, "w").write(s)
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
        # A coarse sweep: the suite is rerun once per mutant and a dense
        # one would make this harness unusable. The sweep's own density
        # is a "make test" concern; what matters here is only that the
        # error paths are reached at all, which a coarse stride still
        # does. plant-panic is caught at 1009.
        env = dict(os.environ, GOPROXY="off", GOFLAGS="",
                   OCIV_SWEEP_STRIDE="1009",
                   GOCACHE=os.environ.get(
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


def check():
    """Every mutant's target appears exactly once in the source it names.

    apply() asserts this already, one mutant at a time, in the middle of
    a sweep that rebuilds and reruns the whole suite per mutant. So the
    first stale record stops the run and hides every mutant behind it,
    and the gate never notices because it runs three of them. Four
    records had rotted that way before this existed, each because the
    line it quotes was edited for an unrelated reason. This asks the
    same question about all fifty in about a second, which is cheap
    enough to put in "make test".
    """
    src, bad, edits = {}, [], 0
    for name, f, es, _why in MUTANTS:
        if f not in src:
            src[f] = open(os.path.join(ROOT, f)).read()
        for old, _new in es:
            edits += 1
            c = src[f].count(old)
            if c != 1:
                bad.append((name, f, c, old.strip().splitlines()[0][:60]))
    for name, f, c, snip in bad:
        print("STALE %-24s %s: target appears %d times, not once: %s"
              % (name, f, c, snip))
    missing = EQUIVALENT - {m[0] for m in MUTANTS}
    for name in sorted(missing):
        print("STALE %-24s EQUIVALENT names a mutant that no longer exists" % name)
    if bad or missing:
        print("mutants: %d of %d records no longer apply to the source"
              % (len(bad) + len(missing), len(MUTANTS)))
        return 1
    print("mutants: %d records, %d edits, every target applies"
          % (len(MUTANTS), edits))
    return 0


def main(argv):
    if "--check" in argv:
        return check()
    if "--list" in argv:
        for n, f, _edits, why in MUTANTS:
            print("%-24s %-10s %s" % (n, f, why))
        return 0
    names = [a for a in argv[1:] if not a.startswith("-")]
    if "--smoke" in argv:
        names = SMOKE
    if not names:
        names = [m[0] for m in MUTANTS]
    known = {m[0] for m in MUTANTS}
    stale = EQUIVALENT - known
    if stale:
        print("mutate: EQUIVALENT names a mutant that no longer exists: %s"
              % " ".join(sorted(stale)))
        return 1
    caught = survived = broken = wrong = 0
    for n in names:
        kind, p, f, detail = run_one(n)
        want = "SURVIVED" if n in EQUIVALENT else "CAUGHT"
        mark = "" if kind == want else "   UNEXPECTED (recorded as %s)" % want
        if kind != want and kind in ("CAUGHT", "SURVIVED"):
            wrong += 1
        if kind == "CAUGHT":
            caught += 1
            print("CAUGHT   %-24s %3d passed %2d failed   %s%s" % (n, p, f, detail[0], mark))
            for d in detail[1:]:
                print("%41s %s" % ("", d))
        elif kind == "SURVIVED":
            survived += 1
            why = next(w for nm, _f, _e, w in MUTANTS if nm == n)
            print("SURVIVED %-24s %3d passed  0 failed   (%s)%s" % (n, p, why, mark))
        else:
            broken += 1
            print("%-8s %-24s %s" % (kind, n, " / ".join(detail)))
    print()
    print("mutants: %d caught, %d survived as recorded equivalent, "
          "%d behaved unlike the record, %d did not build or did not report"
          % (caught - wrong if False else caught, survived, wrong, broken))
    return 1 if wrong or broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
