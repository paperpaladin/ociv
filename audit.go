package main

import (
	"archive/tar"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// The security report. Everything here is a fact about a mode bit, an
// extended attribute or a layer boundary; none of it is a judgement about
// whether the fact is dangerous, because that depends on what the image is
// for and ociv does not know.
//
// The finding that justifies the program is "deleted": a path a later
// layer whiteouted, whose bytes are still sitting in an earlier layer's
// blob. "RUN rm /secrets" in a Dockerfile removes the file from the
// merged view and publishes it anyway, and a tool that reports only the
// merged view cannot see it.

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

// blob and comp name the layer a finding is about by the file it lives
// in. "layer 0" is an index into a manifest the reader may not be
// looking at; a digest is the name of a file in blobs/sha256/, which is
// what a reader with the image in front of them can act on. comp is
// there because the offset in the same finding counts bytes in the
// UNCOMPRESSED stream, so for a gzip layer the number does not index
// the blob until it has been inflated.
func (m *Merged) blob(i int) string {
	if i < 0 || i >= len(m.LayerBlob) {
		return "-"
	}
	return m.LayerBlob[i]
}

func (m *Merged) comp(i int) string {
	if i < 0 || i >= len(m.LayerComp) {
		return "-"
	}
	return m.LayerComp[i]
}

// auditLines builds the whole report as sortable strings. Sorted output
// means the Python second implementation's report can be diffed against
// this one line for line instead of compared as a bag, which is a
// stronger comparison and a much shorter failure message.
func auditLines(m *Merged) []string {
	var out []string
	add := func(format string, a ...any) {
		out = append(out, fmt.Sprintf("audit "+format, a...))
	}
	for i, ents := range m.Entries {
		for _, e := range ents {
			if e.Escapes {
				add("escape layer=%d why=%s phex=%s", i,
					strings.ReplaceAll(e.EscapeWhy, " ", "_"), hx(e.Name))
			}
			if e.Whiteout != "" {
				continue
			}
			t := typeName(e.Type)
			if e.Mode&04000 != 0 {
				add("setuid layer=%d mode=%04o phex=%s", i, e.Mode, hx(e.Path))
			}
			if e.Mode&02000 != 0 {
				add("setgid layer=%d mode=%04o phex=%s", i, e.Mode, hx(e.Path))
			}
			// A symlink's mode bits are not honoured by Linux, so a
			// world-writable symlink is noise and reporting it would
			// bury the findings that matter. A world-writable
			// directory is only a finding when the sticky bit is
			// absent: /tmp is 1777 everywhere and is not a defect.
			if t != "symlink" && e.Mode&02 != 0 {
				if t == "dir" {
					if e.Mode&01000 == 0 {
						add("world-writable-dir-nosticky layer=%d mode=%04o phex=%s", i, e.Mode, hx(e.Path))
					}
				} else {
					add("world-writable layer=%d mode=%04o phex=%s", i, e.Mode, hx(e.Path))
				}
			}
			if v, ok := e.Xattrs["security.capability"]; ok {
				add("capability layer=%d value=%s phex=%s", i, hx(v), hx(e.Path))
			}
			if e.Type == tar.TypeChar || e.Type == tar.TypeBlock {
				add("devnode layer=%d type=%s dev=%d,%d phex=%s", i, t, e.Devmajor, e.Devminor, hx(e.Path))
			}
			if e.Type == tar.TypeLink {
				if _, esc, _ := cleanPath(e.Linkname); esc {
					add("linkescape layer=%d target=%s phex=%s", i, hx(e.Linkname), hx(e.Path))
				}
			}
		}
	}
	// The headline finding. Only regular files: a deleted directory
	// leaks nothing by itself, and its deleted children are each
	// reported in their own right.
	for _, r := range m.Deleted {
		if typeName(r.E.Type) != "file" {
			continue
		}
		add("deleted layer=%d by=%d blob=%s comp=%s size=%d off=%d content=%s phex=%s",
			r.Held, r.By, m.blob(r.Held), m.comp(r.Held),
			r.E.Size, r.E.Offset, r.E.ContentSHA, hx(r.Path))
	}
	// A hard link the image does not carry the target for. Not a
	// judgement: the format allows a layer to link to a path an
	// earlier layer provided, and if no layer did, the image cannot
	// be unpacked as written. GNU tar refuses the link and leaves
	// the path absent, so the merged tree does not have it either,
	// and this line is the only place it is mentioned.
	for _, e := range m.DanglingLinks {
		add("hardlink-dangling layer=%d target=%s phex=%s",
			e.Layer, hx(e.Linkname), hx(e.Path))
	}
	// A path that did not land where its name said. Three different
	// statements, because they call for three different reactions: a
	// relative redirect is normal in images that symlink /bin to
	// /usr/bin, an absolute one means the symlink target is read as the
	// image root by a runtime and as the HOST root by tar, and an
	// escape is an attempt to write outside the image altogether.
	for _, r := range m.Redirects {
		switch {
		case r.Escaped:
			add("symlink-escape layer=%d phex=%s", r.Layer, hx(r.Literal))
		case r.Absolute:
			add("symlink-parent-absolute layer=%d to=%s phex=%s",
				r.Layer, hx(r.Resolved), hx(r.Literal))
		default:
			add("symlink-parent layer=%d to=%s phex=%s",
				r.Layer, hx(r.Resolved), hx(r.Literal))
		}
	}
	for _, s := range m.Shadowed {
		if typeName(s.Old.Type) != "file" {
			continue
		}
		// What changed, as well as that something did. "layer 1
		// overwrote etc/config.ini" is a fact about the image;
		// "overwrote it with different bytes" is the one that says
		// the earlier version is a separate document still being
		// published, and "overwrote it with the same bytes and a
		// different mode" is a chmod, which leaks nothing new.
		// A reader who cannot tell those apart treats every layer
		// rebuild as a credential leak and stops reading the report.
		delta := "none"
		switch {
		case s.Old.ContentSHA != s.New.ContentSHA && s.Old.Mode != s.New.Mode:
			delta = "content+mode"
		case s.Old.ContentSHA != s.New.ContentSHA:
			delta = "content"
		case s.Old.Mode != s.New.Mode:
			delta = "mode"
		}
		add("shadowed layer=%d by=%d blob=%s comp=%s delta=%s size=%d off=%d content=%s new=%s newmode=%04o phex=%s",
			s.OldL, s.NewL, m.blob(s.OldL), m.comp(s.OldL), delta,
			s.Old.Size, s.Old.Offset,
			s.Old.ContentSHA, s.New.ContentSHA, s.New.Mode, hx(s.Path))
	}
	// One line per layer that is still publishing content the merged
	// filesystem does not show. A leak sitting among two hundred audit
	// lines is a leak nobody reads, and the per-layer count is the thing
	// that gets noticed: "layer 1 still publishes 3 files, 112 bytes"
	// names a blob to go and look at.
	//
	// Both kinds are counted because they are the same leak with two
	// shapes. Deleted is RUN rm; shadowed is a later layer writing over
	// the path, which publishes both versions and leaves the earlier one
	// -- the one with the credential still in it -- in the blob.
	type leak struct{ files, shadow int; bytes int64 }
	per := map[int]*leak{}
	at := func(l int) *leak {
		if per[l] == nil {
			per[l] = &leak{}
		}
		return per[l]
	}
	for _, r := range m.Deleted {
		if typeName(r.E.Type) != "file" {
			continue
		}
		k := at(r.Held)
		k.files++
		k.bytes += r.E.Size
	}
	for _, s := range m.Shadowed {
		if typeName(s.Old.Type) != "file" {
			continue
		}
		k := at(s.OldL)
		k.shadow++
		k.bytes += s.Old.Size
	}
	for l, k := range per {
		add("leak layer=%d blob=%s comp=%s deleted=%d shadowed=%d bytes=%d",
			l, m.blob(l), m.comp(l), k.files, k.shadow, k.bytes)
	}
	sort.Strings(out)
	return out
}

func cmdAudit(im *Image) int {
	m, err := im.Merge(true)
	if err != nil {
		fail(exitInvalid, "%v", err)
	}
	for _, l := range auditLines(m) {
		fmt.Println(l)
	}
	return exitOK
}

func cmdTree(im *Image) int {
	m, err := im.Merge(true)
	if err != nil {
		fail(exitInvalid, "%v", err)
	}
	for _, p := range m.SortedPaths() {
		e := m.State[p]
		link := "-"
		switch {
		case e.Type == tar.TypeChar || e.Type == tar.TypeBlock:
			link = hx(fmt.Sprintf("%d,%d", e.Devmajor, e.Devminor))
		case e.Linkname != "":
			link = hx(e.Linkname)
		}
		content := e.ContentSHA
		if content == "" {
			content = "-"
		}
		size := e.Size
		if e.Type == tar.TypeChar || e.Type == tar.TypeBlock {
			size = 0
		}
		fmt.Printf("node %s %04o %d %d %d layer=%d content=%s link=%s phex=%s\n",
			typeName(e.Type), e.Mode, e.UID, e.GID, size, e.Layer, content, link, hx(p))
	}
	return exitOK
}

// cmdStats prints how many of each construct the image actually contains.
// It exists because of the failure mode this collection keeps rediscovering:
// a whiteout test over a corpus with no whiteouts passes while checking
// nothing, and the only defence is to count the constructs and assert a
// floor before the test that depends on them runs.
func cmdStats(im *Image) int {
	m, err := im.Merge(true)
	if err != nil {
		fail(exitInvalid, "%v", err)
	}
	c := map[string]int{}
	for _, k := range []string{"layers", "entries", "whiteout-file",
		"whiteout-opaque", "hardlink", "symlink", "chardev", "dir", "file",
		"setuid", "setgid", "sticky", "world-writable", "xattr",
		"capability", "escape", "longname", "dup-in-layer",
		"path-in-many-layers", "deleted", "shadowed",
		"whiteout-hit-nothing", "merged-paths", "hardlink-dangling",
		"symlink-parent", "symlink-escape"} {
		c[k] = 0
	}
	c["layers"] = len(m.Entries)
	inLayers := map[string]map[int]bool{}
	for i, ents := range m.Entries {
		seen := map[string]bool{}
		for _, e := range ents {
			c["entries"]++
			switch e.Whiteout {
			case "file":
				c["whiteout-file"]++
			case "opaque":
				c["whiteout-opaque"]++
			}
			t := typeName(e.Type)
			if _, ok := c[t]; ok {
				c[t]++
			}
			if e.Mode&04000 != 0 {
				c["setuid"]++
			}
			if e.Mode&02000 != 0 {
				c["setgid"]++
			}
			if e.Mode&01000 != 0 {
				c["sticky"]++
			}
			if t != "symlink" && e.Mode&02 != 0 {
				c["world-writable"]++
			}
			if len(e.Xattrs) > 0 {
				c["xattr"]++
			}
			if _, ok := e.Xattrs["security.capability"]; ok {
				c["capability"]++
			}
			if e.Escapes {
				c["escape"]++
			}
			if len(e.Name) > 100 {
				c["longname"]++
			}
			if seen[e.Path] {
				c["dup-in-layer"]++
			}
			seen[e.Path] = true
			if e.Whiteout == "" && e.Path != "" {
				if inLayers[e.Path] == nil {
					inLayers[e.Path] = map[int]bool{}
				}
				inLayers[e.Path][i] = true
			}
		}
	}
	for _, v := range inLayers {
		if len(v) > 1 {
			c["path-in-many-layers"]++
		}
	}
	c["deleted"] = len(m.Deleted)
	c["shadowed"] = len(m.Shadowed)
	c["whiteout-hit-nothing"] = len(m.NoTarget)
	c["merged-paths"] = len(m.State)
	c["hardlink-dangling"] = len(m.DanglingLinks)
	for _, r := range m.Redirects {
		if r.Escaped {
			c["symlink-escape"]++
		} else {
			c["symlink-parent"]++
		}
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s %d\n", k, c[k])
	}
	return exitOK
}
