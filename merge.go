package main

import (
	"archive/tar"
	"sort"
	"strings"
)

// Node is one path in the merged root filesystem, and the entry that put
// it there. Keeping the layer index is the whole point: "the image has a
// setuid binary" is not actionable and "layer 1 introduced it" is.
type Node struct {
	Path string
	E    Entry
}

// Removal records a path that existed in one layer and was taken out by a
// whiteout in a later one. The bytes are still in the earlier layer's
// blob, which is published, which is the finding this program exists for.
type Removal struct {
	Path    string
	Held    int // the layer whose blob still contains it
	By      int // the layer whose whiteout removed it
	E       Entry
	Opaque  bool
	Subtree bool // removed because an ancestor was whiteouted, not by name
}

// Shadow records a path a later layer replaced. The earlier version is
// still in the earlier blob. Same leak, different shape: the first version
// of a config file is the one with the credential in it.
type Shadow struct {
	Path string
	OldL int
	NewL int
	Old  Entry
	New  Entry
}

// Merged is everything the merge produced, including the parts that do not
// appear in the result.
type Merged struct {
	State    map[string]Entry
	Deleted  []Removal
	Shadowed []Shadow
	// Whiteouts that removed nothing. Not an error: a layer may whiteout
	// a path no lower layer has, and a build system that emits one is
	// doing something harmless. Counted because a corpus where every
	// whiteout hits nothing would pass a whiteout test while proving the
	// opposite of what it claims.
	NoTarget []Removal
	// Hard links whose target is in no layer at or below this one.
	// Not an error here: the format allows a layer to link to a path
	// an earlier layer provided, and if no layer did, the image is
	// broken in a way worth counting rather than guessing about.
	DanglingLinks []Entry
	// Entries whose path was redirected by a symlinked ancestor, and
	// those whose redirection left the root entirely.
	Redirects []SymRedirect
	Entries   [][]Entry
	DiffIDs   []string
	// Per layer, the descriptor digest of the blob on disk and how it
	// is compressed. The leak findings carry both: "layer 0 still
	// holds it" means nothing to anyone holding a directory of blobs
	// named by digest, and the offset in the finding is into the
	// UNCOMPRESSED stream, so a reader has to know whether the blob
	// needs inflating before the number applies to it.
	LayerBlob []string
	LayerComp []string
}

// resolveParents follows symlinks that appear as ANCESTORS of a path,
// the way an unpacker writing to a real filesystem does.
//
// This is not pedantry. GNU tar extracting a member called ./bin/newfile
// into a tree where bin is already a symlink to usr/bin writes
// usr/bin/newfile: verified here, it is what tar does. So a layer can put
// a file somewhere other than where its name says, as long as an earlier
// layer left a symlink in the way. That is the shape of several real
// container escapes, and a reader that treats member names as literal
// paths reports the wrong tree and misses the finding.
//
// Two cases, and they are not the same.
//
// A RELATIVE target is resolved against the symlink's own directory, and
// GNU tar's extraction is the oracle: the suite compares the merged tree
// against what tar actually produced.
//
// An ABSOLUTE target is resolved against the IMAGE root, because that is
// what it means once the image is a container's filesystem. GNU tar,
// extracting into an ordinary directory, resolves it against the HOST
// root instead and tries to write there; that is the divergence, it is
// the reason the symescape image is excluded from the extraction
// comparison, and it is written down in the README rather than smoothed
// over. ociv models the container, not the unpacking directory.
//
// A target that climbs above the root with ".." escapes, and the entry is
// reported and left out of the tree: it is not part of this image's root
// filesystem, it is an attempt to write outside it.
func resolveParents(state map[string]Entry, p string) (resolved string, viaSymlink, viaAbsolute, escapes bool) {
	parts := strings.Split(p, "/")
	if len(parts) == 0 {
		return p, false, false, false
	}
	cur := ""
	for _, c := range parts[:len(parts)-1] {
		if cur == "" {
			cur = c
		} else {
			cur = cur + "/" + c
		}
		// A chain of symlinks is legal. The bound is arbitrary and
		// generous; Linux uses 40 for the same reason, which is that
		// a loop otherwise never terminates.
		for hops := 0; hops < 40; hops++ {
			e, ok := state[cur]
			if !ok || e.Type != tarTypeSymlink {
				break
			}
			viaSymlink = true
			t := e.Linkname
			var base string
			if strings.HasPrefix(t, "/") {
				viaAbsolute = true
				base = ""
				// The leading slash comes off HERE rather than in
				// cleanPath, because cleanPath's escapes flag means
				// two things at once: "absolute" and "above the
				// root". For a MEMBER NAME both are escapes. For a
				// SYMLINK TARGET inside an image, absolute means
				// "the image root", which is not an escape at all,
				// and only ".." climbing past the root is. Leaving
				// the slash on reported /etc as an escape and lost
				// the finding that matters, which is that the entry
				// lands in the image's own etc.
				t = strings.TrimLeft(t, "/")
			} else {
				if i := strings.LastIndex(cur, "/"); i >= 0 {
					base = cur[:i]
				}
			}
			joined := t
			if base != "" {
				joined = base + "/" + t
			}
			next, esc, _ := cleanPath(joined)
			if esc {
				return "", viaSymlink, viaAbsolute, true
			}
			if next == cur {
				break
			}
			cur = next
		}
	}
	last := parts[len(parts)-1]
	if cur == "" {
		return last, viaSymlink, viaAbsolute, false
	}
	return cur + "/" + last, viaSymlink, viaAbsolute, false
}

const tarTypeSymlink = tar.TypeSymlink

// SymRedirect records an entry whose path went somewhere other than where
// its name said, because an ancestor was a symlink.
type SymRedirect struct {
	Layer    int
	Literal  string
	Resolved string
	Absolute bool
	Escaped  bool
}

// descendants returns every path strictly below d. The slash in the prefix
// is load-bearing: without it, whiteouting "var/log" also removes
// "var/logrotate", and nothing in a test that only looks at var/log would
// notice.
func descendants(state map[string]Entry, d string) []string {
	pre := d + "/"
	if d == "" {
		pre = ""
	}
	var out []string
	for p := range state {
		if p != d && strings.HasPrefix(p, pre) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Merge applies the layers in order.
//
// The rule implementations get wrong, stated in the OCI image-spec layer
// document: a whiteout applies to the layers BELOW it and never to the
// layer it appears in. Files in the same layer as a whiteout can only be
// hidden by a whiteout in a LATER layer. So each layer is applied in two
// passes -- its whiteouts against the accumulated lower state, then its
// own entries -- and not in one pass in tar order, which would let a
// whiteout delete a sibling that arrives after it in the same archive.
func (im *Image) Merge(wantContent bool) (*Merged, error) {
	m := &Merged{State: map[string]Entry{}}
	for i := range im.Manifest.Layers {
		ents, diff, err := im.LayerEntries(i, wantContent)
		if err != nil {
			return nil, err
		}
		m.Entries = append(m.Entries, ents)
		m.DiffIDs = append(m.DiffIDs, diff)
		m.LayerBlob = append(m.LayerBlob, im.Manifest.Layers[i].dg())
		comp, known := layerCompression(im.Manifest.Layers[i].mt())
		if !known {
			comp = "unknown"
		}
		m.LayerComp = append(m.LayerComp, comp)

		// Pass one: whiteouts, against the lower layers only.
		// The target goes through the same symlink resolution as any
		// other path: an unpacker deleting bin/foo where bin is a
		// symlink deletes usr/bin/foo.
		for _, e := range ents {
			if e.Whiteout == "" {
				continue
			}
			target, _, _, tesc := resolveParents(m.State, e.WhTarget)
			if tesc {
				m.Redirects = append(m.Redirects, SymRedirect{
					Layer: i, Literal: e.WhTarget, Escaped: true})
				continue
			}
			e.WhTarget = target
			switch e.Whiteout {
			case "opaque":
				victims := descendants(m.State, e.WhTarget)
				if len(victims) == 0 {
					m.NoTarget = append(m.NoTarget, Removal{Path: e.WhTarget, By: i, Opaque: true})
				}
				for _, p := range victims {
					m.Deleted = append(m.Deleted, Removal{
						Path: p, Held: m.State[p].Layer, By: i,
						E: m.State[p], Opaque: true, Subtree: true})
					delete(m.State, p)
				}
			case "file":
				var victims []string
				if _, ok := m.State[e.WhTarget]; ok {
					victims = append(victims, e.WhTarget)
				}
				sub := descendants(m.State, e.WhTarget)
				victims = append(victims, sub...)
				if len(victims) == 0 {
					m.NoTarget = append(m.NoTarget, Removal{Path: e.WhTarget, By: i})
				}
				for k, p := range victims {
					m.Deleted = append(m.Deleted, Removal{
						Path: p, Held: m.State[p].Layer, By: i,
						E: m.State[p], Subtree: k > 0 || p != e.WhTarget})
					delete(m.State, p)
				}
			}
		}

		// Pass two: this layer's real entries, in tar order, so a path
		// named twice in one archive resolves the way extraction
		// would: the last one wins.
		for _, e := range ents {
			if e.Whiteout != "" || e.Path == "" {
				continue
			}
			// A name that still climbs above the root once a
			// leading slash is off it is one GNU tar refuses to
			// write, so it is not part of the filesystem this
			// image unpacks to. It stays in m.Entries and the
			// audit still reports it: dropping it silently would
			// make the image look clean, and keeping it in the
			// tree would report a path no unpacker produces.
			if aboveRoot(e.Name) {
				continue
			}
			// Where the entry actually lands, which is not where
			// its name says when an ancestor is a symlink.
			res, via, abs, esc := resolveParents(m.State, e.Path)
			if via || esc {
				m.Redirects = append(m.Redirects, SymRedirect{
					Layer: i, Literal: e.Path, Resolved: res,
					Absolute: abs, Escaped: esc})
			}
			if esc {
				continue
			}
			e.Path = res
			// A hard link entry carries size 0 and no content of
			// its own: the bytes live at the target. A reader that
			// believes the header reports every hardlinked binary
			// in the image as an empty file, and the merged tree
			// then disagrees with what tar actually extracts.
			// The target is resolved against the state as it
			// stands, which is the lower layers plus this layer's
			// earlier entries -- the same thing an unpacker has
			// available when it reaches this member.
			if e.Type == tar.TypeLink {
				t, _, _ := cleanPath(e.Linkname)
				if tgt, ok := m.State[t]; ok {
					e.Size = tgt.Size
					e.ContentSHA = tgt.ContentSHA
					e.LinkResolved = true
					e.LinkTo = t
				} else {
					m.DanglingLinks = append(m.DanglingLinks, e)
				}
			}
			if old, ok := m.State[e.Path]; ok {
				if old.ContentSHA != e.ContentSHA || old.Mode != e.Mode {
					m.Shadowed = append(m.Shadowed, Shadow{
						Path: e.Path, OldL: old.Layer, NewL: i, Old: old, New: e})
				}
			}
			m.State[e.Path] = e
		}
	}
	return m, nil
}

// SortedPaths returns the merged paths in byte order, which is the order
// the Python second implementation uses so the two outputs can be diffed
// directly rather than compared as sets.
func (m *Merged) SortedPaths() []string {
	out := make([]string, 0, len(m.State))
	for p := range m.State {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
