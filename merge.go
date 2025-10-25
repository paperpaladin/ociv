package main

import (
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
	Entries  [][]Entry
	DiffIDs  []string
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

		// Pass one: whiteouts, against the lower layers only.
		for _, e := range ents {
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
