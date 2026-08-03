package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Entry is one tar member of one layer, with every header field this
// program has an opinion about. Nothing here is derived: these are the
// bytes the header said, so that a comparison against GNU tar is a
// comparison of what was written rather than of what we decided it meant.
type Entry struct {
	Layer    int
	Index    int    // position within the layer, so duplicates are distinguishable
	Name     string // exactly as the header spelled it
	Path     string // normalised: no leading ./ or /, no trailing /
	Type     byte   // tar typeflag
	Mode     int64  // permission bits including setuid, setgid and sticky
	UID      int
	GID      int
	Uname    string
	Gname    string
	Size     int64
	Linkname string
	Devmajor int64
	Devminor int64
	ModTime  int64
	Xattrs   map[string]string

	// Whiteout classification, from the OCI image-spec layer document.
	Whiteout  string // "" , "file" for .wh.NAME, "opaque" for .wh..wh..opq
	WhTarget  string // the path the whiteout removes (the directory, for opaque)
	Escapes   bool   // the name leaves the root: "..", or an absolute path
	EscapeWhy string

	// Where this member's data starts in the UNCOMPRESSED layer stream,
	// counted in bytes from the start of the tar. The point of carrying
	// it is the leak report: a deleted file's bytes are still published,
	// and "layer 0 still holds it" is a sentence where "offset 1536,
	// 41 bytes" is something a reader can go and check with dd. For a
	// gzip layer this is an offset into the decompressed stream, which
	// is the thing the diff_id is over, not into the blob on disk.
	Offset int64

	// Content digest, filled in only where the content was read.
	ContentSHA string

	// Set by the merge for a hard link whose target it could resolve.
	// Size and ContentSHA are then the target's, which is what the
	// path actually holds once the layer is unpacked.
	LinkResolved bool
	LinkTo       string
}

// Normalised type names, so the report does not print a raw byte. GNU tar's
// own -tv first column is the oracle for these and the harness maps between
// the two spellings rather than comparing the words.
func typeName(t byte) string {
	switch t {
	case tar.TypeReg, '\x00':
		return "file"
	case tar.TypeLink:
		return "hardlink"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeChar:
		return "chardev"
	case tar.TypeBlock:
		return "blockdev"
	case tar.TypeDir:
		return "dir"
	case tar.TypeFifo:
		return "fifo"
	case tar.TypeGNUSparse, tar.TypeGNULongName, tar.TypeGNULongLink:
		return "gnu"
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return "pax"
	}
	return fmt.Sprintf("type%c", t)
}

// cleanPath normalises a tar member name to the path it would occupy in the
// root filesystem, and says so when it would not occupy one at all.
//
// This is the function a layer-unpacking bug lives in. The rules are: the
// name is relative to the root, a leading "./" is cosmetic, a leading "/"
// is an absolute path that an unpacker must not honour, and a ".."
// component escapes. Resolving "a/../b" to "b" is correct and resolving
// "a/../../b" to "b" is a directory traversal, so the walk has to track
// depth rather than just textually collapsing.
func cleanPath(name string) (clean string, escapes bool, why string) {
	s := name
	if strings.HasPrefix(s, "/") {
		escapes = true
		why = "absolute path"
		s = strings.TrimLeft(s, "/")
	}
	parts := strings.Split(s, "/")
	var out []string
	for _, p := range parts {
		switch p {
		case "", ".":
			// "./" and doubled slashes are noise.
		case "..":
			if len(out) == 0 {
				escapes = true
				if why == "" {
					why = "parent reference above the root"
				}
			} else {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, p)
		}
	}
	return strings.Join(out, "/"), escapes, why
}

// aboveRoot reports whether a member name still climbs above the root
// after a leading slash has been taken off it.
//
// That is the distinction GNU tar 1.35 draws, measured rather than
// assumed: it strips a leading "/" and writes the member inside the
// extraction directory, and it strips a leading "../" and then REFUSES
// the result, printing "Member name contains '..'" and writing nothing.
// So "/absolute/path" lands at absolute/path and "../etc/shadow" lands
// nowhere, and a merged tree that treats the two the same reports a path
// no unpacker produces.
//
// cleanPath's "why" cannot answer this, because a name that is both
// absolute and climbing gets the absolute reason and keeps it.
//
// A leading slash needs no special handling: it produces an empty first
// component, which is skipped, so the depth count starts at the same
// place either way. The first version stripped it first and a mutation
// that removed the strip survived, which is what said the strip was
// doing nothing.
func aboveRoot(name string) bool {
	depth := 0
	for _, p := range strings.Split(name, "/") {
		switch p {
		case "", ".":
		case "..":
			if depth == 0 {
				return true
			}
			depth--
		default:
			depth++
		}
	}
	return false
}

const (
	whPrefix = ".wh."
	whOpaque = ".wh..wh..opq"
)

// classifyWhiteout applies the OCI layer specification's naming rules. The
// opaque marker has to be tested first because it also begins with ".wh.",
// and a reader that tests the prefix first deletes a file called
// ".wh..wh..opq" from the layer below instead of emptying the directory.
func classifyWhiteout(clean string) (kind, target string) {
	i := strings.LastIndex(clean, "/")
	dir, base := "", clean
	if i >= 0 {
		dir, base = clean[:i], clean[i+1:]
	}
	if base == whOpaque {
		return "opaque", dir
	}
	if strings.HasPrefix(base, whPrefix) {
		t := strings.TrimPrefix(base, whPrefix)
		if dir != "" {
			t = dir + "/" + t
		}
		return "file", t
	}
	return "", ""
}

// layerReader opens layer i and returns a reader over its UNCOMPRESSED
// bytes, together with a function that reports the diff_id once the reader
// has been drained. The two digests are different numbers over different
// bytes and the only way to keep them straight is to compute them in the
// places where those bytes exist: the descriptor digest where the blob is
// read, the diff_id here.
func (im *Image) layerReader(i int) (r io.Reader, diffID func() string, closeFn func() error, err error) {
	d := im.Manifest.Layers[i]
	kind, known := layerCompression(d.mt())
	if !known {
		refuse("layer %d has media type %q, which is not a layer media type this program knows", i, d.mt())
	}
	if kind == "zstd" {
		refuse("layer %d is %q; Go's standard library has no zstd decompressor and this program has no third-party dependencies", i, d.mt())
	}
	rc, err := im.blobReader(d)
	if err != nil {
		return nil, nil, nil, err
	}
	var src io.Reader = rc
	closers := []func() error{rc.Close}
	if kind == "gzip" {
		zr, err := gzip.NewReader(rc)
		if err != nil {
			rc.Close()
			return nil, nil, nil, fmt.Errorf("layer %d: gzip: %w", i, err)
		}
		src = zr
		closers = append([]func() error{zr.Close}, closers...)
	}
	h := sha256.New()
	tee := io.TeeReader(src, h)
	return tee, func() string { return "sha256:" + hex.EncodeToString(h.Sum(nil)) },
		func() error {
			var first error
			for _, c := range closers {
				if e := c(); e != nil && first == nil {
					first = e
				}
			}
			return first
		}, nil
}

// LayerEntries reads every tar member of layer i. The whole layer is
// streamed; content is hashed only for regular files, and only up to
// hashLimit bytes, because the deleted-file report wants to say which bytes
// are still published and a digest is the shortest way to say it.
func (im *Image) LayerEntries(i int, wantContent bool) ([]Entry, string, error) {
	r, diffID, closeFn, err := im.layerReader(i)
	if err != nil {
		return nil, "", err
	}
	defer closeFn()

	var out []Entry
	// archive/tar reads the underlying stream exactly, in 512-byte
	// blocks, so after Next() returns the counter is sitting on the
	// first byte of the member's data. That is an assumption about
	// somebody else's implementation, so the suite checks every offset
	// against python tarfile's offset_data and then dd's the bytes out
	// and hashes them.
	cr := &countReader{r: r}
	tr := tar.NewReader(cr)
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, "", fmt.Errorf("layer %d entry %d: %w", i, n, err)
		}
		e := Entry{
			Layer: i, Index: n, Offset: cr.n,
			Name: h.Name, Type: h.Typeflag, Mode: h.Mode,
			UID: h.Uid, GID: h.Gid, Uname: h.Uname, Gname: h.Gname,
			Size: h.Size, Linkname: h.Linkname,
			Devmajor: h.Devmajor, Devminor: h.Devminor,
		}
		if !h.ModTime.IsZero() {
			e.ModTime = h.ModTime.Unix()
		}
		// PAXRecords carries SCHILY.xattr.* among other things; only
		// the xattr records are of interest and the rest (mtime,
		// atime, path) are already reflected in the header fields.
		for k, v := range h.PAXRecords {
			if strings.HasPrefix(k, "SCHILY.xattr.") {
				if e.Xattrs == nil {
					e.Xattrs = map[string]string{}
				}
				e.Xattrs[strings.TrimPrefix(k, "SCHILY.xattr.")] = v
			}
		}
		// There is deliberately no second pass over h.Xattrs. Go's tar
		// reader fills that deprecated field from the very same
		// SCHILY.xattr records, so reading both was two routes to one
		// fact -- and a mutation that switched the pax route off was
		// invisible, because the duplicate quietly carried on working.
		// Redundant code is a test hole with a plausible explanation.
		e.Path, e.Escapes, e.EscapeWhy = cleanPath(h.Name)
		e.Whiteout, e.WhTarget = classifyWhiteout(e.Path)

		if wantContent && (h.Typeflag == tar.TypeReg || h.Typeflag == 0) {
			ch := sha256.New()
			if _, err := io.Copy(ch, tr); err != nil {
				return out, "", fmt.Errorf("layer %d entry %d (%s): %w", i, n, h.Name, err)
			}
			e.ContentSHA = "sha256:" + hex.EncodeToString(ch.Sum(nil))
		}
		out = append(out, e)
	}
	// Drain whatever the tar reader left: the diff_id is over the whole
	// blob including the trailing zero blocks, and a reader that stops at
	// the end-of-archive marker computes a different number from
	// sha256sum over the same file.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return out, "", err
	}
	return out, diffID(), nil
}

// countReader counts the bytes handed to the tar reader. Nothing else
// can answer "where in the layer is this member", because archive/tar
// does not expose it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}
