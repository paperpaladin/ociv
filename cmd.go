package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// q renders a path for a line-oriented report. The corpus contains a
// filename with a newline in it, on purpose: a tar member name may hold any
// byte except NUL and '/', and a report that prints such a name unquoted
// produces a line that is two lines and a parser that silently disagrees
// about how many entries there were. strconv.Quote is Go syntax, which is
// close enough to tar's own --quoting-style=c for the harness to compare
// the two directly.
func q(s string) string { return strconv.Quote(s) }

// xattrField renders extended attributes as name:hex pairs, sorted. Hex
// because an xattr value is arbitrary bytes and security.capability is a
// 20-byte binary struct; printing it as text would be printing nothing.
func xattrField(x map[string]string) string {
	if len(x) == 0 {
		return ""
	}
	keys := make([]string, 0, len(x))
	for k := range x {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+hex.EncodeToString([]byte(x[k])))
	}
	return "xattr=" + strings.Join(parts, ",")
}

func cmdInfo(im *Image) int {
	fmt.Printf("kind %s\n", im.Src.kind())
	fmt.Printf("manifest %s %d %s\n", im.ManifestDigest, len(im.ManifestRaw), im.Manifest.MediaType)
	fmt.Printf("config %s %d %s\n", im.Manifest.Config.dg(), len(im.ConfigRaw), im.Manifest.Config.mt())
	fmt.Printf("platform %s/%s\n", im.Config.OS, im.Config.Architecture)
	fmt.Printf("rootfs-type %s\n", im.Config.RootFS.Type)
	fmt.Printf("layers %d\n", len(im.Manifest.Layers))
	for i, d := range im.Manifest.Layers {
		kind, known := layerCompression(d.mt())
		if !known {
			kind = "unknown"
		}
		diff := "-"
		if i < len(im.Config.RootFS.DiffIDs) {
			diff = im.Config.RootFS.DiffIDs[i]
		}
		fmt.Printf("layer %d %s %d %s %s %s\n", i, d.dg(), d.sz(), d.mt(), kind, diff)
	}
	for _, f := range im.Findings {
		fmt.Printf("finding %s %s %s\n", f.Code, f.Where, f.Detail)
	}
	if len(im.Findings) > 0 {
		return exitInvalid
	}
	return exitOK
}

// cmdVerify checks every claim the image makes about itself that can be
// checked from the bytes. Each check prints a line whether it passed or
// failed, because a report that only prints failures cannot be told from a
// report that ran nothing.
func cmdVerify(im *Image) int {
	checks := 0
	okf := func(format string, a ...any) {
		checks++
		fmt.Printf("ok %s\n", fmt.Sprintf(format, a...))
	}

	// The manifest's own digest, against index.json's descriptor. In a
	// layout this is the one digest nothing else covers: the manifest is
	// the root of the tree of claims and index.json is the only thing
	// that says what it should be.
	if im.ManifestDigest != "-" {
		if im.ManifestDesc.Digest != nil {
			if im.ManifestDigest == im.ManifestDesc.dg() {
				okf("manifest digest %s", im.ManifestDigest)
			}
		}
		if im.ManifestDesc.Size != nil && im.ManifestDesc.sz() == int64(len(im.ManifestRaw)) {
			okf("manifest size %d", len(im.ManifestRaw))
		}
	}
	if im.Manifest.Config.Digest != nil && SHA256Hex(im.ConfigRaw) == im.Manifest.Config.dg() {
		okf("config digest %s", im.Manifest.Config.dg())
	}

	// Every layer: the descriptor digest over the stored bytes, the
	// stated size, and the config's diff_id over the uncompressed bytes.
	// The third is the one that needs the layer actually decompressed,
	// and it is the one skopeo does not check.
	for i := range im.Manifest.Layers {
		d := im.Manifest.Layers[i]
		dg, err := ParseDigest(d.dg())
		if err != nil {
			im.note("V008", fmt.Sprintf("layer %d", i), "%v", err)
			continue
		}
		if !dg.Supported() {
			refuse("layer %d: digest algorithm %q is not implemented", i, dg.Alg)
		}
		rc, err := im.blobReader(d)
		if err != nil {
			im.note("V010", fmt.Sprintf("layer %d", i), "blob %s cannot be opened: %v", d.dg(), err)
			continue
		}
		n, got, err := dg.VerifyReader(rc)
		rc.Close()
		if err != nil {
			im.note("V010", fmt.Sprintf("layer %d", i), "%v", err)
			continue
		}
		if got == dg.S {
			okf("layer %d digest %s", i, got)
		} else {
			im.note("V012", fmt.Sprintf("layer %d", i), "blob content is %s, descriptor says %s", got, dg.S)
		}
		if d.Size != nil {
			if d.sz() == n {
				okf("layer %d size %d", i, n)
			} else {
				im.note("V011", fmt.Sprintf("layer %d", i), "descriptor says %d bytes, blob is %d", d.sz(), n)
			}
		}
		if _, known := layerCompression(d.mt()); !known {
			im.note("V016", fmt.Sprintf("layer %d", i), "media type %q is not a layer media type", d.mt())
			continue
		}
		if i < len(im.Config.RootFS.DiffIDs) {
			_, diff, err := im.LayerEntries(i, false)
			if err != nil {
				im.note("V021", fmt.Sprintf("layer %d", i), "cannot be read as a tar: %v", err)
				continue
			}
			want := im.Config.RootFS.DiffIDs[i]
			if diff == want {
				okf("layer %d diff_id %s", i, diff)
			} else {
				im.note("V019", fmt.Sprintf("layer %d", i), "uncompressed content is %s, config diff_id says %s", diff, want)
			}
		}
	}

	for _, f := range im.Findings {
		fmt.Printf("BAD %s %s: %s\n", f.Code, f.Where, f.Detail)
	}
	word := "findings"
	if len(im.Findings) == 1 {
		word = "finding"
	}
	fmt.Printf("verify: %d checks, %d %s\n", checks, len(im.Findings), word)
	if len(im.Findings) > 0 {
		return exitInvalid
	}
	return exitOK
}

func cmdLayers(im *Image) int {
	for i := range im.Manifest.Layers {
		ents, diff, err := im.LayerEntries(i, true)
		if err != nil {
			fail(exitInvalid, "%v", err)
		}
		fmt.Printf("layer %d %s entries %d diff_id %s\n", i, im.Manifest.Layers[i].dg(), len(ents), diff)
		for _, e := range ents {
			printEntry(e)
		}
	}
	return exitOK
}

// printEntry is the one place an Entry becomes text. Nine fixed fields,
// then zero or more key=value extras, so that a harness can compare the
// fixed part against GNU tar positionally and still see the rest.
func printEntry(e Entry) {
	extra := []string{}
	if e.Devmajor != 0 || e.Devminor != 0 || e.Type == and3 || e.Type == and4 {
		extra = append(extra, fmt.Sprintf("dev=%d,%d", e.Devmajor, e.Devminor))
	}
	if s := xattrField(e.Xattrs); s != "" {
		extra = append(extra, s)
	}
	if e.Whiteout != "" {
		extra = append(extra, "wh="+e.Whiteout+":"+q(e.WhTarget))
	}
	if e.Escapes {
		extra = append(extra, "escape="+q(e.EscapeWhy))
	}
	if e.ContentSHA != "" {
		extra = append(extra, "content="+e.ContentSHA)
	}
	// Names go out twice: C-quoted for a reader, hex for a comparison.
	// The corpus contains a filename with a newline in it and another
	// with a backslash, and two tools' ideas of how to escape those will
	// differ in some corner. Hex has no corners.
	extra = append(extra, fmt.Sprintf("off=%d", e.Offset))
	extra = append(extra, "path="+q(e.Path))
	extra = append(extra, "nhex="+hex.EncodeToString([]byte(e.Name)))
	if e.Linkname != "" {
		extra = append(extra, "lhex="+hex.EncodeToString([]byte(e.Linkname)))
	}
	fmt.Printf("entry %d %d %s %04o %d %d %d %s %s %s\n",
		e.Layer, e.Index, typeName(e.Type), e.Mode, e.UID, e.GID, e.Size,
		q(e.Name), q(e.Linkname), strings.Join(extra, " "))
}

const (
	and3 = '3' // tar.TypeChar
	and4 = '4' // tar.TypeBlock
)

func run() int {
	args := os.Args[1:]
	cmd, arg := args[0], args[1]
	im, err := OpenImage(arg)
	if err != nil {
		if im != nil {
			for _, f := range im.Findings {
				fmt.Printf("BAD %s %s: %s\n", f.Code, f.Where, f.Detail)
			}
		}
		if IsInvalid(err) {
			fail(exitInvalid, "%v", err)
		}
		fail(exitUsage, "%v", err)
	}
	switch cmd {
	case "info":
		return cmdInfo(im)
	case "verify":
		return cmdVerify(im)
	case "layers":
		return cmdLayers(im)
	case "tree":
		return cmdTree(im)
	case "audit":
		return cmdAudit(im)
	case "stats":
		return cmdStats(im)
	}
	fail(exitUsage, "unknown command %q", cmd)
	return exitUsage
}
