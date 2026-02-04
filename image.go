package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// invalidErr marks an error as a statement about the image rather than
// about the invocation. The two leave by different exit statuses and the
// harness asserts on the difference: "I cannot find your file" and "your
// image is corrupt" are not the same answer, and a tool that returns 2 for
// both lets a corrupt image pass as a typo.
type invalidErr struct{ error }

func (e invalidErr) Unwrap() error { return e.error }

func invalidf(format string, a ...any) error {
	return invalidErr{fmt.Errorf(format, a...)}
}

// IsInvalid reports whether err is a verdict on the image.
func IsInvalid(err error) bool {
	var v invalidErr
	return errors.As(err, &v)
}

// Media types from the OCI image-spec, plus the two Docker types that a
// registry still serves to anything that does not ask for OCI. A reader
// that knows only the OCI spellings works on images built this year and on
// nothing older.
const (
	mtOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mtOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mtOCIConfig     = "application/vnd.oci.image.config.v1+json"
	mtOCILayer      = "application/vnd.oci.image.layer.v1.tar"
	mtOCILayerGzip  = "application/vnd.oci.image.layer.v1.tar+gzip"
	mtOCILayerZstd  = "application/vnd.oci.image.layer.v1.tar+zstd"
	mtOCINonDistrib = "application/vnd.oci.image.layer.nondistributable.v1.tar"

	mtDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	mtDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtDockerConfig    = "application/vnd.docker.container.image.v1+json"
	mtDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	mtDockerLayer     = "application/vnd.docker.image.rootfs.diff.tar"
	mtDockerForeign   = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
)

// layerCompression reports how a layer media type is stored, and whether
// ociv can read it. The three results are distinct on purpose. "none" and
// "gzip" are implemented; "zstd" is a legal media type with no
// decompressor in the Go standard library, which is a refusal and not an
// accusation against the image; anything else is unrecognised.
func layerCompression(mt string) (kind string, known bool) {
	switch mt {
	case mtOCILayer, mtDockerLayer, mtOCINonDistrib:
		return "none", true
	case mtOCILayerGzip, mtDockerLayerGzip, mtDockerForeign,
		"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip":
		return "gzip", true
	case mtOCILayerZstd,
		"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":
		return "zstd", true
	}
	return "", false
}

// Descriptor is the spec's content descriptor. The required fields are
// pointers so that absent and zero can be told apart: a zero size is legal
// for an empty blob, and a reader that treats missing-size as size-zero
// will accept a descriptor with no size at all and then "verify" it.
type Descriptor struct {
	MediaType    *string           `json:"mediaType"`
	Digest       *string           `json:"digest"`
	Size         *int64            `json:"size"`
	URLs         []string          `json:"urls"`
	Annotations  map[string]string `json:"annotations"`
	Data         *string           `json:"data"`
	ArtifactType *string           `json:"artifactType"`
	Platform     *Platform         `json:"platform"`
}

type Platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version"`
	OSFeatures   []string `json:"os.features"`
	Variant      string   `json:"variant"`
}

func (p *Platform) String() string {
	if p == nil {
		return "-"
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

func (d Descriptor) mt() string {
	if d.MediaType == nil {
		return ""
	}
	return *d.MediaType
}

func (d Descriptor) dg() string {
	if d.Digest == nil {
		return ""
	}
	return *d.Digest
}

func (d Descriptor) sz() int64 {
	if d.Size == nil {
		return -1
	}
	return *d.Size
}

// Index is index.json in an image layout, and also a manifest list fetched
// as a manifest.
type Index struct {
	SchemaVersion *int              `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations"`
	Subject       *Descriptor       `json:"subject"`
}

type Manifest struct {
	SchemaVersion *int              `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Subject       *Descriptor       `json:"subject"`
	Annotations   map[string]string `json:"annotations"`
}

type Config struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	Created      string `json:"created"`
	Author       string `json:"author"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		Comment    string `json:"comment"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
	Config json.RawMessage `json:"config"`
}

// blobSource is how the two container formats differ, and the only way
// they differ as far as everything above this line is concerned.
type blobSource interface {
	// open returns the stored bytes for a descriptor. For an OCI layout
	// that is a file named by the digest; for a docker-archive it is a
	// member of the outer tar, looked up by the name the archive's own
	// manifest.json gave it.
	open(d Descriptor) (io.ReadCloser, int64, error)
	kind() string
}

// ---------------------------------------------------------------------------
// OCI image layout
// ---------------------------------------------------------------------------

type ociLayout struct{ root string }

func (o ociLayout) kind() string { return "oci-layout" }

func (o ociLayout) open(d Descriptor) (io.ReadCloser, int64, error) {
	dg, err := ParseDigest(d.dg())
	if err != nil {
		return nil, 0, err
	}
	// blobs/<algorithm>/<encoded>, and the components are checked
	// against the digest grammar before they are joined, so no
	// descriptor can name a path outside the blobs directory.
	p := filepath.Join(o.root, "blobs", dg.Alg, dg.Enc)
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if st.IsDir() {
		f.Close()
		return nil, 0, fmt.Errorf("blob path %s is a directory", p)
	}
	return f, st.Size(), nil
}

// ---------------------------------------------------------------------------
// docker-archive (what "docker save" and "skopeo copy docker-archive:" write)
// ---------------------------------------------------------------------------

type tarArchive struct {
	path string
	// name -> the name under which the member really appears, since a
	// docker-archive may write "./foo" or "foo" for the same thing.
	names map[string]string
	sizes map[string]int64 // member name -> header size, from one scan
}

// scan reads the outer tar once and records every regular member's size.
// The sizes are a fact about the archive, not about ociv, so comparing a
// member's header size against the bytes actually read is a real check and
// a truncated archive fails it.
func (t *tarArchive) scan() error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer f.Close()
	t.sizes = map[string]int64{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg {
			t.sizes[strings.TrimPrefix(h.Name, "./")] = h.Size
		}
	}
}

func (t *tarArchive) kind() string { return "docker-archive" }

// shortcut: a member is found by scanning the outer tar from the start
// every time it is opened, which is O(members) per open. A docker-archive
// holds a handful of members and the alternative is an offset index, which
// archive/tar does not expose directly before Go 1.25's RawOffset. Upgrade
// path: build the index with a counting reader if a corpus ever makes this
// measurable.
func (t *tarArchive) member(name string) (io.ReadCloser, int64, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, 0, err
	}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return nil, 0, err
		}
		if strings.TrimPrefix(h.Name, "./") == name {
			return readCloser{tr, f}, h.Size, nil
		}
	}
	f.Close()
	return nil, 0, fmt.Errorf("%s: no member %q", t.path, name)
}

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r readCloser) Close() error { return r.c.Close() }

// open for a docker-archive looks the blob up by the name the archive's
// own manifest.json gave it. The mapping is built when the archive is
// opened; a descriptor digest means nothing inside a docker-archive, which
// is the central difference between the two formats and the reason this
// interface exists at all.
func (t *tarArchive) open(d Descriptor) (io.ReadCloser, int64, error) {
	name, ok := t.names[d.dg()]
	if !ok {
		return nil, 0, fmt.Errorf("digest %s is not in this archive", d.dg())
	}
	return t.member(name)
}

// ---------------------------------------------------------------------------
// Opening an image
// ---------------------------------------------------------------------------

type Image struct {
	Path     string
	Selector string // the :tag or @digest the user asked for, "" if none
	Src      blobSource

	IndexRaw     []byte
	Index        Index
	ManifestDesc Descriptor
	// Set when index.json pointed at an image index rather than at an
	// image manifest, so info can print the level that was traversed
	// and a second nesting can be refused rather than recursed into.
	nested            bool
	NestedIndexDigest string
	ManifestRaw       []byte
	ManifestDigest    string
	Manifest          Manifest
	ConfigRaw         []byte
	Config            Config

	// Findings accumulated while opening. Opening does not exit: verify
	// wants the whole list, and info wants to print what it could read.
	Findings []Finding
}

// A Finding is one thing wrong with the image. The Code is stable and the
// harness asserts on it, because "the image is invalid" is not a finding
// and a checker that prints the same sentence for fourteen different
// defects has not been shown to distinguish any of them.
type Finding struct {
	Code   string
	Where  string
	Detail string
}

func (im *Image) note(code, where, format string, a ...any) {
	im.Findings = append(im.Findings, Finding{code, where, fmt.Sprintf(format, a...)})
}

// splitSelector peels a :tag or @digest suffix off the path. A Windows
// drive letter is not a concern here and a path containing a colon is, so
// the suffix is only taken when what precedes it exists on disk.
func splitSelector(arg string) (path, sel string) {
	if i := strings.LastIndex(arg, "@"); i > 0 {
		if _, err := os.Stat(arg[:i]); err == nil {
			return arg[:i], arg[i:]
		}
	}
	if i := strings.LastIndex(arg, ":"); i > 0 {
		if _, err := os.Stat(arg[:i]); err == nil {
			return arg[:i], arg[i+1:]
		}
	}
	return arg, ""
}

func OpenImage(arg string) (*Image, error) {
	path, sel := splitSelector(arg)
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	im := &Image{Path: path, Selector: sel}
	// The image is returned even when opening fails, because the
	// findings collected on the way are the useful part of the answer.
	// Returning nil here printed "no such blob" for a malformed digest
	// string and swallowed the V008 that said why the path was wrong:
	// ten assertions about the digest grammar failed for that reason and
	// none of them was about the grammar.
	if st.IsDir() {
		return im, im.openLayout()
	}
	return im, im.openArchive()
}

// openArchive reads a "docker save" tar. The format predates OCI and is
// not content-addressed: manifest.json names its config and layers by
// filename, and the filenames happen to contain digests because the tool
// that wrote them chose to. Two facts are still checkable without trusting
// anything ociv produced, and both are checked:
//
//   - the config member is named <hex>.json, and <hex> must be the sha256
//     of its own contents;
//   - each layer member is named <hex>.tar, and <hex> must be the sha256
//     of its own contents, which for an uncompressed layer is also the
//     diff_id the config declares.
//
// There is no manifest digest, because there is no manifest in the OCI
// sense. ociv prints "-" for it rather than inventing one.
func (im *Image) openArchive() error {
	ar := &tarArchive{path: im.Path, names: map[string]string{}}
	if err := ar.scan(); err != nil {
		return fmt.Errorf("%s: not a tar archive: %w", im.Path, err)
	}
	rc, _, err := ar.member("manifest.json")
	if err != nil {
		return fmt.Errorf("%s: not an OCI layout directory and not a docker-archive: %w", im.Path, err)
	}
	mb, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return err
	}
	var entries []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if err := json.Unmarshal(mb, &entries); err != nil {
		return invalidf("%s/manifest.json: %w", im.Path, err)
	}
	if len(entries) == 0 {
		return invalidf("%s/manifest.json: no entries", im.Path)
	}
	pick := -1
	for i, e := range entries {
		if im.Selector == "" {
			pick = i
			break
		}
		for _, t := range e.RepoTags {
			if t == im.Selector || strings.HasSuffix(t, "/"+im.Selector) ||
				strings.HasSuffix(t, ":"+im.Selector) {
				pick = i
			}
		}
	}
	if pick < 0 {
		return invalidf("%s: no entry matches %q", im.Path, im.Selector)
	}
	if im.Selector == "" && len(entries) > 1 {
		refuse("%s holds %d images and no selector was given; append :TAG", im.Path, len(entries))
	}
	e := entries[pick]
	im.Src = ar
	im.IndexRaw = mb
	im.ManifestDigest = "-"

	// Build descriptors out of filenames, and record the name each
	// digest maps to so blobSource.open can find the member again.
	nameDigest := func(fn, suffix string) (string, bool) {
		base := strings.TrimSuffix(fn, suffix)
		base = base[strings.LastIndex(base, "/")+1:]
		if len(base) != 64 {
			return "", false
		}
		d, err := ParseDigest("sha256:" + base)
		if err != nil {
			return "", false
		}
		return d.S, true
	}
	cdg, ok := nameDigest(e.Config, ".json")
	if !ok {
		return invalidf("%s: config member %q is not named by a sha256 digest", im.Path, e.Config)
	}
	ar.names[cdg] = e.Config
	mt := mtDockerConfig
	csz := ar.sizes[e.Config]
	im.Manifest.Config = Descriptor{MediaType: &mt, Digest: &cdg, Size: &csz}
	for _, ln := range e.Layers {
		ldg, ok := nameDigest(ln, ".tar")
		if !ok {
			return invalidf("%s: layer member %q is not named by a sha256 digest", im.Path, ln)
		}
		ar.names[ldg] = ln
		lmt := mtDockerLayer
		lsz := ar.sizes[ln]
		d := ldg
		im.Manifest.Layers = append(im.Manifest.Layers, Descriptor{MediaType: &lmt, Digest: &d, Size: &lsz})
	}

	cb, err := im.readBlob(im.Manifest.Config, "config")
	if err != nil {
		return err
	}
	im.ConfigRaw = cb
	if err := json.Unmarshal(cb, &im.Config); err != nil {
		return invalidf("config %s: %w", cdg, err)
	}
	if im.Config.RootFS.Type != "layers" {
		im.note("V017", "config.rootfs", "type is %q, spec requires \"layers\"", im.Config.RootFS.Type)
	}
	if n := len(im.Config.RootFS.DiffIDs); n != len(im.Manifest.Layers) {
		im.note("V018", "config.rootfs", "%d diff_ids for %d layers", n, len(im.Manifest.Layers))
	}
	return nil
}

func (im *Image) openLayout() error {
	// oci-layout. The spec says this file MUST exist and MUST carry
	// imageLayoutVersion "1.0.0". skopeo reads a layout without it and
	// reads one claiming 2.0.0; we report both, because the file is the
	// only thing that distinguishes an image layout from a directory
	// that happens to contain a file called index.json.
	lb, err := os.ReadFile(filepath.Join(im.Path, "oci-layout"))
	if err != nil {
		im.note("V001", "oci-layout", "missing or unreadable: %v", err)
	} else {
		var lay struct {
			V *string `json:"imageLayoutVersion"`
		}
		if err := json.Unmarshal(lb, &lay); err != nil {
			im.note("V002", "oci-layout", "not valid JSON: %v", err)
		} else if lay.V == nil {
			im.note("V002", "oci-layout", "no imageLayoutVersion field")
		} else if *lay.V != "1.0.0" {
			im.note("V002", "oci-layout", "imageLayoutVersion is %q, spec requires \"1.0.0\"", *lay.V)
		}
	}

	ib, err := os.ReadFile(filepath.Join(im.Path, "index.json"))
	if err != nil {
		return invalidf("%s: no index.json: %w", im.Path, err)
	}
	im.IndexRaw = ib
	if err := json.Unmarshal(ib, &im.Index); err != nil {
		return invalidf("%s/index.json: %w", im.Path, err)
	}
	if im.Index.SchemaVersion == nil {
		im.note("V004", "index.json", "no schemaVersion field")
	} else if *im.Index.SchemaVersion != 2 {
		im.note("V004", "index.json", "schemaVersion is %d, spec requires 2", *im.Index.SchemaVersion)
	}
	if len(im.Index.Manifests) == 0 {
		return invalidf("%s/index.json: no manifests", im.Path)
	}
	im.Src = ociLayout{root: im.Path}

	d, err := im.selectManifest()
	if err != nil {
		return err
	}
	im.ManifestDesc = d
	return im.loadManifest()
}

// selectManifest picks one descriptor out of index.json. With no selector
// and more than one candidate it refuses: guessing which image the user
// meant is how a verifier ends up verifying something else.
func (im *Image) selectManifest() (Descriptor, error) {
	return im.selectFrom(im.Index.Manifests, "index.json")
}

// selectFrom picks one descriptor out of a list of them. It is used for
// index.json and again for a nested image index reached through it: the
// rules are the same list of rules both times, and writing them twice is
// how the second level ends up behaving differently from the first.
func (im *Image) selectFrom(all []Descriptor, where string) (Descriptor, error) {
	// Whether this list is one a platform can discriminate at all.
	// index.json of a nested layout holds ONE entry, pointing at the
	// image index, and that entry carries no platform field: applying
	// the filter there removes the only candidate and reports the image
	// as not holding the platform, which is what the first version of
	// this did. The filter belongs at the level that distinguishes
	// platforms, and this is how that level is recognised.
	anyPlatform := false
	for _, d := range all {
		if d.Platform != nil {
			anyPlatform = true
		}
	}
	var cands []Descriptor
	for _, d := range all {
		// --platform narrows first and independently of the tag,
		// because a real multi-arch index is one tag over several
		// platforms: the two are not alternatives, they compose.
		if anyPlatform && wantPlatform != "" && d.Platform.String() != wantPlatform {
			continue
		}
		switch {
		case im.Selector == "":
			cands = append(cands, d)
		case strings.HasPrefix(im.Selector, "@"):
			if d.dg() == im.Selector[1:] {
				cands = append(cands, d)
			}
		default:
			if d.Annotations["org.opencontainers.image.ref.name"] == im.Selector {
				cands = append(cands, d)
			}
		}
	}
	if len(cands) == 0 {
		what := strconv.Quote(im.Selector)
		if wantPlatform != "" {
			what = "platform " + wantPlatform
			if im.Selector != "" {
				what += " and " + strconv.Quote(im.Selector)
			}
		}
		var had []string
		for _, d := range all {
			had = append(had, d.Platform.String())
		}
		sort.Strings(had)
		return Descriptor{}, invalidf("no manifest in %s matches %s; it holds %s",
			where, what, strings.Join(had, " "))
	}
	if len(cands) > 1 {
		// Two different situations and the message used to give both
		// the same words, "no selector was given", which is a lie when
		// one was. A real multi-arch image is one tag over several
		// platforms, so :TAG narrows nothing there and telling the
		// user to append a tag sends them round the same loop. Name
		// the platforms, since that is what actually distinguishes the
		// candidates, and fall back to the digest where there is no
		// platform field.
		var names []string
		for _, d := range cands {
			n := d.Platform.String()
			if n == "-" {
				n = d.Annotations["org.opencontainers.image.ref.name"]
			}
			if n == "" || n == "-" {
				n = d.dg()
			}
			names = append(names, n)
		}
		sort.Strings(names)
		if im.Selector == "" {
			refuse("%s has %d manifests and no selector was given; append :TAG, @DIGEST or --platform. Candidates: %s",
				where, len(cands), strings.Join(names, " "))
		}
		refuse("%s has %d manifests matching %q; narrow it with @DIGEST or --platform. Candidates: %s",
			where, len(cands), im.Selector, strings.Join(names, " "))
	}
	return cands[0], nil
}

func (im *Image) loadManifest() error {
	b, err := im.readBlob(im.ManifestDesc, "manifest")
	if err != nil {
		return err
	}
	im.ManifestRaw = b
	im.ManifestDigest = SHA256Hex(b)

	// One level of nesting. An OCI layout written by skopeo copy --all
	// has index.json holding a single entry that points at an image
	// INDEX blob, and the per-platform manifests hang off that. Refusing
	// here, which is what this used to do, means refusing every
	// multi-arch image anyone actually publishes.
	//
	// It is one level and not a loop on purpose. The spec permits an
	// index to reference an index to any depth, nobody writes that, and
	// a reader that follows arbitrary depth needs a cycle guard for a
	// case that has never been seen. Deeper than this is refused by
	// name, with the depth in the message.
	var probe struct {
		MediaType string          `json:"mediaType"`
		Manifests json.RawMessage `json:"manifests"`
	}
	_ = json.Unmarshal(b, &probe)
	if probe.MediaType == mtOCIIndex || probe.MediaType == mtDockerList || probe.Manifests != nil {
		if im.nested {
			refuse("%s is an index inside an index; ociv follows one level of nesting and this is two",
				im.ManifestDigest)
		}
		var inner Index
		if err := json.Unmarshal(b, &inner); err != nil {
			return invalidf("nested index %s: %w", im.ManifestDigest, err)
		}
		if len(inner.Manifests) == 0 {
			return invalidf("nested index %s has no manifests", im.ManifestDigest)
		}
		// The tag was already spent selecting this index out of
		// index.json, and the entries below it carry platforms rather
		// than ref.names. Selecting on the tag again would match
		// nothing and report the image broken.
		outer := im.Selector
		im.Selector = ""
		d, err := im.selectFrom(inner.Manifests, "the nested index "+im.ManifestDigest)
		im.Selector = outer
		if err != nil {
			return err
		}
		im.nested = true
		im.NestedIndexDigest = im.ManifestDigest
		im.ManifestDesc = d
		return im.loadManifest()
	}

	if err := json.Unmarshal(b, &im.Manifest); err != nil {
		return invalidf("manifest %s: %w", im.ManifestDigest, err)
	}
	m := &im.Manifest
	if m.SchemaVersion == nil {
		im.note("V013", "manifest", "no schemaVersion field")
	} else if *m.SchemaVersion != 2 {
		im.note("V013", "manifest", "schemaVersion is %d, spec requires 2", *m.SchemaVersion)
	}
	if m.MediaType != "" && m.MediaType != mtOCIManifest && m.MediaType != mtDockerManifest {
		im.note("V014", "manifest", "mediaType is %q, not an image manifest type", m.MediaType)
	}
	if cmt := m.Config.mt(); cmt != mtOCIConfig && cmt != mtDockerConfig {
		im.note("V015", "manifest.config", "mediaType is %q, expected %s", cmt, mtOCIConfig)
	}

	cb, err := im.readBlob(m.Config, "config")
	if err != nil {
		return err
	}
	im.ConfigRaw = cb
	if err := json.Unmarshal(cb, &im.Config); err != nil {
		return invalidf("config %s: %w", m.Config.dg(), err)
	}
	if im.Config.RootFS.Type != "layers" {
		im.note("V017", "config.rootfs", "type is %q, spec requires \"layers\"", im.Config.RootFS.Type)
	}
	if n := len(im.Config.RootFS.DiffIDs); n != len(m.Layers) {
		im.note("V018", "config.rootfs", "%d diff_ids for %d layers", n, len(m.Layers))
	}
	// history, when present, must have one non-empty_layer entry per
	// layer. Absent history is legal; a wrong one is not.
	if len(im.Config.History) > 0 {
		nonEmpty := 0
		for _, h := range im.Config.History {
			if !h.EmptyLayer {
				nonEmpty++
			}
		}
		if nonEmpty != len(m.Layers) {
			im.note("V020", "config.history", "%d history entries are not empty_layer, but there are %d layers", nonEmpty, len(m.Layers))
		}
	}
	return nil
}

// readBlob fetches a descriptor's bytes and checks them against the
// descriptor. Three separate claims are checked, because an image can get
// any one of them wrong on its own: the digest string is well-formed, the
// stored length is the length the descriptor states, and the content
// hashes to the digest.
func (im *Image) readBlob(d Descriptor, where string) ([]byte, error) {
	if d.Digest == nil {
		im.note("V007", where, "descriptor has no digest field")
		return nil, invalidf("%s: descriptor has no digest", where)
	}
	if d.Size == nil {
		im.note("V007", where, "descriptor has no size field")
	}
	if d.MediaType == nil {
		im.note("V007", where, "descriptor has no mediaType field")
	}
	dg, err := ParseDigest(d.dg())
	if err != nil {
		im.note("V008", where, "%v", err)
		return nil, invalidErr{err}
	}
	if !dg.Supported() {
		refuse("%s: digest algorithm %q is registered but not implemented; only sha256 is", where, dg.Alg)
	}
	rc, size, err := im.Src.open(d)
	if err != nil {
		im.note("V010", where, "blob %s cannot be opened: %v", d.dg(), err)
		return nil, invalidErr{err}
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		im.note("V010", where, "blob %s cannot be read: %v", d.dg(), err)
		return nil, invalidErr{err}
	}
	if d.Size != nil && *d.Size != int64(len(b)) {
		im.note("V011", where, "descriptor says %d bytes, blob %s is %d", *d.Size, d.dg(), len(b))
	}
	_ = size
	if got := SHA256Hex(b); got != dg.S {
		im.note("V012", where, "blob content is %s, descriptor says %s", got, dg.S)
	}
	return b, nil
}

// blobReader streams a blob without holding it in memory, for the layer
// paths where the blob can be large. The digest is verified as a side
// effect by the caller, which is why this returns the reader rather than
// the bytes.
func (im *Image) blobReader(d Descriptor) (io.ReadCloser, error) {
	rc, _, err := im.Src.open(d)
	return rc, err
}
