package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// A Digest is an OCI content descriptor digest: an algorithm, a colon, and
// an encoded value. Kept as the original string as well as its parts,
// because the manifest's bytes are what gets hashed and the spelling in
// those bytes is what the layout path is built from. Re-rendering a digest
// from its parts and using that to open a file is how a reader ends up
// looking in the wrong place for a blob whose algorithm had an uppercase
// letter in it.
type Digest struct {
	S   string // exactly as it appeared
	Alg string // the part before the colon
	Enc string // the part after it
}

// The grammar, from the OCI image-spec descriptor document:
//
//	digest              ::= algorithm ":" encoded
//	algorithm           ::= algorithm-component (algorithm-separator algorithm-component)*
//	algorithm-component ::= [a-z0-9]+
//	algorithm-separator ::= [+._-]
//	encoded             ::= [a-zA-Z0-9=_-]+
//
// Written out by hand rather than as a regexp so the diagnostic can name the
// offending byte and its position. A reader that reports "invalid digest"
// and nothing else turns a one-character typo into a bisection.

func isAlgComponentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isAlgSeparator(c byte) bool {
	return c == '+' || c == '.' || c == '_' || c == '-'
}

func isEncodedByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '=' || c == '_' || c == '-'
}

// ParseDigest validates against the grammar above and, for the two
// registered algorithms, against their stated encoding as well. The spec
// requires sha256 and sha512 to be lowercase hex of a fixed length; the
// general grammar permits far more than that, and a reader that only
// applies the general grammar will happily accept sha256:FOO and then fail
// to find the blob, with a diagnostic about a missing file rather than
// about the digest that was wrong.
func ParseDigest(s string) (Digest, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return Digest{}, fmt.Errorf("digest %q has no algorithm separator", s)
	}
	alg, enc := s[:i], s[i+1:]
	if alg == "" {
		return Digest{}, fmt.Errorf("digest %q has an empty algorithm", s)
	}
	// An algorithm is components joined by separators: no leading
	// separator, no trailing one, and no two in a row.
	prevSep := true // a separator cannot be first
	for j := 0; j < len(alg); j++ {
		c := alg[j]
		switch {
		case isAlgComponentByte(c):
			prevSep = false
		case isAlgSeparator(c):
			if prevSep {
				return Digest{}, fmt.Errorf("digest %q: algorithm separator %q at offset %d is not between two components", s, string(c), j)
			}
			prevSep = true
		default:
			return Digest{}, fmt.Errorf("digest %q: byte %q at offset %d is not legal in an algorithm", s, string(c), j)
		}
	}
	if prevSep {
		return Digest{}, fmt.Errorf("digest %q: algorithm ends with a separator", s)
	}
	if enc == "" {
		return Digest{}, fmt.Errorf("digest %q has an empty encoded portion", s)
	}
	for j := 0; j < len(enc); j++ {
		if !isEncodedByte(enc[j]) {
			return Digest{}, fmt.Errorf("digest %q: byte %q at offset %d is not legal in the encoded portion", s, string(enc[j]), i+1+j)
		}
	}
	d := Digest{S: s, Alg: alg, Enc: enc}
	// Registered algorithms carry an extra requirement that the general
	// grammar does not express.
	if n, ok := registeredHexLen[alg]; ok {
		if len(enc) != n {
			return Digest{}, fmt.Errorf("digest %q: %s requires %d hex characters, got %d", s, alg, n, len(enc))
		}
		for j := 0; j < len(enc); j++ {
			c := enc[j]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return Digest{}, fmt.Errorf("digest %q: %s requires lowercase hex, byte %q at offset %d is not", s, alg, string(c), i+1+j)
			}
		}
	}
	return d, nil
}

// The algorithms the spec registers, and the length of their hex encoding.
// Anything else parses as a well-formed digest and is refused at the point
// where a hash would have to be computed, because "I cannot check this" and
// "this is malformed" are different answers.
var registeredHexLen = map[string]int{
	"sha256": 64,
	"sha512": 128,
}

// Supported reports whether ociv can actually compute this algorithm. Only
// sha256 is implemented. sha512 is a registered algorithm we parse and
// refuse, which is deliberately not the same as rejecting it.
func (d Digest) Supported() bool { return d.Alg == "sha256" }

// New returns a fresh hash for the digest's algorithm.
func (d Digest) New() (hash.Hash, error) {
	if d.Alg != "sha256" {
		return nil, fmt.Errorf("digest algorithm %q is not implemented", d.Alg)
	}
	return sha256.New(), nil
}

// VerifyReader streams r through the digest's hash and reports the byte
// count and whether the result matched. It returns the computed digest
// either way, because "it did not match" without saying what it was is a
// diagnostic that cannot be acted on.
func (d Digest) VerifyReader(r io.Reader) (n int64, got string, err error) {
	h, err := d.New()
	if err != nil {
		return 0, "", err
	}
	n, err = io.Copy(h, r)
	if err != nil {
		return n, "", err
	}
	got = d.Alg + ":" + hex.EncodeToString(h.Sum(nil))
	return n, got, nil
}

// Matches compares two digest strings. The comparison is over the exact
// bytes: the encoded portion of sha256 is required by the spec to be
// lowercase hex, so there is no case folding to do, and folding anyway
// would mean accepting a spelling the layout path cannot resolve.
func (d Digest) Matches(got string) bool { return d.S == got }

// SHA256Hex is the one-line form used where the result is wanted as a
// digest string rather than as a verification.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
