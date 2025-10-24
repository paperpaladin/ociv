# PLAN

## Contract

```
ociv info   IMAGE          header facts: media types, manifest/config digests, layer roster
ociv verify IMAGE          structure and every digest, against the OCI image-spec
ociv layers IMAGE          every tar entry of every layer, one fact per line
ociv tree   IMAGE          the merged root filesystem after whiteouts are applied
ociv audit  IMAGE          the security-relevant facts, one finding per line
ociv stats  IMAGE          how many of each construct the image actually contains
```

`IMAGE` is either a directory holding an OCI image layout (`oci-layout`,
`index.json`, `blobs/<alg>/<hex>`) or a `docker save` style tar
(`manifest.json` plus per-layer directories). A `:tag` or `@sha256:...`
suffix selects one manifest out of a multi-entry index; with no suffix and
more than one entry, ociv refuses rather than guessing.

Pure Go, standard library only. `go.mod` has no require block and the build
runs with `GOPROXY=off`, so a third-party import is a build failure and not a
download. `skopeo`, GNU `tar`, `sha256sum` and `python3` are used by the test
harness and by nothing else.

Exit status, and the three are distinct because the harness counts them
separately:

```
0   the image is well-formed and every digest matched
1   WRONG: the image is invalid -- a digest mismatch, a size mismatch,
      a missing blob, a structural violation of the spec
2   usage error, or the path cannot be read
3   REFUSAL: ociv does not implement what this image needs and says so,
      rather than guessing. Compressed layer media types it has no
      decompressor for, a manifest list with no selector, a digest
      algorithm other than sha256.
```

Output is one fact per line, fields separated by single spaces, stable
ordering, never a table. The harness compares extracted facts as sets or as
ordered lists; it never diffs rendered text against another tool's rendering.

What must not break: `ociv tree` never reports a path that no layer
contains, and `ociv audit` never reports a deleted-file finding for a path
that was not actually removed by a whiteout.

## Hard invariant

**Every digest ociv computes agrees with `sha256sum` and with `skopeo`, every
tar entry fact agrees with GNU tar, and a layer ociv accepts is one GNU tar
also accepts.**

Concretely, and checked by `make test`:

- For every image in the corpus, the manifest digest printed by `ociv info`
  is byte-identical to `skopeo manifest-digest` over the same manifest bytes,
  and to `sha256sum` over the same bytes. Three independent computations of
  one number.
- Every blob digest and size in the manifest is confirmed by `sha256sum` and
  by `wc -c` on the blob file, and by `skopeo copy` refusing the image when
  either is corrupted. skopeo refusing is the half that proves the corruption
  was real and not merely something ociv dislikes.
- For every layer, the set of (path, typeflag, mode, uid, gid, size,
  linkname) tuples from `ociv layers` equals the set GNU tar reports for the
  same blob, entry for entry. Not "the same number of entries".
- The merged tree from `ociv tree` equals the tree produced by extracting the
  layers in order with GNU tar and then applying the whiteout rules with a
  second implementation written in Python against the spec text, not against
  ociv.
- Every construct the corpus is supposed to contain is counted and the count
  asserted nonzero before the test that depends on it runs. A whiteout test
  over a corpus with no whiteouts passes while checking nothing.
- A REFUSAL is never counted as a pass and never as a wrong answer. The
  harness asserts the exit status and the diagnostic separately.

## Oracle

Ranked, by how little of it we control:

1. **`skopeo` 1.18.0.** An independent Go implementation of the same
   specification, written by other people and shipped to every Linux
   container user. `skopeo inspect --raw` for the manifest bytes,
   `skopeo manifest-digest` for the digest of those bytes, `skopeo inspect`
   for the cooked config facts, and `skopeo copy oci: docker-archive:` for a
   conversion that fails loudly when a blob does not match its digest. Where
   we disagree about a manifest, we are wrong.
2. **GNU tar 1.35.** The authority on what a tar archive contains. `tar -tv`,
   `tar --to-command`, and real extraction into a scratch directory. The
   layer format is a tar and every argument about what a layer "contains"
   ends at what tar says it contains.
3. **`sha256sum` from coreutils.** A third implementation of SHA-256, so the
   digest claim does not rest on Go's `crypto/sha256` alone.
4. **`python3` with `hashlib` and `tarfile`.** A second implementation of the
   parts no external tool covers: whiteout application, the merged tree, and
   the deleted-file-still-in-the-blob search. Written against the OCI
   image-spec text in a different language. It is a second opinion, not a
   second source, and the README says so.
5. **The corpus.** Built here with GNU tar and assembled by hand from the
   spec, with deliberate constructs: whiteouts, opaque directories, hard
   links, symlinks, setuid and setgid bits, sticky bits, xattrs, duplicate
   paths across layers, a file deleted in a later layer, a file overwritten
   by a later layer, device nodes, and paths that try to escape the root.
   Nothing is downloaded; no network is assumed.
6. **Deliberate defects in ociv itself.** Each mutation must turn a *named*
   assertion red. Survivors are recorded in the README, with the argument for
   why each is equivalent.

## Non-goals

- Signatures, attestations, SBOMs, Sigstore, Notary. No key material, no
  trust decisions. ociv answers "do these bytes hash to what the manifest
  says", which is a different and smaller question.
- Running or building images. There is no OCI runtime here.
- Registries and the distribution spec. Everything is local bytes. No
  network is assumed and none is used.
- Writing or rewriting images. Read-only, always.
- Vulnerability scanning. ociv reports what files exist and what bits are
  set on them. It has no CVE database and would be lying if it claimed one.
- Being a library. It is a program with a line-oriented output.

## Commit sequence

### Milestone 0: the shape

- [ ] Repository skeleton: go.mod, Makefile, LICENSE, .gitignore, this file
      why: the collection's gate runs `make`, and a repo without a PLAN.md
      is not a member of the set at all.
- [ ] Digest parsing and verification, with the grammar from the spec
      why: everything else is downstream of "is this digest string even
      well-formed", and the spec's grammar for the algorithm and the encoded
      portion is stricter than "contains a colon". A reader that accepts
      `sha256:ABCD` has already lost, because the same blob then has two
      spellings and the layout path will not resolve.
- [ ] OCI image layout reader: oci-layout, index.json, blobs
      why: the layout document is short and precise, and the failure mode of
      getting it wrong is reading somebody else's blob.
- [ ] Manifest and config parsing with spec validation, and `ociv info`
      why: the first point at which skopeo can be asked whether we agree.

### Milestone 1: the oracles, before the interesting code

- [ ] Corpus builder: images with every construct, built with tar and python
      why: a test for whiteouts written before a corpus containing whiteouts
      passes vacuously, and the corpus is the thing that takes longest to
      get right.
- [ ] `t/run.sh` with the three-way digest comparison against skopeo and
      sha256sum
      why: the first external agreement. Until it exists every number in
      this repository is self-reported.
- [ ] `ociv stats` and the vacuity floor in the harness
      why: the harness must assert the corpus contains what the tests need
      before the tests run, and print the counts so a reader can see them.

### Milestone 2: layers, entry by entry

- [ ] Tar entry reader and `ociv layers`
      why: this is where GNU tar becomes the oracle, and the comparison is
      per entry because "the images differ" is not a finding.
- [ ] GNU tar comparison for every entry field, including mode and linkname
      why: a reader that gets the size right and the mode wrong passes any
      comparison that only counts entries, and the mode is the field the
      security half of this program depends on.
- [ ] PAX and GNU long-name handling, checked against tar
      why: a path longer than 100 bytes is the normal case in a real image
      and the two formats encode it differently.
- [ ] Hard link resolution within a layer
      why: a hard link entry has size 0 and the content of its target, so a
      reader that believes the header reports an empty file for every
      hardlinked binary in the image.
- [ ] Gzip-compressed layers, and the diff_id vs digest distinction
      why: the manifest's digest is over the compressed bytes and the
      config's diff_id is over the uncompressed bytes. Conflating them is
      the single most common bug in home-grown image readers, and it is
      invisible on an uncompressed corpus.

### Milestone 3: the merged filesystem

- [ ] Whiteout application and `ociv tree`
      why: the point of the program. The rule that whiteouts apply only to
      lower layers, never to the layer they appear in, is the part that
      implementations get wrong.
- [ ] Opaque directory handling
      why: `.wh..wh..opq` deletes the lower layers' contents of a directory
      while leaving the directory and the current layer's contents, which is
      three separate behaviours in one marker.
- [ ] Directory whiteout removes the whole subtree
      why: whiteouting a directory and leaving its children behind produces
      a tree with orphans, and nothing below the top level would notice.
- [ ] The Python second implementation of the merge, and the comparison
      why: there is no external tool on this machine that applies whiteouts,
      so the honest substitute is a second implementation against the spec
      text in another language, clearly labelled as weaker than skopeo.
- [ ] Sequential GNU tar extraction as the oracle for the non-whiteout half
      why: for everything except whiteouts, "layer N overwrites layer N-1"
      is exactly what `tar -x` into one directory does, and that is an
      external authority rather than a second opinion.

### Milestone 4: the security report

- [ ] setuid and setgid detection, per layer, with the introducing layer named
      why: "the image has a setuid binary" is not actionable; "layer 3
      introduced /usr/bin/foo with mode 4755" is.
- [ ] Deleted-but-still-in-the-blob detection
      why: this is the finding the program exists for. `RUN rm /secrets`
      does not remove the bytes from the published image, and a reader that
      only reports the merged tree cannot see it.
- [ ] Overwritten-but-still-in-the-blob detection
      why: the same leak with a different shape. Replacing a file's contents
      in a later layer publishes both versions, and the first one is the one
      with the credential in it.
- [ ] Extended attribute capabilities
      why: `security.capability` is setuid with better PR, and it travels in
      a PAX record that most tar listings never print.
- [ ] World-writable paths and missing sticky bits on world-writable dirs
      why: cheap to compute, and the sticky-bit distinction is the one that
      separates a finding from noise.
- [ ] Device nodes and path escape attempts
      why: a layer entry named `../../etc/shadow` is a supply-chain attack
      on whatever unpacks it, and the only correct answer is to refuse.

### Milestone 5: the harness earns its keep

- [ ] The mutation suite: deliberate defects, each expected to turn a named
      assertion red
      why: a test that has never been watched to fail is not evidence.
- [ ] Record the survivors, with the argument for each
      why: an honest mutation score needs its denominator and its
      exceptions written down, not rounded away.
- [ ] Malformed-input sweep: truncation and corruption at every stride
      why: an image is attacker-controlled data in any tool that reads one
      from a stranger, and the failure mode to rule out is a panic, not a
      wrong answer.
- [ ] A refusal is checked by the oracle too
      why: ociv rejecting a valid image is the failure mode a
      refusal-counting harness is blind to. Every refusal must be paired
      with skopeo's verdict on the same bytes.
- [ ] README with the measured numbers and the honest limitations
      why: written last so the limitations are observed rather than guessed.

### Milestone 6: what is left

- [ ] Zstd layers
      why: `application/vnd.oci.image.layer.v1.tar+zstd` is in the spec and
      Go's standard library has no zstd. Refused with a diagnostic naming
      the media type, which is the honest answer; implementing zstd is a
      different project.
- [ ] Non-sha256 digest algorithms
      why: the spec permits sha512 and registered others. Refused by name.
- [ ] Multi-platform index traversal
      why: a real index selects by platform, and the platform matching rules
      are their own small specification.
- [ ] Content comparison of shadowed files across layers
      why: reporting that a path was overwritten is weaker than reporting
      that the bytes differ, and weaker still than reporting what the old
      bytes were.
