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

- [x] Repository skeleton: go.mod, Makefile, LICENSE, .gitignore, this file
      why: the collection's gate runs `make`, and a repo without a PLAN.md
      is not a member of the set at all.
- [x] Digest parsing and verification, with the grammar from the spec
      why: everything else is downstream of "is this digest string even
      well-formed", and the spec's grammar for the algorithm and the encoded
      portion is stricter than "contains a colon". A reader that accepts
      `sha256:ABCD` has already lost, because the same blob then has two
      spellings and the layout path will not resolve.
- [x] OCI image layout reader: oci-layout, index.json, blobs
      why: the layout document is short and precise, and the failure mode of
      getting it wrong is reading somebody else's blob.
- [x] Manifest and config parsing with spec validation, and `ociv info`
      why: the first point at which skopeo can be asked whether we agree.

### Milestone 1: the oracles, before the interesting code

- [x] Corpus builder: images with every construct, built with tar and python
      why: a test for whiteouts written before a corpus containing whiteouts
      passes vacuously, and the corpus is the thing that takes longest to
      get right.
- [x] `t/run.sh` with the three-way digest comparison against skopeo and
      sha256sum
      why: the first external agreement. Until it exists every number in
      this repository is self-reported.
- [x] `ociv stats` and the vacuity floor in the harness
      why: the harness must assert the corpus contains what the tests need
      before the tests run, and print the counts so a reader can see them.

### Milestone 2: layers, entry by entry

- [x] Tar entry reader and `ociv layers`
      why: this is where GNU tar becomes the oracle, and the comparison is
      per entry because "the images differ" is not a finding.
- [x] GNU tar comparison for every entry field, including mode and linkname
      why: a reader that gets the size right and the mode wrong passes any
      comparison that only counts entries, and the mode is the field the
      security half of this program depends on.
- [x] PAX and GNU long-name handling, checked against tar
      why: a path longer than 100 bytes is the normal case in a real image
      and the two formats encode it differently.
- [x] Hard link resolution within a layer
      why: a hard link entry has size 0 and the content of its target, so a
      reader that believes the header reports an empty file for every
      hardlinked binary in the image.
- [x] Gzip-compressed layers, and the diff_id vs digest distinction
      why: the manifest's digest is over the compressed bytes and the
      config's diff_id is over the uncompressed bytes. Conflating them is
      the single most common bug in home-grown image readers, and it is
      invisible on an uncompressed corpus.

### Milestone 3: the merged filesystem

- [x] Whiteout application and `ociv tree`
      why: the point of the program. The rule that whiteouts apply only to
      lower layers, never to the layer they appear in, is the part that
      implementations get wrong.
- [x] Opaque directory handling
      why: `.wh..wh..opq` deletes the lower layers' contents of a directory
      while leaving the directory and the current layer's contents, which is
      three separate behaviours in one marker.
- [x] Directory whiteout removes the whole subtree
      why: whiteouting a directory and leaving its children behind produces
      a tree with orphans, and nothing below the top level would notice.
- [x] The Python second implementation of the merge, and the comparison
      why: there is no external tool on this machine that applies whiteouts,
      so the honest substitute is a second implementation against the spec
      text in another language, clearly labelled as weaker than skopeo.
- [x] Sequential GNU tar extraction as the oracle for the non-whiteout half
      why: for everything except whiteouts, "layer N overwrites layer N-1"
      is exactly what `tar -x` into one directory does, and that is an
      external authority rather than a second opinion.

### Milestone 4: the security report

- [x] setuid and setgid detection, per layer, with the introducing layer named
      why: "the image has a setuid binary" is not actionable; "layer 3
      introduced /usr/bin/foo with mode 4755" is.
- [x] Deleted-but-still-in-the-blob detection
      why: this is the finding the program exists for. `RUN rm /secrets`
      does not remove the bytes from the published image, and a reader that
      only reports the merged tree cannot see it.
- [x] Overwritten-but-still-in-the-blob detection
      why: the same leak with a different shape. Replacing a file's contents
      in a later layer publishes both versions, and the first one is the one
      with the credential in it.
- [x] Extended attribute capabilities
      why: `security.capability` is setuid with better PR, and it travels in
      a PAX record that most tar listings never print.
- [x] World-writable paths and missing sticky bits on world-writable dirs
      why: cheap to compute, and the sticky-bit distinction is the one that
      separates a finding from noise.
- [x] Device nodes and path escape attempts
      why: a layer entry named `../../etc/shadow` is a supply-chain attack
      on whatever unpacks it.
      done: reported, not refused, and this item used to say refusing was
      the only correct answer. It is not. The image is well-formed: every
      digest matches and the spec does not forbid the member name. Exit 3
      means "ociv cannot describe this image", and ociv can describe this
      one exactly; refusing would withhold the description a reader came
      for.
      correction: this used to end "the entry is reported and kept out of
      the merged tree", which was never true of a member NAME that
      escapes. ociv puts all three spellings at their normalised paths.
      GNU tar, measured: a leading slash is stripped and the member lands
      inside the root, which ociv matches, and a name containing dot-dot
      is refused by name and nothing is written, which ociv does not. See
      the next item.
- [x] Symlinked parent directories, the three cases kept apart
      why: GNU tar 1.35 extracting `./bin/newfile` into a tree where `bin`
      is already a symlink to `usr/bin` writes `usr/bin/newfile`. Measured,
      exit 0, symlink left alone. So a layer puts a file somewhere other
      than where its name says whenever an earlier layer left a symlink in
      the way, and a reader taking member names literally reports a tree
      no unpacker produces.
      done: a relative target resolves against the symlink's directory, an
      absolute one against the image root, and one climbing past the root
      is an escape that is reported and dropped. Whiteout targets go
      through the same resolution, so `bin/.wh.existing` deletes
      `usr/bin/existing`.
- [x] What GNU tar does with an escaping symlinked parent, measured
      why: the claim "tar would write outside the root" is the reason the
      finding exists, and an unmeasured claim of that shape has been wrong
      in this collection before.
      done: a contained one-level fixture, extracted for real. Exit 0, no
      diagnostic, file written outside the extraction root, symlink left
      in place. GNU tar does not stop it and does not mention it.

### Milestone 5: the harness earns its keep

- [x] The mutation suite: deliberate defects, each expected to turn a named
      assertion red
      why: a test that has never been watched to fail is not evidence.
- [x] A per-layer leak summary, counted and printed
      why: a leak buried among two hundred audit lines is a leak nobody
      reads. The count per layer is the line that gets noticed.
      done: one "audit leak layer=N deleted=D shadowed=S bytes=B" line
      per layer that is still publishing removed content, with the two
      kinds counted apart. Six layers across the corpus produce one.
- [x] Name the blob a leaked file's bytes are still in, and where
      why: "layer 0 still holds etc/secrets.txt" is a sentence. "the
      bytes are at offset N of sha256:abcd..., 41 of them" is something
      a reader can act on, and something GNU tar can be asked to confirm
      by extracting the same member and comparing.
      done: blob= and comp= on every deleted, shadowed and leak line.
      The dd check opens the blob the finding names rather than a
      tarball the harness kept, and inflates it when comp says gzip, so
      26 leaks are confirmed against the published bytes and 10 of them
      go through the compressed path. GNU tar confirming the same member
      is ociv cat, measured against tar -P -xOf.
- [ ] A credential-shaped fixture for the leak, deleted by a later layer
      why: the finding this program exists for has been tested on files
      called "secrets.txt" containing the word secret. The shape that
      matters is a token and a private key header, and the corpus should
      hold one of each so the output can be looked at and believed.
      so far: the token is in etc/config.ini, which layer 1 OVERWRITES,
      and the suite pulls it back out and looks at it. The PEM header is
      in home/user/.ssh/id_rsa, which nothing deletes. So the deleted
      half of the finding has no credential-shaped fixture behind it.
- [ ] Record the survivors, with the argument for each
      why: an honest mutation score needs its denominator and its
      exceptions written down, not rounded away.
- [x] Malformed-input sweep: truncation and corruption at every stride
      why: an image is attacker-controlled data in any tool that reads one
      from a stranger, and the failure mode to rule out is a panic, not a
      wrong answer.
- [x] A refusal is checked by the oracle too
      why: ociv rejecting a valid image is the failure mode a
      refusal-counting harness is blind to. Every refusal must be paired
      with skopeo's verdict on the same bytes.
- [ ] README with the measured numbers and the honest limitations
      why: written last so the limitations are observed rather than guessed.

### Milestone 6: what is left

- [x] Zstd layers
      why: `application/vnd.oci.image.layer.v1.tar+zstd` is in the spec and
      Go's standard library has no zstd. Refused with a diagnostic naming
      the media type, which is the honest answer; implementing zstd is a
      different project.
- [x] Non-sha256 digest algorithms
      why: the spec permits sha512 and registered others. Refused by name.
- [x] Multi-platform index traversal
      why: a real index selects by platform, and the platform matching rules
      are their own small specification.
      done: --platform over a flat three-architecture index and over a
      nested one, checked against skopeo --override-arch. One level of
      nesting is followed and two is refused. os.version and os.features
      are parsed and ignored, which is written down in the README.
- [x] --platform before the command, which did not work
      why: nine assertions about platform selection and every one of
      them spelled the invocation the same way, so the other spelling
      was never run.
      done: run() read os.Args over again instead of the
      list parsePlatform returned, so the flag only worked when it came
      after the command, and every test spelled it that way.
- [ ] Content comparison of shadowed files across layers
      why: reporting that a path was overwritten is weaker than reporting
      that the bytes differ, and weaker still than reporting what the old
      bytes were.
      so far: delta=content, delta=mode and delta=content+mode are
      reported, with both digests, and the suite asserts delta=mode
      really does mean the digests are equal. The old bytes themselves
      still have to be fetched with dd.

### Milestone 7: what writing the README turned up

- [x] Print the aggregate per-entry counts the README quotes
      why: the README says 198 member tuples were compared against GNU
      tar and the suite says "ok multi layer 0 entries". Those are the
      same fact and only one of them is in the output, so the number in
      the README is one somebody counted by hand once.
      done: seven totals with a floor each, and a refused column that
      counts the 25 members of a layer relabelled tar+zstd.
- [x] A member reader, with "tar -xOf" as the oracle
      why: the leak findings give an offset and a digest and the way to
      see the bytes is dd. GNU tar can extract one member by name to
      stdout, which is an external authority for the whole path from
      member name to bytes, and it is the thing that makes the shadowed
      content comparison above possible.
      done: ociv cat IMAGE LAYER PATHHEX, 60 members compared against
      tar -P -xOf. Two differences measured rather than averaged: tar
      writes both members of a duplicated path and cat gives the last,
      and GNU tar without -P will not name a member containing dot-dot
      at all.
- [ ] A dangling hard link in the corpus
      why: the census counts hardlink-dangling and it is 0, so the
      branch that handles a link whose target is not in the layer has
      never been reached by a test. GNU tar has an opinion about such an
      archive and it has not been asked.
- [ ] A whiteout marker that hits nothing
      why: whiteout-hit-nothing is 0 for the same reason. A marker for a
      path no lower layer holds is legal, common in squashed images, and
      must not be reported as a deletion of something.
- [ ] What GNU tar does when the layer also names the symlinked parent
      why: the measured case has a layer writing ./bin/newfile where an
      earlier layer left bin as a symlink, and no ./bin/ member. A layer
      that names the directory too is the case where tar may replace the
      symlink instead of following it, and the answer changes which path
      the file lands at.
- [ ] Drop a dot-dot member from the merged tree, as GNU tar does
      why: measured now. GNU tar 1.35 sanitises the name it was given,
      finds dot-dot still in it, prints "Member name contains dot-dot",
      writes nothing and exits 2. ociv puts the member at the path the
      dot-dot resolves to, so the merged tree holds etc/shadow and
      root/.ssh/authorized_keys and no unpacker produces either. The
      contract says tree never reports a path no layer contains; it
      should also never report a path no unpacker writes.
- [ ] A hard link whose target is not in the image
      why: the census counts hardlink-dangling and it is 0. GNU tar's
      answer is measured already, as a side effect of the above: it
      cannot make the link, says Cannot hard link, and leaves the path
      absent. ociv keeps the entry with the header's size of 0.
- [ ] Put ociv's diagnostic code in the skopeo verdict table
      why: the table prints "skopeo=accept ociv=reject" for nineteen
      images and the reason is in neither column, so the README had to
      carry a hand-written third column saying which spec clause each
      one breaks.
