# ociv

Reads an OCI image layout directory or a `docker save` tar, checks every
digest in it against the image-spec, lists every tar member of every layer,
applies the whiteout rules to produce the merged root filesystem, and reports
what the published layers still carry that the merged filesystem does not
show. Go, standard library only, no `require` block in `go.mod`.

```
ociv info   IMAGE    media types, manifest and config digests, layer roster
ociv verify IMAGE    structure and every digest, against the OCI image-spec
ociv layers IMAGE    every tar entry of every layer, one fact per line
ociv tree   IMAGE    the merged root filesystem after whiteouts are applied
ociv audit  IMAGE    the security-relevant findings, one per line
ociv stats  IMAGE    how many of each construct the image contains
ociv cat    IMAGE LAYER PATHHEX   one member's bytes, to stdout
```

`IMAGE` takes a `:TAG` or `@sha256:HEX` suffix to pick one manifest out of an
index, and `--platform linux/arm64` to pick by platform. Exit 0 is a clean
image, 1 an invalid one, 2 a usage error, 3 a refusal: something in the image
ociv does not implement and will not guess at.

Paths are printed hex-encoded, in a `phex=` field. A tar member name can hold
a space, a tab or a newline, the corpus has all three on purpose, and a
line-oriented format that prints such a name raw stops being line-oriented.

`make test` builds and runs the suite. It needs `skopeo`, GNU `tar`,
`sha256sum` and `python3`, and exits 2 without any one of them rather than
reporting a smaller number having checked less.

## What it is measured against

No number here was worked out by hand. Every assertion compares ociv with
something ociv did not produce.

`skopeo` 1.18.0 is an independent Go implementation of the same
specification. `skopeo inspect --raw` gives the manifest bytes and `skopeo
manifest-digest` the digest of them; `skopeo copy oci: dir:` is the verdict,
run over every image in the corpus, good and broken, so that ociv's answer
can be set beside skopeo's on the same bytes; `skopeo copy oci:
docker-archive:` writes the other container format for the one image read
that way; and `skopeo --override-arch inspect` picks a platform out of a
nested index.

GNU `tar` 1.35 is the authority on what a layer contains. The entry
comparison is against `tar -tv`, and the merge comparison is against tar
actually extracting the layers into a directory, which is a statement about
what tar did rather than an argument about what the spec says.

`sha256sum` from coreutils 9.7 is a third implementation of SHA-256, so the
digest claim does not rest on Go's `crypto/sha256` alone.

Python 3.13 with `hashlib` and `tarfile` is a second implementation of the
parts no external tool covers: the whiteout rules, the merged tree, the
audit, and the construct census. It is a second opinion rather than a second
source, written here, in this repository, against the spec text. It is the
weakest oracle in the list and it is the only one for whiteouts, because
nothing installed on this machine applies them.

The corpus is weaker still, because we wrote all of it.

## Numbers

Measured on 20 October 2026. `make test` prints all of them.

| what | measured |
|---|---|
| assertions | 473 passed, 0 failed |
| manifest digests | 14 images, ociv against skopeo and against sha256sum, 0 differ |
| blob digests and sizes | 55 blobs against `sha256sum` and `wc -c`, 0 differ |
| tar member tuples against GNU tar | 198 compared, 198 same, 0 differ, 25 refused |
| the same tuples against python tarfile | 198 compared, 198 same, 0 differ |
| member data offsets, and the bytes found at them | 86 members, 0 differ, 76 of them non-empty |
| merged trees against the Python merge | 118 nodes over 14 images, 0 differ |
| merged trees against GNU tar extracting the layers | 99 nodes over 11 images, 0 differ |
| audit findings against the Python audit | 55 findings over 14 images, 0 differ |
| construct counts against the Python census | 364 counts over 14 images, 0 differ |
| member bytes against `tar -P -xOf` | 60 members, 0 differ, 2 duplicate paths apart |
| leaked files pulled back out of the blob with `dd` | 16 |
| broken images where skopeo also refuses | 8 of 19 |
| malformed images in `make test` | 316 runs, 313 rejected, 0 crashed, 0 hung |
| malformed images in `make sweep` | 26,660 runs, 26,492 rejected, 0 crashed, 0 hung |
| mutants | 53 planted, 51 caught, 2 equivalent survivors |

The tuple compared per member is (type, mode, uid, gid, size, name, link),
with the name in hex. Not the number of entries: a reader that gets the size
right and the mode wrong agrees with any comparison that only counts, and
mode is the field the audit rests on.

Refusals are counted apart from disagreements, because they need different
work. A disagreement is a bug. A refusal is a feature that is not written.
The 25 in the first row are the members of one layer: `bad-zstd-layer` is
`multi` with layer 0's media type relabelled `tar+zstd` and the bytes left
alone, so GNU tar lists all 25 members of it and ociv declines to read any.
That image is in the corpus so the refused column counts something; a
column that can only ever print zero is decoration.

The other refusals are whole-image, there are five shapes of them, and each
is put to skopeo on the same bytes:

```
a zstd layer               skopeo accepts, ociv exits 3
a sha512 descriptor        skopeo accepts, ociv exits 3
an unregistered algorithm  skopeo rejects, ociv exits 3
an index with several candidates and no selector   ociv exits 3
an index nested two levels deep                    ociv exits 3
```

The first two are the ones that matter: skopeo reads those images and ociv
does not, which is a hole and is recorded as one rather than as caution. A
refusal is never counted as a pass and never as a wrong answer; the harness
asserts the status and the diagnostic separately.

## The leak

`RUN rm /secrets` removes nothing from a published image. The layer that
wrote the file is still in the manifest, still has its digest, and still
holds the bytes; all the later layer contributes is a `.wh.` marker saying
the path is not in the merged filesystem. Overwriting has the same shape:
replacing a config file in a later build step publishes both versions, and
the one with the credential in it is the first.

`ociv audit` reports each one with the layer that still holds the bytes, the
layer that removed them, the size, and the offset of the data in the
uncompressed layer stream:

```
audit deleted  layer=0 by=2 size=61 off=3584  content=sha256:f0892cc6... phex=6574632f736563726574732e747874
audit shadowed layer=0 by=1 delta=content size=55 off=1536 content=sha256:f5a3872f... new=sha256:7832b17b... newmode=0644 phex=6574632f636f6e6669672e696e69
audit leak     layer=0 deleted=6 shadowed=4 bytes=243
```

The offset is there so the finding can be checked rather than believed. The
suite does check it, for all 16 leaked files in the uncompressed images: it
reads `size` bytes from `off` in the layer tarball with `dd`, hashes them
with `sha256sum`, and requires the result to be the digest the finding
names. For `etc/config.ini` it goes further and looks at
what came back, which is the token the merged tree's copy of that path no
longer has.

`ociv cat IMAGE LAYER PATHHEX` writes that member's bytes to stdout, taking
the `phex` field straight off the finding. The path is hex because a member
name may hold a newline and no shell argument survives one. GNU tar writing
the same member with `tar -P -xOf` is the oracle, over all 60 non-duplicated
file members of the corpus.

Two differences there, both pinned rather than smoothed over. A path a layer
names twice: `tar -xOf` by name writes both members one after the other and
`ociv cat` gives the last, which is what extraction leaves on disk. And GNU
tar rewrites the member name it was given before matching, so without `-P`
it refuses `../etc/shadow` with "Member name contains '..'", exit 2, while
the sanitised `etc/shadow` is not in the archive at all. The three escaping
members of the corpus cannot be asked for by name without the flag. ociv has
no such rule and serves what the header says, which is the answer a tool
looking for a supply-chain attack needs.

The `leak` line is one per layer that is still publishing removed content,
with the two counts kept apart, because a leak buried in two hundred audit
lines is a leak nobody reads. Six layers across the corpus produce one.

`delta` separates a layer that changed the bytes from one that only changed
the mode, and the suite asserts both appear and that `delta=mode` really does
mean the two digests are equal. Without that distinction every rebuilt layer
reads as a second copy of the document.

## Symlinked parent directories

A layer entry named `./bin/newfile`, extracted into a tree where an earlier
layer left `bin` as a symlink to `usr/bin`, does not land at `bin/newfile`.
GNU tar 1.35 writes it at `usr/bin/newfile`, exit 0, no diagnostic, and the
symlink is left in place rather than replaced by a directory. Measured, with
the extraction done for real and the result read back with `os.lstat`. The
layer naming the file does not also name `./bin/` as a directory member,
which is the case that makes tar follow the symlink; what tar does when the
layer names the directory too is not measured here.

So a reader that takes member names literally reports a filesystem no
unpacker produces. ociv resolves a symlinked ancestor the way tar does: a
relative target against the symlink's own directory, an absolute one against
the image root. Whiteout targets go through the same resolution, so
`bin/.wh.existing` deletes `usr/bin/existing` and the suite asserts it is
reported at the resolved path.

The case worth measuring is the one where the symlink leaves the root. A
layer holding `out -> ..` and a member `./out/escaped` is a layer that writes
outside whatever directory it is unpacked into, and the claim that tar would
let it is the reason ociv has a finding for it. An unmeasured claim of that
shape has been wrong in this collection before, so it was extracted:

```
GNU tar extracted the escaping layer without an error status
and without a diagnostic
GNU tar wrote the file OUTSIDE the extraction root, at box/escaped
the symlink is still a symlink: tar wrote through it, not over it
```

GNU tar does not stop it and does not mention it. The fixture goes one level
out, inside the run's own scratch directory; the realistic spellings, `/etc`
and `../../..`, are in the corpus and are never extracted, because extracting
them means tar writing at the host's `/etc`.

Asking whether `root/out/escaped` is absent is the wrong question and the
first version of that assertion was red for it. `root/out` is the symlink, so
the path resolves to the file tar just wrote outside the root and the test
succeeds. The question is whether tar left `root/out` alone, which is a
statement about the symlink.

ociv reports the escape and keeps the path out of the merged tree. Reporting
without dropping would put a path in the tree that is not in the image's
filesystem; dropping without reporting would make the image look clean. It is
not a refusal: the image is well-formed, every digest matches, and exit 3
means ociv cannot describe the image, which here it can.

## Where ociv and skopeo disagree

Eleven of the nineteen deliberately broken images are accepted by `skopeo
copy` and rejected by ociv. The harness prints the verdict pair for all
nineteen every run rather than asserting a hand-written list, so a skopeo
upgrade that changes a verdict shows up as a changed line. The code and
reason below are ociv's own first diagnostic for each:

```
bad-no-oci-layout             accept/reject V001 the oci-layout file is missing
bad-bad-layout-version        accept/reject V002 imageLayoutVersion is "2.0.0", spec says "1.0.0"
bad-bad-schema-version        accept/reject V004 index.json schemaVersion is 1, spec says 2
bad-wrong-size                accept/reject V011 layer 0 descriptor says 20481 bytes, blob is 20480
bad-index-size-mismatch       accept/reject V011 manifest descriptor size is 7 bytes out
bad-corrupt-manifest-valid    accept/reject V012 manifest bytes are not the digest the index gives
bad-config-as-layer-mediatype accept/reject V015 manifest.config declares a layer media type
bad-bad-rootfs-type           accept/reject V017 config rootfs.type is "overlay", spec says "layers"
bad-diffid-count              accept/reject V018 5 diff_ids for 4 layers
bad-diffid-mismatch           accept/reject V019 a diff_id is not the layer's uncompressed digest
bad-zstd-layer                accept/refuse      zstd, which ociv has no decompressor for
```

ociv follows the spec, and the reason is what it is for. skopeo's job is to
move an image from one place to another, so a field it does not need to read
is one it can afford to ignore; a verifier that ignores a field is not
verifying it. The one that ought to be uncomfortable is
`bad-corrupt-manifest-valid`, where the manifest blob has been replaced with
different but well-formed JSON and the index's digest for it is now wrong.
skopeo copies the image. The index says what the manifest's bytes are and
they are not those bytes.

Nothing goes the other way: no image skopeo rejects is accepted by ociv, and
the suite asserts that skopeo rejected at least some of them, so that claim
cannot pass by skopeo having accepted everything.

The two refusals in the list are the honest half. On a zstd layer and on a
sha512 descriptor, skopeo is right and ociv is short of a feature.

## What the corpus holds

48 images, all built by `make test` from `t/corpus.sh` and `t/mktar.py`,
none committed. 14 are well-formed, 19 carry one named defect each, 12 are
one malformed digest string each, and three are indexes: a flat
multi-platform one, a nested one, and one nested two levels deep.
Nothing is downloaded and no network is used.

The census below is summed over the well-formed images, with `multigz`
left out because it shares its layers with `multi` and counting both would
make every floor look twice as comfortable. The suite prints it and asserts a
floor under each line, because a whiteout test over a corpus with no
whiteouts passes while checking nothing.

```
layers 23          entries 142        merged-paths 89
dir 67             file 62            symlink 10         chardev 1
hardlink 2         hardlink-dangling 0
whiteout-file 5    whiteout-opaque 2  whiteout-hit-nothing 0
deleted 12         shadowed 5         path-in-many-layers 14   dup-in-layer 1
setuid 1           setgid 1           sticky 1           world-writable 4
xattr 4            capability 2       longname 8
escape 3           symlink-parent 3   symlink-escape 2
```

Two of those are zero and both are holes: no dangling hard link, and no
whiteout marker for a path nothing below holds. The counter can see both
constructs, so they are missing from the corpus rather than invisible to it.

The census comes from the Python reader, not from ociv, which is the
important half. `ociv stats` produces the same numbers per image and the two
are diffed, but if the counter were ociv's own then a construct ociv cannot
see would be one the counter cannot count, and the pair would agree that the
corpus is missing something it holds.

The malformed corpus is generated rather than written: every target file in
an image, which is `index.json`, the manifest, the config and the largest
layer, truncated at every stride and with a byte flipped at every stride,
then every subcommand run over the result. `make test` uses a stride of 251
and `make sweep` a stride of 7. An exit of 0, 1, 2 or 3 is acceptable;
anything else is a failure. A Go panic leaves by status 86, chosen because
ociv cannot produce it any other way, so a crash cannot be read as a
diagnostic. The sweep calls itself vacuous and fails if nothing was rejected,
and the suite checks that by pointing it at a program that panics and at one
that hangs.

## Mutation testing

`make mutants` plants 50 single edits in the Go source, one at a time,
rebuilds in a scratch directory, and runs the whole suite against each. A
mutant that does not apply is not a survivor, so every replacement is a
literal string asserted to occur exactly once; a mutant that does not compile
is not a survivor either and is counted apart. `make test` runs three of
them, one that must survive and two that must be caught, so a harness that
always says CAUGHT and a harness that always says SURVIVED both fail the
gate.

`make test` also runs `mutate.py --check`, which asks of all 50 records
whether the line each one quotes is still in the source. That exists because
four of them had rotted: the full sweep stops at the first stale record, so
one of them hid the other 43 behind it, and the gate ran three mutants and
never looked.

The whole sweep, 20 October 2026: 48 caught, 2 survived, 0 behaved unlike
the record, 0 failed to build. It takes about twenty minutes.

Both survivors are recorded as equivalent in `t/mutate.py`, and the run
fails if reality disagrees with that record in either direction, so a
mutant that quietly moves from caught to equivalent is a failure rather
than a smaller number.

`noop-control` adds `if false { _ = ents }` to the merge. It cannot change
anything and it must survive. It is there because a harness that reports
CAUGHT for everything is a harness reporting failures that the mutation did
not cause, and this is the mutant that would expose one.

`mode-print` appends a dead expression to the entry printer. It replaced a
mutant that was equivalent for a reason worth keeping: the original changed
`%04o` to `%03o` when rendering a mode, and in Go a width in a format verb
is a minimum, so `%03o` renders 04755 as 4755 exactly as `%04o` does. The
mutant was not testing what it looked like it was testing. `mode-print-mask`
is the one that does the job, masking the mode with 0777 at the point of
printing while the header is read correctly, and it fails 8 assertions.

Two results from the sweep are worth more than the score. `entry-offset-zero`
and `entry-offset-header` each fail 42 assertions, which is the largest
number any mutant produces here, because the offset comparison checks the
number against python `tarfile` and then reads the bytes at it: an offset
that is wrong in both implementations the same way still produces the wrong
bytes. And `plant-panic`, which turns a malformed-tar error into a Go panic,
fails only the three malformed-input sweeps. Nothing else in the suite can
see it, which is the whole argument for keeping the sweep in the gate.

## What does not work

**The leak offset indexes the uncompressed layer, not the blob.** For a
gzip layer the blob on disk is compressed and `off=` does not point into it,
so a reader has to decompress first and the output does not say so. The
`dd` check therefore runs over the uncompressed images only, which is 13 of
the 14. The finding also names the layer by its index rather than by its
blob digest, so acting on it means reading `ociv info` as well.

**No zstd.** `application/vnd.oci.image.layer.v1.tar+zstd` is in the spec,
Go's standard library has no decompressor for it, and ociv refuses the image
naming the media type. skopeo reads those images. This is the clearest hole
in the program.

**No digest algorithm but sha256.** The spec registers sha512 and allows
others. ociv refuses by name. skopeo accepts sha512.

**No signatures, attestations or SBOMs.** A stated non-goal, and the first
thing a reader assumes an image verifier does. ociv answers "do these bytes
hash to what the manifest says" and holds no key material and makes no trust
decision.

**A nested index is followed one level and no further.** That is the shape a
registry serves, and the suite has an image nested twice to pin the refusal,
but an index three deep is legal and ociv will not read it.

**Platform matching is `os/architecture/variant` and nothing else.**
`os.version` and `os.features` in a descriptor's platform object are parsed
and ignored, so two entries differing only in those fields are one platform
as far as ociv is concerned, and the selection would refuse as ambiguous.

**Everything is read into memory.** Each blob is read whole and each
compressed layer is decompressed whole. An image larger than RAM cannot be
read at all.

**No image from a registry has ever been read.** The whole corpus is built
here by `tar` and by `t/mktar.py`. skopeo writes the docker-archive case and
converts one image, so some bytes in the suite are skopeo's, but no layer in
this repository came from a real published image. Every hard case in the
corpus is a case somebody thought of.

**The merge has no external oracle for whiteouts.** Nothing installed here
applies them. GNU tar extracting the layers in order is the oracle for
everything else, and for whiteouts it is four lines of `rm -rf` in
`t/extract.sh` driven by the markers tar just unpacked, which is as close to
the spec's own prose as a shell script gets, and is still ours.

**The extraction oracle is blind to three things.** It runs unprivileged, so
every file comes out owned by the invoking user and uid and gid cannot be
compared there; device nodes need `mknod` and are absent, so paths holding
them are dropped from that comparison; and which of a set of hard links was
the original is gone once the inode is shared. The per-entry GNU tar listing
comparison covers ownership and device numbers instead, from the headers.

**One field is normalised before the GNU tar comparison.** `tar -tv` prints
an escaping hard link target as `etc/shadow` where the header says
`../etc/shadow`. ociv and python's `tarfile` both report the header bytes,
which is the answer a security tool needs. The comparison normalises that one
field and the suite asserts the disagreement is still there, so tar changing
its mind becomes a failure rather than a silent renormalisation.

**GNU sparse members are not handled.** A layer written with `tar -S` stores
a sparse file as a map plus the non-hole data, and ociv reports it as the
members tar wrote rather than as the file it represents. There is no sparse
member in the corpus, so this is an argument and not a measurement.

**Extended attributes are read from PAX `SCHILY.xattr.` records only.** That
is what GNU tar and the container runtimes write. A layer storing them any
other way reads as having none, and `security.capability` is the attribute
the audit cares about.

**The audit reports bits, not vulnerabilities.** There is no CVE database
here and a setuid binary is a fact rather than a finding. World-writable
directories without the sticky bit are reported and `/tmp` at 1777 is not,
which is the line between a finding and noise, and it is a judgement.

**docker-archive support is narrow.** It reads the `manifest.json` plus
per-layer form that `skopeo copy` writes, which is the only producer it has
been put to. Older Docker layouts with `repositories` files and nested
`json` metadata are not read.

**The symlinked-parent measurement covers one case of three.** The layer
that writes through the symlink names only the file. A layer that also names
the parent as a directory member, and a layer that creates the symlink and
writes through it in the same archive, are both reachable shapes and neither
has been extracted.

**One machine, one skopeo, one tar.** Every number above comes from skopeo
1.18.0, GNU tar 1.35, coreutils 9.7, Python 3.13.5 and Go 1.24.4 on one
Linux box. The symlinked-parent results are statements about what GNU tar
1.35 did here, not about what the tar format requires. No other tar has been
tried.
