#!/usr/bin/env python3
"""Assemble OCI image layouts out of layer tarballs, for the test corpus.

This is a corpus BUILDER, not an oracle. It writes images; skopeo and GNU
tar are what say whether ociv read them correctly. It is written straight
from the OCI image-layout and image-manifest documents, and deliberately
does not use ociv for anything, so an image it produces is not an image
ociv has already agreed with.

Standard library only.

    oci.py assemble    DIR [--gzip] [--mt MEDIATYPE] [--tag NAME] LAYER.tar...
    oci.py assemble-platforms DIR OS/ARCH[/VARIANT]=LAYER.tar...
    oci.py nest        SRC DST [DEPTH]
    oci.py break       SRC DST DEFECT
    oci.py digestcases SRC OUTDIR
"""
import gzip
import hashlib
import json
import os
import shutil
import sys

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER_TAR = "application/vnd.oci.image.layer.v1.tar"
LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"


def jdump(o):
    """Canonical-ish: no spaces, sorted keys. The exact bytes matter because
    the manifest digest is over them, so this function is the only place
    that serialises and nothing re-serialises after a digest is taken."""
    return json.dumps(o, separators=(",", ":"), sort_keys=True).encode()


class Layout:
    def __init__(self, d):
        self.d = d
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(os.path.join(d, "blobs", "sha256"))

    def put(self, b):
        h = hashlib.sha256(b).hexdigest()
        with open(os.path.join(self.d, "blobs", "sha256", h), "wb") as f:
            f.write(b)
        return {"digest": "sha256:" + h, "size": len(b)}


def assemble(d, layers, use_gzip=False, mediatype=None, tag="latest",
             extra_cfg=None, annotations=None):
    lo = Layout(d)
    ldesc = []
    diff_ids = []
    for p in layers:
        with open(p, "rb") as f:
            raw = f.read()
        # diff_id is over the UNCOMPRESSED bytes; the descriptor digest is
        # over whatever is actually stored. Conflating the two is the bug
        # this corpus exists to be able to see.
        diff_ids.append("sha256:" + hashlib.sha256(raw).hexdigest())
        stored = raw
        mt = mediatype or LAYER_TAR
        if use_gzip:
            # mtime=0 so the blob is reproducible across runs; a corpus
            # whose digests change every build cannot be compared to a
            # recorded number.
            stored = gzip.compress(raw, 6, mtime=0)
            mt = mediatype or LAYER_GZIP
        desc = lo.put(stored)
        desc["mediaType"] = mt
        ldesc.append(desc)

    cfg = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                   "Cmd": ["/bin/sh"]},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": [{"created_by": "ociv corpus layer %d" % i} for i in range(len(layers))],
    }
    if extra_cfg:
        cfg.update(extra_cfg)
    cdesc = lo.put(jdump(cfg))
    cdesc["mediaType"] = OCI_CONFIG

    man = {"schemaVersion": 2, "mediaType": OCI_MANIFEST,
           "config": cdesc, "layers": ldesc}
    if annotations:
        man["annotations"] = annotations
    mdesc = lo.put(jdump(man))
    mdesc["mediaType"] = OCI_MANIFEST
    mdesc["annotations"] = {"org.opencontainers.image.ref.name": tag}

    with open(os.path.join(d, "index.json"), "wb") as f:
        f.write(jdump({"schemaVersion": 2, "mediaType": OCI_INDEX,
                       "manifests": [mdesc]}))
    with open(os.path.join(d, "oci-layout"), "wb") as f:
        f.write(jdump({"imageLayoutVersion": "1.0.0"}))
    print(mdesc["digest"])
    return mdesc["digest"]


def assemble_platforms(d, specs, tag="latest"):
    """One layout, one tag, several platforms. That is what a real
    multi-arch image looks like: docker.io/library/alpine:3.19 is an index
    whose entries differ only in the platform field, and a reader that
    picks the first one verifies somebody else's architecture.

    Each spec is OS/ARCH[/VARIANT]=LAYER.tar. The config's os and
    architecture are set to match the descriptor's platform, because
    skopeo cross-checks them and an index whose entries disagree with
    their own configs is not the image this is meant to be testing."""
    lo = Layout(d)
    mdescs = []
    for spec in specs:
        plat, _, layer = spec.partition("=")
        parts = plat.split("/")
        osn, arch = parts[0], parts[1]
        variant = parts[2] if len(parts) > 2 else ""
        with open(layer, "rb") as f:
            raw = f.read()
        desc = lo.put(raw)
        desc["mediaType"] = LAYER_TAR
        cfg = {"architecture": arch, "os": osn,
               "config": {"Cmd": ["/bin/sh"]},
               "rootfs": {"type": "layers",
                          "diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()]},
               "history": [{"created_by": "ociv corpus %s" % plat}]}
        if variant:
            cfg["variant"] = variant
        cdesc = lo.put(jdump(cfg))
        cdesc["mediaType"] = OCI_CONFIG
        man = {"schemaVersion": 2, "mediaType": OCI_MANIFEST,
               "config": cdesc, "layers": [desc]}
        mdesc = lo.put(jdump(man))
        mdesc["mediaType"] = OCI_MANIFEST
        mdesc["platform"] = {"os": osn, "architecture": arch}
        if variant:
            mdesc["platform"]["variant"] = variant
        # Every entry carries the SAME ref.name, which is the part that
        # makes :TAG insufficient on its own.
        mdesc["annotations"] = {"org.opencontainers.image.ref.name": tag}
        mdescs.append(mdesc)
    with open(os.path.join(d, "index.json"), "wb") as f:
        f.write(jdump({"schemaVersion": 2, "mediaType": OCI_INDEX,
                       "manifests": mdescs}))
    with open(os.path.join(d, "oci-layout"), "wb") as f:
        f.write(jdump({"imageLayoutVersion": "1.0.0"}))
    for m in mdescs:
        print("%s %s" % (m["platform"]["os"] + "/" + m["platform"]["architecture"]
                         + ("/" + m["platform"]["variant"] if "variant" in m["platform"] else ""),
                         m["digest"]))
    return mdescs


def nest(src, dst, depth=1):
    """Turn a flat multi-platform layout into the nested one a registry
    actually serves, and that skopeo copy --all writes: index.json holds
    ONE entry pointing at an image index blob, and the per-platform
    manifests hang off that.

    depth 2 wraps it twice, which is legal and which nothing writes; it
    is here so the refusal for depth beyond one can be tested against an
    image rather than asserted about."""
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    idx = read_index(dst)
    entries = [{k: v for k, v in m.items() if k != "annotations"}
               for m in idx["manifests"]]
    # Not Layout(dst): its constructor wipes the directory, which here
    # would delete the copy that was just made. Writing a blob is three
    # lines and the mistake cost a debugging detour.
    def put(b):
        h = hashlib.sha256(b).hexdigest()
        with open(os.path.join(dst, "blobs", "sha256", h), "wb") as f:
            f.write(b)
        return {"digest": "sha256:" + h, "size": len(b)}
    for level in range(depth):
        inner = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries}
        desc = put(jdump(inner))
        desc["mediaType"] = OCI_INDEX
        entries = [desc]
    top = dict(entries[0])
    top["annotations"] = {"org.opencontainers.image.ref.name": "latest"}
    with open(os.path.join(dst, "index.json"), "wb") as f:
        f.write(jdump({"schemaVersion": 2, "mediaType": OCI_INDEX,
                       "manifests": [top]}))
    print(top["digest"])
    return top["digest"]


# ---------------------------------------------------------------------------
# Deliberately broken images. Each one is a single, named, minimal defect:
# the point is that ociv's diagnostic says WHICH, not merely that something
# is wrong. A checker that reports "invalid image" for all fourteen of these
# has not been shown to distinguish any of them.
# ---------------------------------------------------------------------------

def blobpath(d, digest):
    return os.path.join(d, "blobs", digest.replace(":", "/"))


def read_index(d):
    with open(os.path.join(d, "index.json"), "rb") as f:
        return json.load(f)


def read_manifest(d):
    idx = read_index(d)
    dg = idx["manifests"][0]["digest"]
    with open(blobpath(d, dg), "rb") as f:
        return dg, json.load(f)


def rewrite_index(d, mutate):
    idx = read_index(d)
    mutate(idx)
    with open(os.path.join(d, "index.json"), "wb") as f:
        f.write(jdump(idx))


def break_image(src, dst, defect):
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    mdg, man = read_manifest(dst)

    if defect == "corrupt-layer":
        # One byte, in the middle of the first layer blob. The digest no
        # longer matches and neither does any plausible re-read.
        p = blobpath(dst, man["layers"][0]["digest"])
        with open(p, "r+b") as f:
            f.seek(len(open(p, "rb").read()) // 2)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 0xFF]))

    elif defect == "corrupt-config":
        p = blobpath(dst, man["config"]["digest"])
        with open(p, "r+b") as f:
            f.seek(0)
            f.write(b" ")       # a leading space: still valid JSON, wrong digest

    elif defect == "corrupt-config-valid":
        # A trailing newline. The config is still valid JSON and still
        # parses into the same object, so only the digest comparison can
        # see it. corrupt-config breaks the JSON as well, which means a
        # reader with no digest check at all still fails on the parse --
        # and a mutation that deleted the digest check survived for
        # exactly that reason.
        p = blobpath(dst, man["config"]["digest"])
        with open(p, "ab") as f:
            f.write(b"\n")

    elif defect == "corrupt-manifest-valid":
        p = blobpath(dst, mdg)
        with open(p, "ab") as f:
            f.write(b" ")

    elif defect == "wrong-size":
        # The blob is fine, the descriptor lies about its length. A reader
        # that hashes the file and never looks at size accepts this.
        man["layers"][0]["size"] += 1
        _replace_manifest(dst, mdg, man)

    elif defect == "missing-blob":
        os.remove(blobpath(dst, man["layers"][0]["digest"]))

    elif defect == "bad-digest-string":
        man["layers"][0]["digest"] = "sha256:NOTHEX" + "0" * 57
        _replace_manifest(dst, mdg, man)

    elif defect == "unknown-algorithm":
        man["layers"][0]["digest"] = "blake3:" + "0" * 64
        _replace_manifest(dst, mdg, man)

    elif defect == "no-oci-layout":
        os.remove(os.path.join(dst, "oci-layout"))

    elif defect == "bad-layout-version":
        with open(os.path.join(dst, "oci-layout"), "wb") as f:
            f.write(jdump({"imageLayoutVersion": "2.0.0"}))

    elif defect == "bad-schema-version":
        rewrite_index(dst, lambda i: i.update({"schemaVersion": 1}))

    elif defect == "empty-index":
        rewrite_index(dst, lambda i: i.update({"manifests": []}))

    elif defect == "diffid-mismatch":
        # The layer bytes are right and the config's claim about their
        # uncompressed hash is wrong. Only a reader that actually unpacks
        # the layer can see this.
        cfgdg = man["config"]["digest"]
        with open(blobpath(dst, cfgdg), "rb") as f:
            cfg = json.load(f)
        cfg["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
        _replace_config(dst, mdg, man, cfg)

    elif defect == "diffid-count":
        cfgdg = man["config"]["digest"]
        with open(blobpath(dst, cfgdg), "rb") as f:
            cfg = json.load(f)
        cfg["rootfs"]["diff_ids"].append("sha256:" + "1" * 64)
        _replace_config(dst, mdg, man, cfg)

    elif defect == "bad-rootfs-type":
        cfgdg = man["config"]["digest"]
        with open(blobpath(dst, cfgdg), "rb") as f:
            cfg = json.load(f)
        cfg["rootfs"]["type"] = "overlay"
        _replace_config(dst, mdg, man, cfg)

    elif defect == "index-digest-mismatch":
        # index.json names a digest no blob has. Distinct from
        # missing-blob only in which file is lying.
        def mut(i):
            i["manifests"][0]["digest"] = "sha256:" + "a" * 64
        rewrite_index(dst, mut)

    elif defect == "index-size-mismatch":
        rewrite_index(dst, lambda i: i["manifests"][0].__setitem__(
            "size", i["manifests"][0]["size"] + 7))

    elif defect == "config-as-layer-mediatype":
        man["config"]["mediaType"] = LAYER_TAR
        _replace_manifest(dst, mdg, man)

    elif defect == "zstd-layer":
        # Not a defect: a legal media type ociv has no decompressor for.
        # It belongs in this list because the required answer is a REFUSAL
        # and the harness must see that it is not an accusation.
        man["layers"][0]["mediaType"] = "application/vnd.oci.image.layer.v1.tar+zstd"
        _replace_manifest(dst, mdg, man)

    else:
        sys.exit("unknown defect %r" % defect)
    return dst


# ---------------------------------------------------------------------------
# Digest grammar cases.
#
# Each one spells index.json's manifest digest differently and puts a copy
# of the manifest blob at the path that spelling names, so that the only
# thing wrong with the image is the digest string itself. Without the copy
# every case would fail at "no such file" and the grammar would never be
# reached, which is a test that passes for the wrong reason.
#
# skopeo is the oracle: it rejects ten of the twelve, and the two it does
# not are recorded as divergences rather than smoothed over.
# ---------------------------------------------------------------------------

def digest_cases(src, outdir):
    idx = read_index(src)
    real = idx["manifests"][0]["digest"]
    enc = real.split(":", 1)[1]
    cases = {
        "upper":        "sha256:" + enc.upper(),
        "short":        "sha256:abcd",
        "long":         "sha256:" + enc + "00",
        "trailsep":     "sha256+:" + enc,
        "leadsep":      "+sha256:" + enc,
        "dblsep":       "sha256++x:" + enc,
        "nocolon":      "sha256" + enc,
        "emptyalg":     ":" + enc,
        "emptyenc":     "sha256:",
        "badchar":      "sha256:" + enc[:-1] + "*",
        "unregistered": "multihash+base58:QmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e",
        "sha512":       "sha512:" + "a" * 128,
    }
    for name, dg in sorted(cases.items()):
        d = os.path.join(outdir, "dg-" + name)
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(src, d)
        if ":" in dg:
            alg, e2 = dg.split(":", 1)
            if alg and e2 and "/" not in alg and "/" not in e2:
                tgt = os.path.join(d, "blobs", alg, e2)
                os.makedirs(os.path.dirname(tgt), exist_ok=True)
                shutil.copy(os.path.join(d, "blobs", "sha256", enc), tgt)
        i2 = read_index(d)
        i2["manifests"][0]["digest"] = dg
        with open(os.path.join(d, "index.json"), "wb") as f:
            f.write(jdump(i2))
        print("dg-" + name)


def _replace_manifest(d, olddg, man):
    """Rewrite the manifest blob and point index.json at the new one, so the
    only thing wrong with the image is the defect under test."""
    b = jdump(man)
    h = "sha256:" + hashlib.sha256(b).hexdigest()
    with open(blobpath(d, h), "wb") as f:
        f.write(b)
    if h != olddg:
        try:
            os.remove(blobpath(d, olddg))
        except FileNotFoundError:
            pass

    def mut(i):
        i["manifests"][0]["digest"] = h
        i["manifests"][0]["size"] = len(b)
    rewrite_index(d, mut)


def _replace_config(d, mdg, man, cfg):
    b = jdump(cfg)
    h = "sha256:" + hashlib.sha256(b).hexdigest()
    with open(blobpath(d, h), "wb") as f:
        f.write(b)
    old = man["config"]["digest"]
    if h != old:
        try:
            os.remove(blobpath(d, old))
        except FileNotFoundError:
            pass
    man["config"]["digest"] = h
    man["config"]["size"] = len(b)
    _replace_manifest(d, mdg, man)


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd = argv[1]
    if cmd == "assemble":
        d = argv[2]
        rest = argv[3:]
        use_gzip = False
        mt = None
        tag = "latest"
        layers = []
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--gzip":
                use_gzip = True
            elif a == "--mt":
                i += 1
                mt = rest[i]
            elif a == "--tag":
                i += 1
                tag = rest[i]
            else:
                layers.append(a)
            i += 1
        assemble(d, layers, use_gzip=use_gzip, mediatype=mt, tag=tag)
    elif cmd == "assemble-platforms":
        assemble_platforms(argv[2], argv[3:])
    elif cmd == "nest":
        nest(argv[2], argv[3], int(argv[4]) if len(argv) > 4 else 1)
    elif cmd == "break":
        break_image(argv[2], argv[3], argv[4])
    elif cmd == "digestcases":
        digest_cases(argv[2], argv[3])
    else:
        sys.exit("unknown subcommand %r" % cmd)


if __name__ == "__main__":
    main(sys.argv)
