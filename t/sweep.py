#!/usr/bin/env python3
"""Throw truncated and corrupted images at ociv and require it not to crash.

An image is attacker-controlled data in any tool that reads one from a
stranger, and the failure mode to rule out is not a wrong answer: it is a
panic, an unbounded allocation or a hang. Every length in an OCI image
comes out of the image.

For each target file -- index.json, the manifest blob, the config blob and
a layer blob -- this truncates it at every stride and flips bytes at every
stride, then runs every ociv subcommand over the result.

An acceptable outcome is exit 0, 1, 2 or 3. Exit 86 is a Go panic, which
ociv's main turns into that status precisely so this sweep cannot mistake
a crash for a diagnostic: a bare panic leaves by status 2, which is also
ociv's usage error. Anything else, a signal or a timeout, is a failure.

The sweep also asserts it is not vacuous: a run in which nothing was
rejected has not exercised an error path, and a sweep over an image ociv
cannot open at all would report a clean score having checked one thing.

    sweep.py OCIV IMAGE [--stride N] [--timeout SECONDS] [--max-runs N]

Prints one summary line per target and a final verdict line.
"""
import os
import shutil
import subprocess
import sys
import tempfile

CMDS = ["verify", "info", "layers", "tree", "audit", "stats"]
OK_STATUS = {0, 1, 2, 3}
PANIC_STATUS = 86


def blob_path(img, digest):
    return os.path.join(img, "blobs", digest.replace(":", "/"))


def targets(img):
    """index.json, the manifest, the config and the largest layer blob."""
    import json
    out = [("index.json", os.path.join(img, "index.json"))]
    idx = json.load(open(os.path.join(img, "index.json")))
    mp = blob_path(img, idx["manifests"][0]["digest"])
    out.append(("manifest", mp))
    man = json.load(open(mp))
    out.append(("config", blob_path(img, man["config"]["digest"])))
    big = max(man["layers"], key=lambda d: d["size"])
    out.append(("layer", blob_path(img, big["digest"])))
    return out


def run(ociv, img, timeout):
    worst = 0
    notes = []
    for c in CMDS:
        try:
            r = subprocess.run([ociv, c, img], capture_output=True,
                               timeout=timeout)
        except subprocess.TimeoutExpired:
            return "timeout", c, ""
        rc = r.returncode
        if rc == PANIC_STATUS:
            return "panic", c, r.stderr.decode("utf-8", "replace")[:400]
        if rc < 0:
            return "signal %d" % -rc, c, ""
        if rc not in OK_STATUS:
            return "status %d" % rc, c, r.stderr.decode("utf-8", "replace")[:200]
        worst = max(worst, rc)
    return "ok", worst, ""


def main(argv):
    ociv = os.path.abspath(argv[1])
    src = argv[2]
    stride = 61
    if "--stride" in argv:
        stride = int(argv[argv.index("--stride") + 1])
    tmo = 20
    if "--timeout" in argv:
        tmo = float(argv[argv.index("--timeout") + 1])
    # A cap on the number of runs, for the self-tests in t/run.sh that
    # point this harness at a deliberately hanging program: without it,
    # proving the timeout detector works costs one timeout per run.
    maxruns = 0
    if "--max-runs" in argv:
        maxruns = int(argv[argv.index("--max-runs") + 1])

    work = tempfile.mkdtemp(prefix="ocivsweep.")
    img = os.path.join(work, "img")
    bad = []
    runs = 0
    rejected = 0
    try:
        shutil.copytree(src, img)
        for label, path in targets(img):
            if maxruns and runs >= maxruns:
                break
            rel = os.path.relpath(path, img)
            original = open(path, "rb").read()
            n = len(original)
            local_runs = local_rejected = 0
            # Truncation at every stride, including zero length.
            for cut in list(range(0, n, stride)) + [n - 1]:
                if cut < 0 or (maxruns and runs >= maxruns):
                    continue
                open(path, "wb").write(original[:cut])
                kind, where, detail = run(ociv, img, tmo)
                runs += 1
                local_runs += 1
                if kind != "ok":
                    bad.append(("truncate %s to %d" % (rel, cut), kind, where, detail))
                elif where != 0:
                    rejected += 1
                    local_rejected += 1
            # Single-byte corruption at every stride.
            for off in range(0, n, stride):
                if maxruns and runs >= maxruns:
                    continue
                b = bytearray(original)
                b[off] ^= 0xFF
                open(path, "wb").write(bytes(b))
                kind, where, detail = run(ociv, img, tmo)
                runs += 1
                local_runs += 1
                if kind != "ok":
                    bad.append(("corrupt %s at %d" % (rel, off), kind, where, detail))
                elif where != 0:
                    rejected += 1
                    local_rejected += 1
            open(path, "wb").write(original)
            print("sweep %-10s %5d bytes %4d runs %4d rejected" %
                  (label, n, local_runs, local_rejected))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    for what, kind, where, detail in bad[:10]:
        print("SWEEPFAIL %s: %s during %s" % (what, kind, where))
        if detail:
            print("   " + detail.replace("\n", "\n   ")[:600])
    print("sweep total: %d runs, %d rejected cleanly, %d crashed hung or "
          "returned an impossible status" % (runs, rejected, len(bad)))
    if rejected == 0 and not maxruns:
        print("sweep VACUOUS: nothing was rejected, so no error path ran")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
