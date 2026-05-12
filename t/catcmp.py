#!/usr/bin/env python3
"""Compare "ociv cat" against GNU tar writing the same member to stdout.

    catcmp.py OCIV IMAGE LAYER.tar...

For every regular file member of every layer, this asks GNU tar for the
member's bytes and ociv for the same member's bytes, and compares them.
tar is the external authority for the whole path from "the audit says
phex=X in layer N" to the bytes, which is the sentence that makes a leak
finding actionable rather than merely true.

Member names go to tar NUL-terminated through --files-from, and to ociv
as hex, because the corpus deliberately holds a name with a newline in
it and no spelling of a shell argument survives that.

tar runs with -P. Without it, GNU tar 1.35 rewrites the name it was
given before matching, so asking for "../etc/shadow" produces
"Removing leading ../ from member names" and then
"../etc/shadow: Member name contains '..'", exit 2, and asking for the
sanitised "etc/shadow" finds nothing: the member in the archive is the
unsanitised one. So the three escaping members of the corpus are
unreachable by name without -P. t/run.sh pins that behaviour
separately; here the flag is on so the oracle can answer at all.

A path a layer names twice is left out and counted apart. tar -xOf by
name writes BOTH members one after the other; ociv cat gives the last
one, which is what extraction leaves on disk. That is a real difference
and t/run.sh asserts it directly rather than letting it look like a
mismatch here.

Prints one line per layer and a final "catcmp: N compared, M differ,
K duplicate paths skipped".

Standard library only.
"""
import hashlib
import subprocess
import sys
import tarfile


def members(path):
    """Regular file members as (archive name bytes, normalised path bytes).

    The normalisation is the layer document's: a leading "./" and any
    trailing "/" come off. Done here rather than read out of ociv's
    output, so the comparison is not ociv checking its own spelling.
    """
    out = []
    with tarfile.open(path, "r:*") as t:
        for m in t.getmembers():
            if not m.isreg():
                continue
            n = m.name.encode("utf-8", "surrogateescape")
            p = n[2:] if n.startswith(b"./") else n
            out.append((n, p.rstrip(b"/")))
    return out


def main(argv):
    ociv, image, layers = argv[1], argv[2], argv[3:]
    compared = differ = skipped = 0
    details = []
    for i, lp in enumerate(layers):
        ms = members(lp)
        seen = {}
        for _n, p in ms:
            seen[p] = seen.get(p, 0) + 1
        for n, p in ms:
            if seen[p] > 1:
                skipped += 1
                continue
            want = subprocess.run(["tar", "-P", "-xOf", lp, "--null", "-T", "-"],
                                  input=n + b"\0", capture_output=True)
            got = subprocess.run([ociv, "cat", image, str(i), p.hex()],
                                 capture_output=True)
            compared += 1
            if want.stdout != got.stdout or got.returncode != 0:
                differ += 1
                if len(details) < 5:
                    details.append(
                        "  layer %d %s: tar %s (%d bytes), ociv %s (%d bytes, exit %d)"
                        % (i, p.hex(),
                           hashlib.sha256(want.stdout).hexdigest()[:16],
                           len(want.stdout),
                           hashlib.sha256(got.stdout).hexdigest()[:16],
                           len(got.stdout), got.returncode))
    for d in details:
        print(d)
    print("catcmp: %d compared, %d differ, %d duplicate paths skipped"
          % (compared, differ, skipped))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
