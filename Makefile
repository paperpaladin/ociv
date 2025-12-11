# ociv -- OCI image verifier and layer analyser.
#
# No third-party dependencies: `go build` here never touches the network,
# and `go.mod` has no require block. GOFLAGS=-mod=mod is not needed and
# GOPROXY=off is set so a stray import becomes a build error rather than
# a download.
GO      ?= go
GOFLAGS ?=
export GOPROXY = off
export GOTOOLCHAIN = local

all: ociv

ociv: $(wildcard *.go) go.mod
	$(GO) build $(GOFLAGS) -trimpath -o ociv .

# The mutants run FIRST so that t/run.sh's "N passed, M failed" is the
# last line of the target. The collection's tooling parses that line, and
# it reported "mutants: 2 caught, 1 survived as recorded equivale" for one
# commit because the mutation summary was printed after it.
test: all
	@echo "[mutants] three planted defects: one must survive, two must be caught"
	./t/mutate.py --smoke
	@echo
	./t/run.sh

# The full sweep: every planted defect, each rebuilt and run against the
# whole suite. Minutes, not seconds, which is why "make test" runs three
# of them instead. It exits nonzero if any mutant behaves unlike the
# record in t/mutate.py, in either direction.
mutants: all
	./t/mutate.py

# The dense malformed-input sweep, at a stride of 7 over seven images.
# "make test" runs the same thing at 251, because this takes minutes.
sweep: all
	@d=$$(mktemp -d "$${TMPDIR:-/tmp}/ocivsweep.XXXXXX"); \
	 trap "rm -rf $$d" EXIT; \
	 ./t/corpus.sh $$d >/dev/null 2>&1 || exit 1; \
	 rc=0; \
	 for i in single multi multigz xattr escape longpax opq samelayer; do \
	   echo "== $$i"; ./t/sweep.py ./ociv $$d/img/$$i --stride 7 --timeout 20 || rc=1; \
	 done; \
	 rm -rf $$d; exit $$rc

vet: 
	$(GO) vet ./...

clean:
	rm -f ociv
	rm -rf t/tmp.*

.PHONY: all test mutants sweep vet clean
