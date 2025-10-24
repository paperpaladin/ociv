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

test: all
	./t/run.sh

vet: 
	$(GO) vet ./...

clean:
	rm -f ociv
	rm -rf t/tmp.*

.PHONY: all test vet clean
