// ociv -- an OCI container image verifier and layer analyser.
//
// It reads an OCI image layout or a docker-archive tar, validates the
// manifest and config against the OCI image specification, verifies every
// digest, applies the layers in order honouring whiteouts and opaque
// directories, and reports what the final root filesystem contains plus the
// security-relevant facts about how it got that way.
//
// Standard library only. See PLAN.md for the contract and README.md for what
// does not work.
package main

import (
	"fmt"
	"os"
)

// Exit statuses. These are three different claims and the test harness
// counts them separately: conflating a refusal with a wrong answer is how a
// tool ends up with a reassuring pass rate over the cases it declined.
const (
	exitOK      = 0 // well-formed, every digest matched
	exitInvalid = 1 // the image is invalid: a fact about the image
	exitUsage   = 2 // bad arguments, or the path cannot be read
	exitRefuse  = 3 // ociv does not implement what this image needs
)

const usage = `usage: ociv COMMAND IMAGE

  info    IMAGE   media types, manifest and config digests, layer roster
  verify  IMAGE   structure and every digest, against the OCI image-spec
  layers  IMAGE   every tar entry of every layer, one fact per line
  tree    IMAGE   the merged root filesystem after whiteouts are applied
  audit   IMAGE   the security-relevant findings, one per line
  stats   IMAGE   how many of each construct the image contains

IMAGE is an OCI image layout directory or a docker-archive tar, optionally
suffixed with :TAG or @sha256:HEX to select one manifest from an index.

exit 0 clean, 1 the image is invalid, 2 usage, 3 refused as unimplemented.
`

// fail prints a diagnostic to stderr and exits with the given status. Every
// exit from a command path goes through here or through refuse, so that the
// status and the message cannot drift apart.
func fail(status int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ociv: "+format+"\n", a...)
	os.Exit(status)
}

// refuse is fail for the one case that is not an accusation against the
// image: ociv has met something the specification permits and ociv does not
// implement. The word REFUSE is in the message so the harness can tell a
// decline from a verdict without parsing prose.
func refuse(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ociv: REFUSE: "+format+"\n", a...)
	os.Exit(exitRefuse)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	cmd := args[0]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		os.Exit(exitOK)
	}
	if len(args) != 2 {
		fail(exitUsage, "%s takes exactly one IMAGE argument", cmd)
	}
	switch cmd {
	case "info", "verify", "layers", "tree", "audit", "stats":
		os.Exit(run())
	default:
		fail(exitUsage, "unknown command %q", cmd)
	}
}
