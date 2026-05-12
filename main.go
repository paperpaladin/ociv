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
	"runtime/debug"
	"strings"
)

// Exit statuses. These are three different claims and the test harness
// counts them separately: conflating a refusal with a wrong answer is how a
// tool ends up with a reassuring pass rate over the cases it declined.
const (
	exitOK      = 0 // well-formed, every digest matched
	exitInvalid = 1 // the image is invalid: a fact about the image
	exitUsage   = 2 // bad arguments, or the path cannot be read
	exitRefuse  = 3 // ociv does not implement what this image needs

	// A Go panic normally leaves by status 2, which is also this
	// program's usage error. A sweep over truncated and corrupted
	// images would then record a crash as a clean diagnostic, which is
	// the exact failure the sweep exists to detect. 86 is chosen
	// because nothing else here can produce it.
	exitPanic = 86
)

const usage = `usage: ociv COMMAND IMAGE

  info    IMAGE   media types, manifest and config digests, layer roster
  verify  IMAGE   structure and every digest, against the OCI image-spec
  layers  IMAGE   every tar entry of every layer, one fact per line
  tree    IMAGE   the merged root filesystem after whiteouts are applied
  audit   IMAGE   the security-relevant findings, one per line
  stats   IMAGE   how many of each construct the image contains
  cat     IMAGE LAYER PATHHEX   one member's bytes, to stdout

IMAGE is an OCI image layout directory or a docker-archive tar, optionally
suffixed with :TAG or @sha256:HEX to select one manifest from an index.

  --platform OS/ARCH[/VARIANT]   select by the index entry's platform field

A published image is one tag over several architectures, so :TAG does not
narrow such an index at all and --platform is the thing that does. With
more than one candidate left, ociv refuses and lists them.

PATHHEX for cat is the phex field an audit or tree line prints, so a
finding can be turned back into its bytes without retyping a path that
may contain a newline.

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

// wantPlatform is the --platform value, "" if none was given. A package
// variable rather than a parameter threaded through six commands: there
// is exactly one of it and it is read in exactly one place.
var wantPlatform string

// cmdArgs is the argument list with the flags taken out, which is what
// run() must read. run() used to read os.Args[1:] itself, so
// "ociv --platform linux/arm64 verify IMG" took "--platform" as the
// command and "linux/arm64" as the image and said "stat linux/arm64: no
// such file or directory". Only the trailing spelling worked, and only
// the trailing spelling had ever been tried.
var cmdArgs []string

// parsePlatform pulls --platform and its value out of the argument list
// and returns what is left, so the existing "COMMAND IMAGE" shape is
// untouched. --platform= with the value attached is accepted too, because
// that is the spelling people type.
func parsePlatform(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--platform":
			if i+1 >= len(args) {
				fail(exitUsage, "--platform needs a value, OS/ARCH or OS/ARCH/VARIANT")
			}
			i++
			wantPlatform = args[i]
		case strings.HasPrefix(args[i], "--platform="):
			wantPlatform = strings.TrimPrefix(args[i], "--platform=")
		default:
			out = append(out, args[i])
		}
	}
	if wantPlatform != "" {
		n := len(strings.Split(wantPlatform, "/"))
		if n < 2 || n > 3 {
			fail(exitUsage, "--platform %q: want OS/ARCH or OS/ARCH/VARIANT", wantPlatform)
		}
	}
	return out
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "ociv: INTERNAL PANIC: %v\n%s\n", r, debug.Stack())
			os.Exit(exitPanic)
		}
	}()
	cmdArgs = parsePlatform(os.Args[1:])
	args := cmdArgs
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	cmd := args[0]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		os.Exit(exitOK)
	}
	if cmd == "cat" {
		// Three arguments, and the path in hex rather than as text,
		// so the phex field of an audit line goes straight in. A
		// member name may contain a newline and no shell argument
		// survives one.
		if len(args) != 4 {
			fail(exitUsage, "cat takes IMAGE, a layer number and a hex path")
		}
		os.Exit(run())
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
