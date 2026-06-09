package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/talkincode/sshx/internal/app"
)

// Version is the sshx version string. The default is overridden at build time
// via -ldflags "-X main.Version=<version>" (see the Makefile and the release
// workflow).
var Version = "dev"

func main() {
	app.Version = Version

	if handleVersionFlag(os.Args) {
		os.Exit(0)
	}

	err := app.Run(os.Args)
	if err == nil {
		os.Exit(0)
	}

	// A remote command that exited non-zero: propagate its status verbatim.
	var exitErr *app.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}

	// A structured (JSON) result was already written to stdout.
	if errors.Is(err, app.ErrReported) {
		os.Exit(255)
	}

	// Usage was printed to stdout.
	if errors.Is(err, app.ErrUsage) {
		os.Exit(1)
	}

	// Any other sshx-level failure.
	fmt.Fprintf(os.Stderr, "sshx: %v\n", err)
	os.Exit(255)
}

// handleVersionFlag prints the version string and reports whether a version
// flag (--version, -v, or -V) was present in args. The scan stops at the first
// positional argument so that a token inside the remote command (e.g.
// `sshx -h=host grep -v foo`) is never mistaken for a version request.
func handleVersionFlag(args []string) bool {
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") {
			break
		}
		switch arg {
		case "--version", "-v", "-V":
			fmt.Printf("sshx %s\n", Version)
			return true
		}
	}
	return false
}
