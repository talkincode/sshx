package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/talkincode/sshx/internal/app"
)

func main() {
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
