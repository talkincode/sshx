package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/talkincode/sshx/internal/app"
)

func main() {
	if err := app.Run(os.Args); err != nil {
		if errors.Is(err, app.ErrUsage) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "sshx: %v\n", err)
		os.Exit(1)
	}
}
