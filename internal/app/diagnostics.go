package app

import (
	"fmt"
	"io"

	"github.com/talkincode/sshx/pkg/logger"
)

// writeDiagnosticNote writes a best-effort diagnostic note to w.
//
// Notes explain a result that has already been reported on stdout, so a failed
// write must never change the command's outcome and has nowhere better to go
// than the debug log (which is itself stderr-only, keeping --json stdout pure).
func writeDiagnosticNote(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		logger.GetLogger().Debug("failed to write diagnostic note: %v", err)
	}
}
