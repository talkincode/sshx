package app

import (
	"fmt"
	"io"
	"os"

	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// noticeWriter is where human notices go for one invocation: stderr normally, and
// nothing at all when --quiet asked for a notice-free stream. A notice explains or
// narrates a result that has already been reported, so suppressing it never changes
// stdout, the exit code, or the JSON document (issue #86).
func noticeWriter(config *sshclient.Config) io.Writer {
	if config != nil && config.Quiet {
		return io.Discard
	}
	return os.Stderr
}

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
