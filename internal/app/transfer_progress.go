package app

import (
	"io"
	"time"
)

func uploadProgress(w io.Writer) func(string, int64, int64) {
	start := time.Now()
	var last, phaseStart time.Time
	var currentPhase string
	return func(phase string, done, total int64) {
		now := time.Now()
		if phase != currentPhase {
			currentPhase, phaseStart, last = phase, now, time.Time{}
		}
		if now.Sub(start) < 3*time.Second || now.Sub(last) < time.Second {
			return
		}
		last = now
		if elapsed := now.Sub(phaseStart); done > 0 && total > 0 && elapsed > 0 && phase != "publish" {
			writeDiagnosticNote(w, "sshx: SFTP %s %d/%d bytes (%.1f%%, %.1f MiB/s)\n",
				phase, done, total, 100*float64(done)/float64(total), float64(done)/(1<<20)/elapsed.Seconds())
			return
		}
		writeDiagnosticNote(w, "sshx: SFTP %s (%d bytes)\n", phase, total)
	}
}
