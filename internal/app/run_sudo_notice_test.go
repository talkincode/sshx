package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunScriptSudoNotice(t *testing.T) {
	setTestHome(t, t.TempDir())

	tests := []struct {
		name   string
		script string
		sudo   bool
		quiet  bool
		want   bool
	}{
		{
			name:   "nested sudo",
			script: "#!/bin/sh\nsudo -n true\n",
			want:   true,
		},
		{
			name:   "sudo requested",
			script: "#!/bin/sh\nsudo -n true\n",
			sudo:   true,
		},
		{
			name:   "quiet",
			script: "#!/bin/sh\nsudo -n true\n",
			quiet:  true,
		},
		{
			name:   "sudo is only an argument",
			script: "#!/bin/sh\necho sudo\n",
		},
		{
			name:   "sudo is only a comment",
			script: "#!/bin/sh\n# sudo reboot\necho ready\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scriptPath := filepath.Join(t.TempDir(), "script.sh")
			require.NoError(t, os.WriteFile(scriptPath, []byte(tt.script), 0o600))

			args := []string{
				"sshx", "run", "--address=192.0.2.1", "--script-file=" + scriptPath,
				"--dry-run", "--json", "--no-audit",
			}
			if tt.sudo {
				args = append(args, "--sudo")
			}
			if tt.quiet {
				args = append(args, "--quiet")
			}

			var runErr error
			stdout, stderr := captureStreams(t, func() {
				runErr = Run(args)
			})
			require.NoError(t, runErr)
			assert.True(t, len(stdout) > 0, "dry-run should retain its JSON document")

			noticeCount := strings.Count(string(stderr), "the script contains `sudo`")
			if tt.want {
				assert.Equal(t, 1, noticeCount, "notice should be written once")
				assert.Contains(t, string(stderr), "its stdin carries the script")
				assert.Contains(t, string(stderr), "Re-run with --sudo")
			} else {
				assert.Zero(t, noticeCount)
			}
		})
	}
}
