package main

import (
	"os"
	"testing"
)

func TestHandleVersionFlag(t *testing.T) {
	// Redirect stdout to /dev/null so the version line printed on a match does
	// not pollute test output.
	old := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("failed to open %s: %v", os.DevNull, err)
	}
	os.Stdout = devNull
	defer func() {
		os.Stdout = old
		if cerr := devNull.Close(); cerr != nil {
			t.Logf("failed to close %s: %v", os.DevNull, cerr)
		}
	}()

	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"long flag", []string{"sshx", "--version"}, true},
		{"short v", []string{"sshx", "-v"}, true},
		{"short V", []string{"sshx", "-V"}, true},
		{"flag after other flags", []string{"sshx", "-h=host", "--version"}, true},
		{"no version flag", []string{"sshx", "-h=host", "uptime"}, false},
		{"no args", []string{"sshx"}, false},
		{"token inside remote command is ignored", []string{"sshx", "-h=host", "grep", "-v", "foo"}, false},
		{"version after positional command is ignored", []string{"sshx", "-h=host", "run", "--version"}, false},
		{"version after separator is remote command", []string{"sshx", "-h=host", "--", "--version"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := handleVersionFlag(tc.args); got != tc.want {
				t.Errorf("handleVersionFlag(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}
