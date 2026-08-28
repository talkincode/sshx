package app

import (
	"runtime"
	"testing"
)

// setTestHome points the user home directory at dir for one test. Go resolves
// os.UserHomeDir() from HOME on Unix and USERPROFILE on Windows, so setting
// only HOME would leave Windows tests writing into the real user profile.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}
