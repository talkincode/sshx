package app

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/talkincode/sshx/pkg/logger"
)

// setTestHome points the user home directory at dir for one test. Go resolves
// os.UserHomeDir() from HOME on Unix and USERPROFILE on Windows, so setting
// only HOME would leave Windows tests writing into the real user profile.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("SSHX_HOME", "")
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
	// The process-global logger keeps <home>/.sshx/sshx.log open for the rest
	// of the run. Windows cannot delete an open file, so release the handle
	// before t.TempDir cleanup removes this home directory.
	t.Cleanup(func() {
		if _, statErr := os.Stat(filepath.Join(dir, ".sshx", logger.DefaultLogFile)); statErr != nil {
			return
		}
		if err := logger.GetLogger().DisableFileLogging(); err != nil {
			t.Logf("failed to release test log file: %v", err)
		}
	})
}
