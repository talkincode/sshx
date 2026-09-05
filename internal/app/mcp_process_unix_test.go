//go:build unix

package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPChildProcessGroupCleanup(t *testing.T) {
	for _, mode := range []string{"tree", "tree-exit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := filepath.Join(t.TempDir(), "ready")
			cmd := mcpTestCommand(t, mode, ready)
			done := make(chan error, 1)
			go func() {
				_, _, err := execMCPCommand(ctx, cmd, "", 0, nil)
				done <- err
			}()
			mcpWaitReady(t, ready)
			data, err := os.ReadFile(ready) // #nosec G304 -- This test's isolated readiness file.
			require.NoError(t, err)
			pid, err := strconv.Atoi(string(data))
			require.NoError(t, err)
			t.Cleanup(func() {
				killErr := syscall.Kill(pid, syscall.SIGKILL)
				if killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
					t.Errorf("clean up helper process: %v", killErr)
				}
			})
			if mode == "tree" {
				cancel()
			}
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(mcpShutdownGrace + 3*time.Second):
				t.Fatal("child process group cleanup did not finish")
			}
			assert.Eventually(t, func() bool {
				return syscall.Kill(pid, 0) == syscall.ESRCH
			}, 3*time.Second, 10*time.Millisecond, "owned descendant %d still exists", pid)
		})
	}
}
