package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMCPApplyStagePreview(t *testing.T) {
	client := startMCPClient(t, t.TempDir(), nil)
	failed, output := client.callTool("sshx_apply", map[string]any{"target": "192.0.2.1", "path": "/tmp/fixture", "content": "fixture", "sudo": true, "stage_dir": "/data/private-stage", "dry_run": true})
	assert.False(t, failed, output)
	assert.Contains(t, output, "/data/private-stage")
	failed, output = client.callTool("sshx_apply", map[string]any{"target": "192.0.2.1", "path": "/tmp/fixture", "content": "fixture", "stage_dir": "/data/private-stage", "dry_run": true})
	assert.True(t, failed, output)
}
