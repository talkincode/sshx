package app

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/internal/textsafe"
)

func TestTextRequestFromFileDefaults(t *testing.T) {
	req, err := textRequestFrom(&sshclient.Config{
		RemotePath: "/var/log/app.log",
		TextRedact: true,
	})
	require.NoError(t, err)
	require.Equal(t, textsafe.SourceFile, req.Kind)
	require.Equal(t, textsafe.ScanEnd, req.Scan)
	require.Equal(t, []string{"exception", "error", "panic", "oom"}, req.Presets)
	require.True(t, req.Redact)
}

func TestTextRequestFromRejectsCommandShapedFlags(t *testing.T) {
	_, err := textRequestFrom(&sshclient.Config{})
	require.Error(t, err)
	_, err = textRequestFrom(&sshclient.Config{RemotePath: "relative.log"})
	require.Error(t, err)
	_, err = textRequestFrom(&sshclient.Config{RemotePath: "/var/log/a.log", TextJournal: "nginx.service"})
	require.Error(t, err)
}

func TestBuildTextArgs(t *testing.T) {
	args, err := buildTextArgs(mcpTextInput{
		Target: "prod", Path: "/var/log/app.log", Presets: []string{"exception"}, Context: 2, Sudo: true,
	})
	require.NoError(t, err)
	joined := strings.Join(args, " ")
	require.Contains(t, joined, "text --json -h=prod")
	require.Contains(t, joined, "--path=/var/log/app.log")
	require.Contains(t, joined, "--preset=exception")
	require.Contains(t, joined, "--sudo")
	_, err = buildTextArgs(mcpTextInput{Target: "prod"})
	require.Error(t, err)
	_, err = buildTextArgs(mcpTextInput{Target: "prod", Path: "/a", Journal: "nginx.service"})
	require.Error(t, err)
}
