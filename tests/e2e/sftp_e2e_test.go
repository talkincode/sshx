package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLISFTPWorkflowCoversWriteReadRemoveAndPermissionFailure(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	operatorHome := t.TempDir()
	localSource := filepath.Join(operatorHome, "local.txt")
	require.NoError(t, os.WriteFile(localSource, []byte("sftp-payload\n"), 0o600))
	operatorBase := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
	}
	operatorEnv := map[string]string{"SSH_PASSWORD": operatorPassword}

	upload := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...),
		"--accept-unknown-host", "--upload="+localSource, "--to=uploaded.txt"), operatorEnv)
	require.Equal(t, 0, upload.exitCode, upload.stderr)
	remoteContent, err := os.ReadFile(filepath.Join(server.root, "uploaded.txt"))
	require.NoError(t, err)
	assert.Equal(t, "sftp-payload\n", string(remoteContent))

	listing := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...), "--list=."), operatorEnv)
	require.Equal(t, 0, listing.exitCode, listing.stderr)
	assert.Contains(t, listing.stdout, "uploaded.txt")

	localDownload := filepath.Join(operatorHome, "downloaded.txt")
	download := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...),
		"--download=uploaded.txt", "--to="+localDownload), operatorEnv)
	require.Equal(t, 0, download.exitCode, download.stderr)
	downloaded, err := os.ReadFile(localDownload) // #nosec G304 -- path is inside this test's temporary HOME.
	require.NoError(t, err)
	assert.Equal(t, "sftp-payload\n", string(downloaded))

	mkdir := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...), "--mkdir=nested/dir"), operatorEnv)
	require.Equal(t, 0, mkdir.exitCode, mkdir.stderr)
	info, err := os.Stat(filepath.Join(server.root, "nested", "dir"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	removeDir := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...), "--rm=nested"), operatorEnv)
	require.Equal(t, 0, removeDir.exitCode, removeDir.stderr)
	_, err = os.Stat(filepath.Join(server.root, "nested"))
	assert.ErrorIs(t, err, os.ErrNotExist)

	readerHome := t.TempDir()
	readerBase := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=reader",
		"--no-key",
	}
	readerEnv := map[string]string{"SSH_PASSWORD": readerPassword}
	readerDownload := filepath.Join(readerHome, "reader-copy.txt")
	readAllowed := runSSHX(t, readerHome, append(append([]string{}, readerBase...),
		"--accept-unknown-host", "--download=uploaded.txt", "--to="+readerDownload), readerEnv)
	require.Equal(t, 0, readAllowed.exitCode, readAllowed.stderr)

	readerSource := filepath.Join(readerHome, "forbidden.txt")
	require.NoError(t, os.WriteFile(readerSource, []byte("must-not-land"), 0o600))
	writeDenied := runSSHX(t, readerHome, append(append([]string{}, readerBase...),
		"--upload="+readerSource, "--to=forbidden.txt"), readerEnv)
	require.Equal(t, 255, writeDenied.exitCode)
	assert.Contains(t, writeDenied.stderr, "permission denied")
	_, err = os.Stat(filepath.Join(server.root, "forbidden.txt"))
	assert.ErrorIs(t, err, os.ErrNotExist, "failed upload must not leave a destination file")
}

func TestCLIServerToServerTransferCoversSuccessFailureAndRecovery(t *testing.T) {
	source := startSSHServer(t, serverOptions{})
	destination := startSSHServer(t, serverOptions{})
	locked := startSSHServer(t, serverOptions{sftpReadOnly: true})
	require.NoError(t, os.WriteFile(filepath.Join(source.root, "payload.txt"), []byte("streamed-between-hosts\n"), 0o600))

	home := t.TempDir()
	writeNamedHosts(t, home, map[string]*testSSHServer{
		"source": source,
		"dest":   destination,
		"locked": locked,
	})
	env := map[string]string{"SSH_PASSWORD": operatorPassword}

	success := runSSHX(t, home, []string{
		"--transfer=source:payload.txt",
		"--to=dest:received.txt",
		"--no-key",
		"--accept-unknown-host",
	}, env)
	require.Equal(t, 0, success.exitCode, success.stderr)
	content, err := os.ReadFile(filepath.Join(destination.root, "received.txt"))
	require.NoError(t, err)
	assert.Equal(t, "streamed-between-hosts\n", string(content))

	failed := runSSHX(t, home, []string{
		"--transfer=source:payload.txt",
		"--to=locked:partial.txt",
		"--no-key",
		"--accept-unknown-host",
	}, env)
	require.Equal(t, 255, failed.exitCode)
	assert.Contains(t, failed.stderr, "permission denied")
	_, err = os.Stat(filepath.Join(locked.root, "partial.txt"))
	assert.ErrorIs(t, err, os.ErrNotExist, "failed transfer must not leave a destination file")

	recovered := runSSHX(t, home, []string{
		"--transfer=source:payload.txt",
		"--to=dest:recovered.txt",
		"--no-key",
	}, env)
	require.Equal(t, 0, recovered.exitCode, recovered.stderr)
	recoveredContent, err := os.ReadFile(filepath.Join(destination.root, "recovered.txt"))
	require.NoError(t, err)
	assert.Equal(t, "streamed-between-hosts\n", string(recoveredContent))
}

func writeNamedHosts(t *testing.T, home string, servers map[string]*testSSHServer) {
	t.Helper()
	type host struct {
		Name string `json:"name"`
		Host string `json:"host"`
		Port string `json:"port"`
		User string `json:"user"`
	}
	type settings struct {
		Hosts []host `json:"hosts"`
	}

	fixture := settings{Hosts: make([]host, 0, len(servers))}
	for name, server := range servers {
		fixture.Hosts = append(fixture.Hosts, host{Name: name, Host: server.host, Port: server.port, User: "operator"})
	}
	data, err := json.Marshal(fixture)
	require.NoError(t, err)
	dir := filepath.Join(home, ".sshx")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "settings.json"), data, 0o600))
}
