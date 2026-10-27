package sshclient

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSudoFramingAcrossEveryPacketBoundary(t *testing.T) {
	const prompt = "SSHX_SUDO_PROMPT_fixture"
	const ready = "SSHX_SUDO_READY_fixture"
	text := "notice:" + prompt + "authenticated:" + ready + "application stderr"
	for split := 0; split <= len(text); split++ {
		exchange := &sudoExchange{prompt: prompt, ready: ready, events: make(chan bool, 2), abort: func() { t.Fatal("unexpected protocol rejection") }}
		var out bytes.Buffer
		writer := &sudoControlWriter{dst: &out, auth: exchange}
		_, err := writer.Write([]byte(text[:split]))
		require.NoError(t, err)
		_, err = writer.Write([]byte(text[split:]))
		require.NoError(t, err)
		require.NoError(t, writer.flush())
		assert.Equal(t, "notice:authenticated:application stderr", out.String())
		assert.False(t, <-exchange.events)
		assert.True(t, <-exchange.events)
	}
}

func TestSudoNoPromptDoesNotRequestCredential(t *testing.T) {
	exchange := &sudoExchange{prompt: "PROMPT", ready: "READY", events: make(chan bool, 2), abort: func() { t.Fatal("unexpected abort") }}
	var out bytes.Buffer
	writer := &sudoControlWriter{dst: &out, auth: exchange}
	_, err := writer.Write([]byte("READYpayload"))
	require.NoError(t, err)
	require.Len(t, exchange.events, 1)
	assert.True(t, <-exchange.events)
	assert.Equal(t, "payload", out.String())
}

func TestSudoCommandKeepsShellBoundary(t *testing.T) {
	for _, cmd := range []string{`sudo cat`, `sudo -u root -n sh -c 'printf x' | grep x`, `sudo -H echo "a b" > /tmp/file`, `sudo --user=root -- cat`} {
		wrapped, err := sudoReadyCommand(cmd, "PROMPT", "READY")
		require.NoError(t, err)
		assert.Contains(t, wrapped, `exec "$@"`)
		if strings.Contains(cmd, " | grep x") {
			assert.True(t, strings.HasSuffix(wrapped, `sh -c 'printf x' | grep x`))
		}
	}
	for _, cmd := range []string{"sudo", "sudo -i", "sudo -s sh", "sudo -u", "sudo -u $(whoami) id"} {
		_, err := sudoReadyCommand(cmd, "PROMPT", "READY")
		require.Error(t, err, cmd)
	}
}
