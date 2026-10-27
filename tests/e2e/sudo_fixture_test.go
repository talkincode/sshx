package e2e

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

type sudoFixtureChannel struct {
	ssh.Channel
	input io.Reader
}

func (c sudoFixtureChannel) Read(p []byte) (int, error) { return c.input.Read(p) }

func unwrapSudoFixture(ch ssh.Channel, command string) (ssh.Channel, string) {
	prompt := regexp.MustCompile(`SSHX_SUDO_PROMPT_[a-f0-9]+`).FindString(command)
	ready := regexp.MustCompile(`SSHX_SUDO_READY_[a-f0-9]+`).FindString(command)
	_, suffix, ok := strings.Cut(command, `' sh `)
	if prompt == "" || ready == "" || !ok {
		return ch, command
	}
	_, _ = io.WriteString(ch.Stderr(), prompt) //nolint:errcheck // fixture transport teardown
	reader := bufio.NewReader(ch)
	password, err := reader.ReadString('\n')
	if err != nil {
		return ch, "fixture-auth-failed"
	}
	_, _ = io.WriteString(ch.Stderr(), ready) //nolint:errcheck // fixture transport teardown
	return sudoFixtureChannel{ch, io.MultiReader(strings.NewReader(password), reader)}, "sudo -S -p '' " + suffix
}
