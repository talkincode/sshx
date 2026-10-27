package sshclient

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

// Keep existing domain fixtures focused on their action, while honoring the
// authentication/readiness transport protocol. Dedicated boundary tests also
// execute actual shells without this compatibility adapter.
func unwrapSudoFixture(ch ssh.Channel, command string) (ssh.Channel, string) {
	prompt := regexp.MustCompile(`SSHX_SUDO_PROMPT_[a-f0-9]+`).FindString(command)
	ready := regexp.MustCompile(`SSHX_SUDO_READY_[a-f0-9]+`).FindString(command)
	_, suffix, ok := strings.Cut(command, `' sh `)
	if prompt == "" || ready == "" || !ok {
		return ch, command
	}
	writeAll(ch.Stderr(), prompt)
	reader := bufio.NewReader(ch)
	password, err := reader.ReadString('\n')
	if err != nil {
		return ch, "fixture-auth-failed"
	}
	writeAll(ch.Stderr(), ready)
	return sudoFixtureChannel{ch, io.MultiReader(strings.NewReader(password), reader)}, "sudo -S -p '' " + suffix
}
