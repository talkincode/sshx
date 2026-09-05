//go:build unix

package app

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

type mcpProcess struct{ cmd *exec.Cmd }

func prepareMCPProcess(cmd *exec.Cmd) (*mcpProcess, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	return &mcpProcess{cmd: cmd}, nil
}

func (p *mcpProcess) started() error { return nil }

func (p *mcpProcess) interrupt() error {
	return syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT)
}

func (p *mcpProcess) kill() error {
	return syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
}

func (p *mcpProcess) close() {}

// Pollable duplicates let transport Close interrupt a blocked pipe write/read.
// Closing ordinary inherited *os.File handles need not interrupt synchronous IO.
func mcpStdioFiles() (*os.File, *os.File, error) {
	duplicate := func(file *os.File) (*os.File, error) {
		fd, err := syscall.Dup(int(file.Fd()))
		if err != nil {
			return nil, err
		}
		syscall.CloseOnExec(fd)
		if err := syscall.SetNonblock(fd, true); err != nil {
			mcpCleanup("unconfigured descriptor", syscall.Close(fd))
			return nil, err
		}
		return os.NewFile(uintptr(fd), file.Name()), nil
	}
	input, err := duplicate(os.Stdin)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare MCP stdin: %w", err)
	}
	output, err := duplicate(os.Stdout)
	if err != nil {
		mcpCleanup("stdin after initialization failure", input.Close())
		return nil, nil, fmt.Errorf("prepare MCP stdout: %w", err)
	}
	return input, output, nil
}
