package app

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type mcpProcess struct {
	cmd *exec.Cmd
	job windows.Handle
	pid uint32
}

func prepareMCPProcess(cmd *exec.Cmd) (*mcpProcess, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create MCP child job: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { // #nosec G103 -- Windows requires a pointer to this sized native structure.
		mcpCleanup("unconfigured job", windows.CloseHandle(job))
		return nil, fmt.Errorf("configure MCP child job: %w", err)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Suspend until job assignment so even an immediately spawned descendant
	// belongs to our kill-on-close job. A post-start assignment alone races.
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED
	return &mcpProcess{cmd: cmd, job: job}, nil
}

func (p *mcpProcess) started() error {
	pid := p.cmd.Process.Pid
	if pid <= 0 || uint64(pid) > math.MaxUint32 {
		return fmt.Errorf("invalid MCP child process identifier")
	}
	p.pid = uint32(pid)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, p.pid)
	if err != nil {
		return fmt.Errorf("open MCP child process: %w", err)
	}
	defer func() { mcpCleanup("process handle", windows.CloseHandle(process)) }()
	if assignErr := windows.AssignProcessToJobObject(p.job, process); assignErr != nil {
		return fmt.Errorf("assign MCP child job: %w", assignErr)
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("enumerate suspended MCP child thread: %w", err)
	}
	defer func() { mcpCleanup("thread snapshot", windows.CloseHandle(snapshot)) }()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err := windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != p.pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return fmt.Errorf("open suspended MCP child thread: %w", err)
		}
		_, resumeErr := windows.ResumeThread(thread)
		mcpCleanup("resumed thread handle", windows.CloseHandle(thread))
		if resumeErr != nil {
			return fmt.Errorf("resume MCP child: %w", resumeErr)
		}
		return nil
	}
	return fmt.Errorf("suspended MCP child thread not found")
}

func (p *mcpProcess) interrupt() error {
	// CTRL_BREAK reaches Go's os.Interrupt handler for a console process
	// group. GUI/no-console parents may not support it; bounded job
	// termination remains the honest fallback, not a fake canceled result.
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, p.pid)
}

func (p *mcpProcess) kill() error {
	return windows.TerminateJobObject(p.job, 1)
}

func (p *mcpProcess) close() {
	mcpCleanup("job handle", windows.CloseHandle(p.job))
}

func mcpStdioFiles() (*os.File, *os.File, error) {
	// os.File.Close cancels pending IO on Windows pipe handles.
	return os.Stdin, os.Stdout, nil
}
