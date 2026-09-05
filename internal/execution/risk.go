package execution

import (
	"strings"

	"github.com/talkincode/sshx/internal/sshclient"
)

type Risk string

const (
	RiskRead        Risk = "read"
	RiskMutation    Risk = "mutation"
	RiskPrivileged  Risk = "privileged"
	RiskDestructive Risk = "destructive"
)

// Effects retain facts that cannot be represented by a single risk level.
type Effects struct {
	Unknown     bool `json:"unknown"`
	RemoteWrite bool `json:"remote_write"`
	LocalWrite  bool `json:"local_write"`
	Privileged  bool `json:"privileged"`
	Destructive bool `json:"destructive"`
}

func (e Effects) Risk() Risk {
	switch {
	case e.Destructive:
		return RiskDestructive
	case e.Privileged:
		return RiskPrivileged
	case e.RemoteWrite || e.Unknown:
		return RiskMutation
	default:
		return RiskRead
	}
}

// ClassifyRisk is deliberately narrower than shell validation: admission to
// the command guardrail does not establish that a command is read-only.
func ClassifyRisk(action, command string, sudo bool) (Risk, Effects) {
	e := Effects{Privileged: sudo || sshclient.CommandUsesSudo(command)}
	switch action {
	case "download":
		e.LocalWrite = true
	case "list", "ls", "host-list":
	case "upload", "mkdir", "transfer", "apply":
		e.RemoteWrite = true
	case "remove", "rm":
		e.RemoteWrite, e.Destructive = true, true
	case "command":
		switch strings.TrimSpace(command) {
		case "uname", "uname -a", "uname -s", "id", "whoami", "pwd", "uptime", "true", "false":
		default:
			e.Unknown, e.RemoteWrite = true, true
		}
		e.Destructive = sshclient.CommandIsDestructive(command)
	case "script":
		e.Unknown, e.RemoteWrite = true, true
		e.Destructive = sshclient.CommandIsDestructive(command)
	default:
		e.Unknown, e.RemoteWrite = true, true
	}
	return e.Risk(), e
}
