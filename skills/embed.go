// Package skills exposes the Agent skills shipped with sshx as embedded assets.
package skills

import _ "embed"

//go:embed sshx/SKILL.md
var sshxSkill []byte

// SSHX returns a copy of the canonical sshx Agent skill bundled in the binary.
func SSHX() []byte {
	return append([]byte(nil), sshxSkill...)
}
