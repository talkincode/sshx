package sshclient

import (
	"strings"
	"testing"
)

// TestNonLeadingSudoHint covers the case that produced 29 "sudo: a password is
// required" failures in one session: sudo reachable only after `&&`, inside a
// shell script, or behind a wrapper, where the leading-token auto-fill cannot
// apply.
func TestNonLeadingSudoHint(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		{"chained after cd", `cd /data/appdata/teamsacs && sudo docker compose up -d`, true},
		{"chained after semicolon", `cd /srv/app; sudo systemctl restart api`, true},
		{"pipeline", `ls /etc | sudo tee /etc/x`, true},
		{"inside sh -c", `sh -c 'sudo systemctl restart nginx'`, true},
		{"inside bash -lc", `bash -lc 'cd /srv && sudo docker compose restart'`, true},
		{"env prefix", `PATH=/usr/bin sudo id`, true},
		{"behind wrapper", `nohup sudo rm -rf /tmp/scratch`, true},
		{"standalone sudo", `sudo`, false},
		{"leading sudo", `sudo systemctl restart nginx`, false},
		{"leading sudo with flag", `sudo -n /usr/local/bin/deploy.sh`, false},
		{"no sudo", `systemctl restart nginx`, false},
		{"sudo as argument", `echo sudo`, false},
		{"sudo in grep pattern", `grep -n sudo /var/log/auth.log`, false},
		{"sudo in path", `/usr/bin/sudoedit -s /etc/sudoers`, false},
		{"container exec owns its sudo", `docker exec app sudo id`, false},
		{"empty", ``, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hint, got := NonLeadingSudoHint(tc.cmd)
			if got != tc.want {
				t.Fatalf("NonLeadingSudoHint(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
			if got {
				if hint == "" {
					t.Fatal("hint must not be empty when reported")
				}
				lowered := strings.ToLower(hint)
				for _, want := range []string{"sudo", "leading"} {
					if !strings.Contains(lowered, want) {
						t.Fatalf("hint %q must mention %q", hint, want)
					}
				}
			} else if hint != "" {
				t.Fatalf("hint must be empty when not reported, got %q", hint)
			}
		})
	}
}

// TestSudoPasswordPromptFailure pins the detection used to explain a refusal
// after the fact, when the warning before connecting was not seen.
func TestSudoPasswordPromptFailure(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"classic", "sudo: a password is required\n", true},
		{"no tty", "sudo: no tty present and no askpass program specified", true},
		{"no password provided", "sudo: no password was provided", true},
		{"mixed with other stderr", "warning: none\nsudo: a password is required\n", true},
		{"uppercase", "SUDO: A PASSWORD IS REQUIRED", true},
		{"plain failure", "bash: docker: command not found", false},
		{"success", "", false},
		{"unrelated sudo text", "sudo: unable to resolve host db1", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SudoPasswordPromptFailure(tc.output); got != tc.want {
				t.Fatalf("SudoPasswordPromptFailure(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}
