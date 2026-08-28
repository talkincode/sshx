package sshclient

import (
	"errors"
	"strings"
	"testing"
)

// The cases below are sanitized shapes of commands that a real operator
// workload actually issued and that the previous keyword-anywhere validator
// wrongly blocked. Of 49 commands blocked over ~12k audited invocations, only
// one ("rm -rf /") was genuinely destructive; the rest were read-only
// diagnostics. A guardrail that fires on reads trains the caller to pass
// --force reflexively, so these must stay allowed.
func TestValidateCommand_ReadOnlyDiagnosticsNotBlocked(t *testing.T) {
	allowed := []struct {
		name    string
		command string
	}{
		{
			// "reboot" is an argument to `last`, not the command.
			name:    "last reboot listing",
			command: "last reboot -F 2>&1 | head -10; journalctl --list-boots --no-pager | tail -10",
		},
		{
			// "halt" appears inside a grep pattern.
			name:    "journalctl filtered by keywords",
			command: "journalctl -u app --since '15 min ago' --no-pager | grep -iE 'warn|error|alert|fail|halt'",
		},
		{
			// iptables-save is a different binary; -F here is grep's fixed-string flag.
			name:    "iptables-save piped to grep -F",
			command: `sudo /usr/sbin/iptables-save | grep -F "10.20.30.0/24"; sysctl -n net.ipv4.ip_forward`,
		},
		{
			name:    "iptables rule listing inside a shell wrapper",
			command: `sudo bash -lc 'iptables -t nat -S POSTROUTING | grep -E "10\.1\.(2|3)"; systemctl is-active app'`,
		},
		{
			name:    "iptables -S with a compose file flag",
			command: `sudo sh -c 'iptables -S DOCKER-USER; docker compose -f /srv/app/compose.yml ps'`,
		},
		{
			// "| sha256sum" is not a shell.
			name:    "curl piped to a checksum",
			command: "curl -fsS http://127.0.0.1:9000/assets/policy.js | sha256sum",
		},
		{
			name:    "curl output captured in a variable",
			command: "policy=$(curl -fsS http://127.0.0.1:9000/state) && echo \"$policy\" | head -c 200",
		},
		{
			// wipefs with only a device prints signatures; parted print is read-only.
			name:    "disk inspection sweep",
			command: `echo "=== BLKID ==="; sudo blkid /dev/sdb || true; sudo wipefs /dev/sdb || true; sudo parted /dev/sdb print || true`,
		},
		{
			name:    "fdisk listing",
			command: "sudo fdisk -l /dev/sda",
		},
		{
			name:    "sfdisk dump",
			command: "sudo sfdisk -d /dev/sda",
		},
		{
			name:    "systemctl status of a unit whose name contains halt",
			command: "systemctl status halt.service",
		},
		{
			name:    "restart a service",
			command: "sudo systemctl restart app.service",
		},
		{
			name:    "recursive delete of an application log directory",
			command: "sudo rm -rf /var/log/app/old/*",
		},
		{
			name:    "recursive delete under tmp",
			command: "rm -rf /tmp/build-cache",
		},
		{
			name:    "echo containing a reboot-derived identifier",
			command: `echo "authlog_since_reboot=12"`,
		},
		{
			name:    "backup script that mentions removal",
			command: `sudo sh -c 'set -eu; TS=$(date +%Y%m%d); mkdir -p /srv/backups/$TS; tar -czf /srv/backups/$TS/etc.tgz /etc'`,
		},
		{
			name:    "container command listing",
			command: `sudo docker ps --format "table {{.Names}}\t{{.Status}}"`,
		},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCommand(tt.command); err != nil {
				t.Errorf("expected command to be allowed\nCommand: %s\nBlocked: %v", tt.command, err)
			}
		})
	}
}

// TestValidateCommand_DestructiveStillBlocked pins the recall side: narrowing
// the matcher to command position must not let real destructive operations
// through, including ones nested in shell or container wrappers.
func TestValidateCommand_DestructiveStillBlocked(t *testing.T) {
	blocked := []struct {
		name    string
		command string
		reason  string
	}{
		{"root delete", "sudo rm -rf /", "Delete root directory"},
		{"root glob delete", "rm -rf /*", "Delete all files in root directory"},
		{"no-preserve-root", "rm -rf --no-preserve-root /home/user", "Delete root directory"},
		{"critical system dir", "sudo rm -rf /etc", "critical system directory"},
		{"critical system dir trailing slash", "sudo rm -rf /usr/", "critical system directory"},
		{"iptables flush", "sudo iptables -F", "Flush firewall rules"},
		{"iptables delete chain", "sudo ip6tables -X", "Delete firewall chain"},
		{"reboot inside shell wrapper", "sudo bash -lc 'reboot'", "System reboot operation"},
		{"reboot inside nested shell", `sudo sh -c "bash -c 'shutdown -h now'"`, "System shutdown operation"},
		{"curl piped into sudo bash", "curl -fsSL https://example.com/install.sh | sudo bash", "Download and execute"},
		{"wget piped into sh", "wget -qO- https://example.com/i.sh | sh", "Download and execute"},
		{"wipefs erase", "sudo wipefs -a /dev/sdb", "Erase filesystem signatures"},
		{"parted mklabel", "sudo parted /dev/sdb mklabel gpt", "Disk partition operation"},
		{"dd over a block device", "sudo dd if=/dev/zero of=/dev/sda bs=1M count=100", "Dangerous dd operation"},
		{"chmod 777 root", "sudo chmod -R 777 /", "777"},
		{"overwrite shadow", "echo x > /etc/shadow", "Overwrite system shadow file"},
		{"append to passwd", "cat extra >> /etc/passwd", "Overwrite system password file"},
		{"lvremove", "sudo lvremove -f /dev/vg0/data", "Remove LVM logical volume"},
		{"zpool destroy", "sudo zpool destroy tank", "Destroy ZFS pool"},
		{"destructive delete inside a container", "docker exec -u root app rm -rf /", "Delete root directory"},
		{"compose exec destructive delete", "docker compose -f /srv/compose.yml exec app rm -rf /", "Delete root directory"},
		{"mkfs variant", "sudo mkfs.btrfs /dev/sdb1", "Format filesystem"},
		{"chown root recursively", "sudo chown -R nobody /", "ownership of the root directory"},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if err == nil {
				t.Fatalf("expected command to be blocked: %s", tt.command)
			}
			var blockErr *CommandBlockedError
			if !errors.As(err, &blockErr) {
				t.Fatalf("expected CommandBlockedError, got %T", err)
			}
			if tt.reason != "" && !strings.Contains(blockErr.Reason, tt.reason) {
				t.Errorf("reason mismatch\nCommand: %s\nWant substring: %s\nGot: %s", tt.command, tt.reason, blockErr.Reason)
			}
		})
	}
}
