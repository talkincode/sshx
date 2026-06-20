package app

import (
	"os"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestParseArgs_BasicSSH(t *testing.T) {
	args := []string{"sshx", "-h=192.168.1.100", "uptime"}
	config := ParseArgs(args)

	if config.Host != "192.168.1.100" {
		t.Errorf("Expected host 192.168.1.100, got %s", config.Host)
	}
	if config.Command != "uptime" {
		t.Errorf("Expected command 'uptime', got %s", config.Command)
	}
	if config.Mode != "ssh" {
		t.Errorf("Expected mode 'ssh', got %s", config.Mode)
	}
}

func TestParseArgs_SSHWithPort(t *testing.T) {
	args := []string{"sshx", "-h=192.168.1.100", "-p=2222", "ls -la"}
	config := ParseArgs(args)

	if config.Host != "192.168.1.100" {
		t.Errorf("Expected host 192.168.1.100, got %s", config.Host)
	}
	if config.Port != "2222" {
		t.Errorf("Expected port 2222, got %s", config.Port)
	}
	if config.Command != "ls -la" {
		t.Errorf("Expected command 'ls -la', got %s", config.Command)
	}
}

func TestParseArgs_SSHWithUser(t *testing.T) {
	args := []string{"sshx", "-h=example.com", "-u=admin", "whoami"}
	config := ParseArgs(args)

	if config.User != "admin" {
		t.Errorf("Expected user 'admin', got %s", config.User)
	}
	if config.Host != "example.com" {
		t.Errorf("Expected host example.com, got %s", config.Host)
	}
}

func TestParseArgs_SSHWithKeyPath(t *testing.T) {
	args := []string{"sshx", "-h=192.168.1.100", "-i=/path/to/key", "uptime"}
	config := ParseArgs(args)

	if config.KeyPath != "/path/to/key" {
		t.Errorf("Expected key path '/path/to/key', got %s", config.KeyPath)
	}
	if !config.UseKeyAuth {
		t.Errorf("Expected UseKeyAuth to be true when key path is provided")
	}
}

func TestParseArgs_NoKeyFlagDisablesKeyAuth(t *testing.T) {
	args := []string{"sshx", "-h=host", "--no-key", "uptime"}
	config := ParseArgs(args)

	if config.UseKeyAuth {
		t.Errorf("Expected UseKeyAuth to be false when --no-key is set")
	}
	if config.KeyPath != "" {
		t.Errorf("Expected key path to be empty when key auth disabled, got %s", config.KeyPath)
	}
}

func TestParseArgs_KeyFlagReenablesKeyAuth(t *testing.T) {
	args := []string{"sshx", "-h=host", "--no-key", "--key=/tmp/custom", "uptime"}
	config := ParseArgs(args)

	if !config.UseKeyAuth {
		t.Errorf("Expected UseKeyAuth to be true after specifying --key")
	}
	if config.KeyPath != "/tmp/custom" {
		t.Errorf("Expected key path '/tmp/custom', got %s", config.KeyPath)
	}
}

func TestParseArgs_ForceFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"short form", []string{"sshx", "-h=host", "-f", "uptime"}},
		{"long form", []string{"sshx", "-h=host", "--force", "uptime"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if !config.Force {
				t.Errorf("Expected Force to be true")
			}
		})
	}
}

func TestParseArgs_HostKeyFlags(t *testing.T) {
	args := []string{"sshx", "-h=host", "--accept-unknown-host", "--known-hosts=/tmp/known", "--insecure-hostkey", "uptime"}
	config := ParseArgs(args)
	if !config.AcceptUnknownHost {
		t.Fatalf("expected AcceptUnknownHost to be true")
	}
	if config.KnownHostsPath != "/tmp/known" {
		t.Fatalf("expected KnownHostsPath '/tmp/known', got %s", config.KnownHostsPath)
	}
	if !config.AllowInsecureHostKey {
		t.Fatalf("expected AllowInsecureHostKey to be true")
	}

	args = []string{"sshx", "-h=host", "--accept-unknown-host", "--strict-host-key", "uptime"}
	config = ParseArgs(args)
	if config.AllowInsecureHostKey {
		t.Fatalf("expected AllowInsecureHostKey to be false after --strict-host-key")
	}
}

func TestParseArgs_NoSafetyCheck(t *testing.T) {
	args := []string{"sshx", "-h=host", "--no-safety-check", "uptime"}
	config := ParseArgs(args)

	if config.SafetyCheck {
		t.Errorf("Expected SafetyCheck to be false")
	}
}

func TestParseArgs_DryRun(t *testing.T) {
	args := []string{"sshx", "-h=host", "--dry-run", "--json", "uptime"}
	config := ParseArgs(args)

	if !config.DryRun {
		t.Errorf("Expected DryRun to be true")
	}
	if !config.JSONOutput {
		t.Errorf("Expected JSONOutput to be true")
	}
	if config.Command != "uptime" {
		t.Errorf("Expected command 'uptime', got %s", config.Command)
	}
}

func TestParseArgs_AuditOptions(t *testing.T) {
	config := ParseArgs([]string{"sshx", "-h=host", "--audit-output=/tmp/sshx-audit", "uptime"})
	if !config.AuditEnabled {
		t.Error("Expected audit to be enabled by default")
	}
	if config.AuditOutput != "/tmp/sshx-audit" {
		t.Errorf("Expected audit output path, got %q", config.AuditOutput)
	}

	config = ParseArgs([]string{"sshx", "-h=host", "--no-audit", "uptime"})
	if config.AuditEnabled {
		t.Error("Expected audit to be disabled by --no-audit")
	}
}

func TestParseArgs_SFTPUpload(t *testing.T) {
	args := []string{"sshx", "-h=host", "--upload=local.txt", "--to=/remote/path.txt"}
	config := ParseArgs(args)

	if config.Mode != "sftp" {
		t.Errorf("Expected mode 'sftp', got %s", config.Mode)
	}
	if config.SftpAction != "upload" {
		t.Errorf("Expected sftp action 'upload', got %s", config.SftpAction)
	}
	if config.LocalPath != "local.txt" {
		t.Errorf("Expected local path 'local.txt', got %s", config.LocalPath)
	}
	if config.RemotePath != "/remote/path.txt" {
		t.Errorf("Expected remote path '/remote/path.txt', got %s", config.RemotePath)
	}
}

func TestParseArgs_SFTPDownload(t *testing.T) {
	args := []string{"sshx", "-h=host", "--download=/remote/file.log", "--to=./local.log"}
	config := ParseArgs(args)

	if config.Mode != "sftp" {
		t.Errorf("Expected mode 'sftp', got %s", config.Mode)
	}
	if config.SftpAction != "download" {
		t.Errorf("Expected sftp action 'download', got %s", config.SftpAction)
	}
	if config.RemotePath != "/remote/file.log" {
		t.Errorf("Expected remote path '/remote/file.log', got %s", config.RemotePath)
	}
	if config.LocalPath != "./local.log" {
		t.Errorf("Expected local path './local.log', got %s", config.LocalPath)
	}
}

func TestParseArgs_SFTPList(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"--list", []string{"sshx", "-h=host", "--list=/var/log"}},
		{"--ls", []string{"sshx", "-h=host", "--ls=/var/log"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if config.Mode != "sftp" {
				t.Errorf("Expected mode 'sftp', got %s", config.Mode)
			}
			if config.SftpAction != "list" {
				t.Errorf("Expected sftp action 'list', got %s", config.SftpAction)
			}
			if config.RemotePath != "/var/log" {
				t.Errorf("Expected remote path '/var/log', got %s", config.RemotePath)
			}
		})
	}
}

func TestParseArgs_SFTPMkdir(t *testing.T) {
	args := []string{"sshx", "-h=host", "--mkdir=/tmp/newdir"}
	config := ParseArgs(args)

	if config.Mode != "sftp" {
		t.Errorf("Expected mode 'sftp', got %s", config.Mode)
	}
	if config.SftpAction != "mkdir" {
		t.Errorf("Expected sftp action 'mkdir', got %s", config.SftpAction)
	}
	if config.RemotePath != "/tmp/newdir" {
		t.Errorf("Expected remote path '/tmp/newdir', got %s", config.RemotePath)
	}
}

func TestParseArgs_SFTPRemove(t *testing.T) {
	args := []string{"sshx", "-h=host", "--rm=/tmp/oldfile"}
	config := ParseArgs(args)

	if config.Mode != "sftp" {
		t.Errorf("Expected mode 'sftp', got %s", config.Mode)
	}
	if config.SftpAction != "remove" {
		t.Errorf("Expected sftp action 'remove', got %s", config.SftpAction)
	}
	if config.RemotePath != "/tmp/oldfile" {
		t.Errorf("Expected remote path '/tmp/oldfile', got %s", config.RemotePath)
	}
}

func TestParseArgs_PasswordSet(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedKey    string
		expectedValue  string
		expectedAction string
	}{
		{
			name:           "with value",
			args:           []string{"sshx", "--password-set=master:mypass"},
			expectedKey:    "master",
			expectedValue:  "mypass",
			expectedAction: "set",
		},
		{
			name:           "without value",
			args:           []string{"sshx", "--password-set=master"},
			expectedKey:    "master",
			expectedValue:  "",
			expectedAction: "set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if config.Mode != "password" {
				t.Errorf("Expected mode 'password', got %s", config.Mode)
			}
			if config.PasswordAction != tt.expectedAction {
				t.Errorf("Expected password action '%s', got %s", tt.expectedAction, config.PasswordAction)
			}
			if config.PasswordKey != tt.expectedKey {
				t.Errorf("Expected password key '%s', got %s", tt.expectedKey, config.PasswordKey)
			}
			if config.PasswordValue != tt.expectedValue {
				t.Errorf("Expected password value '%s', got %s", tt.expectedValue, config.PasswordValue)
			}
		})
	}
}

func TestParseArgs_PasswordGet(t *testing.T) {
	args := []string{"sshx", "--password-get=master"}
	config := ParseArgs(args)

	if config.Mode != "password" {
		t.Errorf("Expected mode 'password', got %s", config.Mode)
	}
	if config.PasswordAction != "get" {
		t.Errorf("Expected password action 'get', got %s", config.PasswordAction)
	}
	if config.PasswordKey != "master" {
		t.Errorf("Expected password key 'master', got %s", config.PasswordKey)
	}
}

func TestParseArgs_PasswordDelete(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"--password-delete", []string{"sshx", "--password-delete=testkey"}},
		{"--password-del", []string{"sshx", "--password-del=testkey"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if config.Mode != "password" {
				t.Errorf("Expected mode 'password', got %s", config.Mode)
			}
			if config.PasswordAction != "delete" {
				t.Errorf("Expected password action 'delete', got %s", config.PasswordAction)
			}
			if config.PasswordKey != "testkey" {
				t.Errorf("Expected password key 'testkey', got %s", config.PasswordKey)
			}
		})
	}
}

func TestParseArgs_PasswordCheck(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"--password-check", []string{"sshx", "--password-check=testkey"}},
		{"--password-exists", []string{"sshx", "--password-exists=testkey"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if config.Mode != "password" {
				t.Errorf("Expected mode 'password', got %s", config.Mode)
			}
			if config.PasswordAction != "check" {
				t.Errorf("Expected password action 'check', got %s", config.PasswordAction)
			}
			if config.PasswordKey != "testkey" {
				t.Errorf("Expected password key 'testkey', got %s", config.PasswordKey)
			}
		})
	}
}

func TestParseArgs_PasswordList(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"--password-list", []string{"sshx", "--password-list"}},
		{"--password-ls", []string{"sshx", "--password-ls"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if config.Mode != "password" {
				t.Errorf("Expected mode 'password', got %s", config.Mode)
			}
			if config.PasswordAction != "list" {
				t.Errorf("Expected password action 'list', got %s", config.PasswordAction)
			}
		})
	}
}

func TestParseArgs_HostTestAll(t *testing.T) {
	args := []string{"sshx", "--host-test-all"}
	config := ParseArgs(args)

	if config.Mode != "host" {
		t.Fatalf("expected mode 'host', got %s", config.Mode)
	}
	if config.HostAction != "test-all" {
		t.Fatalf("expected host action 'test-all', got %s", config.HostAction)
	}
}

func TestParseArgs_EnvVariables(t *testing.T) {
	// Save original env
	origPassword := os.Getenv("SSH_PASSWORD")
	origKeyPath := os.Getenv("SSH_KEY_PATH")
	origNoSafety := os.Getenv("SSH_NO_SAFETY_CHECK")
	origForce := os.Getenv("SSH_FORCE")
	origSudoKey := os.Getenv("SSH_SUDO_KEY")
	origDisableKey := os.Getenv("SSH_DISABLE_KEY")
	origKnownHosts := os.Getenv("SSH_KNOWN_HOSTS")
	origAcceptUnknown := os.Getenv("SSH_ACCEPT_UNKNOWN_HOST")
	origInsecure := os.Getenv("SSH_INSECURE_HOST_KEY")

	// Cleanup
	defer func() {
		if err := os.Setenv("SSH_PASSWORD", origPassword); err != nil {
			t.Logf("Failed to restore SSH_PASSWORD: %v", err)
		}
		if err := os.Setenv("SSH_KEY_PATH", origKeyPath); err != nil {
			t.Logf("Failed to restore SSH_KEY_PATH: %v", err)
		}
		if err := os.Setenv("SSH_NO_SAFETY_CHECK", origNoSafety); err != nil {
			t.Logf("Failed to restore SSH_NO_SAFETY_CHECK: %v", err)
		}
		if err := os.Setenv("SSH_FORCE", origForce); err != nil {
			t.Logf("Failed to restore SSH_FORCE: %v", err)
		}
		if err := os.Setenv("SSH_SUDO_KEY", origSudoKey); err != nil {
			t.Logf("Failed to restore SSH_SUDO_KEY: %v", err)
		}
		if err := os.Setenv("SSH_DISABLE_KEY", origDisableKey); err != nil {
			t.Logf("Failed to restore SSH_DISABLE_KEY: %v", err)
		}
		if err := os.Setenv("SSH_KNOWN_HOSTS", origKnownHosts); err != nil {
			t.Logf("Failed to restore SSH_KNOWN_HOSTS: %v", err)
		}
		if err := os.Setenv("SSH_ACCEPT_UNKNOWN_HOST", origAcceptUnknown); err != nil {
			t.Logf("Failed to restore SSH_ACCEPT_UNKNOWN_HOST: %v", err)
		}
		if err := os.Setenv("SSH_INSECURE_HOST_KEY", origInsecure); err != nil {
			t.Logf("Failed to restore SSH_INSECURE_HOST_KEY: %v", err)
		}
	}()

	// Test password from env
	if err := os.Setenv("SSH_PASSWORD", "envpass"); err != nil {
		t.Fatalf("Failed to set SSH_PASSWORD: %v", err)
	}
	if err := os.Setenv("SSH_KEY_PATH", "/env/key/path"); err != nil {
		t.Fatalf("Failed to set SSH_KEY_PATH: %v", err)
	}
	if err := os.Setenv("SSH_NO_SAFETY_CHECK", "true"); err != nil {
		t.Fatalf("Failed to set SSH_NO_SAFETY_CHECK: %v", err)
	}
	if err := os.Setenv("SSH_FORCE", "true"); err != nil {
		t.Fatalf("Failed to set SSH_FORCE: %v", err)
	}
	if err := os.Setenv("SSH_SUDO_KEY", "custom-sudo"); err != nil {
		t.Fatalf("Failed to set SSH_SUDO_KEY: %v", err)
	}
	if err := os.Setenv("SSH_KNOWN_HOSTS", "/env/known_hosts"); err != nil {
		t.Fatalf("Failed to set SSH_KNOWN_HOSTS: %v", err)
	}
	if err := os.Setenv("SSH_ACCEPT_UNKNOWN_HOST", "1"); err != nil {
		t.Fatalf("Failed to set SSH_ACCEPT_UNKNOWN_HOST: %v", err)
	}
	if err := os.Setenv("SSH_INSECURE_HOST_KEY", "true"); err != nil {
		t.Fatalf("Failed to set SSH_INSECURE_HOST_KEY: %v", err)
	}

	args := []string{"sshx", "-h=host", "uptime"}
	config := ParseArgs(args)

	if config.Password != "envpass" {
		t.Errorf("Expected password from env 'envpass', got %s", config.Password)
	}
	if config.KeyPath != "/env/key/path" {
		t.Errorf("Expected key path from env '/env/key/path', got %s", config.KeyPath)
	}
	if config.SafetyCheck {
		t.Errorf("Expected SafetyCheck to be false from env")
	}
	if !config.Force {
		t.Errorf("Expected Force to be true from env")
	}
	if config.SudoKey != "custom-sudo" {
		t.Errorf("Expected sudo key 'custom-sudo', got %s", config.SudoKey)
	}
	if !config.UseKeyAuth {
		t.Errorf("Expected UseKeyAuth to remain true when not disabled")
	}
	if config.KnownHostsPath != "/env/known_hosts" {
		t.Errorf("Expected KnownHostsPath '/env/known_hosts', got %s", config.KnownHostsPath)
	}
	if !config.AcceptUnknownHost {
		t.Errorf("Expected AcceptUnknownHost to be true from env")
	}
	if !config.AllowInsecureHostKey {
		t.Errorf("Expected AllowInsecureHostKey to be true from env")
	}
}

func TestParseArgs_DisableKeyEnv(t *testing.T) {
	origDisable := os.Getenv("SSH_DISABLE_KEY")
	origKey := os.Getenv("SSH_KEY_PATH")
	defer func() {
		if err := os.Setenv("SSH_DISABLE_KEY", origDisable); err != nil {
			t.Logf("Failed to restore SSH_DISABLE_KEY: %v", err)
		}
		if err := os.Setenv("SSH_KEY_PATH", origKey); err != nil {
			t.Logf("Failed to restore SSH_KEY_PATH: %v", err)
		}
	}()

	if err := os.Setenv("SSH_DISABLE_KEY", "true"); err != nil {
		t.Fatalf("Failed to set SSH_DISABLE_KEY: %v", err)
	}
	if err := os.Setenv("SSH_KEY_PATH", "/env/key/path"); err != nil {
		t.Fatalf("Failed to set SSH_KEY_PATH: %v", err)
	}

	config := ParseArgs([]string{"sshx", "-h=host", "uptime"})

	if config.UseKeyAuth {
		t.Errorf("Expected UseKeyAuth to be false when SSH_DISABLE_KEY is true")
	}
	if config.KeyPath != "" {
		t.Errorf("Expected key path to be cleared when SSH_DISABLE_KEY is true, got %s", config.KeyPath)
	}
}

func TestParseArgs_DefaultSudoKey(t *testing.T) {
	// Clear SSH_SUDO_KEY
	origSudoKey := os.Getenv("SSH_SUDO_KEY")
	if err := os.Unsetenv("SSH_SUDO_KEY"); err != nil {
		t.Fatalf("Failed to unset SSH_SUDO_KEY: %v", err)
	}
	defer func() {
		if err := os.Setenv("SSH_SUDO_KEY", origSudoKey); err != nil {
			t.Logf("Failed to restore SSH_SUDO_KEY: %v", err)
		}
	}()

	args := []string{"sshx", "-h=host", "uptime"}
	config := ParseArgs(args)

	if config.SudoKey != sshclient.DefaultSudoKey {
		t.Errorf("Expected default sudo key '%s', got %s", sshclient.DefaultSudoKey, config.SudoKey)
	}
}

func TestParseArgs_DefaultValues(t *testing.T) {
	args := []string{"sshx", "-h=host", "uptime"}
	config := ParseArgs(args)

	if config.Mode != "ssh" {
		t.Errorf("Expected default mode 'ssh', got %s", config.Mode)
	}
	if !config.SafetyCheck {
		t.Errorf("Expected default SafetyCheck to be true")
	}
	if config.Force {
		t.Errorf("Expected default Force to be false")
	}
}

func TestParseArgs_LongFormOptions(t *testing.T) {
	args := []string{
		"sshx",
		"--host=example.com",
		"--port=2222",
		"--user=admin",
		"--key=/path/to/key",
		"uptime",
	}
	config := ParseArgs(args)

	if config.Host != "example.com" {
		t.Errorf("Expected host 'example.com', got %s", config.Host)
	}
	if config.Port != "2222" {
		t.Errorf("Expected port '2222', got %s", config.Port)
	}
	if config.User != "admin" {
		t.Errorf("Expected user 'admin', got %s", config.User)
	}
	if config.KeyPath != "/path/to/key" {
		t.Errorf("Expected key path '/path/to/key', got %s", config.KeyPath)
	}
}

func TestParseArgs_ComplexCommand(t *testing.T) {
	args := []string{
		"sshx",
		"-h=host",
		"ps aux | grep nginx | awk '{print $2}'",
	}
	config := ParseArgs(args)

	expected := "ps aux | grep nginx | awk '{print $2}'"
	if config.Command != expected {
		t.Errorf("Expected command '%s', got '%s'", expected, config.Command)
	}
}

func TestParseArgs_RemoteCommandPreservesFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command string
		force   bool
		json    bool
	}{
		{
			name:    "remote grep flag after command start",
			args:    []string{"sshx", "-h=host", "--json", "grep", "-v", "foo"},
			command: "grep -v foo",
			json:    true,
		},
		{
			name:    "remote long help flag after command start",
			args:    []string{"sshx", "-h=host", "grep", "--help"},
			command: "grep --help",
		},
		{
			name:    "remote token matching local force after command start",
			args:    []string{"sshx", "-h=host", "echo", "--force"},
			command: "echo --force",
			force:   false,
		},
		{
			name:    "separator allows remote command to start with dash",
			args:    []string{"sshx", "-h=host", "--", "--version"},
			command: "--version",
		},
		{
			name:    "local force before command still applies",
			args:    []string{"sshx", "-h=host", "--force", "reboot"},
			command: "reboot",
			force:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ParseArgs(tt.args)
			if config.Command != tt.command {
				t.Fatalf("expected command %q, got %q", tt.command, config.Command)
			}
			if config.Force != tt.force {
				t.Fatalf("expected force=%t, got %t", tt.force, config.Force)
			}
			if config.JSONOutput != tt.json {
				t.Fatalf("expected json=%t, got %t", tt.json, config.JSONOutput)
			}
		})
	}
}
