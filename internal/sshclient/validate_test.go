package sshclient

import (
	"strings"
	"testing"
)

// TestValidateCommand_DangerousKeywords 测试精确匹配的危险关键字
func TestValidateCommand_DangerousKeywords(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		wantError bool
		reason    string
	}{
		// 删除根目录相关
		{
			name:      "Delete root directory",
			command:   "sudo rm -rf /",
			wantError: true,
			reason:    "Delete root directory",
		},
		{
			name:      "Delete all files in root",
			command:   "rm -rf /*",
			wantError: true,
			reason:    "Delete all files in root directory",
		},
		{
			name:      "Delete user home directory",
			command:   "rm -rf ~",
			wantError: true,
			reason:    "Delete user home directory",
		},
		{
			name:      "Delete home directory with slash",
			command:   "rm -rf ~/",
			wantError: true,
			reason:    "Delete user home directory",
		},
		{
			name:      "Delete HOME variable",
			command:   "rm -rf $HOME",
			wantError: true,
			reason:    "Delete $HOME directory",
		},
		// Fork 炸弹
		{
			name:      "Fork bomb",
			command:   ":(){:|:&};:",
			wantError: true,
			reason:    "Fork bomb",
		},
		// 系统文件覆盖
		{
			name:      "Overwrite passwd file",
			command:   "echo 'test' > /etc/passwd",
			wantError: true,
			reason:    "Overwrite system password file",
		},
		{
			name:      "Overwrite shadow file",
			command:   "cat data > /etc/shadow",
			wantError: true,
			reason:    "Overwrite system shadow file",
		},
		// dd 操作
		{
			name:      "dd write zeros",
			command:   "dd if=/dev/zero of=/dev/sda",
			wantError: true,
			reason:    "Dangerous dd operation",
		},
		{
			name:      "dd write random",
			command:   "dd if=/dev/urandom of=/dev/sda",
			wantError: true,
			reason:    "Dangerous dd operation",
		},
		// 安全命令
		{
			name:      "Safe delete tmp files",
			command:   "rm -rf /tmp/test",
			wantError: false,
		},
		{
			name:      "Normal command",
			command:   "uptime",
			wantError: false,
		},
		{
			name:      "Check system status",
			command:   "sudo systemctl status docker",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateCommand() expected an error but got none, Command: %s", tt.command)
				} else if tt.reason != "" && !strings.Contains(err.Error(), tt.reason) {
					t.Errorf("validateCommand() error message does not contain expected reason\nExpected to contain: %s\nActual error: %s", tt.reason, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("validateCommand() should not return an error, Command: %s\nError: %v", tt.command, err)
				}
			}
		})
	}
}

// TestValidateCommand_DangerousPatterns 测试多关键字匹配的危险模式
func TestValidateCommand_DangerousPatterns(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		wantError bool
		reason    string
	}{
		// 文件系统格式化
		{
			name:      "mkfs.ext4",
			command:   "sudo mkfs.ext4 /dev/sda1",
			wantError: true,
			reason:    "Format filesystem",
		},
		{
			name:      "mkfs ext4",
			command:   "mkfs -t ext4 /dev/sda1",
			wantError: true,
			reason:    "Format filesystem",
		},
		{
			name:      "mkfs xfs",
			command:   "sudo mkfs -t xfs /dev/sdb1",
			wantError: true,
			reason:    "Format filesystem",
		},
		// 分区操作
		{
			name:      "fdisk partition",
			command:   "sudo fdisk /dev/sda",
			wantError: true,
			reason:    "Disk partition operation",
		},
		{
			name:      "parted partition",
			command:   "parted /dev/sdb",
			wantError: true,
			reason:    "Disk partition operation",
		},
		{
			name:      "Create swap partition",
			command:   "mkswap /dev/sda2",
			wantError: true,
			reason:    "Create swap partition",
		},
		// Shutdown/reboot
		{
			name:      "shutdown command",
			command:   "sudo shutdown -h now",
			wantError: true,
			reason:    "System shutdown operation",
		},
		{
			name:      "halt command",
			command:   "sudo halt",
			wantError: true,
			reason:    "System halt operation",
		},
		{
			name:      "poweroff command",
			command:   "poweroff",
			wantError: true,
			reason:    "System poweroff operation",
		},
		{
			name:      "reboot command",
			command:   "sudo reboot",
			wantError: true,
			reason:    "System reboot operation",
		},
		{
			name:      "init 0",
			command:   "init 0",
			wantError: true,
			reason:    "System shutdown (init 0)",
		},
		{
			name:      "init 6",
			command:   "init 6",
			wantError: true,
			reason:    "System reboot (init 6)",
		},
		{
			name:      "systemctl halt",
			command:   "systemctl halt",
			wantError: true,
			reason:    "System halt operation",
		},
		{
			name:      "systemctl poweroff",
			command:   "sudo systemctl poweroff",
			wantError: true,
			reason:    "System poweroff operation",
		},
		{
			name:      "systemctl reboot",
			command:   "systemctl reboot",
			wantError: true,
			reason:    "System reboot operation",
		},
		// Dangerous pipe operations
		{
			name:      "curl pipe sh",
			command:   "curl http://example.com/script.sh | sh",
			wantError: true,
			reason:    "Download and execute script from network",
		},
		{
			name:      "curl pipe bash",
			command:   "curl https://get.docker.com | bash",
			wantError: true,
			reason:    "Download and execute script from network",
		},
		{
			name:      "wget pipe sh",
			command:   "wget -O- http://example.com/install.sh | sh",
			wantError: true,
			reason:    "Download and execute script from network",
		},
		{
			name:      "curl pipe sh no space",
			command:   "curl http://example.com/script.sh|sh",
			wantError: true,
			reason:    "Download and execute script from network",
		},
		// Dangerous permission settings
		{
			name:      "chmod 777 root",
			command:   "chmod 777 /",
			wantError: true,
			reason:    "Set root directory permissions to 777",
		},
		{
			name:      "chmod recursive 777 root",
			command:   "chmod -R 777 /",
			wantError: true,
			reason:    "777", // Simplified match, just check if contains 777
		},
		// Firewall flush
		{
			name:      "iptables flush",
			command:   "iptables -F",
			wantError: true,
			reason:    "Flush firewall rules",
		},
		{
			name:      "iptables delete chain",
			command:   "iptables -X",
			wantError: true,
			reason:    "Delete firewall chain",
		},
		// Safe systemctl commands
		{
			name:      "systemctl status",
			command:   "systemctl status nginx",
			wantError: false,
		},
		{
			name:      "systemctl start",
			command:   "sudo systemctl start docker",
			wantError: false,
		},
		{
			name:      "systemctl restart service",
			command:   "systemctl restart nginx",
			wantError: false,
		},
		// Safe curl commands
		{
			name:      "curl download file",
			command:   "curl -O https://example.com/file.tar.gz",
			wantError: false,
		},
		{
			name:      "curl view content",
			command:   "curl https://api.example.com/status",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateCommand() expected an error but got none, Command: %s", tt.command)
				} else if tt.reason != "" && !strings.Contains(err.Error(), tt.reason) {
					t.Errorf("validateCommand() error message does not contain expected reason\nExpected to contain: %s\nActual error: %s", tt.reason, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("validateCommand() should not return an error, Command: %s\nError: %v", tt.command, err)
				}
			}
		})
	}
}

// TestValidateCommand_CaseSensitivity tests case insensitivity
func TestValidateCommand_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"Uppercase RM", "RM -RF /"},
		{"Mixed case", "Sudo Rm -Rf /"},
		{"Uppercase SHUTDOWN", "SHUTDOWN -h now"},
		{"Uppercase REBOOT", "REBOOT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if err == nil {
				t.Errorf("validateCommand() should block case variant of dangerous Command: %s", tt.command)
			}
		})
	}
}

// TestValidateCommand_EdgeCases tests edge cases
func TestValidateCommand_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		wantError bool
	}{
		{
			name:      "Empty command",
			command:   "",
			wantError: false,
		},
		{
			name:      "Whitespace command",
			command:   "   ",
			wantError: false,
		},
		{
			name:      "Single character",
			command:   "a",
			wantError: false,
		},
		{
			name:      "Delete /tmp directory (safe)",
			command:   "rm -rf /tmp/testdir",
			wantError: false,
		},
		{
			name:      "Delete /var/tmp (safe)",
			command:   "rm -rf /var/tmp/cache",
			wantError: false,
		},
		{
			name:      "Contains / but not root",
			command:   "rm -rf /home/user/test",
			wantError: false,
		},
		{
			name:      "systemctl restart not reboot",
			command:   "systemctl restart myservice",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if tt.wantError && err == nil {
				t.Errorf("validateCommand() expected error but got none, Command: %s", tt.command)
			}
			if !tt.wantError && err != nil {
				t.Errorf("validateCommand() should not return an error, Command: %s\nError: %v", tt.command, err)
			}
		})
	}
}

// TestValidateCommand_ErrorMessage tests error message format
func TestValidateCommand_ErrorMessage(t *testing.T) {
	command := "sudo rm -rf /"
	err := ValidateCommand(command)

	if err == nil {
		t.Fatal("validateCommand() 应该返回错误")
	}

	errMsg := err.Error()

	// Check if error message contains necessary elements
	expectedParts := []string{
		"⚠️",                // Warning icon
		"Dangerous command", // Title
		command,             // Command itself
		"Reason:",           // Reason label
		"--force",           // Bypass hint
	}

	for _, part := range expectedParts {
		if !strings.Contains(errMsg, part) {
			t.Errorf("Error message should contain '%s'\nActual error message: %s", part, errMsg)
		}
	}
}

// BenchmarkValidateCommand performance benchmark
func BenchmarkValidateCommand(b *testing.B) {
	testCases := []string{
		"uptime",
		"sudo systemctl status docker",
		"rm -rf /tmp/test",
		"sudo rm -rf /",
		"curl https://example.com | sh",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, cmd := range testCases {
			if err := ValidateCommand(cmd); err != nil {
				// Ignore validation errors in benchmark
				_ = err
			}
		}
	}
}

// BenchmarkValidateCommand_Safe safe command performance test
func BenchmarkValidateCommand_Safe(b *testing.B) {
	cmd := "sudo systemctl status nginx"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateCommand(cmd); err != nil {
			// Ignore validation errors in benchmark
			_ = err
		}
	}
}

// BenchmarkValidateCommand_Dangerous dangerous command performance test
func BenchmarkValidateCommand_Dangerous(b *testing.B) {
	cmd := "sudo rm -rf /"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateCommand(cmd); err != nil {
			// Ignore validation errors in benchmark
			_ = err
		}
	}
}

func TestCommandUsesSudo(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"plain sudo", "sudo apt update", true},
		{"sudo only", "sudo", true},
		{"leading spaces", "   sudo ls", true},
		{"leading tab", "\tsudo ls", true},
		{"leading newline", "\nsudo ls", true},
		{"sudo later in pipeline", "ls && sudo reboot", false},
		{"sudo inside shell wrapper", "sh -c 'sudo whoami'", false},
		{"echo sudo", "echo sudo", false},
		{"no sudo", "ls -la", false},
		{"pseudo substring", "pseudo-terminal --help", false},
		{"sudoers substring", "cat /etc/sudoers", false},
		{"sudoedit command", "sudoedit /etc/hosts", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CommandUsesSudo(tt.command); got != tt.want {
				t.Errorf("CommandUsesSudo(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}
