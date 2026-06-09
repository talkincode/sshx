package app

import "fmt"

// PrintUsage prints the usage information for the sshx command.
func PrintUsage() {
	fmt.Println(`
SSH & SFTP Remote Tool with Password Manager (Cross-Platform)

Usage:
  sshx -h=<host> [options] <command>              # SSH mode
  sshx -h=<host> [options] --upload=<file>        # SFTP upload
  sshx -h=<host> [options] --download=<file>      # SFTP download
  sshx --password-set=<key>[:<password>]          # Set password in keyring
  sshx --password-get=<key>                       # Get password from keyring
  sshx --password-delete=<key>                    # Delete password from keyring
  sshx --password-list                            # List common password keys
  sshx --host-add                                 # Add host configuration
  sshx --host-update                              # Update host configuration
  sshx --host-list                                # List configured hosts
  sshx --host-test=<name>                         # Test host connection
  sshx --host-test-all                            # Test all host connections
  sshx --host-remove=<name>                       # Remove host configuration

SSH Options:
  -h, --host=HOST          Remote host address (required)
  -p, --port=PORT          SSH port (default: 22)
  -u, --user=USER          SSH username (default: master)
  -i, --key=PATH           SSH private key path (default: ~/.ssh/id_rsa)
  -pk, --password-key=KEY  Sudo password keyring key name (default: master)
  --help                   Show this help message

Safety Options:
  -f, --force           Force execution, bypass safety checks (use with caution!)
  --no-safety-check     Disable safety checks completely (not recommended)

  Safety checks protect against:
    - Destructive operations (rm -rf /, mkfs, dd)
    - System shutdown/reboot commands
    - Critical file modifications (/etc/passwd, /etc/shadow)
    - Dangerous pipe operations (curl | sh)
    - Fork bombs and other malicious patterns

SFTP Options:
  --upload=<local>      Upload file (use with --to=<remote>)
  --download=<remote>   Download file (use with --to=<local>)
  --to=<path>           Target path for upload/download
  --list=<path>         List directory contents (alias: --ls)
  --mkdir=<path>        Create remote directory
  --rm=<path>           Remove remote file or directory

Password Management (Cross-Platform):
  --password-set=<key>[:<password>]   Set password in system keyring
                                      If password omitted, will prompt
  --password-get=<key>                Get password from keyring
  --password-check=<key>              Check if password exists (alias: --password-exists)
  --password-delete=<key>             Delete password from keyring (alias: --password-del)
  --password-list                     List common password keys (alias: --password-ls)

  Platform Support:
    macOS:   Uses Keychain
    Linux:   Uses Secret Service (gnome-keyring/kwallet)
    Windows: Uses Credential Manager

Host Management:
  --host-add                          Add new host (interactive or with options)
  --host-update                       Update existing host configuration
  --host-list                         List all configured hosts (alias: --host-ls)
  --host-test=<name>                  Test connection to configured host
  --host-test-all                     Test connections for all configured hosts
  --host-remove=<name>                Remove host from configuration (alias: --host-rm)

  Host Add/Update Options:
    --host-name=<name>                Host name (unique identifier, required for update)
    --host-desc=<description>         Host description
    -h=<address>                      Host address (IP or hostname)
    -p=<port>                         SSH port
    -u=<user>                         SSH username
    -i=<key>, --key=<key>            SSH private key path for this host (optional)
    -pk=<key>                         Password key name
    --host-type=<type>                System type (linux/windows/macos)

  Configuration file: ~/.sshx/settings.json

Environment Variables (.env):
  SSH_PASSWORD          SSH password (not recommended, use SSH keys or keyring)
  SSH_KEY_PATH          SSH private key path
  SSH_SUDO_KEY          Sudo password keyring key name (default: master)
  SSH_NO_SAFETY_CHECK   Disable safety checks (true/false)
  SSH_FORCE             Force execution mode (true/false)

SSH Examples:
  # Execute simple command (default user: master)
  sshx -h=192.168.1.100 "uptime"

  # Execute sudo command (auto password from keyring: master)
  sshx -h=192.168.1.100 "sudo systemctl status docker"

  # Use custom sudo password key for specific server
  sshx -h=192.168.1.100 -pk=server-A "sudo systemctl restart nginx"
  sshx -h=192.168.1.101 -pk=server-B "sudo systemctl restart nginx"

  # Custom SSH port
  sshx -h=192.168.1.100 -p=2222 "ps aux | grep nginx"

  # Dangerous command will be blocked
  sshx -h=192.168.1.100 "sudo rm -rf /tmp/*"  # Safe
  sshx -h=192.168.1.100 "sudo rm -rf /"       # ⚠️ BLOCKED!

  # Force execute (bypass safety check - use with caution!)
  sshx -h=192.168.1.100 --force "sudo reboot"
  sshx -h=192.168.1.100 -f "sudo systemctl reboot"

SFTP Examples:
  # Upload file
  sshx -h=192.168.1.100 --upload=local.txt --to=/tmp/remote.txt

  # Download file
  sshx -h=192.168.1.100 --download=/var/log/app.log --to=./app.log

  # List directory
  sshx -h=192.168.1.100 --list=/var/log

  # Create directory
  sshx -h=192.168.1.100 --mkdir=/tmp/newdir

  # Remove file
  sshx -h=192.168.1.100 --rm=/tmp/oldfile.txt

  # Batch upload
  for file in *.txt; do
    sshx -h=192.168.1.100 --upload=$file --to=/backup/$file
  done

Password Management Examples:
  # Set default sudo password (interactive prompt)
  sshx --password-set=master

  # Set sudo password (inline, not recommended for security)
  sshx --password-set=master:mypassword

  # Set passwords for different servers with same username
  sshx --password-set=server-A
  sshx --password-set=server-B
  sshx --password-set=server-C

  # Use different password keys for different servers
  sshx -h=192.168.1.100 -pk=server-A "sudo systemctl status nginx"
  sshx -h=192.168.1.101 -pk=server-B "sudo systemctl status nginx"
  sshx -h=192.168.1.102 -pk=server-C "sudo systemctl status nginx"

  # Set password for specific user
  sshx --password-set=root
  sshx --password-set=admin

  # Get password from keyring
  sshx --password-get=master

  # Check if password exists
  sshx --password-check=server-A

  # List common password keys
  sshx --password-list

  # Delete password from keyring
  sshx --password-delete=server-A

Host Management Examples:
  # Add host interactively
  sshx --host-add

  # Add host with command line options
  sshx --host-add --host-name=prod-web -h=192.168.1.100 -u=root -pk=prod-web --host-desc="Production Web Server"

  # Add host with its own SSH private key
  sshx --host-add --host-name=prod-db -h=192.168.1.200 -u=admin -i=~/.ssh/prod-db.pem

  # Update host IP address
  sshx --host-update --host-name=prod-web -h=192.168.1.101

  # Update host SSH key
  sshx --host-update --host-name=prod-web -i=~/.ssh/new-key.pem

  # Update host password key
  sshx --host-update --host-name=prod-web -pk=new-password-key

  # Update multiple fields
  sshx --host-update --host-name=prod-web -h=192.168.1.101 -u=admin -pk=new-key

  # List all configured hosts
  sshx --host-list

  # Test connection to a configured host
  sshx --host-test=prod-web

  # Test all configured hosts and get a report with auth methods
  sshx --host-test-all

  # Remove a host from configuration
  sshx --host-remove=prod-web

  # Use configured host (looks up from settings if not an IP)
  sshx -h=prod-web "uptime"

Note:
  - SSH key authentication is tried first, then password authentication
  - Sudo password is automatically retrieved from system keyring
  - SFTP operations use the same SSH connection
  - Password manager works across macOS/Linux/Windows
  - Default user: master, Default sudo key: master
  - Host configurations are stored in ~/.sshx/settings.json`)
}
