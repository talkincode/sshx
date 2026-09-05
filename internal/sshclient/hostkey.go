package sshclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func getHostKeyCallback(cfg *Config) (ssh.HostKeyCallback, error) {
	lg := logger.GetLogger()
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.KnownHostsData != nil {
		callback, err := snapshotHostKeyCallback(cfg.KnownHostsData)
		if err != nil {
			return nil, boundaryError("host_key", "load admitted known_hosts", err)
		}
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if err := callback(hostname, remote, key); err != nil {
				return boundaryError("host_key", "verify admitted host key", err)
			}
			cfg.HostKeyFingerprint = ssh.FingerprintSHA256(key)
			return nil
		}, nil
	}

	knownHostsPath := cfg.KnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			lg.Warning("Unable to determine home directory for known_hosts: %v", err)
			if cfg.AllowInsecureHostKey {
				lg.Warning("Falling back to insecure host key verification (explicitly allowed)")
				return insecureHostKeyCallback(cfg), nil
			}
			return nil, fmt.Errorf("unable to determine known_hosts path (set HOME or use --known-hosts): %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	if err := ensureKnownHostsFile(knownHostsPath); err != nil {
		if cfg.AllowInsecureHostKey {
			lg.Warning("Unable to prepare known_hosts at %s: %v", knownHostsPath, err)
			lg.Warning("Falling back to insecure host key verification (explicitly allowed)")
			return insecureHostKeyCallback(cfg), nil
		}
		return nil, err
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if cfg.AllowInsecureHostKey {
			lg.Warning("Failed to load known_hosts from %s: %v", knownHostsPath, err)
			lg.Warning("Falling back to insecure host key verification (explicitly allowed)")
			return insecureHostKeyCallback(cfg), nil
		}
		return nil, fmt.Errorf("failed to load known_hosts from %s: %w", knownHostsPath, err)
	}

	var callbackMu sync.Mutex

	// Wrap the callback to handle key verification errors gracefully
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		callbackMu.Lock()
		defer callbackMu.Unlock()

		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			cfg.HostKeyFingerprint = ssh.FingerprintSHA256(key)
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}

		// If there are known keys but they don't match, it's a key change
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("⚠️  HOST KEY VERIFICATION FAILED!\n"+
				"The host key for %s has changed.\n"+
				"This could indicate a man-in-the-middle attack.\n"+
				"Remove the old key from %s and verify the new key before connecting.\n"+
				"Original error: %w", hostname, knownHostsPath, err)
		}

		if cfg.AcceptUnknownHost {
			hostPatterns := normalizeHostPatterns(hostname, remote)
			if len(hostPatterns) == 0 {
				hostPatterns = []string{hostname}
			}
			if appendErr := appendHostKey(knownHostsPath, hostPatterns, key); appendErr != nil {
				return fmt.Errorf("failed to record new host key for %s: %w", hostname, appendErr)
			}
			lg.Success("Trusted new host %s and saved its key to %s", hostname, knownHostsPath)
			freshCallback, reloadErr := knownhosts.New(knownHostsPath)
			if reloadErr != nil {
				return fmt.Errorf("failed to reload known_hosts after adding %s: %w", hostname, reloadErr)
			}
			hostKeyCallback = freshCallback
			cfg.HostKeyFingerprint = ssh.FingerprintSHA256(key)
			return nil
		}

		return fmt.Errorf("⚠️  Host %s is not in known_hosts file (%s).\n"+
			"To add this host, run:\n"+
			"  ssh-keyscan -H %s >> %s\n"+
			"Or re-run sshx with --accept-unknown-host to trust it automatically.\n"+
			"Original error: %w",
			hostname, knownHostsPath, hostname, knownHostsPath, err)
	}, nil
}

func insecureHostKeyCallback(cfg *Config) ssh.HostKeyCallback {
	// #nosec G106 -- this callback is reached only after the operator explicitly
	// opts into insecure host-key handling. Fingerprinting still binds snapshots
	// to the key observed during this connection.
	ignore := ssh.InsecureIgnoreHostKey()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := ignore(hostname, remote, key); err != nil {
			return err
		}
		cfg.HostKeyFingerprint = ssh.FingerprintSHA256(key)
		return nil
	}
}

func ensureKnownHostsFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s for known_hosts: %w", dir, err)
	}

	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("known_hosts path %s is a directory", path)
		}
		return nil
	}

	if os.IsNotExist(err) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- user-provided path validated earlier
		if createErr != nil {
			return fmt.Errorf("failed to create known_hosts file at %s: %w", path, createErr)
		}
		return file.Close()
	}

	return fmt.Errorf("unable to access known_hosts file at %s: %w", path, err)
}

func appendHostKey(path string, hostnames []string, key ssh.PublicKey) (err error) {
	if len(hostnames) == 0 {
		return fmt.Errorf("no hostnames provided for known_hosts entry")
	}
	line := knownhosts.Line(hostnames, key)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- caller controls path and permissions
	if os.IsNotExist(err) {
		if ensureErr := ensureKnownHostsFile(path); ensureErr != nil {
			return ensureErr
		}
		file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path validated above
	}
	if err != nil {
		return fmt.Errorf("failed to open known_hosts file %s: %w", path, err)
	}
	defer errutil.HandleCloseError(&err, file)
	if _, writeErr := file.WriteString(line + "\n"); writeErr != nil {
		return fmt.Errorf("failed to append host key to %s: %w", path, writeErr)
	}
	return nil
}

func normalizeHostPatterns(hostname string, remote net.Addr) []string {
	patterns := map[string]struct{}{}
	add := func(value string) {
		if value == "" {
			return
		}
		patterns[value] = struct{}{}
	}

	if host, port, err := net.SplitHostPort(hostname); err == nil {
		add(fmt.Sprintf("[%s]:%s", host, port))
		add(host)
	} else {
		add(hostname)
	}

	if remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil {
			add(host)
		}
	}

	result := make([]string, 0, len(patterns))
	for entry := range patterns {
		result = append(result, entry)
	}
	sort.Strings(result)
	return result
}
