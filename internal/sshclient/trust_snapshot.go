package sshclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- OpenSSH known_hosts hashed-name format requires HMAC-SHA1.
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type trustPattern struct {
	negated bool
	match   func(string) bool
}

type trustEntry struct {
	patterns  []trustPattern
	key       knownhosts.KnownKey
	authority bool
}

func (e trustEntry) matches(address string) bool {
	address = knownhosts.Normalize(address)
	found := false
	for _, p := range e.patterns {
		if p.match(address) {
			if p.negated {
				return false
			}
			found = true
		}
	}
	return found
}

// x/crypto/knownhosts only exposes a filename-based constructor. Parse the
// admitted bytes in memory so execution never reopens mutable trust material.
func snapshotHostKeyCallback(data []byte) (ssh.HostKeyCallback, error) {
	var entries []trustEntry
	revoked := map[string]knownhosts.KnownKey{}
	for i, line := range bytes.Split(data, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		marker := ""
		if strings.HasPrefix(fields[0], "@") {
			marker, fields = fields[0], fields[1:]
			if marker != "@cert-authority" && marker != "@revoked" {
				return nil, fmt.Errorf("known_hosts line %d: unsupported marker", i+1)
			}
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("known_hosts line %d: malformed entry", i+1)
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			return nil, fmt.Errorf("known_hosts line %d: %w", i+1, err)
		}
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			return nil, fmt.Errorf("known_hosts line %d: %w", i+1, err)
		}
		entry := trustEntry{key: knownhosts.KnownKey{Key: key, Filename: "admitted known_hosts", Line: i + 1}, authority: marker == "@cert-authority"}
		if marker == "@revoked" {
			revoked[string(key.Marshal())] = entry.key
			continue
		}
		for _, pattern := range strings.Split(fields[0], ",") {
			matcher, err := newTrustPattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("known_hosts line %d: %w", i+1, err)
			}
			entry.patterns = append(entry.patterns, matcher)
		}
		entries = append(entries, entry)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(key ssh.PublicKey, address string) bool {
			for _, entry := range entries {
				if entry.authority && entry.matches(address) && bytes.Equal(entry.key.Key.Marshal(), key.Marshal()) {
					return true
				}
			}
			return false
		},
		IsRevoked: func(cert *ssh.Certificate) bool {
			_, certRevoked := revoked[string(cert.Marshal())]
			_, keyRevoked := revoked[string(cert.SignatureKey.Marshal())]
			return certRevoked || keyRevoked
		},
		HostKeyFallback: func(address string, remote net.Addr, key ssh.PublicKey) error {
			if known, ok := revoked[string(key.Marshal())]; ok {
				return &knownhosts.RevokedError{Revoked: known}
			}
			if address == "" && remote != nil {
				address = remote.String()
			}
			if _, _, err := net.SplitHostPort(address); err != nil {
				return err
			}
			mismatch := &knownhosts.KeyError{}
			for _, entry := range entries {
				if entry.authority || !entry.matches(address) {
					continue
				}
				mismatch.Want = append(mismatch.Want, entry.key)
				if bytes.Equal(entry.key.Key.Marshal(), key.Marshal()) {
					return nil
				}
			}
			return mismatch
		},
	}
	return checker.CheckHostKey, nil
}

func newTrustPattern(value string) (trustPattern, error) {
	pattern := trustPattern{}
	if strings.HasPrefix(value, "!") {
		pattern.negated = true
		value = value[1:]
	}
	if value == "" {
		return pattern, fmt.Errorf("empty host pattern")
	}
	if strings.HasPrefix(value, "|") {
		parts := strings.Split(value, "|")
		if len(parts) != 4 || parts[1] != "1" {
			return pattern, fmt.Errorf("invalid hashed host")
		}
		salt, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return pattern, err
		}
		hash, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil || len(hash) != sha1.Size {
			return pattern, fmt.Errorf("invalid hashed host digest")
		}
		pattern.match = func(address string) bool {
			mac := hmac.New(sha1.New, salt)
			_, _ = mac.Write([]byte(address)) //nolint:errcheck // hash.Hash.Write cannot fail
			return hmac.Equal(hash, mac.Sum(nil))
		}
		return pattern, nil
	}
	host, port, splitErr := net.SplitHostPort(value)
	if splitErr != nil {
		if strings.HasPrefix(value, "[") {
			return pattern, splitErr
		}
		host, port = value, "22"
	}
	expression := regexp.QuoteMeta(host)
	expression = strings.ReplaceAll(expression, `\*`, ".*")
	expression = strings.ReplaceAll(expression, `\?`, ".")
	matcher, err := regexp.Compile("^" + expression + "$")
	if err != nil {
		return pattern, err
	}
	pattern.match = func(address string) bool {
		actualHost, actualPort, err := net.SplitHostPort(address)
		if err != nil {
			actualHost, actualPort = address, "22"
		}
		return port == actualPort && matcher.MatchString(actualHost)
	}
	return pattern, nil
}
