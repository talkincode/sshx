package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// Payload holds a byte-preserving script body and its digest metadata.
type Payload struct {
	Bytes  []byte
	SHA256 string
	Size   int
	// Shebang is the interpreter basename declared by a leading `#!` line,
	// empty when the payload declares none.
	Shebang string
}

// supportedScriptRunners are POSIX-shell-family interpreters sshx can drive
// over stdin with `<shell> -s --`. Other interpreters use different stdin
// conventions and are rejected rather than silently executed by sh.
var supportedScriptRunners = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
}

// SupportedScriptRunner reports whether name can be used as a script runner.
func SupportedScriptRunner(name string) bool {
	return supportedScriptRunners[name]
}

// parseShebang returns the interpreter basename declared by a leading `#!`
// line. `#!/usr/bin/env bash` resolves to bash, `#!/bin/sh` to sh.
func parseShebang(data []byte) string {
	if len(data) < 3 || data[0] != '#' || data[1] != '!' {
		return ""
	}
	line := data[2:]
	if idx := bytes.IndexAny(line, "\n\r"); idx >= 0 {
		line = line[:idx]
	}
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return ""
	}
	interp := path.Base(fields[0])
	// `#!/usr/bin/env bash` — the real interpreter is the next word. Skip
	// env's own NAME=value assignments and options.
	if interp == "env" {
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue
			}
			return path.Base(f)
		}
		return ""
	}
	return interp
}

// LoadScriptFile reads one local regular file as a script payload.
func LoadScriptFile(path string, maxBytes int) (Payload, error) {
	if path == "" {
		return Payload{}, fmt.Errorf("%w: script path is empty", ErrConfig)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPayload
	}
	info, err := os.Stat(path)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: stat script file: %v", ErrLocalIO, err)
	}
	if !info.Mode().IsRegular() {
		return Payload{}, fmt.Errorf("%w: script path must be a regular file", ErrLocalIO)
	}
	if info.Size() > int64(maxBytes) {
		return Payload{}, fmt.Errorf("%w: script payload exceeds %d-byte limit", ErrLocalIO, maxBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- caller-provided local script path
	if err != nil {
		return Payload{}, fmt.Errorf("%w: read script file: %v", ErrLocalIO, err)
	}
	return digestPayload(data, maxBytes)
}

// LoadScriptStdin reads process stdin as a script payload.
func LoadScriptStdin(r io.Reader, maxBytes int) (Payload, error) {
	if r == nil {
		return Payload{}, fmt.Errorf("%w: script stdin reader is nil", ErrConfig)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPayload
	}
	// Read one extra byte to detect oversized input without loading unbounded data.
	limited := io.LimitReader(r, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: read script stdin: %v", ErrLocalIO, err)
	}
	return digestPayload(data, maxBytes)
}

func digestPayload(data []byte, maxBytes int) (Payload, error) {
	if len(data) == 0 {
		return Payload{}, fmt.Errorf("%w: script payload is empty", ErrConfig)
	}
	if len(data) > maxBytes {
		return Payload{}, fmt.Errorf("%w: script payload exceeds %d-byte limit", ErrLocalIO, maxBytes)
	}
	sum := sha256.Sum256(data)
	return Payload{
		Bytes:   data,
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    len(data),
		Shebang: parseShebang(data),
	}, nil
}
