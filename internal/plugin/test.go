package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func Test(id, fixture string) (*Resolved, Result, string, error) {
	resolved, err := Resolve(id)
	if err != nil {
		return nil, Result{}, "", err
	}
	if fixture != "" {
		fixturePath, pathErr := FixturePath(resolved, fixture)
		if pathErr != nil {
			return resolved, Result{}, "", pathErr
		}
		data, readErr := readRegularFile(fixturePath, MaxFixture, 0o022)
		if readErr != nil {
			return resolved, Result{}, fixture, fmt.Errorf("read fixture %q: %w", fixture, readErr)
		}
		result, validateErr := validateAndRedactTestResult(resolved, data)
		return resolved, result, fixture, validateErr
	}

	if resolved.Builtin {
		return nil, Result{}, "", fmt.Errorf("built-in capability tests run through the compiled-binary E2E suite")
	}
	if resolved.Manifest.Runner.Type != "sh" {
		return nil, Result{}, "", fmt.Errorf("local test does not support runner %q", resolved.Manifest.Runner.Type)
	}
	timeout, timeoutErr := time.ParseDuration(resolved.Manifest.Timeout)
	if timeoutErr != nil {
		return resolved, Result{}, "", fmt.Errorf("parse collector timeout: %w", timeoutErr)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	entrypoint, err := safeChild(resolved.Path, resolved.Manifest.Runner.Entrypoint)
	if err != nil {
		return resolved, Result{}, "", err
	}
	command := exec.CommandContext(ctx, "sh", entrypoint) // #nosec G204 -- explicit user request to test a locally owned plugin.
	command.Env = minimalTestEnvironment()
	stdout := newLimitBuffer(MaxFixture)
	stderr := newLimitBuffer(MaxFixture)
	command.Stdout = stdout
	command.Stderr = stderr
	if runErr := command.Run(); runErr != nil {
		if ctx.Err() != nil {
			return resolved, Result{}, "", fmt.Errorf("collector timed out after %s", timeout)
		}
		return resolved, Result{}, "", fmt.Errorf("collector failed: %w", runErr)
	}
	if stdout.truncated {
		return resolved, Result{}, "", fmt.Errorf("collector stdout exceeds %d-byte limit", MaxFixture)
	}
	result, err := validateAndRedactTestResult(resolved, stdout.Bytes())
	return resolved, result, "", err
}

func validateAndRedactTestResult(resolved *Resolved, data []byte) (Result, error) {
	result, err := ValidateResult(resolved, data)
	if err != nil {
		return Result{}, err
	}
	result, _ = RedactResult(result, resolved.Manifest.Redaction)
	redacted, err := json.Marshal(result)
	if err != nil {
		return Result{}, fmt.Errorf("encode redacted test result: %w", err)
	}
	return ValidateResult(resolved, redacted)
}

func SupportsPlatform(platforms []string, target string) bool {
	for _, platform := range platforms {
		if platform == target {
			return true
		}
	}
	return false
}

func minimalTestEnvironment() []string {
	allowed := []string{"HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TEMP", "TMP"}
	result := make([]string, 0, len(allowed))
	for _, name := range allowed {
		if value, ok := os.LookupEnv(name); ok {
			result = append(result, name+"="+value)
		}
	}
	return result
}

type limitBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func newLimitBuffer(limit int) *limitBuffer { return &limitBuffer{limit: limit} }

func (buffer *limitBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.truncated = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, err := buffer.Buffer.Write(data[:remaining])
		buffer.truncated = true
		return len(data), err
	}
	return buffer.Buffer.Write(data)
}
