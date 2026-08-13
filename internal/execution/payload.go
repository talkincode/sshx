package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Payload holds a byte-preserving script body and its digest metadata.
type Payload struct {
	Bytes  []byte
	SHA256 string
	Size   int
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
		Bytes:  data,
		SHA256: hex.EncodeToString(sum[:]),
		Size:   len(data),
	}, nil
}
