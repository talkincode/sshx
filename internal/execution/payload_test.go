package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadScriptFile_DigestAndLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	body := []byte("printf '%s\\n' \"a b\" '$HOME' \"$(literal)\" \"你好\" \"*.log\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadScriptFile(path, DefaultMaxPayload)
	if err != nil {
		t.Fatalf("LoadScriptFile: %v", err)
	}
	if !bytes.Equal(p.Bytes, body) {
		t.Fatalf("payload bytes changed")
	}
	sum := sha256.Sum256(body)
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest mismatch")
	}

	if _, err := LoadScriptFile(path, 4); err == nil {
		t.Fatal("expected oversized script failure")
	}
}

func TestLoadScriptStdin(t *testing.T) {
	body := []byte("echo hello\n")
	p, err := LoadScriptStdin(bytes.NewReader(body), DefaultMaxPayload)
	if err != nil {
		t.Fatalf("LoadScriptStdin: %v", err)
	}
	if !bytes.Equal(p.Bytes, body) {
		t.Fatalf("stdin payload mismatch")
	}
	big := bytes.Repeat([]byte("x"), 32)
	if _, err := LoadScriptStdin(bytes.NewReader(big), 16); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected limit error, got %v", err)
	}
}
