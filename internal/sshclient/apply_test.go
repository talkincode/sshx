package sshclient

import (
	"strings"
	"testing"
)

func TestValidateApplyPath(t *testing.T) {
	t.Parallel()
	if err := ValidateApplyPath("/etc/nginx/nginx.conf"); err != nil {
		t.Fatalf("absolute file path should be accepted: %v", err)
	}
	for _, path := range []string{"", "relative.conf", "/etc/nginx/", "/", "/tmp/foo/../bar", "/tmp/foo/"} {
		if err := ValidateApplyPath(path); err == nil {
			t.Fatalf("expected rejection for %q", path)
		}
	}
}

func TestApplyPathBlocked(t *testing.T) {
	t.Parallel()
	if !ApplyPathBlocked("/etc/passwd") || !ApplyPathBlocked("/etc/sudoers.d/app") {
		t.Fatal("critical identity paths must be blocked")
	}
	if ApplyPathBlocked("/etc/nginx/nginx.conf") {
		t.Fatal("ordinary config paths must not be blocked")
	}
}

func TestNormalizeApplySHA256(t *testing.T) {
	t.Parallel()
	got, err := NormalizeApplySHA256("  " + strings.Repeat("A", 64) + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.Repeat("a", 64) {
		t.Fatalf("expected lowercase digest, got %q", got)
	}
	if _, err := NormalizeApplySHA256("deadbeef"); err == nil {
		t.Fatal("short digest must be rejected")
	}
}

func TestCheckApplyPrecondition(t *testing.T) {
	t.Parallel()
	req := ApplyRequest{ExpectSHA256: strings.Repeat("b", 64)}
	if err := checkApplyPrecondition(true, "", req); err == nil {
		t.Fatal("missing target with expect hash must fail")
	}
	if err := checkApplyPrecondition(false, strings.Repeat("a", 64), req); err == nil {
		t.Fatal("hash mismatch must fail")
	}
	if err := checkApplyPrecondition(false, strings.Repeat("b", 64), req); err != nil {
		t.Fatalf("matching hash should pass: %v", err)
	}
	if err := checkApplyPrecondition(false, strings.Repeat("a", 64), ApplyRequest{Force: true, ExpectSHA256: strings.Repeat("b", 64)}); err != nil {
		t.Fatalf("force should skip precondition: %v", err)
	}
}

func TestShellSafeToken(t *testing.T) {
	t.Parallel()
	if !shellSafeToken("/etc/nginx/nginx.conf") {
		t.Fatal("ordinary path should be safe")
	}
	if shellSafeToken("/tmp/foo'bar") || shellSafeToken("/tmp/foo$(x)") {
		t.Fatal("metacharacters must be rejected")
	}
}
