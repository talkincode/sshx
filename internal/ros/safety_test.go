package ros

import (
	"testing"
)

func TestValidateSafety_DangerousCommands(t *testing.T) {
	dangerous := []string{
		"/system/reset-configuration",
		"/system reset-configuration keep-users=yes",
		"/system/reboot",
		"/disk format drive=nand",
	}

	for _, cmd := range dangerous {
		req, err := ParseInvocation([]string{"raw", cmd})
		if err != nil {
			t.Fatalf("unexpected invocation error: %v", err)
		}

		// Blocked without force
		safeErr := ValidateSafety(req, true, false)
		if safeErr == nil {
			t.Errorf("expected dangerous command %q to be blocked without force", cmd)
		} else if safeErr.ErrorCode != ErrCodeDangerousCommandBlocked {
			t.Errorf("expected %s, got %s", ErrCodeDangerousCommandBlocked, safeErr.ErrorCode)
		}

		// Allowed with force
		safeErrForce := ValidateSafety(req, true, true)
		if safeErrForce != nil {
			t.Errorf("expected dangerous command %q to be allowed with force, got %v", cmd, safeErrForce)
		}
	}
}

func TestValidateSafety_RawMutations(t *testing.T) {
	// Raw write command without allowWrite or force
	req, err := ParseInvocation([]string{"raw", "/ip/address/add address=1.1.1.1/24 interface=ether1"})
	if err != nil {
		t.Fatalf("unexpected invocation error: %v", err)
	}

	safeErr := ValidateSafety(req, false, false)
	if safeErr == nil {
		t.Errorf("expected raw mutation to be blocked without allowWrite")
	}

	safeErrAllowed := ValidateSafety(req, true, false)
	if safeErrAllowed != nil {
		t.Errorf("expected raw mutation to be allowed with allowWrite")
	}
}

func TestValidateScriptSource(t *testing.T) {
	// Valid small script
	valid := []byte(":put \"hello world\"\n")
	if err := ValidateScriptSource(valid, "test.rsc"); err != nil {
		t.Errorf("unexpected error for valid script: %v", err)
	}

	// Too large script
	large := make([]byte, MaxScriptSourceBytes+1)
	if err := ValidateScriptSource(large, "large.rsc"); err == nil {
		t.Errorf("expected too large error")
	} else if err.ErrorCode != ErrCodeFileTooLarge {
		t.Errorf("expected %s, got %s", ErrCodeFileTooLarge, err.ErrorCode)
	}

	// Non-UTF8 script
	invalidUTF8 := []byte{0xff, 0xfe, 0xfd}
	if err := ValidateScriptSource(invalidUTF8, "binary.rsc"); err == nil {
		t.Errorf("expected non-utf8 error")
	} else if err.ErrorCode != ErrCodeUsageError {
		t.Errorf("expected %s, got %s", ErrCodeUsageError, err.ErrorCode)
	}
}
