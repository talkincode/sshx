//go:build darwin && !sshx_e2e

package keyringstore

import (
	"errors"
	"testing"
)

func TestClassifyKeychainFailure(t *testing.T) {
	cause := errors.New("exit status 1")
	for _, tc := range []struct {
		diagnostic string
		want       error
	}{
		{"security: User interaction is not allowed.", ErrInteractionRequired},
		{"security: The specified item could not be found in the keychain.", ErrNotFound},
		{"security: The user canceled the operation.", ErrAccessDenied},
		{"security: Internal error", cause},
	} {
		if got := classifyKeychainFailure(tc.diagnostic, cause); !errors.Is(got, tc.want) {
			t.Errorf("classifyKeychainFailure(%q) = %v, want %v", tc.diagnostic, got, tc.want)
		}
	}
}
