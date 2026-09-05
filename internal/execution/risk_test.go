package execution

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnifiedRiskMatrix(t *testing.T) {
	for _, tc := range []struct {
		action, command string
		sudo            bool
		risk            Risk
		unknown, local  bool
	}{
		{"command", "uname -a", false, RiskRead, false, false},
		{"command", "custom-tool", false, RiskMutation, true, false},
		{"command", "uname -a > /tmp/file", false, RiskMutation, true, false},
		{"command", "sudo uname -a", true, RiskPrivileged, true, false},
		{"command", "mkfs.ext4 /dev/test", false, RiskDestructive, true, false},
		{"script", "", false, RiskMutation, true, false},
		{"apply", "", false, RiskMutation, false, false},
		{"apply", "", true, RiskPrivileged, false, false},
		{"upload", "", false, RiskMutation, false, false},
		{"download", "", false, RiskRead, false, true},
		{"remove", "", false, RiskDestructive, false, false},
		{"transfer", "", false, RiskMutation, false, false},
	} {
		t.Run(tc.action+tc.command, func(t *testing.T) {
			risk, effects := ClassifyRisk(tc.action, tc.command, tc.sudo)
			require.Equal(t, tc.risk, risk)
			require.Equal(t, tc.unknown, effects.Unknown)
			require.Equal(t, tc.local, effects.LocalWrite)
		})
	}
}
