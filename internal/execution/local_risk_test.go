package execution

import (
	"strings"
	"testing"
)

func TestClassifyLocalRisk(t *testing.T) {
	tests := []struct {
		mode, actions string
		risk          Risk
		write         bool
		destructive   bool
	}{
		{"host", "add update import", RiskMutation, true, false},
		{"host", "remove", RiskDestructive, true, true},
		{"host", "list", RiskRead, false, false},
		{"password", "set", RiskMutation, true, false},
		{"password", "delete del rm", RiskDestructive, true, true},
		{"password", "get check exists list ls", RiskRead, false, false},
		{"plugin", "create trust", RiskMutation, true, false},
		{"plugin", "remove", RiskDestructive, true, true},
		{"plugin", "list show validate test", RiskRead, false, false},
		{"skill", "install", RiskMutation, true, false},
	}
	for _, tt := range tests {
		for _, action := range strings.Fields(tt.actions) {
			t.Run(tt.mode+"/"+action, func(t *testing.T) {
				risk, effects, ok := ClassifyLocalRisk(tt.mode, action)
				want := Effects{LocalWrite: tt.write, Destructive: tt.destructive}
				if !ok || risk != tt.risk || effects != want {
					t.Fatalf("ClassifyLocalRisk = %q %+v %t, want %q %+v true", risk, effects, ok, tt.risk, want)
				}
			})
		}
	}
}

func TestClassifyLocalRiskExcludesRemoteAndUnknownActions(t *testing.T) {
	for _, tt := range [][2]string{
		{"host", "test"}, {"host", "test-all"}, {"host", "unknown"}, {"host", ""},
		{"sftp", "remove"}, {"inspect", "system"}, {"command", "uptime"}, {"skill", "list"},
	} {
		if risk, effects, ok := ClassifyLocalRisk(tt[0], tt[1]); ok || risk != "" || effects != (Effects{}) {
			t.Fatalf("unexpected local classification for %s/%s: %q %+v %t", tt[0], tt[1], risk, effects, ok)
		}
	}
}

func TestLocalRiskDoesNotChangeDownloadRisk(t *testing.T) {
	risk, effects := ClassifyRisk("download", "", false)
	if risk != RiskRead || !effects.LocalWrite || effects.RemoteWrite {
		t.Fatalf("remote download risk changed: %q %+v", risk, effects)
	}
}
