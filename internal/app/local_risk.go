package app

import "github.com/talkincode/sshx/internal/execution"

type localRiskMetadata struct {
	Risk    execution.Risk     `json:"risk,omitempty"`
	Effects *execution.Effects `json:"effects,omitempty"`
}

func localRiskFields(mode, action string) localRiskMetadata {
	risk, effects, ok := execution.ClassifyLocalRisk(mode, action)
	if !ok {
		return localRiskMetadata{}
	}
	return localRiskMetadata{Risk: risk, Effects: &effects}
}
