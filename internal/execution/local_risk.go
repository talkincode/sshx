package execution

// ClassifyLocalRisk describes supported local management actions, not observed
// state changes. Remote host diagnostics and unknown actions are excluded.
func ClassifyLocalRisk(mode, action string) (Risk, Effects, bool) {
	var effects Effects
	switch mode + "/" + action {
	case "host/add", "host/update", "host/import",
		"password/set", "plugin/create", "plugin/trust", "skill/install":
		effects.LocalWrite = true
	case "host/remove", "password/delete", "password/del", "password/rm", "plugin/remove":
		effects.LocalWrite, effects.Destructive = true, true
	case "host/list", "password/get", "password/check", "password/exists",
		"password/list", "password/ls", "plugin/list", "plugin/show",
		"plugin/validate", "plugin/test":
	default:
		return "", Effects{}, false
	}
	risk := RiskRead
	if effects.LocalWrite {
		risk = RiskMutation
	}
	if effects.Destructive {
		risk = RiskDestructive
	}
	return risk, effects, true
}
