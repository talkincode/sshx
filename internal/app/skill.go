package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/talkincode/sshx/internal/skillinstall"
	"github.com/talkincode/sshx/internal/sshclient"
)

type skillActionResult struct {
	Success   bool   `json:"success"`
	Action    string `json:"action"`
	Status    string `json:"status,omitempty"`
	Path      string `json:"path,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Source    string `json:"source,omitempty"`
	Version   string `json:"version,omitempty"`
	ErrorKind string `json:"error_kind,omitempty"`
	Error     string `json:"error,omitempty"`
}

// HandleSkillManagement installs the canonical Agent skill embedded in sshx.
func HandleSkillManagement(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return reportSkillError(config, "config", fmt.Errorf("%s", config.ArgumentError))
	}
	if config.SkillAction == "" {
		return reportSkillError(config, "config", fmt.Errorf("skill action is required: install"))
	}
	if config.SkillAction != "install" {
		return reportSkillError(config, "config", fmt.Errorf("unknown skill action %q", config.SkillAction))
	}

	result, err := skillinstall.Install(skillinstall.Options{
		Dir:   config.SkillDir,
		Force: config.Force,
	})
	if err != nil {
		return reportSkillError(config, classifySkillError(err), err)
	}

	payload := skillActionResult{
		Success: true,
		Action:  "install",
		Status:  result.Status,
		Path:    result.Path,
		SHA256:  result.SHA256,
		Source:  result.Source,
		Version: Version,
	}
	return emitSkillResult(config, payload)
}

func classifySkillError(err error) string {
	switch {
	case errors.Is(err, skillinstall.ErrConflict):
		return "conflict"
	case errors.Is(err, skillinstall.ErrUnsafeTarget):
		return "unsafe_target"
	default:
		return "install_error"
	}
}

func reportSkillError(config *sshclient.Config, kind string, err error) error {
	if !config.JSONOutput {
		return fmt.Errorf("skill %s failed: %w", config.SkillAction, err)
	}
	payload := skillActionResult{
		Success:   false,
		Action:    config.SkillAction,
		Version:   Version,
		ErrorKind: kind,
		Error:     redactError(err),
	}
	if emitErr := emitSkillResult(config, payload); emitErr != nil {
		return emitErr
	}
	return ErrReported
}

func emitSkillResult(config *sshclient.Config, result skillActionResult) error {
	if config.JSONOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		envelope := struct {
			skillActionResult
			localRiskMetadata
		}{result, localRiskFields("skill", result.Action)}
		return encoder.Encode(envelope)
	}
	if result.Status == "current" {
		fmt.Printf("Agent skill is current: %s\n", result.Path)
		return nil
	}
	fmt.Printf("Agent skill %s: %s\n", result.Status, result.Path)
	return nil
}
