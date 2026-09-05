package app

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	pluginpkg "github.com/talkincode/sshx/internal/plugin"
	"github.com/talkincode/sshx/internal/sshclient"
)

func HandlePluginManagement(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return reportPluginError(config, "config", fmt.Errorf("%s", config.ArgumentError))
	}
	action := config.PluginAction
	if action == "" {
		return reportPluginError(config, "config", fmt.Errorf("plugin action is required: create, list, show, validate, test, trust, or remove"))
	}

	var result pluginpkg.ActionResult
	var err error
	switch action {
	case "create":
		if config.PluginID == "" {
			err = fmt.Errorf("plugin id is required")
			break
		}
		var created *pluginpkg.CreateResult
		created, err = pluginpkg.Create(pluginpkg.CreateOptions{
			ID:        config.PluginID,
			Runner:    config.PluginRunner,
			Platform:  config.PluginPlatform,
			Privilege: config.PluginPrivilege,
			Template:  config.PluginTemplate,
			Replace:   config.PluginReplace,
		})
		if err == nil {
			result = pluginpkg.ActionResult{
				Success:    true,
				Action:     action,
				PluginID:   created.Resolved.Manifest.ID,
				Path:       created.Resolved.Path,
				BackupPath: created.BackupPath,
				Digest:     created.Resolved.Digest,
				Trusted:    created.Resolved.Trusted,
				Valid:      true,
				Files:      created.Files,
				NextActions: []string{
					"edit collector",
					"sshx plugin validate " + config.PluginID + " --json",
					"sshx plugin test " + config.PluginID + " --json",
					"sshx plugin trust " + config.PluginID + " --json",
				},
			}
		}
	case "list":
		var plugins []pluginpkg.Summary
		plugins, err = pluginpkg.List()
		result = pluginpkg.ActionResult{Success: err == nil, Action: action, Plugins: plugins}
	case "show", "validate":
		if config.PluginID == "" {
			err = fmt.Errorf("plugin id is required")
			break
		}
		var resolved *pluginpkg.Resolved
		resolved, err = pluginpkg.Resolve(config.PluginID)
		if err == nil {
			summary := pluginpkg.SummaryFromResolved(resolved)
			result = pluginpkg.ActionResult{Success: true, Action: action, PluginID: config.PluginID, Path: resolved.Path, Digest: resolved.Digest, Trusted: resolved.Trusted, Valid: true, Plugin: &summary, Manifest: &resolved.Manifest}
		}
	case "test":
		if config.PluginID == "" {
			err = fmt.Errorf("plugin id is required")
			break
		}
		var resolved *pluginpkg.Resolved
		var fixture string
		var testResult pluginpkg.Result
		resolved, testResult, fixture, err = pluginpkg.Test(config.PluginID, config.PluginFixture)
		if err == nil {
			result = pluginpkg.ActionResult{Success: true, Action: action, PluginID: config.PluginID, Path: resolved.Path, Digest: resolved.Digest, Trusted: resolved.Trusted, Valid: true, Fixture: fixture, TestResult: &testResult}
		}
	case "trust":
		if config.PluginID == "" {
			err = fmt.Errorf("plugin id is required")
			break
		}
		var resolved *pluginpkg.Resolved
		resolved, err = pluginpkg.Trust(config.PluginID)
		if err == nil {
			result = pluginpkg.ActionResult{Success: true, Action: action, PluginID: config.PluginID, Path: resolved.Path, Digest: resolved.Digest, Trusted: true, Valid: true}
		}
	case "remove":
		if config.PluginID == "" {
			err = fmt.Errorf("plugin id is required")
			break
		}
		var backup string
		backup, err = pluginpkg.Remove(config.PluginID)
		if err == nil {
			result = pluginpkg.ActionResult{Success: true, Action: action, PluginID: config.PluginID, BackupPath: backup}
		}
	default:
		err = fmt.Errorf("unknown plugin action %q", action)
	}
	if err != nil {
		return reportPluginError(config, classifyPluginError(err), err)
	}
	return emitPluginResult(config, result)
}

func classifyPluginError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	switch {
	case containsAny(message, "plugin id"):
		return "invalid_plugin_id"
	case containsAny(message, "entrypoint"):
		return "invalid_entrypoint"
	case containsAny(message, "result schema", "compile schema", "schema"):
		return "invalid_schema"
	case containsAny(message, "fixture", "collector stdout", "collector output"):
		return "invalid_fixture"
	case containsAny(message, "read manifest", "parse manifest", "manifest id", "api_version", "plugin version", "plugin kind", "target platform", "privilege policy", "timeout", "remote.read effect", "redaction deny_fields"):
		return "invalid_manifest"
	case containsAny(message, "not found"):
		return "not_found"
	case containsAny(message, "already exists"):
		return "already_exists"
	case containsAny(message, "untrusted"):
		return "untrusted_plugin"
	case containsAny(message, "runner", "platform", "privilege", "template"):
		return "invalid_plugin"
	default:
		return "plugin_error"
	}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func reportPluginError(config *sshclient.Config, kind string, err error) error {
	config.ReportedErrorKind = kind
	config.ReportedError = redactError(err)
	if !config.JSONOutput {
		return err
	}
	if emitErr := emitPluginResult(config, pluginpkg.ActionResult{Success: false, Action: config.PluginAction, PluginID: config.PluginID, ErrorKind: kind, Error: redactError(err)}); emitErr != nil {
		return emitErr
	}
	return ErrReported
}

func emitPluginResult(config *sshclient.Config, result pluginpkg.ActionResult) error {
	if config.JSONOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		envelope := struct {
			pluginpkg.ActionResult
			localRiskMetadata
		}{result, localRiskFields("plugin", result.Action)}
		if err := encoder.Encode(envelope); err != nil {
			return fmt.Errorf("encode plugin result: %w", err)
		}
		return nil
	}
	if result.Action == "list" {
		for _, summary := range result.Plugins {
			fmt.Printf("%s\t%s\ttrusted=%t\tbuiltin=%t\tvalid=%t\n", summary.ID, summary.Version, summary.Trusted, summary.Builtin, summary.Valid)
		}
		return nil
	}
	fmt.Printf("plugin %s: %s", result.Action, result.PluginID)
	if result.Path != "" {
		fmt.Printf(" (%s)", result.Path)
	}
	if result.BackupPath != "" {
		fmt.Printf("; backup=%s", result.BackupPath)
	}
	fmt.Println()
	return nil
}
