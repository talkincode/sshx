package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	pluginpkg "github.com/talkincode/sshx/internal/plugin"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
)

type inspectFailure struct {
	Success    bool   `json:"success"`
	Capability string `json:"capability,omitempty"`
	ErrorKind  string `json:"error_kind"`
	Error      string `json:"error"`
}

const targetMetadataScript = `#!/bin/sh
set -u
uname -s 2>/dev/null || printf unknown
printf '\n'
if [ -r /proc/sys/kernel/random/boot_id ]; then
  cat /proc/sys/kernel/random/boot_id
else
  printf unknown
fi
printf '\n'
id -u 2>/dev/null || printf unknown
printf '\n'
`

func HandleInspection(config *sshclient.Config, audit *auditRecorder) (err error) {
	if config.ArgumentError != "" {
		return reportInspectFailure(config, "config", fmt.Errorf("%s", config.ArgumentError))
	}
	if config.InspectCapability == "" {
		return reportInspectFailure(config, "config", fmt.Errorf("inspection capability is required"))
	}
	resolved, err := pluginpkg.Resolve(config.InspectCapability)
	if err != nil {
		return reportInspectFailure(config, classifyPluginError(err), err)
	}
	if !resolved.Trusted {
		return reportInspectFailure(config, "untrusted_plugin", fmt.Errorf("plugin %q digest %s is untrusted; run sshx plugin trust %s", resolved.Manifest.ID, resolved.Digest, resolved.Manifest.ID))
	}
	if config.InspectCacheMode != "off" && config.InspectCacheMode != "remote-prefer" {
		return reportInspectFailure(config, "config", fmt.Errorf("invalid --cache mode %q", config.InspectCacheMode))
	}
	if config.Timeout < 0 || config.InspectMaxAge < 0 {
		return reportInspectFailure(config, "config", fmt.Errorf("timeout and max-age values must be valid non-negative durations"))
	}
	pluginTimeout, parseErr := time.ParseDuration(resolved.Manifest.Timeout)
	if parseErr != nil {
		return reportInspectFailure(config, "invalid_plugin", fmt.Errorf("parse plugin timeout: %w", parseErr))
	}
	if config.Timeout == 0 || config.Timeout > pluginTimeout {
		config.Timeout = pluginTimeout
	}
	maxAge, hardMax, err := inspectionFreshness(config, resolved.Manifest)
	if err != nil {
		return reportInspectFailure(config, "config", err)
	}
	useSudo, privilege, err := inspectionPrivilege(config, resolved.Manifest)
	if err != nil {
		return reportInspectFailure(config, "config", err)
	}

	if config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			// Preserve the existing direct-hostname fallback contract.
			_ = resolveErr
		}
	}
	if config.Host == "" {
		return reportInspectFailure(config, "config", fmt.Errorf("host is required"))
	}
	if useSudo {
		password, passwordErr := sshclient.GetSudoPassword(config.SudoKey)
		if passwordErr != nil {
			return reportInspectFailure(config, "secret", fmt.Errorf("resolve sudo password key %q: %w", config.SudoKey, passwordErr))
		}
		config.SudoPassword = password
	}

	client, err := sshclient.NewSSHClient(config)
	if err != nil {
		return reportInspectFailure(config, "config", fmt.Errorf("create SSH client: %w", err))
	}
	defer errutil.HandleCloseError(&err, client)
	if err = client.ConnectDirect(); err != nil {
		return reportInspectFailure(config, classifyError(err), fmt.Errorf("connect for inspection: %w", err))
	}
	if audit != nil {
		audit.event.AuthMethod = string(client.AuthMethodUsed())
	}

	target, err := inspectTarget(client, config)
	if err != nil {
		return reportInspectFailure(config, classifyError(err), err)
	}
	if !pluginpkg.SupportsPlatform(resolved.Manifest.Platforms, target.Platform) {
		observation := newUnsupportedObservation(resolved, target, privilege, config.InspectCacheMode, maxAge)
		setAuditObservation(audit, observation)
		return emitObservation(config, observation)
	}
	parameters := parametersDigest()

	var remoteSnapshotPath string
	if config.InspectCacheMode == "remote-prefer" {
		remoteHome, homeErr := client.RemoteHome()
		if homeErr != nil {
			return reportInspectFailure(config, "cache", homeErr)
		}
		remoteSnapshotPath = path.Join(remoteHome, ".sshx", "observations", "v1", resolved.Manifest.ID+".json")
		if !config.InspectRefresh {
			cached, readErr := client.ReadRemoteFile(remoteSnapshotPath, pluginpkg.MaxObservation, target.UID)
			if readErr == nil {
				observation, cacheErr := validatedCachedObservation(cached, resolved, target, privilege, parameters, maxAge, hardMax, config.InspectAllowStale)
				if cacheErr != nil {
					return reportInspectFailure(config, "cache_invalid", cacheErr)
				}
				if observation != nil {
					if audit != nil {
						audit.event.CacheHit = true
					}
					setAuditObservation(audit, *observation)
					return emitObservation(config, *observation)
				}
			} else if !errors.Is(readErr, os.ErrNotExist) && !isSFTPNotExist(readErr) {
				return reportInspectFailure(config, "cache_invalid", fmt.Errorf("read remote observation: %w", readErr))
			}
		}
	}

	result, collectErr := client.RunScript(resolved.Collector, useSudo)
	if collectErr != nil {
		return reportInspectFailure(config, classifyError(collectErr), collectErr)
	}
	if result.StdoutTruncated {
		return reportInspectFailure(config, "output_too_large", fmt.Errorf("collector stdout exceeded capture limit"))
	}
	if result.ExitCode != 0 {
		return reportInspectFailure(config, "collector_exit", fmt.Errorf("collector exited with status %d", result.ExitCode))
	}
	parsed, err := pluginpkg.ValidateResult(resolved, []byte(result.Stdout))
	if err != nil {
		return reportInspectFailure(config, "invalid_output", err)
	}
	parsed, redacted := pluginpkg.RedactResult(parsed, resolved.Manifest.Redaction)
	validatedJSON, marshalErr := json.Marshal(parsed)
	if marshalErr != nil {
		return reportInspectFailure(config, "invalid_output", fmt.Errorf("encode redacted result: %w", marshalErr))
	}
	if _, err := pluginpkg.ValidateResult(resolved, validatedJSON); err != nil {
		return reportInspectFailure(config, "invalid_output", fmt.Errorf("redacted result violates schema: %w", err))
	}

	now := time.Now().UTC()
	ttl, ttlErr := time.ParseDuration(resolved.Manifest.Cache.RecommendedTTL)
	if ttlErr != nil {
		return reportInspectFailure(config, "invalid_plugin", fmt.Errorf("parse plugin cache ttl: %w", ttlErr))
	}
	if ttl > hardMax {
		ttl = hardMax
	}
	observation := pluginpkg.Observation{
		Schema:      pluginpkg.ObservationV1,
		Capability:  pluginpkg.CapabilityRef{ID: resolved.Manifest.ID, Version: resolved.Manifest.Version, Digest: resolved.Digest, Builtin: resolved.Builtin},
		Target:      target,
		CollectedAt: now,
		ExpiresAt:   now.Add(ttl),
		Status:      parsed.Status,
		Privilege:   privilege,
		Parameters:  parameters,
		Cache:       pluginpkg.CacheState{Mode: config.InspectCacheMode, Hit: false},
		Facts:       parsed.Facts,
		Evidence:    parsed.Evidence,
		Errors:      parsed.Errors,
		Redaction:   redacted,
	}
	if remoteSnapshotPath != "" {
		data, marshalErr := json.Marshal(observation)
		if marshalErr != nil {
			return reportInspectFailure(config, "cache", marshalErr)
		}
		if len(data)+1 > pluginpkg.MaxObservation {
			return reportInspectFailure(config, "output_too_large", fmt.Errorf("observation exceeds %d-byte limit", pluginpkg.MaxObservation))
		}
		if writeErr := client.WriteRemoteFileAtomic(remoteSnapshotPath, append(data, '\n')); writeErr != nil {
			return reportInspectFailure(config, "cache", fmt.Errorf("write remote observation: %w", writeErr))
		}
	}
	setAuditObservation(audit, observation)
	return emitObservation(config, observation)
}

func setAuditObservation(audit *auditRecorder, observation pluginpkg.Observation) {
	if audit == nil {
		return
	}
	audit.event.ObservationStatus = observation.Status
}

func inspectionFreshness(config *sshclient.Config, manifest pluginpkg.Manifest) (time.Duration, time.Duration, error) {
	recommended, recommendedErr := time.ParseDuration(manifest.Cache.RecommendedTTL)
	if recommendedErr != nil {
		return 0, 0, fmt.Errorf("parse recommended_ttl: %w", recommendedErr)
	}
	hardMax, hardMaxErr := time.ParseDuration(manifest.Cache.HardMaxAge)
	if hardMaxErr != nil {
		return 0, 0, fmt.Errorf("parse hard_max_age: %w", hardMaxErr)
	}
	maxAge := config.InspectMaxAge
	if maxAge == 0 {
		maxAge = recommended
	}
	if maxAge > hardMax {
		return 0, hardMax, fmt.Errorf("--max-age %s exceeds plugin hard_max_age %s", maxAge, hardMax)
	}
	return maxAge, hardMax, nil
}

func inspectionPrivilege(config *sshclient.Config, manifest pluginpkg.Manifest) (bool, string, error) {
	switch manifest.Privilege {
	case "never":
		if config.InspectUseSudo {
			return false, "user", fmt.Errorf("capability %q forbids sudo", manifest.ID)
		}
		return false, "user", nil
	case "required":
		return true, "sudo", nil
	case "optional":
		if config.InspectUseSudo {
			return true, "sudo", nil
		}
		return false, "user", nil
	default:
		return false, "user", fmt.Errorf("invalid privilege policy %q", manifest.Privilege)
	}
}

func inspectTarget(client *sshclient.SSHClient, config *sshclient.Config) (pluginpkg.TargetRef, error) {
	previousTimeout := config.Timeout
	if config.Timeout == 0 || config.Timeout > 10*time.Second {
		config.Timeout = 10 * time.Second
	}
	result, err := client.RunScript([]byte(targetMetadataScript), false)
	config.Timeout = previousTimeout
	if err != nil {
		return pluginpkg.TargetRef{}, fmt.Errorf("inspect target identity: %w", err)
	}
	if result.ExitCode != 0 || result.StdoutTruncated {
		return pluginpkg.TargetRef{}, fmt.Errorf("inspect target identity returned incomplete output")
	}
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	platform := "unknown"
	if len(lines) > 0 {
		switch strings.ToLower(strings.TrimSpace(lines[0])) {
		case "linux":
			platform = "linux"
		case "darwin":
			platform = "darwin"
		case "windows_nt", "mingw", "msys":
			platform = "windows"
		}
	}
	bootID := ""
	if len(lines) > 1 && strings.TrimSpace(lines[1]) != "unknown" {
		bootID = strings.TrimSpace(lines[1])
	}
	uid := ""
	if len(lines) > 2 && strings.TrimSpace(lines[2]) != "unknown" {
		uid = strings.TrimSpace(lines[2])
	}
	return pluginpkg.TargetRef{
		Host:               config.Host,
		Port:               config.Port,
		User:               config.User,
		UID:                uid,
		HostKeyFingerprint: config.HostKeyFingerprint,
		Platform:           platform,
		BootID:             bootID,
	}, nil
}

func validatedCachedObservation(data []byte, resolved *pluginpkg.Resolved, target pluginpkg.TargetRef, privilege, parameters string, maxAge, hardMax time.Duration, allowStale bool) (*pluginpkg.Observation, error) {
	observation, err := pluginpkg.DecodeObservation(data)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	reusable, stale, _ := pluginpkg.CacheReusable(observation, resolved, target, privilege, parameters, now, maxAge)
	if !reusable || stale && !allowStale {
		return nil, nil
	}
	if allowStale && hardMax > 0 && now.Sub(observation.CollectedAt) > hardMax {
		return nil, nil
	}
	result := pluginpkg.Result{Status: observation.Status, Facts: observation.Facts, Evidence: observation.Evidence, Errors: observation.Errors}
	data, err = json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if _, err := pluginpkg.ValidateResult(resolved, data); err != nil {
		return nil, fmt.Errorf("cached facts violate plugin schema: %w", err)
	}
	result, redacted := pluginpkg.RedactResult(result, resolved.Manifest.Redaction)
	observation.Facts = result.Facts
	observation.Evidence = result.Evidence
	observation.Errors = result.Errors
	observation.Redaction = append(observation.Redaction, redacted...)
	observation.Cache = pluginpkg.CacheState{Mode: "remote-prefer", Hit: true, Stale: stale, AgeSeconds: int64(now.Sub(observation.CollectedAt).Seconds())}
	return &observation, nil
}

func newUnsupportedObservation(resolved *pluginpkg.Resolved, target pluginpkg.TargetRef, privilege, cacheMode string, maxAge time.Duration) pluginpkg.Observation {
	now := time.Now().UTC()
	return pluginpkg.Observation{
		Schema:      pluginpkg.ObservationV1,
		Capability:  pluginpkg.CapabilityRef{ID: resolved.Manifest.ID, Version: resolved.Manifest.Version, Digest: resolved.Digest, Builtin: resolved.Builtin},
		Target:      target,
		CollectedAt: now,
		ExpiresAt:   now.Add(maxAge),
		Status:      "unsupported",
		Privilege:   privilege,
		Parameters:  parametersDigest(),
		Cache:       pluginpkg.CacheState{Mode: cacheMode},
		Facts:       map[string]any{},
		Evidence:    []pluginpkg.Evidence{},
		Errors:      []pluginpkg.ResultError{{Kind: "unsupported_platform", Message: "target platform is not declared by the capability"}},
	}
}

func parametersDigest() string {
	sum := sha256.Sum256([]byte("{}"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isSFTPNotExist(err error) bool {
	var status *sftp.StatusError
	return errors.As(err, &status) && status.Code == 2
}

func emitObservation(config *sshclient.Config, observation pluginpkg.Observation) error {
	if config.JSONOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(observation)
	}
	fmt.Printf("%s: %s (cache_hit=%t stale=%t)\n", observation.Capability.ID, observation.Status, observation.Cache.Hit, observation.Cache.Stale)
	data, err := json.MarshalIndent(observation.Facts, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func reportInspectFailure(config *sshclient.Config, kind string, err error) error {
	config.ReportedErrorKind = kind
	config.ReportedError = redactError(err)
	if !config.JSONOutput {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if encodeErr := encoder.Encode(inspectFailure{Success: false, Capability: config.InspectCapability, ErrorKind: kind, Error: redactError(err)}); encodeErr != nil {
		return encodeErr
	}
	return ErrReported
}
