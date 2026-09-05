package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/keyringstore"
	pluginpkg "github.com/talkincode/sshx/internal/plugin"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
	"golang.org/x/crypto/ssh"
)

type preparedKey struct{}
type resolvedKey struct{}

type preparedOperation struct {
	plan    *execution.Plan
	preview dryRunPlan
	plugin  *pluginpkg.Resolved
	meta    execution.Metadata
	cleanup func() error
	audit   *auditRecorder
}

func preparedFrom(config *sshclient.Config) *preparedOperation {
	if config.Context == nil {
		return nil
	}
	if p, ok := config.Context.Value(preparedKey{}).(*preparedOperation); ok {
		return p
	}
	return nil
}

func remoteOperation(config *sshclient.Config) bool {
	switch config.Mode {
	case "ssh", "sftp", "transfer", "apply", "sql", "inspect":
		return true
	default:
		return false
	}
}

func planInputs(config *sshclient.Config) map[string]string {
	dialTimeout := config.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = sshclient.DefaultTimeout
	}
	outputLimit := config.MaxOutputBytes
	if outputLimit <= 0 {
		outputLimit = sshclient.MaxCaptureBytes
	}
	return map[string]string{
		"command_sha256":        execution.Digest([]byte(config.Command)),
		"command_timeout_ns":    strconv.FormatInt(int64(config.Timeout), 10),
		"host_timeout_ns":       strconv.FormatInt(int64(config.HostTimeout), 10),
		"global_timeout_ns":     strconv.FormatInt(int64(config.GlobalTimeout), 10),
		"dial_timeout_ns":       strconv.FormatInt(int64(dialTimeout), 10),
		"max_output_bytes":      strconv.Itoa(outputLimit),
		"key_auth":              strconv.FormatBool(config.UseKeyAuth),
		"ssh_password_provided": strconv.FormatBool(config.Password != ""),
		"secret_backend":        keyringstore.Inspect().Backend,
		"pty":                   strconv.FormatBool(config.UsePTY),
		"safety":                strconv.FormatBool(config.SafetyCheck),
		"force":                 strconv.FormatBool(config.Force),
		"bypass_reason_sha256":  execution.Digest([]byte(config.BypassReason)),
		"accept_unknown_host":   strconv.FormatBool(config.AcceptUnknownHost),
		"insecure_host_key":     strconv.FormatBool(config.AllowInsecureHostKey),
	}
}

func prepareOperation(config *sshclient.Config) (*preparedOperation, error) {
	if err := execution.ValidatePlanHash(config.ExpectPlan); err != nil {
		return nil, err
	}
	explicitKey := config.KeyPath
	previewConfig := *config
	// Binding admission follows public normalization, not preview validation.
	previewConfig.ExpectPlan = ""
	p := &preparedOperation{preview: buildDryRunPlan(&previewConfig)}
	previewConfig.ExpectPlan = config.ExpectPlan
	*config = previewConfig
	if !p.preview.Valid {
		return p, &execution.BoundaryError{Kind: firstNonEmpty(
			p.preview.ConfigCheck.ErrorKind, p.preview.SafetyCheck.ErrorKind, "config"),
			Message: firstNonEmpty(p.preview.ConfigCheck.Message, p.preview.SafetyCheck.Message, "invalid execution plan")}
	}
	markPublicResolution(config)
	action := p.preview.Action
	risk, effects := execution.ClassifyRisk(action, config.Command, p.preview.UsesSudo)
	plan := &execution.Plan{Action: action, Inputs: planInputs(config), Risk: risk, Effects: effects}
	plan.Inputs["use_sudo"] = strconv.FormatBool(p.preview.UsesSudo)
	p.plan = plan
	if config.Mode == "transfer" {
		for _, endpoint := range []struct{ role, host string }{{"source", config.TransferSrcHost}, {"destination", config.TransferDstHost}} {
			copyConfig := *config
			copyConfig.Mode, copyConfig.Host = "ssh", endpoint.host
			copyConfig.Command = "true"
			copyConfig.KeyPath = explicitKey
			preview := buildDryRunPlan(&copyConfig)
			if !preview.Valid {
				return p, fmt.Errorf("%w: invalid transfer %s: %s", execution.ErrConfig, endpoint.role, preview.ConfigCheck.Message)
			}
			markPublicResolution(&copyConfig)
			plan.Targets = append(plan.Targets, publicPlanTarget(&copyConfig, endpoint.host, endpoint.role, plan))
			if endpoint.role == "source" {
				config.TransferSource = &copyConfig
			} else {
				config.TransferDestination = &copyConfig
			}
		}
		plan.Inputs["source_path"], plan.Inputs["destination_path"] = config.TransferSrcPath, config.TransferDstPath
		plan.Inputs["recursive"] = "source_type"
	} else {
		plan.Targets = []execution.PlanTarget{publicPlanTarget(config, p.preview.HostInput, "target", plan)}
	}
	switch config.Mode {
	case "apply":
		plan.Inputs["payload_sha256"] = execution.Digest(config.PreparedPayload)
		plan.Inputs["payload_bytes"] = strconv.Itoa(len(config.PreparedPayload))
		plan.Inputs["remote_path"] = config.RemotePath
		plan.Inputs["expect_sha256"] = config.ApplyExpectSHA256
		plan.Inputs["backup_dir"] = config.ApplyBackupDir
		plan.Inputs["no_backup"] = strconv.FormatBool(config.ApplyNoBackup)
	case "sftp":
		plan.Inputs["remote_path"] = config.RemotePath
		if config.SftpAction == "upload" {
			hash, count, cleanup, err := prepareUpload(config)
			p.cleanup = cleanup
			if err != nil {
				return p, err
			}
			plan.Inputs["payload_sha256"], plan.Inputs["payload_bytes"] = hash, strconv.FormatInt(count, 10)
		}
		if config.SftpAction == "download" {
			destination, err := filepath.Abs(config.LocalPath)
			if err != nil {
				return p, fmt.Errorf("%w: resolve download destination: %v", execution.ErrLocalIO, err)
			}
			plan.Inputs["local_destination"] = destination
		}
	case "sql":
		cls, err := sqlsafe.ClassifyFor(config.SQLEngine, config.SQLStatement)
		if err != nil {
			return p, err
		}
		plan.Effects.Unknown = false
		plan.Effects.RemoteWrite = cls.Class != sqlsafe.ClassRead && !config.SQLExplainOnly
		plan.Effects.Destructive = cls.Destructive && !config.SQLExplainOnly
		plan.Inputs["statement_sha256"] = execution.Digest([]byte(config.SQLStatement))
		plan.Inputs["engine"], plan.Inputs["database"] = config.SQLEngine, config.SQLDatabase
		plan.Inputs["db_role"], plan.Inputs["db_host"], plan.Inputs["db_port"] = config.SQLUser, config.SQLHost, config.SQLPort
		plan.Inputs["db_password_key"], plan.Inputs["db_cred_from"] = config.SQLPasswordKey, config.SQLCredFrom
		plan.Inputs["container"] = config.SQLDockerContainer
		plan.Inputs["explain_only"] = strconv.FormatBool(config.SQLExplainOnly)
		plan.Inputs["allow_full_table"] = strconv.FormatBool(config.SQLAllowFullTable)
		plan.Inputs["no_backup"] = strconv.FormatBool(config.SQLNoBackup)
		plan.Inputs["backup_dir"] = config.SQLBackupDir
		threshold := config.SQLRowThreshold
		if threshold == 0 {
			threshold = sqlsafe.DefaultRowThreshold
		}
		plan.Inputs["row_threshold"] = strconv.FormatInt(threshold, 10)
		plan.Inputs["backup_policy"] = "dialect-v1"
		if config.SQLDatabase == "" || (config.SQLEngine != sqlsafe.EngineSQLite && config.SQLUser == "") {
			plan.Unresolved = append(plan.Unresolved, "database and database role must be explicit")
		}
		if config.SQLEngine != sqlsafe.EngineSQLite && (config.SQLHost == "" || config.SQLPort == "") {
			plan.Unresolved = append(plan.Unresolved, "database host and port must be explicit")
		}
		if config.SQLCredFrom != "" || config.SQLDockerContainer != "" {
			plan.Unresolved = append(plan.Unresolved, "remote credential/container identity is not pinned offline")
		}
	case "inspect":
		resolved := p.preview.resolvedPlugin
		if resolved == nil {
			return p, fmt.Errorf("%w: inspection plugin was not prepared", execution.ErrConfig)
		}
		p.plugin = resolved
		pluginTimeout, parseErr := time.ParseDuration(resolved.Manifest.Timeout)
		if parseErr != nil {
			return p, fmt.Errorf("%w: invalid plugin timeout: %v", execution.ErrConfig, parseErr)
		}
		if config.Timeout == 0 || config.Timeout > pluginTimeout {
			config.Timeout = pluginTimeout
		}
		maxAge, _, freshnessErr := inspectionFreshness(config, resolved.Manifest)
		if freshnessErr != nil {
			return p, fmt.Errorf("%w: %v", execution.ErrConfig, freshnessErr)
		}
		config.InspectMaxAge = maxAge
		useSudo, privilege, privilegeErr := inspectionPrivilege(config, resolved.Manifest)
		if privilegeErr != nil {
			return p, fmt.Errorf("%w: %v", execution.ErrConfig, privilegeErr)
		}
		p.preview.Timeout, p.preview.UsesSudo = config.Timeout.String(), useSudo
		plan.Inputs["command_timeout_ns"] = strconv.FormatInt(int64(config.Timeout), 10)
		plan.Inputs["use_sudo"], plan.Inputs["privilege_mode"] = strconv.FormatBool(useSudo), privilege
		plan.Effects.Privileged = useSudo
		p.preview.PluginDigest = resolved.Digest
		plan.Inputs["plugin_digest"] = resolved.Digest
		plan.Inputs["cache"], plan.Inputs["max_age_ns"] = config.InspectCacheMode, strconv.FormatInt(int64(config.InspectMaxAge), 10)
		plan.Inputs["refresh"], plan.Inputs["allow_stale"] = strconv.FormatBool(config.InspectRefresh), strconv.FormatBool(config.InspectAllowStale)
		plan.Effects.Unknown = !resolved.Builtin
		plan.Effects.RemoteWrite = plan.Effects.Unknown || config.InspectCacheMode == "remote-prefer"
	}
	if config.User == "root" {
		plan.Effects.Privileged = true
	}
	plan.Risk = plan.Effects.Risk()
	if err := plan.Seal(); err != nil {
		return p, err
	}
	config.PlanHash, config.Risk = plan.PlanHash, string(plan.Risk)
	p.preview.Plan, p.preview.PlanHash, p.preview.Risk = plan, plan.PlanHash, plan.Risk
	p.meta = execution.NewMetadata(plan, config.ExecutionID)
	return p, plan.CheckExpected(config.ExpectPlan)
}

func publicPlanTarget(config *sshclient.Config, alias, role string, plan *execution.Plan) execution.PlanTarget {
	t := execution.PlanTarget{
		Role: role, Alias: alias, Address: config.Host, Port: config.Port, User: config.User,
		Bind: config.Bind, SSHPasswordKey: config.SSHPasswordKey, SudoKey: config.SudoKey,
	}
	if config.User == "root" {
		plan.Effects.Privileged = true
	}
	if net.ParseIP(config.Host) == nil {
		plan.Unresolved = append(plan.Unresolved, role+": address requires an explicit IP for offline binding")
	}
	if addr, err := sshclient.ResolveBind(config.Bind, config.Host); err == nil && addr != nil {
		if tcp, ok := addr.(*net.TCPAddr); ok {
			t.Bind = tcp.IP.String()
			if tcp.Zone != "" {
				t.Bind += "%" + tcp.Zone
			}
			config.Bind = t.Bind
		} else {
			plan.Unresolved = append(plan.Unresolved, role+": unsupported source bind address")
		}
	} else if err != nil {
		plan.Unresolved = append(plan.Unresolved, role+": source bind is unresolved")
	}
	if config.UseKeyAuth {
		data, err := os.ReadFile(config.KeyPath + ".pub")
		if err == nil {
			key, _, _, _, parseErr := ssh.ParseAuthorizedKey(data)
			if parseErr == nil {
				t.KeyFingerprint = ssh.FingerprintSHA256(key)
				if config.ExpectPlan != "" {
					config.ExpectedKeyFingerprint = t.KeyFingerprint
				}
			}
		}
		if t.KeyFingerprint == "" {
			plan.Unresolved = append(plan.Unresolved, role+": SSH public key sidecar is unavailable")
		}
	}
	trustPath := config.KnownHostsPath
	if trustPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			trustPath = filepath.Join(home, ".ssh", "known_hosts")
		}
	}
	data, err := os.ReadFile(trustPath) // #nosec G304 -- caller-selected public known-hosts trust store.
	if err != nil {
		plan.Unresolved = append(plan.Unresolved, role+": known-host trust is unavailable")
	} else {
		var records []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				records = append(records, line)
			}
		}
		sort.Strings(records)
		t.TrustSHA256 = execution.Digest([]byte(strings.Join(records, "\n")))
		if config.ExpectPlan != "" {
			config.KnownHostsData = append([]byte{}, data...)
		}
	}
	if config.AcceptUnknownHost || config.AllowInsecureHostKey {
		plan.Unresolved = append(plan.Unresolved, role+": relaxed host trust cannot bind a peer identity")
	}
	return t
}

func prepareUpload(config *sshclient.Config) (string, int64, func() error, error) {
	source, err := os.Open(config.LocalPath)
	if err != nil {
		return "", 0, nil, fmt.Errorf("%w: read upload: %v", execution.ErrLocalIO, err)
	}
	defer func() { _ = source.Close() }() //nolint:errcheck // read-only source
	hash := sha256.New()
	var destination io.Writer = hash
	var spool *os.File
	var cleanup func() error
	if !config.DryRun && config.ExpectPlan != "" {
		spool, err = os.CreateTemp("", "sshx-payload-*")
		if err != nil {
			return "", 0, nil, fmt.Errorf("%w: snapshot upload: %v", execution.ErrLocalIO, err)
		}
		cleanup = func() error { return os.Remove(spool.Name()) }
		destination = io.MultiWriter(hash, spool)
	}
	count, copyErr := io.Copy(destination, source)
	if spool != nil {
		closeErr := spool.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		config.LocalPath = spool.Name()
	}
	if copyErr != nil {
		return "", count, cleanup, fmt.Errorf("%w: snapshot upload: %v", execution.ErrLocalIO, copyErr)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), count, cleanup, nil
}

func attachPrepared(config *sshclient.Config, p *preparedOperation) {
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	config.Context = context.WithValue(ctx, preparedKey{}, p)
}

func markPublicResolution(config *sshclient.Config) {
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	config.Context = context.WithValue(ctx, resolvedKey{}, true)
}

func publiclyResolved(config *sshclient.Config) bool {
	return config.Context != nil && config.Context.Value(resolvedKey{}) == true
}

func prepareRunPlan(config *sshclient.Config, req *execution.Request, snap *execution.TargetSnapshot, payload *execution.Payload) (*execution.Plan, error) {
	plan := &execution.Plan{Action: req.Action.Kind, Inputs: planInputs(config)}
	command := req.Action.Command
	if payload != nil {
		command = string(payload.Bytes)
	}
	plan.Risk, plan.Effects = execution.ClassifyRisk(req.Action.Kind, command, req.Action.UseSudo)
	plan.Inputs["payload_sha256"], plan.Inputs["payload_bytes"] = req.Action.PayloadSHA256, strconv.Itoa(req.Action.PayloadBytes)
	plan.Inputs["shell"], plan.Inputs["intent"] = req.Action.ScriptRunner, req.Action.Intent
	plan.Inputs["use_sudo"] = strconv.FormatBool(req.Action.UseSudo)
	plan.Inputs["concurrency"] = strconv.Itoa(req.Limits.Concurrency)
	plan.Inputs["global_timeout_ns"] = strconv.FormatInt(int64(req.Limits.GlobalTimeout), 10)
	plan.Inputs["max_output_bytes"] = strconv.Itoa(req.Limits.MaxOutputBytesPerTarget)
	plan.Inputs["max_payload_bytes"] = strconv.Itoa(req.Limits.MaxPayloadBytes)
	plan.Inputs["failure_mode"], plan.Inputs["max_failures"] = req.Policy.FailureMode, strconv.Itoa(req.Policy.MaxFailures)
	for i := range snap.Targets {
		t := &snap.Targets[i]
		copyConfig := *config
		copyConfig.Host, copyConfig.Port, copyConfig.User, copyConfig.Bind = t.Address, t.Port, t.User, t.Bind
		copyConfig.KeyPath = firstNonEmpty(req.Policy.KeyPath, t.KeyPath)
		if copyConfig.UseKeyAuth && copyConfig.KeyPath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				copyConfig.KeyPath = filepath.Join(home, ".ssh", "id_rsa")
			}
		}
		copyConfig.SSHPasswordKey = firstNonEmpty(req.Policy.SSHPasswordKey, t.SSHPasswordKey)
		copyConfig.SudoKey = firstNonEmpty(req.Policy.SudoPasswordKey, t.SudoPasswordKey)
		plan.Targets = append(plan.Targets, publicPlanTarget(&copyConfig, t.Alias, "target", plan))
		t.KnownHostsData, t.ExpectedKeyFingerprint = copyConfig.KnownHostsData, copyConfig.ExpectedKeyFingerprint
		t.Bind = copyConfig.Bind
		if t.User == "root" {
			plan.Effects.Privileged = true
		}
	}
	plan.Risk = plan.Effects.Risk()
	if err := plan.Seal(); err != nil {
		return nil, err
	}
	req.Plan, req.ExecutionID = plan, config.ExecutionID
	config.PlanHash, config.Risk = plan.PlanHash, string(plan.Risk)
	return plan, plan.CheckExpected(config.ExpectPlan)
}
