package app

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func runSFTP(client *sshclient.SSHClient, config *sshclient.Config, audit *auditRecorder) error {
	start := time.Now()
	outcome, operationErr := client.ExecuteSftpResult()
	result, err := fileOperationResult(config, outcome, start, operationErr)
	if err != nil {
		return err
	}
	if finishErr := finishOperation(config, audit, result, operationErr); finishErr != nil {
		return finishErr
	}
	if !config.JSONOutput {
		if renderErr := sshclient.RenderSFTPOutcome(outcome); renderErr != nil {
			return fmt.Errorf("%w: render SFTP result: %w", execution.ErrLocalIO, renderErr)
		}
	}
	return nil
}

func fileOperationResult(config *sshclient.Config, outcome *sshclient.SFTPOutcome, start time.Time, operationErr error) (map[string]any, error) {
	result := map[string]any{}
	if outcome != nil {
		publicOutcome := *outcome
		publicOutcome.Entries = append([]sshclient.FileOutcome(nil), outcome.Entries...)
		if p := preparedFrom(config); p != nil && config.SftpAction == "upload" {
			publicOutcome.SourcePath = p.preview.LocalPath
			for i := range publicOutcome.Entries {
				publicOutcome.Entries[i].SourcePath = p.preview.LocalPath
			}
		}
		raw, err := json.Marshal(publicOutcome)
		if err != nil {
			return nil, fmt.Errorf("encode file outcome: %w", err)
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("decode file outcome: %w", err)
		}
		if result == nil {
			result = map[string]any{}
		}
		var conditions []execution.Condition
		for _, entry := range outcome.Entries {
			status := "unknown"
			if entry.Verified {
				status = "passed"
			}
			if config.SftpAction == "remove" || config.SftpAction == "rm" {
				observed := "unknown"
				if entry.Verified {
					observed = "absent"
				}
				conditions = append(conditions, execution.Condition{Kind: "path_absent", Subject: entry.Path, Expected: "absent", Observed: observed, Status: status})
				continue
			}
			if entry.SourceSHA256 != "" || entry.SHA256 != "" {
				digestStatus := "unknown"
				observed := entry.SHA256
				if entry.SourceSHA256 != "" && entry.SHA256 != "" {
					digestStatus = "failed"
					if entry.SourceSHA256 == entry.SHA256 {
						digestStatus = "passed"
					}
				}
				if !entry.Published {
					if entry.SHA256 != "" {
						conditions = append(conditions, execution.Condition{Kind: "staging_sha256", Subject: entry.StagingPath,
							Expected: entry.SourceSHA256, Observed: entry.SHA256, Status: digestStatus})
					}
					digestStatus, observed = "unknown", ""
				}
				conditions = append(conditions, execution.Condition{Kind: "file_sha256", Subject: entry.Path,
					Expected: entry.SourceSHA256, Observed: observed, Status: digestStatus})
			}
			conditions = append(conditions,
				execution.Condition{Kind: "file_type", Subject: entry.Path, Observed: entry.Type, Status: status},
				execution.Condition{Kind: "file_size", Subject: entry.Path, Observed: strconv.FormatInt(entry.Size, 10), Status: status},
			)
			if entry.Mode != "" {
				conditions = append(conditions, execution.Condition{Kind: "file_mode", Subject: entry.Path, Observed: entry.Mode, Status: status})
			}
			if entry.UID != nil {
				conditions = append(conditions, execution.Condition{Kind: "file_uid", Subject: entry.Path, Observed: strconv.FormatUint(uint64(*entry.UID), 10), Status: status})
			}
			if entry.GID != nil {
				conditions = append(conditions, execution.Condition{Kind: "file_gid", Subject: entry.Path, Observed: strconv.FormatUint(uint64(*entry.GID), 10), Status: status})
			}
			if entry.StagingPath != "" {
				conditions = append(conditions, execution.Condition{Kind: "staging_cleanup", Subject: entry.StagingPath, Expected: "absent", Status: "unknown"})
			}
		}
		result["postconditions"] = conditions
	}
	result["schema_version"] = execution.ResultSchemaVersion
	result["action"] = firstNonEmpty(config.SftpAction, config.Mode)
	result["host"], result["port"], result["user"] = config.Host, config.Port, config.User
	result["remote_path"] = config.RemotePath
	result["success"] = operationErr == nil
	result["duration_ms"] = time.Since(start).Milliseconds()
	result["exit_code"], result["status"] = 0, execution.StatusSucceeded
	if operationErr != nil {
		result["exit_code"], result["status"] = -1, execution.StatusFailed
		result["error_kind"], result["error"] = execution.Classify(operationErr), redactError(operationErr)
	}
	if _, exists := result["phase"]; !exists {
		result["phase"] = execution.PhaseComplete
		if operationErr != nil {
			result["phase"] = execution.PhaseExecute
		}
	}
	if _, exists := result["completion"]; !exists {
		result["completion"] = execution.CompletionCompleted
		if operationErr != nil {
			result["completion"] = execution.CompletionUnknown
			if outcome == nil || !outcome.Started {
				result["completion"] = execution.CompletionNotStarted
			}
		}
	}
	return result, nil
}
