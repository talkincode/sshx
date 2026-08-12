package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

const MaxObservation = 10 << 20

func DecodeObservation(data []byte) (Observation, error) {
	if len(data) > MaxObservation {
		return Observation{}, fmt.Errorf("observation exceeds %d-byte limit", MaxObservation)
	}
	var observation Observation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Observation{}, err
	}
	if observation.Schema != ObservationV1 {
		return Observation{}, fmt.Errorf("unsupported observation schema %q", observation.Schema)
	}
	if err := ValidateID(observation.Capability.ID); err != nil {
		return Observation{}, err
	}
	if observation.Capability.Version == "" || observation.Capability.Digest == "" {
		return Observation{}, fmt.Errorf("observation capability identity is incomplete")
	}
	if observation.Target.Host == "" || observation.Target.Port == "" || observation.Target.User == "" || observation.Target.HostKeyFingerprint == "" || observation.Target.Platform == "" {
		return Observation{}, fmt.Errorf("observation target identity is incomplete")
	}
	if observation.CollectedAt.IsZero() || observation.ExpiresAt.IsZero() || observation.ExpiresAt.Before(observation.CollectedAt) {
		return Observation{}, fmt.Errorf("observation freshness timestamps are invalid")
	}
	switch observation.Status {
	case "complete", "partial", "unsupported", "failed":
	default:
		return Observation{}, fmt.Errorf("invalid observation status %q", observation.Status)
	}
	if observation.Privilege != "user" && observation.Privilege != "sudo" {
		return Observation{}, fmt.Errorf("invalid observation privilege %q", observation.Privilege)
	}
	if observation.Parameters == "" {
		return Observation{}, fmt.Errorf("observation parameters digest is missing")
	}
	if observation.Facts == nil || observation.Evidence == nil || observation.Errors == nil {
		return Observation{}, fmt.Errorf("observation must include non-null facts, evidence, and errors")
	}
	return observation, nil
}

func CacheReusable(observation Observation, resolved *Resolved, target TargetRef, privilege, parameters string, now time.Time, maxAge time.Duration) (bool, bool, string) {
	switch {
	case observation.Capability.ID != resolved.Manifest.ID:
		return false, false, "capability_id_changed"
	case observation.Capability.Version != resolved.Manifest.Version:
		return false, false, "capability_version_changed"
	case observation.Capability.Digest != resolved.Digest:
		return false, false, "capability_digest_changed"
	case observation.Target.Host != target.Host:
		return false, false, "host_changed"
	case observation.Target.Port != target.Port:
		return false, false, "port_changed"
	case observation.Target.User != target.User:
		return false, false, "user_changed"
	case observation.Target.HostKeyFingerprint != target.HostKeyFingerprint:
		return false, false, "host_key_changed"
	case observation.Target.Platform != target.Platform:
		return false, false, "platform_changed"
	case observation.Target.UID != target.UID:
		return false, false, "uid_changed"
	case observation.Target.BootID != "" && target.BootID != "" && observation.Target.BootID != target.BootID:
		return false, false, "boot_id_changed"
	case observation.Privilege != privilege:
		return false, false, "privilege_changed"
	case observation.Parameters != parameters:
		return false, false, "parameters_changed"
	}
	age := now.Sub(observation.CollectedAt)
	if age < 0 {
		return false, false, "collected_at_in_future"
	}
	stale := now.After(observation.ExpiresAt) || maxAge > 0 && age > maxAge
	if stale {
		return true, true, "stale"
	}
	return true, false, "fresh"
}
