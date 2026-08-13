package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

// HostRecord is the inventory shape required by selector resolution.
// The app package adapts settings HostConfig into this type.
type HostRecord struct {
	Name            string
	Address         string
	Port            string
	User            string
	KeyPath         string
	SSHPasswordKey  string
	SudoPasswordKey string
	Groups          []string
	Tags            map[string]string
}

// ResolveTargets freezes a deterministic target snapshot from configured hosts.
//
// Semantics:
//   - names and groups form a candidate union
//   - every tag predicate is an AND filter
//   - if only tags are provided, all configured hosts are the candidate set
//   - --all-hosts selects the full inventory before tag filters
//   - multi-host selectors never accept literal addresses
//   - zero matches is a request-level failure (returned as error)
func ResolveTargets(hosts []HostRecord, sel TargetSelector, defaults HostRecord) (TargetSnapshot, error) {
	if err := validateSelector(sel); err != nil {
		return TargetSnapshot{}, err
	}

	byName := make(map[string]HostRecord, len(hosts))
	for _, h := range hosts {
		byName[h.Name] = h
	}

	// Explicit literal single-target address path.
	if strings.TrimSpace(sel.Address) != "" {
		port := sel.Port
		if port == "" {
			port = defaults.Port
		}
		if port == "" {
			port = "22"
		}
		user := sel.User
		if user == "" {
			user = defaults.User
		}
		if user == "" {
			user = "master"
		}
		target := ResolvedTarget{
			Index:           0,
			Address:         strings.TrimSpace(sel.Address),
			Port:            port,
			User:            user,
			KeyPath:         defaults.KeyPath,
			SSHPasswordKey:  defaults.SSHPasswordKey,
			SudoPasswordKey: defaults.SudoPasswordKey,
			Literal:         true,
		}
		snap := TargetSnapshot{
			Targets: []ResolvedTarget{target},
			Count:   1,
		}
		snap.SelectorDigest = snapshotDigest(snap)
		return snap, nil
	}

	candidates := map[string]HostRecord{}
	var skipped []SkippedTarget

	useUnion := len(sel.Names) > 0 || len(sel.Groups) > 0 || sel.AllHosts
	onlyTags := !useUnion && len(sel.Tags) > 0

	if sel.AllHosts || onlyTags {
		for _, h := range hosts {
			candidates[h.Name] = h
		}
	}

	for _, name := range sel.Names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		h, ok := byName[name]
		if !ok {
			skipped = append(skipped, SkippedTarget{Alias: name, Reason: "alias_not_found"})
			continue
		}
		candidates[h.Name] = h
	}

	if len(sel.Groups) > 0 {
		groupSet := map[string]struct{}{}
		for _, g := range sel.Groups {
			g = strings.TrimSpace(g)
			if g != "" {
				groupSet[g] = struct{}{}
			}
		}
		for _, h := range hosts {
			for _, g := range h.Groups {
				if _, ok := groupSet[g]; ok {
					candidates[h.Name] = h
					break
				}
			}
		}
	}

	// Apply AND tag filters.
	if len(sel.Tags) > 0 {
		for name, h := range candidates {
			if !matchAllTags(h.Tags, sel.Tags) {
				delete(candidates, name)
			}
		}
	}

	if len(candidates) == 0 {
		snap := TargetSnapshot{Skipped: skipped, Count: 0}
		snap.SelectorDigest = snapshotDigest(snap)
		return snap, ErrNoTargets
	}

	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)

	targets := make([]ResolvedTarget, 0, len(names))
	for i, name := range names {
		h := candidates[name]
		port := h.Port
		if port == "" {
			port = "22"
		}
		user := h.User
		if user == "" {
			user = "master"
		}
		keyPath := h.KeyPath
		if keyPath == "" {
			keyPath = defaults.KeyPath
		}
		targets = append(targets, ResolvedTarget{
			Index:           i,
			Alias:           h.Name,
			Address:         h.Address,
			Port:            port,
			User:            user,
			KeyPath:         keyPath,
			SSHPasswordKey:  firstNonEmpty(h.SSHPasswordKey, defaults.SSHPasswordKey),
			SudoPasswordKey: firstNonEmpty(h.SudoPasswordKey, defaults.SudoPasswordKey),
			Groups:          append([]string(nil), h.Groups...),
			Tags:            copyTags(h.Tags),
		})
	}

	sort.Slice(skipped, func(i, j int) bool {
		return skipped[i].Alias < skipped[j].Alias
	})

	snap := TargetSnapshot{
		Targets: targets,
		Skipped: skipped,
		Count:   len(targets),
	}
	snap.SelectorDigest = snapshotDigest(snap)
	return snap, nil
}

func validateSelector(sel TargetSelector) error {
	hasMulti := len(sel.Names) > 0 || len(sel.Groups) > 0 || len(sel.Tags) > 0 || sel.AllHosts
	hasLiteral := strings.TrimSpace(sel.Address) != ""
	if hasLiteral && hasMulti {
		return fmt.Errorf("%w: --address cannot combine with multi-host selectors", ErrConfig)
	}
	if !hasLiteral && !hasMulti {
		return fmt.Errorf("%w: at least one target selector is required", ErrConfig)
	}
	// Multi-host selectors must not smuggle literal IPs through --target names.
	for _, name := range sel.Names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if net.ParseIP(name) != nil {
			return fmt.Errorf("%w: literal address %q requires --address, not --target", ErrConfig, name)
		}
	}
	return nil
}

func matchAllTags(have, want map[string]string) bool {
	if len(want) == 0 {
		return true
	}
	if have == nil {
		return false
	}
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func snapshotDigest(snap TargetSnapshot) string {
	type digTarget struct {
		Alias   string `json:"alias,omitempty"`
		Address string `json:"address"`
		Port    string `json:"port"`
		User    string `json:"user"`
	}
	type digSnap struct {
		Targets []digTarget     `json:"targets"`
		Skipped []SkippedTarget `json:"skipped,omitempty"`
	}
	d := digSnap{Skipped: snap.Skipped}
	for _, t := range snap.Targets {
		d.Targets = append(d.Targets, digTarget{
			Alias:   t.Alias,
			Address: t.Address,
			Port:    t.Port,
			User:    t.User,
		})
	}
	raw, err := json.Marshal(d)
	if err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", snap.Count)))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func copyTags(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
