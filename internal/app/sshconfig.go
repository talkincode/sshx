package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/talkincode/sshx/internal/sshclient"
)

// sshConfigEntry is one concrete "Host <alias>" block parsed from an OpenSSH
// client configuration file, reduced to the fields sshx can represent.
type sshConfigEntry struct {
	Alias        string
	HostName     string
	Port         string
	User         string
	IdentityFile string
	Bind         string
	// IgnoredOptions lists option keywords present in the block that sshx
	// does not import (e.g. ProxyJump, ForwardAgent), so the user can see
	// exactly what a selective import leaves behind.
	IgnoredOptions []string
}

// importCandidate is an entry that can be imported as-is.
type importCandidate struct {
	Entry sshConfigEntry
	Host  HostConfig
}

// skippedEntry records why an entry was excluded from the import plan.
type skippedEntry struct {
	Alias  string
	Reason string
}

// importPlan is the result of matching parsed ssh_config entries against the
// current settings: what can be imported and what is skipped (with reasons).
type importPlan struct {
	Candidates []importCandidate
	Skipped    []skippedEntry
	Notes      []string
}

// defaultSSHConfigPath returns ~/.ssh/config.
func defaultSSHConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// isWildcardAlias reports whether an ssh_config Host alias is a pattern
// (wildcard or negation) rather than a concrete host alias.
func isWildcardAlias(alias string) bool {
	return strings.ContainsAny(alias, "*?") || strings.HasPrefix(alias, "!")
}

// importedConfigKeys are the ssh_config keywords sshx maps onto HostConfig.
var importedConfigKeys = map[string]bool{
	"hostname":      true,
	"port":          true,
	"user":          true,
	"identityfile":  true,
	"bindaddress":   true,
	"bindinterface": true,
}

// parseSSHConfig parses an OpenSSH client config stream into per-alias
// entries. A "Host a b" line yields one entry per alias sharing the same
// options. Match blocks are skipped entirely; Include directives are not
// followed (a note is returned so the user knows).
func parseSSHConfig(r io.Reader) ([]sshConfigEntry, []string, error) {
	var (
		entries      []sshConfigEntry
		notes        []string
		current      []int // indexes into entries for the active Host block
		inMatchBlock bool
		sawInclude   bool
	)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value := splitSSHConfigLine(line)
		if key == "" {
			continue
		}

		switch key {
		case "host":
			inMatchBlock = false
			current = current[:0]
			for _, alias := range strings.Fields(value) {
				entries = append(entries, sshConfigEntry{Alias: unquoteSSHValue(alias)})
				current = append(current, len(entries)-1)
			}
			continue
		case "match":
			inMatchBlock = true
			current = nil
			continue
		case "include":
			sawInclude = true
			continue
		}

		if inMatchBlock || len(current) == 0 {
			continue
		}

		for _, idx := range current {
			applySSHConfigOption(&entries[idx], key, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to read ssh config: %w", err)
	}

	if sawInclude {
		notes = append(notes, "Include directives are not followed; import from included files separately with --ssh-config=<path>")
	}
	return entries, notes, nil
}

// splitSSHConfigLine splits "Key Value", "Key=Value", or "Key = Value" into a
// lowercased keyword and its raw value.
func splitSSHConfigLine(line string) (key, value string) {
	if idx := strings.IndexAny(line, " \t="); idx >= 0 {
		key = line[:idx]
		value = strings.TrimLeft(line[idx:], " \t=")
	} else {
		key = line
	}
	return strings.ToLower(key), strings.TrimSpace(value)
}

// unquoteSSHValue strips one pair of surrounding double quotes.
func unquoteSSHValue(value string) string {
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		return value[1 : len(value)-1]
	}
	return value
}

// applySSHConfigOption records a single option on an entry. The first
// occurrence of an imported key wins (matching OpenSSH semantics, where the
// first obtained value is used). Unsupported keys are collected as ignored.
func applySSHConfigOption(entry *sshConfigEntry, key, value string) {
	value = unquoteSSHValue(value)
	switch key {
	case "hostname":
		if entry.HostName == "" {
			entry.HostName = value
		}
	case "port":
		if entry.Port == "" {
			entry.Port = value
		}
	case "user":
		if entry.User == "" {
			entry.User = value
		}
	case "identityfile":
		if entry.IdentityFile == "" {
			entry.IdentityFile = value
		}
	case "bindaddress", "bindinterface":
		if entry.Bind == "" {
			entry.Bind = value
		}
	default:
		if !importedConfigKeys[key] && !containsFold(entry.IgnoredOptions, key) {
			entry.IgnoredOptions = append(entry.IgnoredOptions, key)
		}
	}
}

func containsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

// buildImportPlan filters parsed entries against the current settings and
// produces the selective-import plan. Pollution guards:
//   - wildcard/negated aliases are never importable;
//   - aliases already present in settings are skipped;
//   - host+port pairs already present in settings are skipped;
//   - options from other blocks (including "Host *") are never merged in;
//   - identity files containing % tokens are dropped from the candidate (noted).
func buildImportPlan(entries []sshConfigEntry, settings *Settings) importPlan {
	plan := importPlan{}

	existingNames := make(map[string]bool, len(settings.Hosts))
	existingAddrs := make(map[string]string, len(settings.Hosts))
	for _, h := range settings.Hosts {
		existingNames[h.Name] = true
		port := h.Port
		if port == "" {
			port = sshclient.DefaultSSHPort
		}
		existingAddrs[h.Host+":"+port] = h.Name
	}

	plannedAddrs := make(map[string]string)

	for _, entry := range entries {
		if isWildcardAlias(entry.Alias) {
			plan.Skipped = append(plan.Skipped, skippedEntry{Alias: entry.Alias, Reason: "wildcard/negated pattern, not a concrete host"})
			continue
		}
		if existingNames[entry.Alias] {
			plan.Skipped = append(plan.Skipped, skippedEntry{Alias: entry.Alias, Reason: "already exists in settings"})
			continue
		}

		host := HostConfig{
			Name:        entry.Alias,
			Description: "Imported from ssh_config",
			Host:        entry.HostName,
			Port:        entry.Port,
			User:        entry.User,
			Type:        DefaultHostType,
			Bind:        entry.Bind,
		}
		// "Host web1" with no HostName means the alias itself is the address.
		if host.Host == "" {
			host.Host = entry.Alias
		}
		if host.Port == "" {
			host.Port = sshclient.DefaultSSHPort
		}

		addr := host.Host + ":" + host.Port
		if name, ok := existingAddrs[addr]; ok {
			plan.Skipped = append(plan.Skipped, skippedEntry{Alias: entry.Alias, Reason: fmt.Sprintf("address %s already configured as '%s'", addr, name)})
			continue
		}
		if name, ok := plannedAddrs[addr]; ok {
			plan.Skipped = append(plan.Skipped, skippedEntry{Alias: entry.Alias, Reason: fmt.Sprintf("address %s duplicates ssh_config entry '%s'", addr, name)})
			continue
		}

		if entry.IdentityFile != "" {
			if strings.Contains(entry.IdentityFile, "%") {
				plan.Notes = append(plan.Notes, fmt.Sprintf("'%s': IdentityFile %q uses %% tokens and was not imported", entry.Alias, entry.IdentityFile))
			} else {
				host.Key = entry.IdentityFile
			}
		}

		plannedAddrs[addr] = entry.Alias
		plan.Candidates = append(plan.Candidates, importCandidate{Entry: entry, Host: host})
	}

	return plan
}

// selectCandidatesByName resolves a comma-separated name list against the
// plan. It is all-or-nothing: any name that is not an importable candidate
// fails the whole selection, so scripted imports stay deterministic.
func selectCandidatesByName(plan importPlan, names string) ([]importCandidate, error) {
	byName := make(map[string]importCandidate, len(plan.Candidates))
	for _, c := range plan.Candidates {
		byName[c.Host.Name] = c
	}
	skippedReason := make(map[string]string, len(plan.Skipped))
	for _, s := range plan.Skipped {
		skippedReason[s.Alias] = s.Reason
	}

	var selected []importCandidate
	seen := make(map[string]bool)
	for _, raw := range strings.Split(names, ",") {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		candidate, ok := byName[name]
		if !ok {
			if reason, wasSkipped := skippedReason[name]; wasSkipped {
				return nil, fmt.Errorf("host '%s' cannot be imported: %s", name, reason)
			}
			return nil, fmt.Errorf("host '%s' not found in ssh config", name)
		}
		selected = append(selected, candidate)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no host names given (use --host-import=<name1,name2> or interactive --host-import)")
	}
	return selected, nil
}

// candidateSummary renders one candidate as a single scannable line.
func candidateSummary(c importCandidate) string {
	target := fmt.Sprintf("%s@%s:%s", firstNonEmpty(c.Host.User, sshclient.DefaultSSHUser), c.Host.Host, c.Host.Port)
	summary := fmt.Sprintf("%-20s → %s", c.Host.Name, target)
	if c.Host.Key != "" {
		summary += "  key=" + c.Host.Key
	}
	if c.Host.Bind != "" {
		summary += "  bind=" + c.Host.Bind
	}
	if len(c.Entry.IgnoredOptions) > 0 {
		summary += "  (ignored: " + strings.Join(c.Entry.IgnoredOptions, ", ") + ")"
	}
	return summary
}
