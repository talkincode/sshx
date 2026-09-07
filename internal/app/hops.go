package app

import (
	"fmt"
	"strings"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func settingsHostRecords(settings *Settings) []execution.HostRecord {
	if settings == nil {
		return nil
	}
	hosts := make([]execution.HostRecord, 0, len(settings.Hosts))
	for _, host := range settings.Hosts {
		hosts = append(hosts, hostToRecord(host))
	}
	return hosts
}

func ensureJumpChain(config *sshclient.Config) error {
	if config == nil || len(config.JumpChain) > 0 {
		return nil
	}
	if strings.TrimSpace(config.Via) == "" && !config.ViaSet {
		return nil
	}
	settings, err := LoadSettings()
	if err != nil {
		return err
	}
	return materializeJumpChain(config, settings)
}

func applyInventoryVia(config *sshclient.Config, host HostConfig) {
	if config == nil || config.ViaSet {
		return
	}
	config.Via = host.Via
}

func materializeJumpChain(config *sshclient.Config, settings *Settings) error {
	if config == nil {
		return fmt.Errorf("%w: config is required", execution.ErrConfig)
	}
	records := settingsHostRecords(settings)
	target := execution.ResolvedTarget{
		Alias:   config.HostAlias,
		Address: config.Host,
		Port:    config.Port,
		User:    config.User,
		Via:     config.Via,
	}
	var override *string
	if config.ViaSet {
		via := config.Via
		override = &via
	}
	resolved, err := execution.ResolveJumps(records, target, override)
	if err != nil {
		return err
	}
	config.Via = resolved.Via
	config.JumpChain = jumpConfigs(config, resolved.Jumps)
	return nil
}

func jumpConfigs(parent *sshclient.Config, jumps []execution.ResolvedTarget) []*sshclient.Config {
	if parent == nil || len(jumps) == 0 {
		return nil
	}
	out := make([]*sshclient.Config, 0, len(jumps))
	for i, hop := range jumps {
		cfg := &sshclient.Config{
			HostAlias:            hop.Alias,
			Host:                 hop.Address,
			Port:                 hop.Port,
			User:                 hop.User,
			KeyPath:              hop.KeyPath,
			UseKeyAuth:           parent.UseKeyAuth,
			SSHPasswordKey:       hop.SSHPasswordKey,
			DialTimeout:          parent.DialTimeout,
			AcceptUnknownHost:    parent.AcceptUnknownHost,
			AllowInsecureHostKey: parent.AllowInsecureHostKey,
			KnownHostsPath:       parent.KnownHostsPath,
			KnownHostsData:       parent.KnownHostsData,
			Context:              parent.Context,
		}
		if !parent.UseKeyAuth {
			cfg.KeyPath = ""
		}
		if i == 0 {
			cfg.Bind = parent.Bind
		}
		out = append(out, cfg)
	}
	return out
}

func resolveJumpSecrets(config *sshclient.Config) error {
	if config == nil {
		return nil
	}
	for _, hop := range config.JumpChain {
		if hop == nil || hop.Password != "" {
			continue
		}
		if hop.SSHPasswordKey != "" {
			password, err := sshclient.GetSudoPassword(hop.SSHPasswordKey)
			if err != nil {
				return &sshclient.HopError{Role: "jump", Alias: hopAlias(hop), Err: fmt.Errorf("resolve jump SSH password role %q: %w", hop.SSHPasswordKey, err)}
			}
			hop.Password = password
			continue
		}
		if config.Password != "" {
			hop.Password = config.Password
		}
	}
	return nil
}

func hopAlias(hop *sshclient.Config) string {
	if hop == nil {
		return ""
	}
	if hop.HostAlias != "" {
		return hop.HostAlias
	}
	return hop.Host
}

func validateHostVia(settings *Settings, host HostConfig) error {
	if settings == nil {
		settings = &Settings{}
	}
	hosts := append([]HostConfig{}, settings.Hosts...)
	replaced := false
	for i, existing := range hosts {
		if existing.Name == host.Name {
			hosts[i] = host
			replaced = true
			break
		}
	}
	if !replaced {
		hosts = append(hosts, host)
	}
	records := make([]execution.HostRecord, 0, len(hosts))
	for _, item := range hosts {
		records = append(records, hostToRecord(item))
	}
	target := execution.ResolvedTarget{
		Alias:   host.Name,
		Address: host.Host,
		Port:    host.Port,
		User:    host.User,
		Via:     host.Via,
	}
	_, err := execution.ResolveJumps(records, target, nil)
	return err
}

func hostsUsingJump(settings *Settings, name string) []string {
	if settings == nil {
		return nil
	}
	var names []string
	for _, host := range settings.Hosts {
		if host.Via == name {
			names = append(names, host.Name)
		}
	}
	return names
}
