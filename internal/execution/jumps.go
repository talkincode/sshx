package execution

import (
	"fmt"
	"strings"
)

// MaxJumpHops is the maximum number of intermediate bastion hops, not counting
// the target. Longer chains are a config error and never touch the network.
const MaxJumpHops = 4

// ResolveJumps walks named-host via pointers from target to the outermost
// bastion. viaOverride, when non-nil, replaces the target's inventory via
// (including an empty value that forces a direct connection).
//
// Returned Jumps are outermost-first. Each hop must be a configured alias;
// literal addresses are rejected so secrets and host-key decisions stay named.
func ResolveJumps(hosts []HostRecord, target ResolvedTarget, viaOverride *string) (ResolvedTarget, error) {
	via := strings.TrimSpace(target.Via)
	if viaOverride != nil {
		via = strings.TrimSpace(*viaOverride)
	}
	if via == "" {
		target.Via = ""
		target.Jumps = nil
		return target, nil
	}

	byName := make(map[string]HostRecord, len(hosts))
	for _, host := range hosts {
		if host.Name == "" {
			continue
		}
		byName[host.Name] = host
	}

	seen := map[string]struct{}{}
	if alias := strings.TrimSpace(target.Alias); alias != "" {
		seen[alias] = struct{}{}
	}

	var innerFirst []ResolvedTarget
	current := via
	for current != "" {
		if _, loop := seen[current]; loop {
			return target, fmt.Errorf("%w: jump chain cycle involving %q", ErrConfig, current)
		}
		if len(innerFirst) >= MaxJumpHops {
			return target, fmt.Errorf("%w: jump chain exceeds %d hops", ErrConfig, MaxJumpHops)
		}
		host, ok := byName[current]
		if !ok {
			return target, fmt.Errorf("%w: jump host %q is not a named sshx host", ErrConfig, current)
		}
		seen[current] = struct{}{}
		innerFirst = append(innerFirst, hopFromRecord(host))
		current = strings.TrimSpace(host.Via)
	}

	jumps := make([]ResolvedTarget, len(innerFirst))
	for i := range innerFirst {
		jumps[len(innerFirst)-1-i] = innerFirst[i]
	}
	target.Via = via
	target.Jumps = jumps
	return target, nil
}

func hopFromRecord(host HostRecord) ResolvedTarget {
	port := host.Port
	if port == "" {
		port = "22"
	}
	user := host.User
	if user == "" {
		user = "master"
	}
	return ResolvedTarget{
		Alias:           host.Name,
		Address:         host.Address,
		Port:            port,
		User:            user,
		KeyPath:         host.KeyPath,
		SSHPasswordKey:  host.SSHPasswordKey,
		SudoPasswordKey: host.SudoPasswordKey,
		Bind:            host.Bind,
		Via:             host.Via,
	}
}
