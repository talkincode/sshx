package plugin

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var builtinDescriptions = map[string]string{
	"system.identity":    "Inspect operating system, kernel, architecture, init system, and boot identity",
	"system.resources":   "Inspect CPU, memory, load, filesystems, and mount pressure",
	"network.interfaces": "Inspect network interface addresses and link state",
	"network.routes":     "Inspect IPv4 and IPv6 routing tables",
	"network.dns":        "Inspect resolver configuration and resolver status",
	"network.listeners":  "Inspect listening TCP and UDP sockets",
	"network.firewall":   "Inspect the active nftables, iptables, ufw, or firewalld backend",
	"system.baseline":    "Inspect the stable system, resource, and network baseline in one collection",
}

func resolveBuiltin(id string) (*Resolved, bool) {
	description, ok := builtinDescriptions[id]
	if !ok {
		return nil, false
	}
	collector := []byte(builtinCollector(id))
	var schemaDoc any
	if err := json.Unmarshal([]byte(resultSchema), &schemaDoc); err != nil {
		panic(fmt.Sprintf("invalid embedded result schema: %v", err))
	}
	manifest := Manifest{
		APIVersion:  SchemaVersion,
		ID:          id,
		Version:     "1.0.0",
		Kind:        "inspect",
		Description: description,
		Platforms:   []string{"linux"},
		Runner:      Runner{Type: "sh", Entrypoint: "embedded"},
		Privilege:   "never",
		Timeout:     "30s",
		Effects:     []string{"remote.read"},
		Output:      OutputContract{Schema: "embedded"},
		Cache:       CachePolicy{RecommendedTTL: builtinTTL(id), HardMaxAge: "24h"},
		Redaction:   RedactionPolicy{DenyFields: defaultDenyFields()},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		panic(fmt.Sprintf("encode embedded manifest: %v", err))
	}
	digest := calculateDigest(manifestBytes, collector, []byte(resultSchema))
	return &Resolved{
		Manifest:  manifest,
		Path:      "builtin:" + id,
		Digest:    digest,
		Trusted:   true,
		Builtin:   true,
		Collector: collector,
		Schema:    schemaDoc,
	}, true
}

func BuiltinSummaries() []Summary {
	ids := make([]string, 0, len(builtinDescriptions))
	for id := range builtinDescriptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	summaries := make([]Summary, 0, len(ids))
	for _, id := range ids {
		resolved, _ := resolveBuiltin(id)
		summaries = append(summaries, SummaryFromResolved(resolved))
	}
	return summaries
}

func builtinTTL(id string) string {
	switch id {
	case "system.identity":
		return "1h"
	case "system.resources":
		return "30s"
	default:
		return "5m"
	}
}

func defaultDenyFields() []string {
	return []string{"authorization", "cookie", "credentials", "env", "password", "private_key", "secret", "token"}
}

func builtinCollector(id string) string {
	return strings.ReplaceAll(builtinCollectorScript, "__SSHX_CAPABILITY__", id)
}

const builtinCollectorScript = `#!/bin/sh
set -u

capability='__SSHX_CAPABILITY__'

safe_text() {
  LC_ALL=C tr -cd '[:alnum:]_./:,@%+= ()[]{}*?-\n' | awk 'BEGIN { first=1 } { if (!first) printf "; "; printf "%s", $0; first=0 }'
}

run_text() {
  if output=$(sh -c "$1" 2>/dev/null); then
    printf '%s' "$output" | safe_text
  else
    printf 'unavailable'
  fi
}

identity() {
  sysname=$(run_text 'uname -s')
  release=$(run_text 'uname -r')
  machine=$(run_text 'uname -m')
  hostname=$(run_text 'hostname')
  os_release=$(run_text 'test -r /etc/os-release && sed -n "s/^PRETTY_NAME=//p" /etc/os-release | tr -d "\""')
  init_system=$(run_text 'if command -v systemctl >/dev/null 2>&1; then printf systemd; elif command -v rc-service >/dev/null 2>&1; then printf openrc; else printf unknown; fi')
  boot_id=$(run_text 'test -r /proc/sys/kernel/random/boot_id && cat /proc/sys/kernel/random/boot_id || printf unknown')
  printf '"identity":{"hostname":"%s","os":"%s","kernel":"%s","architecture":"%s","distribution":"%s","init":"%s","boot_id":"%s"}' "$hostname" "$sysname" "$release" "$machine" "$os_release" "$init_system" "$boot_id"
}

resources() {
  cpus=$(run_text 'getconf _NPROCESSORS_ONLN 2>/dev/null || printf unknown')
  memory=$(run_text 'grep -E "^MemTotal:|^MemAvailable:" /proc/meminfo 2>/dev/null | head -n 2 || printf unknown')
  load=$(run_text 'cat /proc/loadavg 2>/dev/null || uptime')
  filesystems=$(run_text 'df -P -T 2>/dev/null | head -n 80')
  mounts=$(run_text 'findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | head -n 120 || mount | head -n 120')
  printf '"resources":{"cpu_count":"%s","memory":"%s","load":"%s","filesystems":"%s","mounts":"%s"}' "$cpus" "$memory" "$load" "$filesystems" "$mounts"
}

interfaces() {
  links=$(run_text 'if command -v ip >/dev/null 2>&1; then ip -details -o link show; elif command -v ifconfig >/dev/null 2>&1; then ifconfig -a; else exit 1; fi')
  addresses=$(run_text 'if command -v ip >/dev/null 2>&1; then ip -o address show; elif command -v ifconfig >/dev/null 2>&1; then ifconfig -a; else exit 1; fi')
  printf '"interfaces":{"links":"%s","addresses":"%s"}' "$links" "$addresses"
}

routes() {
  ipv4=$(run_text 'if command -v ip >/dev/null 2>&1; then ip -4 route show table all; else netstat -rn -f inet; fi')
  ipv6=$(run_text 'if command -v ip >/dev/null 2>&1; then ip -6 route show table all; else netstat -rn -f inet6; fi')
  printf '"routes":{"ipv4":"%s","ipv6":"%s"}' "$ipv4" "$ipv6"
}

dns() {
  resolv_conf=$(run_text 'test -r /etc/resolv.conf && sed -n "1,120p" /etc/resolv.conf')
  resolver=$(run_text 'if command -v resolvectl >/dev/null 2>&1; then resolvectl status | head -n 160; elif command -v scutil >/dev/null 2>&1; then scutil --dns | head -n 160; else printf unavailable; fi')
  printf '"dns":{"resolv_conf":"%s","resolver_status":"%s"}' "$resolv_conf" "$resolver"
}

listeners() {
  sockets=$(run_text 'if command -v ss >/dev/null 2>&1; then ss -H -lntup | head -n 200; elif command -v netstat >/dev/null 2>&1; then netstat -an | head -n 200; else exit 1; fi')
  printf '"listeners":{"sockets":"%s"}' "$sockets"
}

firewall() {
  backend=none
  rules=unavailable
  if command -v nft >/dev/null 2>&1; then
    backend=nftables
    rules=$(run_text 'nft list ruleset 2>/dev/null | head -n 240')
  elif command -v iptables >/dev/null 2>&1; then
    backend=iptables
    rules=$(run_text 'iptables-save 2>/dev/null | head -n 240')
  elif command -v ufw >/dev/null 2>&1; then
    backend=ufw
    rules=$(run_text 'ufw status verbose 2>/dev/null | head -n 240')
  elif command -v firewall-cmd >/dev/null 2>&1; then
    backend=firewalld
    rules=$(run_text 'firewall-cmd --list-all-zones 2>/dev/null | head -n 240')
  fi
  printf '"firewall":{"backend":"%s","rules":"%s"}' "$backend" "$rules"
}

case "$capability" in
  system.identity) facts=$(identity) ;;
  system.resources) facts=$(resources) ;;
  network.interfaces) facts=$(interfaces) ;;
  network.routes) facts=$(routes) ;;
  network.dns) facts=$(dns) ;;
  network.listeners) facts=$(listeners) ;;
  network.firewall) facts=$(firewall) ;;
  system.baseline)
    facts="$(identity),$(resources),$(interfaces),$(routes),$(dns),$(listeners),$(firewall)"
    ;;
  *)
    printf '%s\n' '{"status":"unsupported","facts":{},"evidence":[],"errors":[{"kind":"unknown_capability"}]}'
    exit 0
    ;;
esac

if printf '%s' "$facts" | grep -q 'unavailable'; then
  status=partial
  errors='[{"kind":"section_unavailable","message":"one or more commands were unavailable or permission-limited"}]'
else
  status=complete
  errors='[]'
fi
printf '{"status":"%s","facts":{%s},"evidence":[{"kind":"direct","source":"standard operating-system interfaces"}],"errors":%s}\n' "$status" "$facts" "$errors"
`
