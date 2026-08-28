package sshclient

import (
	"strings"
)

// This file detects destructive commands by inspecting the token in *command
// position*, reusing the shell segmentation used by the guarded-SQL detector.
//
// The previous implementation matched keywords anywhere in the raw command
// string, which produced overwhelming false positives on ordinary read-only
// operations: `last reboot -F` matched "reboot", `journalctl | grep -iE
// 'fail|halt'` matched "halt", and `iptables-save | grep -F ...` matched the
// ("iptables", "-f") keyword pair. A guardrail that fires on reads trains the
// operator to reflexively pass --force, which defeats its purpose.
//
// Like ValidateCommand as a whole, this is a guardrail against accidental
// mistakes, NOT a security boundary.

// destructiveRule matches the arguments of one command in command position.
// args excludes the command name itself.
type destructiveRule struct {
	reason string
	match  func(args []string) bool
}

// destructiveCommands maps a lowercased command basename to its rules. Rules
// are evaluated in order and the first match wins. `rm` and `mkfs.<fstype>`
// are handled in matchDestructiveRules because they need a dynamic reason.
var destructiveCommands = map[string][]destructiveRule{
	"fdisk":     {{reason: "Disk partition operation", match: partitionsDevice}},
	"sfdisk":    {{reason: "Disk partition operation", match: partitionsDevice}},
	"parted":    {{reason: "Disk partition operation", match: partitionsDevice}},
	"mkswap":    {{reason: "Create swap partition", match: hasDevicePath}},
	"mkfs":      {{reason: "Format filesystem", match: always}},
	"shutdown":  {{reason: "System shutdown operation", match: always}},
	"halt":      {{reason: "System halt operation", match: always}},
	"poweroff":  {{reason: "System poweroff operation", match: always}},
	"reboot":    {{reason: "System reboot operation", match: always}},
	"init":      {{reason: "System shutdown (init 0)", match: initRunlevel("0")}, {reason: "System reboot (init 6)", match: initRunlevel("6")}},
	"systemctl": {{reason: "System halt operation", match: systemctlVerb("halt")}, {reason: "System poweroff operation", match: systemctlVerb("poweroff")}, {reason: "System reboot operation", match: systemctlVerb("reboot")}, {reason: "System kexec operation", match: systemctlVerb("kexec")}},
	"iptables":  {{reason: "Flush firewall rules", match: iptablesFlag("-F", "--flush")}, {reason: "Delete firewall chain", match: iptablesFlag("-X", "--delete-chain")}},
	"ip6tables": {{reason: "Flush firewall rules", match: iptablesFlag("-F", "--flush")}, {reason: "Delete firewall chain", match: iptablesFlag("-X", "--delete-chain")}},
	"chmod":     {{reason: "Set root directory permissions to 777", match: chmod777Root}},
	"chown":     {{reason: "Recursively change ownership of the root directory", match: chownRoot}},
	"dd":        {{reason: "Dangerous dd operation", match: ddDangerous}},
	"vgremove":  {{reason: "Remove LVM volume group", match: always}},
	"lvremove":  {{reason: "Remove LVM logical volume", match: always}},
	"pvremove":  {{reason: "Remove LVM physical volume", match: always}},
	"wipefs":    {{reason: "Erase filesystem signatures", match: wipefsDestructive}},
	"shred":     {{reason: "Irreversibly shred a block device", match: hasDevicePath}},
	"zpool":     {{reason: "Destroy ZFS pool", match: firstWordIs("destroy")}},
	"zfs":       {{reason: "Destroy ZFS dataset", match: firstWordIs("destroy")}},
}

func always([]string) bool { return true }

// tildeTargets and homeVarTargets are home-directory spellings whose recursive
// deletion is blocked. They are separated so the reported reason matches the
// spelling the caller actually used.
var tildeTargets = map[string]bool{
	"~": true, "~/": true, "~/*": true,
}

var homeVarTargets = map[string]bool{
	"$home": true, "${home}": true, "$home/": true, "${home}/": true,
	"$home/*": true, "${home}/*": true,
}

// systemDirTargets are top-level system directories whose recursive removal
// breaks the host even though they are not literally "/".
var systemDirTargets = map[string]bool{
	"/bin": true, "/boot": true, "/etc": true, "/lib": true, "/lib64": true,
	"/proc": true, "/sbin": true, "/sys": true, "/usr": true, "/var": true,
}

// rmVerdict reports whether an `rm` invocation recursively targets the root,
// the user home, or a critical system directory. A recursive delete of any
// ordinary path (/tmp/x, /home/user/test, /var/log/app) is left alone.
func rmVerdict(args []string) (string, bool) {
	recursive := false
	noPreserveRoot := false
	var targets []string
	for _, a := range args {
		lower := strings.ToLower(a)
		switch {
		case lower == "--no-preserve-root":
			noPreserveRoot = true
		case lower == "--recursive":
			recursive = true
		case strings.HasPrefix(a, "--"):
			// other long option
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if strings.Contains(lower[1:], "r") {
				recursive = true
			}
		default:
			targets = append(targets, a)
		}
	}
	if !recursive {
		return "", false
	}
	if noPreserveRoot {
		return "Delete root directory", true
	}
	for _, t := range targets {
		lower := strings.ToLower(t)
		switch {
		case t == "/" || t == "/.":
			return "Delete root directory", true
		case t == "/*":
			return "Delete all files in root directory", true
		case homeVarTargets[lower]:
			return "Delete $HOME directory", true
		case tildeTargets[lower]:
			return "Delete user home directory", true
		}
		if systemDirTargets[strings.TrimSuffix(lower, "/")] {
			return "Delete a critical system directory (" + t + ")", true
		}
	}
	return "", false
}

// readOnlyDiskArgs are arguments that make a partition tool report instead of
// modify. `-s` is deliberately absent: it means "print size" for fdisk but
// "script mode" for parted, where it enables unattended destructive edits.
var readOnlyDiskArgs = map[string]bool{
	"-l": true, "--list": true, "-d": true, "--dump": true,
	"print": true, "p": true, "-v": true, "--version": true,
}

// partitionsDevice blocks partition editors that name a device, while leaving
// the reporting forms (`fdisk -l /dev/sda`, `parted /dev/sdb print`) alone.
func partitionsDevice(args []string) bool {
	for _, a := range args {
		if readOnlyDiskArgs[strings.ToLower(a)] {
			return false
		}
	}
	return hasDevicePath(args)
}

func hasDevicePath(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "/dev/") {
			return true
		}
	}
	return false
}

// wipefsDestructive blocks wipefs only when it actually erases. Invoked with
// just a device it prints the detected signatures, and -n/--no-act is a dry run.
func wipefsDestructive(args []string) bool {
	if !hasDevicePath(args) {
		return false
	}
	erases := false
	for _, a := range args {
		switch {
		case a == "-n" || a == "--no-act":
			return false
		case a == "-a" || a == "--all" || a == "-o" || a == "--offset":
			erases = true
		case strings.HasPrefix(a, "--offset="):
			erases = true
		}
	}
	return erases
}

func chownRoot(args []string) bool {
	recursive := false
	for _, a := range args {
		lower := strings.ToLower(a)
		if lower == "--recursive" {
			recursive = true
			continue
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(lower[1:], "r") {
			recursive = true
		}
	}
	if !recursive {
		return false
	}
	for _, a := range args {
		if a == "/" {
			return true
		}
	}
	return false
}

func firstWordIs(want string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			return strings.EqualFold(a, want)
		}
		return false
	}
}

func initRunlevel(level string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			return a == level
		}
		return false
	}
}

// systemctlVerb matches `systemctl <verb>`; it compares whole tokens so unit
// names such as reboot.target or a `systemctl status halt.service` query are
// not treated as a power action.
func systemctlVerb(verb string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			return strings.EqualFold(a, verb)
		}
		return false
	}
}

// iptablesFlag matches iptables control flags. Matching is case-sensitive
// because iptables distinguishes -F (flush) from -f (fragment) and -X
// (delete chain) from -x (exact).
func iptablesFlag(flags ...string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			for _, f := range flags {
				if a == f {
					return true
				}
			}
		}
		return false
	}
}

func chmod777Root(args []string) bool {
	has777 := false
	rootTarget := false
	for _, a := range args {
		if a == "777" || a == "0777" {
			has777 = true
			continue
		}
		if a == "/" {
			rootTarget = true
		}
	}
	return has777 && rootTarget
}

func ddDangerous(args []string) bool {
	for _, a := range args {
		lower := strings.ToLower(a)
		if lower == "if=/dev/zero" || lower == "if=/dev/urandom" || lower == "if=/dev/random" {
			return true
		}
		// Writing straight to a whole block device destroys its contents.
		if v, ok := strings.CutPrefix(lower, "of=/dev/"); ok {
			if v != "null" && v != "stdout" && v != "stderr" {
				return true
			}
		}
	}
	return false
}

// maxDestructiveDepth bounds recursion into nested shell payloads.
const maxDestructiveDepth = 6

// detectDestructiveCommand reports the reason a command is considered
// destructive, inspecting only tokens in command position.
func detectDestructiveCommand(command string, depth int) (string, bool) {
	if depth > maxDestructiveDepth {
		return "", false
	}
	segments := splitShellSegments(command)
	sawDownloader := false

	for _, seg := range segments {
		name, args, kind := commandInPosition(seg)
		switch kind {
		case positionShellStdin:
			// `curl ... | sh` — a shell reading its script from the pipe.
			if sawDownloader {
				return "Download and execute script from network", true
			}
		case positionShellScript:
			if reason, found := detectDestructiveCommand(args[0], depth+1); found {
				return reason, true
			}
		case positionCommand:
			if reason, found := matchDestructiveRules(name, args); found {
				return reason, true
			}
			if name == "curl" || name == "wget" {
				sawDownloader = true
			}
		}
		if reason, found := redirectOverwrite(seg); found {
			return reason, true
		}
	}
	return "", false
}

func matchDestructiveRules(name string, args []string) (string, bool) {
	if name == "rm" {
		return rmVerdict(args)
	}
	// mkfs.<fstype> variants beyond the explicit table entries.
	if strings.HasPrefix(name, "mkfs.") {
		return "Format filesystem", true
	}
	rules, ok := destructiveCommands[name]
	if !ok {
		return "", false
	}
	for _, r := range rules {
		if r.match == nil {
			continue
		}
		if r.match(args) {
			return r.reason, true
		}
	}
	return "", false
}

// redirectOverwrite detects `> /etc/passwd`-style truncation of critical
// identity files anywhere in a segment's tokens.
func redirectOverwrite(tokens []string) (string, bool) {
	critical := map[string]string{
		"/etc/passwd": "Overwrite system password file",
		"/etc/shadow": "Overwrite system shadow file",
	}
	for i, tok := range tokens {
		var target string
		switch {
		case tok == ">" || tok == ">>":
			if i+1 < len(tokens) {
				target = tokens[i+1]
			}
		case strings.HasPrefix(tok, ">>"):
			target = tok[2:]
		case strings.HasPrefix(tok, ">"):
			target = tok[1:]
		}
		if target == "" {
			continue
		}
		if reason, ok := critical[strings.ToLower(target)]; ok {
			return reason, true
		}
	}
	return "", false
}

type positionKind int

const (
	positionNone positionKind = iota
	positionCommand
	// positionShellScript is `sh -c '<script>'`; args[0] holds the script.
	positionShellScript
	// positionShellStdin is a bare shell reading a script from stdin.
	positionShellStdin
)

// composeValueFlags are `docker compose` flags that consume a value before the
// subcommand.
var composeValueFlags = map[string]bool{
	"-f": true, "--file": true, "-p": true, "--project-name": true,
	"--project-directory": true, "--env-file": true, "--profile": true,
}

// containerExecTokens returns the inner command tokens of
// `docker|podman|nerdctl exec [flags] NAME CMD...` (and the compose exec/run
// form), so a destructive command inside a container is still inspected. A
// bind-mounted volume makes `docker exec c rm -rf /` destructive on the host.
func containerExecTokens(args []string) ([]string, bool) {
	i := skipFlags(args, 0, containerGlobalValueFlags)
	if i >= len(args) {
		return nil, false
	}
	sub := strings.ToLower(args[i])
	i++
	switch sub {
	case "compose":
		i = skipFlags(args, i, composeValueFlags)
		if i >= len(args) {
			return nil, false
		}
		if s := strings.ToLower(args[i]); s != "exec" && s != "run" {
			return nil, false
		}
		i++
	case "exec":
	default:
		return nil, false
	}
	i = skipFlags(args, i, containerExecValueFlags)
	i++ // container or service name
	if i >= len(args) {
		return nil, false
	}
	return args[i:], true
}

// commandInPosition walks environment assignments and command wrappers to find
// the token that actually executes, mirroring analyzeSegment in validate_sql.go.
func commandInPosition(tokens []string) (string, []string, positionKind) {
	i := 0
	for i < len(tokens) {
		tok := tokens[i]
		if isEnvAssignment(tok) {
			i++
			continue
		}
		name := strings.ToLower(commandBasename(tok))
		if valueFlags, ok := commandWrappers[name]; ok {
			i++
			i = skipFlags(tokens, i, valueFlags)
			if name == "timeout" && i < len(tokens) && looksLikeDuration(tokens[i]) {
				i++
			}
			continue
		}
		if name == "docker" || name == "podman" || name == "nerdctl" {
			if inner, ok := containerExecTokens(tokens[i+1:]); ok {
				tokens = inner
				i = 0
				continue
			}
			return name, tokens[i+1:], positionCommand
		}
		if shellNames[name] {
			if script, ok := shellScriptArg(tokens[i+1:]); ok {
				return name, []string{script}, positionShellScript
			}
			return name, tokens[i+1:], positionShellStdin
		}
		return name, tokens[i+1:], positionCommand
	}
	return "", nil, positionNone
}

// shellScriptArg returns the script passed to a shell via -c (including
// combined flags such as -lc or -ec).
func shellScriptArg(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "--" {
			continue
		}
		if strings.Contains(a[1:], "c") && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}
