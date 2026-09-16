package ros

import (
	"fmt"
	"sort"
	"strings"
)

var staticCommands = []CommandMapping{
	{
		CLIPath:      []string{"raw"},
		Action:       "raw",
		ActionKind:   ActionRaw,
		RouterOSPath: "/<routeros-path>", //nolint:misspell // RouterOS domain placeholder
		SideEffects:  []string{"raw-ros-command"},
		Idempotency:  "unknown",
		Summary:      "Explicitly pass a RouterOS API path plus read-only print options or key=value words for advanced unsupported commands",
		Arguments: []ArgumentSpec{
			{
				Name:        "routeros-path", //nolint:misspell // RouterOS domain argument name
				Style:       "positional",
				Required:    true,
				Type:        "classic-api-path",
				Description: "RouterOS classic API path beginning with `/`, e.g. /system/resource/print",
				Example:     "/system/resource/print",
			},
			{
				Name:        "key=value",
				Style:       "key-value",
				Required:    false,
				Type:        "string",
				Description: "Additional RouterOS API word arguments",
				Example:     "detail=yes",
			},
			{
				Name:        "--allow-write",
				Style:       "flag",
				Required:    false,
				Type:        "bool",
				Description: "Explicitly permit raw commands that mutate RouterOS state (e.g. /ip/address/add)",
				Example:     "--allow-write",
			},
		},
		Examples: []string{
			"sshx ros -h=router raw /system/resource/print --json",
			"sshx ros -h=router raw /interface/print detail --json",
			"sshx ros -h=router raw /ip/address/add address=192.168.88.1/24 interface=ether1 --allow-write",
		},
	},
	{
		CLIPath:      []string{"ip", "dhcp-client"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/dhcp-client/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print DHCP client leases and status",
	},
	{
		CLIPath:      []string{"interface"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/interface/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print network interfaces and properties",
	},
	{
		CLIPath:      []string{"interface", "wireguard"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/interface/wireguard/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print WireGuard interfaces and status",
	},
	{
		CLIPath:      []string{"interface", "wireguard", "peers"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/interface/wireguard/peers/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print configured WireGuard peers",
	},
	{
		CLIPath:      []string{"ip", "address"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/address/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print IPv4 address assignments",
	},
	{
		CLIPath:      []string{"ip", "address"},
		Action:       "add",
		ActionKind:   ActionAdd,
		RouterOSPath: "/ip/address/add",
		SideEffects:  []string{"creates-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Add an IPv4 address assignment to an interface",
		Arguments: []ArgumentSpec{
			{Name: "address", Style: "key-value", Required: true, Type: "cidr", Description: "IPv4 address and netmask (e.g. 192.168.88.1/24)", Example: "192.168.88.1/24"},
			{Name: "interface", Style: "key-value", Required: true, Type: "string", Description: "Name of target interface", Example: "ether1"},
			{Name: "comment", Style: "key-value", Required: false, Type: "string", Description: "Descriptive comment for address record"},
			{Name: "disabled", Style: "key-value", Required: false, Type: "bool", Description: "Whether address assignment is initially disabled"},
			{Name: "network", Style: "key-value", Required: false, Type: "ip", Description: "Network address (calculated automatically if omitted)"},
		},
		Examples: []string{
			"sshx ros -h=router ip address add address=192.168.88.1/24 interface=ether1",
		},
	},
	{
		CLIPath:      []string{"ip", "address"},
		Action:       "set",
		ActionKind:   ActionSet,
		RouterOSPath: "/ip/address/set",
		SideEffects:  []string{"updates-ros-record"},
		Idempotency:  "idempotent",
		Summary:      "Modify an existing IPv4 address assignment",
		Arguments: []ArgumentSpec{
			{Name: "numbers", Style: "key-value", Required: true, Type: "string", Description: "Target item index or ID (.id)", Example: "*1 or 0"},
			{Name: "address", Style: "key-value", Required: false, Type: "cidr", Description: "Updated IPv4 address and netmask"},
			{Name: "interface", Style: "key-value", Required: false, Type: "string", Description: "Updated target interface"},
			{Name: "disabled", Style: "key-value", Required: false, Type: "bool", Description: "Enable or disable address assignment"},
			{Name: "comment", Style: "key-value", Required: false, Type: "string", Description: "Updated comment"},
		},
	},
	{
		CLIPath:      []string{"ip", "address"},
		Action:       "remove",
		ActionKind:   ActionRemove,
		RouterOSPath: "/ip/address/remove",
		SideEffects:  []string{"deletes-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Remove an IPv4 address assignment",
		Arguments: []ArgumentSpec{
			{Name: "numbers", Style: "key-value", Required: true, Type: "string", Description: "Target item index or ID (.id)", Example: "*1 or 0"},
		},
	},
	{
		CLIPath:      []string{"ip", "firewall", "address-list"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/firewall/address-list/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print firewall address-list entries",
	},
	{
		CLIPath:      []string{"ip", "firewall", "filter"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/firewall/filter/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print firewall filter rules",
	},
	{
		CLIPath:      []string{"ip", "firewall", "filter"},
		Action:       "add",
		ActionKind:   ActionAdd,
		RouterOSPath: "/ip/firewall/filter/add",
		SideEffects:  []string{"creates-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Add a firewall filter rule",
		Arguments: []ArgumentSpec{
			{Name: "chain", Style: "key-value", Required: true, Type: "string", Description: "Firewall chain (e.g. input, forward, output)", Example: "input"},
			{Name: "action", Style: "key-value", Required: true, Type: "string", Description: "Filter action (accept, drop, reject, etc.)", Example: "accept"},
			{Name: "src-address", Style: "key-value", Required: false, Type: "string", Description: "Source IP address or CIDR"},
			{Name: "dst-address", Style: "key-value", Required: false, Type: "string", Description: "Destination IP address or CIDR"},
			{Name: "protocol", Style: "key-value", Required: false, Type: "string", Description: "IP protocol (tcp, udp, icmp, etc.)"},
			{Name: "dst-port", Style: "key-value", Required: false, Type: "string", Description: "Destination port"},
			{Name: "comment", Style: "key-value", Required: false, Type: "string", Description: "Descriptive comment"},
		},
	},
	{
		CLIPath:      []string{"ip", "firewall", "filter"},
		Action:       "set",
		ActionKind:   ActionSet,
		RouterOSPath: "/ip/firewall/filter/set",
		SideEffects:  []string{"updates-ros-record"},
		Idempotency:  "idempotent",
		Summary:      "Modify an existing firewall filter rule",
	},
	{
		CLIPath:      []string{"ip", "firewall", "filter"},
		Action:       "remove",
		ActionKind:   ActionRemove,
		RouterOSPath: "/ip/firewall/filter/remove",
		SideEffects:  []string{"deletes-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Remove a firewall filter rule",
	},
	{
		CLIPath:      []string{"ip", "firewall", "nat"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/firewall/nat/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print firewall NAT rules",
	},
	{
		CLIPath:      []string{"ip", "firewall", "nat"},
		Action:       "add",
		ActionKind:   ActionAdd,
		RouterOSPath: "/ip/firewall/nat/add",
		SideEffects:  []string{"creates-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Add a firewall NAT rule",
	},
	{
		CLIPath:      []string{"ip", "firewall", "nat"},
		Action:       "set",
		ActionKind:   ActionSet,
		RouterOSPath: "/ip/firewall/nat/set",
		SideEffects:  []string{"updates-ros-record"},
		Idempotency:  "idempotent",
		Summary:      "Modify a firewall NAT rule",
	},
	{
		CLIPath:      []string{"ip", "firewall", "nat"},
		Action:       "remove",
		ActionKind:   ActionRemove,
		RouterOSPath: "/ip/firewall/nat/remove",
		SideEffects:  []string{"deletes-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Remove a firewall NAT rule",
	},
	{
		CLIPath:      []string{"ip", "firewall", "mangle"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/firewall/mangle/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print firewall packet mangle rules",
	},
	{
		CLIPath:      []string{"ip", "firewall", "connection"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/firewall/connection/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print active firewall connections tracking table",
	},
	{
		CLIPath:      []string{"ip", "route"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/ip/route/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print IPv4 routing table entries",
	},
	{
		CLIPath:      []string{"ip", "route"},
		Action:       "add",
		ActionKind:   ActionAdd,
		RouterOSPath: "/ip/route/add",
		SideEffects:  []string{"creates-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Add a route to the routing table",
		Arguments: []ArgumentSpec{
			{Name: "dst-address", Style: "key-value", Required: true, Type: "cidr", Description: "Destination network or host", Example: "0.0.0.0/0"},
			{Name: "gateway", Style: "key-value", Required: true, Type: "string", Description: "Gateway IP or interface", Example: "192.168.88.254"},
			{Name: "distance", Style: "key-value", Required: false, Type: "int", Description: "Administrative distance"},
			{Name: "comment", Style: "key-value", Required: false, Type: "string", Description: "Descriptive comment"},
		},
	},
	{
		CLIPath:      []string{"ip", "route"},
		Action:       "set",
		ActionKind:   ActionSet,
		RouterOSPath: "/ip/route/set",
		SideEffects:  []string{"updates-ros-record"},
		Idempotency:  "idempotent",
		Summary:      "Modify an existing route",
	},
	{
		CLIPath:      []string{"ip", "route"},
		Action:       "remove",
		ActionKind:   ActionRemove,
		RouterOSPath: "/ip/route/remove",
		SideEffects:  []string{"deletes-ros-record"},
		Idempotency:  "not-idempotent",
		Summary:      "Remove an entry from the routing table",
	},
	{
		CLIPath:      []string{"system", "resource"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/system/resource/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print system resource usage (CPU, memory, uptime, version)",
	},
	{
		CLIPath:      []string{"system", "routerboard"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/system/routerboard/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print RouterBOARD hardware model and firmware information",
	},
	{
		CLIPath:      []string{"system", "package"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/system/package/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print installed RouterOS package bundles and versions",
	},
	{
		CLIPath:      []string{"system", "script"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/system/script/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print installed RouterOS scripts",
	},
	{
		CLIPath:      []string{"system", "script"},
		Action:       "add",
		ActionKind:   ActionAdd,
		RouterOSPath: "/system/script/add",
		SideEffects:  []string{"creates-ros-script"},
		Idempotency:  "not-idempotent",
		Summary:      "Add or install a script in /system/script",
		Arguments: []ArgumentSpec{
			{Name: "name", Style: "key-value", Required: true, Type: "string", Description: "Unique name of the script"},
			{Name: "source", Style: "key-value", Required: true, Type: "string", Description: "Script source text"},
			{Name: "owner", Style: "key-value", Required: false, Type: "string", Description: "Script owner"},
		},
	},
	{
		CLIPath:      []string{"tool", "mac-server"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/tool/mac-server/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print MAC server interface configuration",
	},
	{
		CLIPath:      []string{"tool", "netwatch"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/tool/netwatch/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print netwatch host monitoring entries",
	},
	{
		CLIPath:      []string{"user"},
		Action:       "print",
		ActionKind:   ActionPrint,
		RouterOSPath: "/user/print",
		SideEffects:  nil,
		Idempotency:  "read-only",
		Summary:      "Print RouterOS user accounts",
	},
}

// AllCommands returns the complete slice of statically registered commands.
func AllCommands() []CommandMapping {
	res := make([]CommandMapping, len(staticCommands))
	copy(res, staticCommands)
	return res
}

// LookupCommand searches for a matching static command mapping.
func LookupCommand(path []string, action string) (*CommandMapping, bool) {
	// Handle raw special cases (e.g. `raw`, `help raw`, `schema raw`, `schema command raw`)
	if (len(path) == 0 && strings.EqualFold(action, "raw")) ||
		(len(path) == 1 && strings.EqualFold(path[0], "raw")) ||
		(len(path) == 1 && strings.EqualFold(path[0], "command") && strings.EqualFold(action, "raw")) {
		for i := range staticCommands {
			if staticCommands[i].IsRaw() {
				return &staticCommands[i], true
			}
		}
	}

	for i := range staticCommands {
		cmd := &staticCommands[i]
		if slicesEqual(cmd.CLIPath, path) && strings.EqualFold(cmd.Action, action) {
			return cmd, true
		}
	}
	return nil, false
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// ParseInvocation processes raw CLI tokens into a ROSRequest.
func ParseInvocation(tokens []string) (*ROSRequest, error) {
	if len(tokens) == 0 {
		return nil, NewUsageError("missing RouterOS command", "run `sshx ros help` or `sshx ros commands` to list available commands")
	}

	// Handle `raw` command or direct RouterOS CLI path starting with '/' or ':'
	isRaw := tokens[0] == "raw" || strings.HasPrefix(tokens[0], "/") || strings.HasPrefix(tokens[0], ":")
	if isRaw {
		rawTokenIndex := 0
		if tokens[0] == "raw" {
			if len(tokens) < 2 {
				return nil, NewUsageError(
					"raw command requires a RouterOS API path, e.g. sshx ros raw /system/resource/print --json",
					"pass a RouterOS path starting with `/`",
				)
			}
			rawTokenIndex = 1
		}

		rawPath := strings.TrimSpace(tokens[rawTokenIndex])
		var restTokens []string
		if strings.Contains(rawPath, " ") {
			fields := strings.Fields(rawPath)
			rawPath = fields[0]
			restTokens = append(fields[1:], tokens[rawTokenIndex+1:]...)
		} else {
			restTokens = tokens[rawTokenIndex+1:]
		}

		if !strings.HasPrefix(rawPath, "/") && !strings.HasPrefix(rawPath, ":") {
			rawPath = "/" + rawPath
		}

		args := make(map[string]string)
		var flags []string
		for _, tok := range restTokens {
			if strings.Contains(tok, "=") {
				kv := strings.SplitN(tok, "=", 2)
				args[kv[0]] = kv[1]
			} else {
				flags = append(flags, tok)
			}
		}

		// Determine action kind from rawPath
		actionKind := ActionRaw
		parts := strings.Split(strings.Trim(rawPath, "/"), "/")
		if len(parts) > 0 {
			last := strings.ToLower(parts[len(parts)-1])
			switch last {
			case "print":
				actionKind = ActionPrint
			case "add":
				actionKind = ActionAdd
			case "set":
				actionKind = ActionSet
			case "remove", "del", "delete":
				actionKind = ActionRemove
			}
		}

		isPrint := actionKind == ActionPrint
		idempotency := "unknown"
		var sideEffects []string
		if isPrint {
			idempotency = "read-only"
		} else {
			sideEffects = []string{"raw-ros-command"}
		}

		return &ROSRequest{
			Path:       []string{"raw"},
			Action:     "raw",
			RawCommand: rawPath,
			Args:       args,
			Flags:      flags,
			Mapping: &CommandMapping{
				CLIPath:      []string{"raw"},
				Action:       "raw",
				ActionKind:   actionKind,
				RouterOSPath: rawPath,
				SideEffects:  sideEffects,
				Idempotency:  idempotency,
				Summary:      "Raw RouterOS command: " + rawPath,
			},
		}, nil
	}

	// Parse tokens: collect path words, then action, then arguments and flags.
	// Common action verbs: print, add, set, remove, get, export, monitor
	knownActions := map[string]ActionKind{
		"print":   ActionPrint,
		"add":     ActionAdd,
		"set":     ActionSet,
		"remove":  ActionRemove,
		"del":     ActionRemove,
		"delete":  ActionRemove,
		"get":     ActionPrint,
		"monitor": ActionPrint,
		"export":  ActionPrint,
	}

	var path []string
	var action string
	actionIdx := -1

	// If the first token starts with '/', it's a direct RouterOS path, e.g. `/ip/address/print` or `/ip address print`
	if strings.HasPrefix(tokens[0], "/") {
		trimmed := strings.TrimPrefix(tokens[0], "/")
		parts := strings.Split(trimmed, "/")
		if len(parts) > 1 {
			last := parts[len(parts)-1]
			if _, ok := knownActions[last]; ok {
				path = parts[:len(parts)-1]
				action = last
				actionIdx = 0
			} else {
				path = parts
			}
		} else {
			path = parts
		}
	}

	if action == "" {
		for i, tok := range tokens {
			if strings.Contains(tok, "=") {
				// We hit key=value arguments
				break
			}
			if strings.HasPrefix(tok, "-") {
				// We hit a flag
				break
			}
			if _, ok := knownActions[strings.ToLower(tok)]; ok {
				action = strings.ToLower(tok)
				actionIdx = i
				break
			}
			path = append(path, tok)
		}
	}

	if action == "" {
		// Default to "print" if only a path was specified
		action = "print"
	}

	// Parse remaining tokens as arguments (key=value) or flags
	args := make(map[string]string)
	var flags []string
	startIndex := actionIdx + 1
	if actionIdx == -1 {
		startIndex = len(path)
	}

	for i := startIndex; i < len(tokens); i++ {
		tok := tokens[i]
		if strings.Contains(tok, "=") {
			k, v, _ := strings.Cut(tok, "=")
			args[strings.TrimSpace(k)] = strings.TrimSpace(v)
		} else {
			flags = append(flags, tok)
		}
	}

	req := &ROSRequest{
		Path:   path,
		Action: action,
		Args:   args,
		Flags:  flags,
	}

	// Look up mapping in static catalog
	if mapping, found := LookupCommand(path, action); found {
		req.Mapping = mapping
		// Validate required arguments if any
		for _, argSpec := range mapping.Arguments {
			if argSpec.Required {
				if _, ok := args[argSpec.Name]; !ok {
					return nil, NewUsageError(
						fmt.Sprintf("missing required argument %q for command %s %s", argSpec.Name, strings.Join(path, " "), action),
						fmt.Sprintf("pass %s=<value>", argSpec.Name),
					)
				}
			}
		}
	} else {
		// Dynamic mapping for valid unlisted RouterOS CLI path
		actionKind := ActionRaw
		if k, ok := knownActions[action]; ok {
			actionKind = k
		}
		rosPath := "/" + strings.Join(path, "/") + "/" + action
		req.Mapping = &CommandMapping{
			CLIPath:      path,
			Action:       action,
			ActionKind:   actionKind,
			RouterOSPath: rosPath,
			SideEffects:  nil,
			Idempotency:  "unknown",
			Summary:      "RouterOS command: " + rosPath,
		}
	}

	return req, nil
}

// BuildRouterOSCommand formats the RouterOS CLI command line string to be executed over SSH.
func BuildRouterOSCommand(req *ROSRequest) string {
	if req.Mapping != nil && req.Mapping.IsRaw() {
		var sb strings.Builder
		rawCmd := strings.TrimSpace(req.RawCommand)
		if rawCmd == "" {
			rawCmd = req.Action
		}
		if !strings.HasPrefix(rawCmd, "/") && !strings.HasPrefix(rawCmd, ":") {
			rawCmd = "/" + rawCmd
		}
		sb.WriteString(rawCmd)

		for _, flag := range req.Flags {
			sb.WriteString(" ")
			sb.WriteString(flag)
		}

		if len(req.Args) > 0 {
			keys := make([]string, 0, len(req.Args))
			for k := range req.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := req.Args[k]
				sb.WriteString(" ")
				if strings.Contains(v, " ") && !strings.HasPrefix(v, "\"") {
					fmt.Fprintf(&sb, "%s=%q", k, v)
				} else {
					fmt.Fprintf(&sb, "%s=%s", k, v)
				}
			}
		}

		if req.Mapping.ActionKind == ActionPrint {
			lower := strings.ToLower(sb.String())
			if !strings.Contains(lower, "without-paging") {
				sb.WriteString(" without-paging")
			}
		}

		return sb.String()
	}

	var sb strings.Builder
	sb.WriteString("/")
	sb.WriteString(strings.Join(req.Path, " "))
	sb.WriteString(" ")
	sb.WriteString(req.Action)

	// Add key=value arguments in deterministic sorted order
	if len(req.Args) > 0 {
		keys := make([]string, 0, len(req.Args))
		for k := range req.Args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := req.Args[k]
			sb.WriteString(" ")
			if strings.Contains(v, " ") && !strings.HasPrefix(v, "\"") {
				fmt.Fprintf(&sb, "%s=%q", k, v)
			} else {
				fmt.Fprintf(&sb, "%s=%s", k, v)
			}
		}
	}

	// Add flags
	for _, flag := range req.Flags {
		sb.WriteString(" ")
		sb.WriteString(flag)
	}

	// If print command and without-paging is not already present, append without-paging
	if req.Action == "print" {
		hasPagingFlag := false
		for _, f := range req.Flags {
			if strings.EqualFold(f, "without-paging") {
				hasPagingFlag = true
				break
			}
		}
		if !hasPagingFlag {
			sb.WriteString(" without-paging")
		}
	}

	return sb.String()
}
