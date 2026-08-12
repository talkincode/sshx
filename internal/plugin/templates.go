package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type CreateOptions struct {
	ID        string
	Runner    string
	Platform  string
	Privilege string
	Template  string
	Replace   bool
}

type CreateResult struct {
	Resolved   *Resolved
	Files      []string
	BackupPath string
}

func Create(options CreateOptions) (*CreateResult, error) {
	if err := ValidateID(options.ID); err != nil {
		return nil, err
	}
	if _, builtin := resolveBuiltin(options.ID); builtin {
		return nil, fmt.Errorf("plugin id %q is reserved by a built-in capability", options.ID)
	}
	if options.Runner == "" {
		options.Runner = "sh"
	}
	if options.Platform == "" {
		options.Platform = "linux"
	}
	if options.Privilege == "" {
		options.Privilege = "never"
	}
	if options.Template == "" {
		options.Template = "generic"
	}
	if options.Runner != "sh" {
		return nil, fmt.Errorf("plugin create currently supports only --runner=sh")
	}
	if options.Platform != "linux" && options.Platform != "darwin" {
		return nil, fmt.Errorf("sh plugins support --platform=linux or darwin")
	}
	if options.Privilege != "never" && options.Privilege != "optional" && options.Privilege != "required" {
		return nil, fmt.Errorf("invalid privilege policy %q", options.Privilege)
	}
	if options.Template != "generic" && options.Template != "docker" && options.Template != "nginx" {
		return nil, fmt.Errorf("unknown plugin template %q", options.Template)
	}

	root, rootErr := Root()
	if rootErr != nil {
		return nil, rootErr
	}
	if mkdirErr := os.MkdirAll(root, 0o700); mkdirErr != nil {
		return nil, fmt.Errorf("create plugin root: %w", mkdirErr)
	}
	if chmodErr := os.Chmod(root, 0o700); chmodErr != nil { // #nosec G302 -- private directory requires owner traversal.
		return nil, fmt.Errorf("secure plugin root: %w", chmodErr)
	}
	target := filepath.Join(root, options.ID)
	var backupPath string
	if _, lstatErr := os.Lstat(target); lstatErr == nil {
		if !options.Replace {
			return nil, fmt.Errorf("plugin %q already exists; use --replace to preserve it as a backup", options.ID)
		}
		var backupErr error
		backupPath, backupErr = backupExisting(target, options.ID)
		if backupErr != nil {
			return nil, backupErr
		}
	} else if !os.IsNotExist(lstatErr) {
		return nil, fmt.Errorf("inspect existing plugin: %w", lstatErr)
	}

	tempDir, tempErr := os.MkdirTemp(root, ".create-"+options.ID+"-*")
	if tempErr != nil {
		return nil, fmt.Errorf("create temporary plugin: %w", tempErr)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tempDir) //nolint:errcheck // best-effort cleanup inside constrained plugin root
		}
	}()
	if chmodErr := os.Chmod(tempDir, 0o700); chmodErr != nil { // #nosec G302 -- private directory requires owner traversal.
		return nil, chmodErr
	}

	manifest := templateManifest(options)
	manifestData, marshalErr := json.MarshalIndent(manifest, "", "  ")
	if marshalErr != nil {
		return nil, marshalErr
	}
	files := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		ManifestFile:               {append(manifestData, '\n'), 0o600},
		manifest.Runner.Entrypoint: {[]byte(templateCollector(options.Template)), 0o700},
		manifest.Output.Schema:     {[]byte(resultSchema), 0o600},
		"README.md":                {[]byte(templateReadme(options)), 0o600},
		"fixtures/complete.json":   {[]byte(completeFixture), 0o600},
		"fixtures/partial.json":    {[]byte(partialFixture), 0o600},
	}
	written := make([]string, 0, len(files))
	for relative, file := range files {
		filePath, pathErr := safeChild(tempDir, relative)
		if pathErr != nil {
			return nil, pathErr
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(filePath), 0o700); mkdirErr != nil {
			return nil, mkdirErr
		}
		if writeErr := os.WriteFile(filePath, file.data, file.mode); writeErr != nil { // #nosec G306 -- restrictive modes are intentional.
			return nil, fmt.Errorf("write %s: %w", relative, writeErr)
		}
		written = append(written, relative)
	}
	if renameErr := os.Rename(tempDir, target); renameErr != nil {
		return nil, fmt.Errorf("install plugin: %w", renameErr)
	}
	cleanup = false
	sort.Strings(written)
	resolved, resolveErr := Resolve(options.ID)
	if resolveErr != nil {
		return nil, fmt.Errorf("validate created plugin: %w", resolveErr)
	}
	return &CreateResult{Resolved: resolved, Files: written, BackupPath: backupPath}, nil
}

func Remove(id string) (string, error) {
	if _, builtin := resolveBuiltin(id); builtin {
		return "", fmt.Errorf("built-in capability %q cannot be removed", id)
	}
	pluginPath, pathErr := Path(id)
	if pathErr != nil {
		return "", pathErr
	}
	if _, lstatErr := os.Lstat(pluginPath); lstatErr != nil {
		if os.IsNotExist(lstatErr) {
			return "", fmt.Errorf("plugin %q not found", id)
		}
		return "", lstatErr
	}
	backup, backupErr := backupExisting(pluginPath, id)
	if backupErr != nil {
		return "", backupErr
	}
	lock, lockErr := loadLock()
	if lockErr != nil {
		return "", lockErr
	}
	delete(lock.Plugins, id)
	if saveErr := saveLock(lock); saveErr != nil {
		return "", saveErr
	}
	return backup, nil
}

func backupExisting(source, id string) (string, error) {
	root, err := runtimeRoot()
	if err != nil {
		return "", err
	}
	backupRoot := filepath.Join(root, "plugin-backups")
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return "", fmt.Errorf("create plugin backup directory: %w", err)
	}
	backup := filepath.Join(backupRoot, fmt.Sprintf("%s-%s", id, time.Now().UTC().Format("20060102T150405.000000000Z")))
	if err := os.Rename(source, backup); err != nil {
		return "", fmt.Errorf("preserve existing plugin: %w", err)
	}
	return backup, nil
}

func runtimeRoot() (string, error) {
	plugins, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Dir(plugins), nil
}

func templateManifest(options CreateOptions) Manifest {
	description := "Custom host inspection capability"
	required := []string{}
	cacheTTL := "15m"
	hardMax := "1h"
	switch options.Template {
	case "docker":
		description = "Inspect a Docker and Compose deployment without collecting secrets"
		required = []string{"docker"}
		cacheTTL = "10m"
	case "nginx":
		description = "Inspect Nginx installation and runtime metadata without reading configuration contents"
		required = []string{"nginx"}
	}
	return Manifest{
		APIVersion:       SchemaVersion,
		ID:               options.ID,
		Version:          "0.1.0",
		Kind:             "inspect",
		Description:      description,
		Platforms:        []string{options.Platform},
		Runner:           Runner{Type: options.Runner, Entrypoint: "collectors/" + options.Platform + ".sh"},
		RequiredCommands: required,
		Privilege:        options.Privilege,
		Timeout:          "30s",
		Effects:          []string{"remote.read"},
		Output:           OutputContract{Schema: "result.schema.json"},
		Cache:            CachePolicy{RecommendedTTL: cacheTTL, HardMaxAge: hardMax},
		Redaction: RedactionPolicy{DenyFields: []string{
			"authorization", "cookie", "credentials", "env", "password", "private_key", "secret", "token",
		}},
	}
}

func templateCollector(template string) string {
	switch template {
	case "docker":
		return dockerCollector
	case "nginx":
		return nginxCollector
	default:
		return genericCollector
	}
}

func templateReadme(options CreateOptions) string {
	return fmt.Sprintf(`# %s

This directory is owned by sshx under its local runtime root. Agent skills do
not own or embed this collector.

Validate and trust the current digest before remote use:

`+"```text"+`
sshx plugin validate %s --json
sshx plugin test %s --fixture=complete --json
sshx plugin trust %s --json
sshx inspect -h=<host> %s --json
`+"```"+`

The collector must write exactly one JSON document to stdout. Diagnostics may
go to stderr. Do not emit environment variables, credentials, raw application
configuration, registry auth, cookies, tokens, or secrets.
`, options.ID, options.ID, options.ID, options.ID, options.ID)
}

const resultSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["status", "facts", "evidence", "errors"],
  "properties": {
    "status": {"enum": ["complete", "partial", "unsupported", "failed"]},
    "facts": {"type": "object"},
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "source"],
        "properties": {
          "kind": {"enum": ["direct", "inferred"]},
          "source": {"type": "string", "minLength": 1}
        }
      }
    },
    "errors": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind"],
        "properties": {
          "kind": {"type": "string", "minLength": 1},
          "section": {"type": "string"},
          "message": {"type": "string"}
        }
      }
    }
  }
}
`

const completeFixture = `{
  "status": "complete",
  "facts": {"present": true},
  "evidence": [{"kind": "direct", "source": "fixture"}],
  "errors": []
}
`

const partialFixture = `{
  "status": "partial",
  "facts": {"present": true},
  "evidence": [{"kind": "direct", "source": "fixture"}],
  "errors": [{"kind": "permission_denied", "section": "runtime"}]
}
`

const genericCollector = `#!/bin/sh
set -eu
printf '%s\n' '{"status":"complete","facts":{"present":true},"evidence":[{"kind":"direct","source":"custom collector"}],"errors":[]}'
`

const dockerCollector = `#!/bin/sh
set -eu

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' '{"status":"complete","facts":{"present":false},"evidence":[{"kind":"direct","source":"command -v docker"}],"errors":[]}'
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  printf '%s\n' '{"status":"partial","facts":{"present":true,"daemon_accessible":false},"evidence":[{"kind":"direct","source":"docker info"}],"errors":[{"kind":"permission_or_daemon_unavailable","section":"docker_api"}]}'
  exit 0
fi

tmp_dir="${TMPDIR:-/tmp}/sshx-docker-$$"
mkdir -m 700 "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

docker version --format '{"client":{{json .Client.Version}},"server":{{json .Server.Version}}}' >"$tmp_dir/version.json"
docker info --format '{"docker_root_dir":{{json .DockerRootDir}},"storage_driver":{{json .Driver}},"cgroup_driver":{{json .CgroupDriver}},"server_version":{{json .ServerVersion}},"rootless":{{json .SecurityOptions}}}' >"$tmp_dir/info.json"

rootless=false
if grep -qi 'rootless' "$tmp_dir/info.json"; then
  rootless=true
fi

: >"$tmp_dir/containers.lines"
for container_id in $(docker ps -aq --no-trunc); do
  docker inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"state":{{json .State.Status}},"restart_count":{{json .RestartCount}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}},"mounts":{{json .Mounts}},"compose":{"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"working_dir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},"config_files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}}}}' "$container_id" >>"$tmp_dir/containers.lines"
done

if [ -s "$tmp_dir/containers.lines" ]; then
  containers=$(awk 'BEGIN { printf "[" } NR > 1 { printf "," } { printf "%s", $0 } END { print "]" }' "$tmp_dir/containers.lines")
else
  containers='[]'
fi

docker image ls --no-trunc --format '{"id":{{json .ID}},"repository":{{json .Repository}},"tag":{{json .Tag}},"digest":{{json .Digest}},"size":{{json .Size}}}' >"$tmp_dir/images.lines"
docker network ls --no-trunc --format '{"id":{{json .ID}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}}}' >"$tmp_dir/networks.lines"
docker volume ls --format '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}}}' >"$tmp_dir/volumes.lines"

json_lines_array() {
  if [ -s "$1" ]; then
    awk 'BEGIN { printf "[" } NR > 1 { printf "," } { printf "%s", $0 } END { print "]" }' "$1"
  else
    printf '[]'
  fi
}

images=$(json_lines_array "$tmp_dir/images.lines")
networks=$(json_lines_array "$tmp_dir/networks.lines")
volumes=$(json_lines_array "$tmp_dir/volumes.lines")

printf '{"status":"complete","facts":{"present":true,"daemon_accessible":true,"rootless":%s,"version":' "$rootless"
cat "$tmp_dir/version.json"
printf ',"info":'
cat "$tmp_dir/info.json"
printf ',"containers":%s,"images":%s,"networks":%s,"volumes":%s},"evidence":[{"kind":"direct","source":"docker version/info/ps/inspect/image/network/volume"}],"errors":[]}\n' "$containers" "$images" "$networks" "$volumes"
`

const nginxCollector = `#!/bin/sh
set -eu
if ! command -v nginx >/dev/null 2>&1; then
  printf '%s\n' '{"status":"complete","facts":{"present":false},"evidence":[{"kind":"direct","source":"command -v nginx"}],"errors":[]}'
  exit 0
fi
version=$(nginx -v 2>&1 | sed 's/^[^:]*: //')
state="unknown"
if command -v systemctl >/dev/null 2>&1; then
  state=$(systemctl is-active nginx 2>/dev/null || true)
fi
escaped_version=$(printf '%s' "$version" | sed 's/\\/\\\\/g; s/"/\\"/g')
escaped_state=$(printf '%s' "$state" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '{"status":"complete","facts":{"present":true,"version":"%s","service_state":"%s"},"evidence":[{"kind":"direct","source":"nginx -v/systemctl"}],"errors":[]}\n' "$escaped_version" "$escaped_state"
`

func CurrentPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}

func FixturePath(resolved *Resolved, fixture string) (string, error) {
	if resolved.Builtin {
		return "", fmt.Errorf("built-in capability fixtures are compiled into sshx")
	}
	if fixture == "" {
		fixture = "complete"
	}
	if strings.ContainsAny(fixture, `/\\`) || fixture == "." || fixture == ".." {
		return "", fmt.Errorf("invalid fixture name %q", fixture)
	}
	return safeChild(resolved.Path, filepath.Join("fixtures", fixture+".json"))
}
