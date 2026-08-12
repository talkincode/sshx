package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/talkincode/sshx/internal/runtimepath"
)

var (
	pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	versionPattern  = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
)

func ValidateID(id string) error {
	if !pluginIDPattern.MatchString(id) {
		return fmt.Errorf("invalid plugin id %q: use lowercase letters, digits, dots, underscores, or hyphens", id)
	}
	return nil
}

func Root() (string, error) { return runtimepath.Plugins() }

func Path(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, id), nil
}

func Resolve(id string) (*Resolved, error) {
	if builtin, ok := resolveBuiltin(id); ok {
		return builtin, nil
	}
	pluginPath, err := Path(id)
	if err != nil {
		return nil, err
	}
	return loadFromPath(pluginPath, id)
}

func loadFromPath(pluginPath, expectedID string) (*Resolved, error) {
	pluginRoot := filepath.Dir(pluginPath)
	rootInfo, rootErr := os.Lstat(pluginRoot)
	if rootErr != nil {
		if os.IsNotExist(rootErr) {
			return nil, fmt.Errorf("plugin %q not found", expectedID)
		}
		return nil, fmt.Errorf("inspect plugin root: %w", rootErr)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("plugin root must be a real directory not writable by group or others: %s", pluginRoot)
	}
	info, statErr := os.Lstat(pluginPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, fmt.Errorf("plugin %q not found", expectedID)
		}
		return nil, fmt.Errorf("inspect plugin path: %w", statErr)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("plugin path must be a real directory: %s", pluginPath)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("plugin directory has unsafe permissions %04o", info.Mode().Perm())
	}

	manifestPath := filepath.Join(pluginPath, ManifestFile)
	manifestBytes, manifestReadErr := readRegularFile(manifestPath, MaxManifest, 0o077)
	if manifestReadErr != nil {
		return nil, fmt.Errorf("read manifest: %w", manifestReadErr)
	}
	var manifest Manifest
	if decodeErr := decodeStrictJSON(manifestBytes, &manifest); decodeErr != nil {
		return nil, fmt.Errorf("parse manifest: %w", decodeErr)
	}
	if manifestErr := validateManifest(manifest, expectedID); manifestErr != nil {
		return nil, manifestErr
	}

	entrypointPath, entrypointPathErr := safeChild(pluginPath, manifest.Runner.Entrypoint)
	if entrypointPathErr != nil {
		return nil, fmt.Errorf("entrypoint: %w", entrypointPathErr)
	}
	collector, collectorErr := readRegularFile(entrypointPath, MaxCollector, 0o022)
	if collectorErr != nil {
		return nil, fmt.Errorf("read entrypoint: %w", collectorErr)
	}
	schemaPath, schemaPathErr := safeChild(pluginPath, manifest.Output.Schema)
	if schemaPathErr != nil {
		return nil, fmt.Errorf("result schema: %w", schemaPathErr)
	}
	schemaBytes, schemaReadErr := readRegularFile(schemaPath, MaxSchema, 0o022)
	if schemaReadErr != nil {
		return nil, fmt.Errorf("read result schema: %w", schemaReadErr)
	}
	var schemaDoc any
	if decodeErr := decodeSingleJSON(schemaBytes, &schemaDoc); decodeErr != nil {
		return nil, fmt.Errorf("parse result schema: %w", decodeErr)
	}
	if _, schemaErr := compileSchema(schemaDoc); schemaErr != nil {
		return nil, fmt.Errorf("compile result schema: %w", schemaErr)
	}

	digest := calculateDigest(manifestBytes, []byte(manifest.Runner.Entrypoint), collector, []byte(manifest.Output.Schema), schemaBytes)
	trusted, trustErr := isTrusted(manifest.ID, digest)
	if trustErr != nil {
		return nil, trustErr
	}
	return &Resolved{
		Manifest:  manifest,
		Path:      pluginPath,
		Digest:    digest,
		Trusted:   trusted,
		Builtin:   false,
		Collector: collector,
		Schema:    schemaDoc,
	}, nil
}

func validateManifest(manifest Manifest, expectedID string) error {
	if manifest.APIVersion != SchemaVersion {
		return fmt.Errorf("unsupported api_version %q", manifest.APIVersion)
	}
	if err := ValidateID(manifest.ID); err != nil {
		return err
	}
	if expectedID != "" && manifest.ID != expectedID {
		return fmt.Errorf("manifest id %q does not match plugin directory %q", manifest.ID, expectedID)
	}
	if !versionPattern.MatchString(manifest.Version) {
		return fmt.Errorf("invalid plugin version %q", manifest.Version)
	}
	if manifest.Kind != "inspect" {
		return fmt.Errorf("unsupported plugin kind %q", manifest.Kind)
	}
	if len(manifest.Platforms) == 0 {
		return fmt.Errorf("at least one target platform is required")
	}
	seenPlatforms := map[string]bool{}
	for _, platform := range manifest.Platforms {
		if platform != "linux" && platform != "darwin" {
			return fmt.Errorf("unsupported target platform %q", platform)
		}
		if seenPlatforms[platform] {
			return fmt.Errorf("duplicate target platform %q", platform)
		}
		seenPlatforms[platform] = true
	}
	if manifest.Runner.Type != "sh" {
		return fmt.Errorf("unsupported runner type %q", manifest.Runner.Type)
	}
	if manifest.Runner.Entrypoint == "" {
		return fmt.Errorf("runner entrypoint is required")
	}
	if manifest.Privilege != "never" && manifest.Privilege != "optional" && manifest.Privilege != "required" {
		return fmt.Errorf("invalid privilege policy %q", manifest.Privilege)
	}
	timeout, err := time.ParseDuration(manifest.Timeout)
	if err != nil || timeout <= 0 {
		return fmt.Errorf("invalid positive timeout %q", manifest.Timeout)
	}
	if timeout > 10*time.Minute {
		return fmt.Errorf("plugin timeout exceeds hard limit of 10m")
	}
	if len(manifest.Effects) != 1 || manifest.Effects[0] != "remote.read" {
		return fmt.Errorf("inspect plugins must declare exactly the remote.read effect")
	}
	if manifest.Output.Schema == "" {
		return fmt.Errorf("output schema is required")
	}
	recommended, err := time.ParseDuration(manifest.Cache.RecommendedTTL)
	if err != nil || recommended <= 0 {
		return fmt.Errorf("invalid positive recommended_ttl %q", manifest.Cache.RecommendedTTL)
	}
	hardMax, err := time.ParseDuration(manifest.Cache.HardMaxAge)
	if err != nil || hardMax < recommended {
		return fmt.Errorf("hard_max_age must be a duration no shorter than recommended_ttl")
	}
	for _, field := range manifest.Redaction.DenyFields {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("redaction deny_fields may not contain empty values")
		}
	}
	return nil
}

func safeChild(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path must be relative")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes plugin directory")
	}
	full := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes plugin directory")
	}
	current := root
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("path contains symlink %s", current)
		}
	}
	return full, nil
}

func readRegularFile(path string, limit int64, forbiddenPerm os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, limit)
	}
	if info.Mode().Perm()&forbiddenPerm != 0 {
		return nil, fmt.Errorf("%s has unsafe permissions %04o", path, info.Mode().Perm())
	}
	file, err := os.Open(path) // #nosec G304 -- path is constrained below the sshx plugin root.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only cleanup
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, limit)
	}
	return data, nil
}

func decodeStrictJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func decodeSingleJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON documents are not allowed")
	}
	return err
}

func compileSchema(schemaDoc any) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("sshx-plugin-result.json", schemaDoc); err != nil {
		return nil, err
	}
	return compiler.Compile("sshx-plugin-result.json")
}

func ValidateResult(resolved *Resolved, data []byte) (Result, error) {
	if len(data) > MaxFixture {
		return Result{}, fmt.Errorf("collector output exceeds %d-byte limit", MaxFixture)
	}
	var value any
	if err := decodeSingleJSON(data, &value); err != nil {
		return Result{}, fmt.Errorf("collector stdout must contain exactly one JSON document: %w", err)
	}
	schema, err := compileSchema(resolved.Schema)
	if err != nil {
		return Result{}, fmt.Errorf("compile result schema: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return Result{}, fmt.Errorf("collector output does not match result schema: %w", err)
	}
	var result Result
	if err := decodeStrictJSON(data, &result); err != nil {
		return Result{}, err
	}
	switch result.Status {
	case "complete", "partial", "unsupported", "failed":
	default:
		return Result{}, fmt.Errorf("collector output has invalid status %q", result.Status)
	}
	if result.Facts == nil || result.Evidence == nil || result.Errors == nil {
		return Result{}, fmt.Errorf("collector output must include non-null facts, evidence, and errors")
	}
	for _, evidence := range result.Evidence {
		if (evidence.Kind != "direct" && evidence.Kind != "inferred") || strings.TrimSpace(evidence.Source) == "" {
			return Result{}, fmt.Errorf("collector output contains invalid evidence")
		}
	}
	for _, resultErr := range result.Errors {
		if strings.TrimSpace(resultErr.Kind) == "" {
			return Result{}, fmt.Errorf("collector output contains an error without a kind")
		}
	}
	return result, nil
}

func calculateDigest(parts ...[]byte) string {
	hasher := sha256.New()
	for _, part := range parts {
		_, _ = hasher.Write(strconv.AppendInt(nil, int64(len(part)), 10)) //nolint:errcheck // hash writes cannot fail
		_, _ = hasher.Write([]byte{':'})                                  //nolint:errcheck // hash writes cannot fail
		_, _ = hasher.Write(part)                                         //nolint:errcheck // hash writes cannot fail
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

func List() ([]Summary, error) {
	summaries := BuiltinSummaries()
	root, err := Root()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return summaries, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list plugins: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		resolved, resolveErr := Resolve(id)
		if resolveErr != nil {
			summaries = append(summaries, Summary{ID: id, Path: filepath.Join(root, id), Valid: false, ErrorKind: classifyValidationError(resolveErr), Error: resolveErr.Error()})
			continue
		}
		summaries = append(summaries, SummaryFromResolved(resolved))
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].ID < summaries[j].ID })
	return summaries, nil
}

func classifyValidationError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "entrypoint"):
		return "invalid_entrypoint"
	case strings.Contains(message, "schema"):
		return "invalid_schema"
	case strings.Contains(message, "manifest") || strings.Contains(message, "api_version"):
		return "invalid_manifest"
	default:
		return "invalid_plugin"
	}
}

func SummaryFromResolved(resolved *Resolved) Summary {
	return Summary{
		ID:          resolved.Manifest.ID,
		Version:     resolved.Manifest.Version,
		Description: resolved.Manifest.Description,
		Path:        resolved.Path,
		Digest:      resolved.Digest,
		Trusted:     resolved.Trusted,
		Builtin:     resolved.Builtin,
		Valid:       true,
	}
}

func lockPath() (string, error) {
	root, err := runtimepath.Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, LockFile), nil
}

func loadLock() (Lock, error) {
	lock := Lock{Version: 1, Plugins: map[string]LockEntry{}}
	path, err := lockPath()
	if err != nil {
		return lock, err
	}
	data, err := readRegularFile(path, MaxManifest, 0o077)
	if os.IsNotExist(err) {
		return lock, nil
	}
	if err != nil {
		return lock, fmt.Errorf("read plugin lock: %w", err)
	}
	if err := decodeStrictJSON(data, &lock); err != nil {
		return lock, fmt.Errorf("parse plugin lock: %w", err)
	}
	if lock.Version != 1 {
		return lock, fmt.Errorf("unsupported plugin lock version %d", lock.Version)
	}
	if lock.Plugins == nil {
		lock.Plugins = map[string]LockEntry{}
	}
	return lock, nil
}

func isTrusted(id, digest string) (bool, error) {
	lock, err := loadLock()
	if err != nil {
		return false, err
	}
	entry, ok := lock.Plugins[id]
	return ok && entry.Digest == digest, nil
}

func Trust(id string) (*Resolved, error) {
	resolved, err := Resolve(id)
	if err != nil {
		return nil, err
	}
	if resolved.Builtin {
		return resolved, nil
	}
	lock, err := loadLock()
	if err != nil {
		return nil, err
	}
	lock.Plugins[id] = LockEntry{Digest: resolved.Digest, TrustedAt: time.Now().UTC()}
	if err := saveLock(lock); err != nil {
		return nil, err
	}
	resolved.Trusted = true
	return resolved, nil
}

func saveLock(lock Lock) error {
	path, err := lockPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	file, err := os.CreateTemp(dir, ".sshx-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // best-effort cleanup
	if err := file.Chmod(mode); err != nil {
		_ = file.Close() //nolint:errcheck // preserve primary error
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close() //nolint:errcheck // preserve primary error
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close() //nolint:errcheck // preserve primary error
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
