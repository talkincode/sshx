package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPortablePluginFixtureAndPathConfinement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "plugins with spaces 目录")
	t.Setenv("SSHX_HOME", root)
	created, err := Create(CreateOptions{ID: "portable.inspect"})
	if err != nil {
		t.Fatal(err)
	}
	_, result, _, err := Test(created.Resolved.Manifest.ID, "complete")
	if err != nil || result.Status != "complete" {
		t.Fatalf("portable JSON fixture validation = %#v, %v", result, err)
	}
	for _, relative := range []string{"", "..", "../outside", filepath.Join("..", "outside"), root} {
		if _, pathErr := safeChild(created.Resolved.Path, relative); pathErr == nil {
			t.Fatalf("safeChild(%q) accepted an unconfined path", relative)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "portable.inspect" {
		t.Fatalf("unexpected plugin directory artifacts: %v", entries)
	}
}
