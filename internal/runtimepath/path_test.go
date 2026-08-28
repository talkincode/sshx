package runtimepath

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRootUsesSSHXHome(t *testing.T) {
	configured := filepath.Join(t.TempDir(), "runtime")
	t.Setenv(EnvHome, configured)

	root, err := Root()
	if err != nil {
		t.Fatalf("Root() error = %v", err)
	}
	if root != configured {
		t.Fatalf("Root() = %q, want %q", root, configured)
	}
}

func TestRootRejectsFilesystemRootOverride(t *testing.T) {
	t.Setenv(EnvHome, string(filepath.Separator))
	if _, err := Root(); err == nil {
		t.Fatal("Root() accepted a filesystem root override")
	}
}

func TestRootDefaultsBelowUserHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvHome, "")
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	root, err := Root()
	if err != nil {
		t.Fatalf("Root() error = %v", err)
	}
	want := filepath.Join(home, DefaultDir)
	if root != want {
		t.Fatalf("Root() = %q, want %q", root, want)
	}
}

func TestDerivedDirectoriesStayBelowRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	t.Setenv(EnvHome, root)

	plugins, err := Plugins()
	if err != nil {
		t.Fatalf("Plugins() error = %v", err)
	}
	observations, err := Observations()
	if err != nil {
		t.Fatalf("Observations() error = %v", err)
	}
	if plugins != filepath.Join(root, "plugins") {
		t.Fatalf("Plugins() = %q", plugins)
	}
	if observations != filepath.Join(root, "observations") {
		t.Fatalf("Observations() = %q", observations)
	}
}
