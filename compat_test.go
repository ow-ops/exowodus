package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestEnvironmentNames(t *testing.T) {
	t.Setenv("EXODUS_FROM_TOKEN", "legacy-token")
	t.Setenv("EXOWODUS_FROM_TOKEN", "")
	if err := os.Unsetenv("EXOWODUS_FROM_TOKEN"); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		var source sourceFlags
		source.register(&cobra.Command{})
		if source.token != want {
			t.Fatalf("source token = %q, want %q", source.token, want)
		}
	}
	check("legacy-token")
	t.Setenv("EXOWODUS_FROM_TOKEN", "new-token")
	check("new-token")
	t.Setenv("EXOWODUS_FROM_TOKEN", "")
	check("")
}

func TestArchiveDirectoryDefaults(t *testing.T) {
	t.Chdir(t.TempDir())
	if got := defaultArchiveDir(); got != "exowodus-archive" {
		t.Fatalf("fresh default = %s", got)
	}
	if err := os.Mkdir("exodus-archive", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("exodus-archive", "manifest.json"), []byte(`{"version":8}`), 0600); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	for _, cmd := range root.Commands() {
		if flag := cmd.Flags().Lookup("archive"); flag != nil && flag.DefValue != "exodus-archive" {
			t.Errorf("%s did not reuse the existing archive: %s", cmd.Name(), flag.DefValue)
		}
	}
	if err := os.Mkdir("exowodus-archive", 0700); err != nil {
		t.Fatal(err)
	}
	if got := defaultArchiveDir(); got != "exowodus-archive" {
		t.Fatalf("new archive did not take precedence: %s", got)
	}
}
