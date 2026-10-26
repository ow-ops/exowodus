package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResetImport(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	user, room := a.UserDir("@alice:example.org"), a.RoomDir("!room:example.org")
	reset := []string{
		filepath.Join(a.Dir, "sessions.json"),
		filepath.Join(a.Dir, "credentials.csv"),
		filepath.Join(a.Dir, "continuwuity-signing-key-backup.txt"),
		filepath.Join(user, "import.json"),
		filepath.Join(user, "migration-session.json"),
		filepath.Join(user, "password-restored.json"),
		filepath.Join(room, "import.json"),
	}
	kept := []string{
		filepath.Join(a.Dir, "manifest.json"),
		filepath.Join(a.Dir, "federation-outbox.sqlite"),
		filepath.Join(user, "user.json"),
		filepath.Join(user, "secrets.json"),
		filepath.Join(room, "room.json"),
		filepath.Join(room, "pdus.json"),
	}
	for _, path := range append(reset, kept...) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backup, moved, err := a.ResetImport()
	if err != nil || moved != len(reset) {
		t.Fatalf("moved %d of %d: %v", moved, len(reset), err)
	}
	for _, path := range reset {
		rel, _ := filepath.Rel(a.Dir, path)
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s was not moved", rel)
		}
		if data, err := os.ReadFile(filepath.Join(backup, rel)); err != nil || string(data) != path {
			t.Fatalf("%s backup: %q %v", rel, data, err)
		}
	}
	for _, path := range kept {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("export file removed: %v", err)
		}
	}
}
