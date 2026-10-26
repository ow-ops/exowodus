package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Written by import, finish and the proxy; export data is not touched.
var (
	importFiles     = []string{"sessions.json", "passwords.json", "server-import.json", "credentials.csv", "import-report.json", "continuwuity-signing-key-backup.txt", "continuwuity-old-verify-key.toml"}
	importItemFiles = []string{"import.json", "import-report.json", "migration-session.json", "password-restored.json"}
)

// ResetImport moves the previous import's progress into a reset-<time>
// directory, so the archive can be imported into an empty destination.
func (a *Archive) ResetImport() (string, int, error) {
	backup := filepath.Join(a.Dir, "reset-"+time.Now().UTC().Format("20060102T150405Z"))
	moved := 0
	move := func(rel string) error {
		from := filepath.Join(a.Dir, rel)
		if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		to := filepath.Join(backup, rel)
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		if err := os.Rename(from, to); err != nil {
			return err
		}
		moved++
		return nil
	}
	for _, name := range importFiles {
		if err := move(name); err != nil {
			return backup, moved, err
		}
	}
	for _, kind := range []string{"users", "rooms"} {
		entries, err := os.ReadDir(filepath.Join(a.Dir, kind))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return backup, moved, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, name := range importItemFiles {
				if err := move(filepath.Join(kind, entry.Name(), name)); err != nil {
					return backup, moved, err
				}
			}
		}
	}
	return backup, moved, nil
}
