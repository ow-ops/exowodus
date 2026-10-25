package archive

import (
	"errors"
	"io"
	"path/filepath"
)

func (a *Archive) LockAccountRepair() (io.Closer, error) {
	return a.lockProxyFile("export-progress.lock")
}

// WriteRecoveredAccount publishes user.json last. An interrupted repair cannot
// expose an active user before its keys and sessions are saved.
func (a *Archive) WriteRecoveredAccount(u *User, secrets *Secrets, backup *KeyBackup) error {
	if secrets == nil || u.Deactivated || !u.Passwordless {
		return errors.New("account recovery requires a passwordless user and its secrets")
	}
	dir := a.UserDir(u.UserID)
	if err := writeJSONFile(filepath.Join(dir, "secrets.json"), secrets, true); err != nil {
		return err
	}
	if backup != nil {
		if err := writeJSONFile(filepath.Join(dir, "key_backup.json"), backup, true); err != nil {
			return err
		}
	}
	return writeJSONFile(filepath.Join(dir, "user.json"), u, true)
}
