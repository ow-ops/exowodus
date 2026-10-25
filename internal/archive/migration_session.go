package archive

import (
	"errors"
	"os"
	"path/filepath"
)

// MigrationSession records the destination account and temporary device owned
// by this import. Ownership is recorded only after authenticated API success.
type MigrationSession struct {
	UserID   string `json:"user_id,omitempty"`
	DeviceID string `json:"device_id"`
	Token    string `json:"token,omitempty"`
	Owned    bool   `json:"owned,omitempty"`
	Legacy   bool   `json:"legacy,omitempty"`
}

func (a *Archive) ReadMigrationSession(userID string) (*MigrationSession, error) {
	var session MigrationSession
	err := readOptionalJSON(filepath.Join(a.UserDir(userID), "migration-session.json"), &session)
	return &session, err
}

func (a *Archive) WriteMigrationSession(userID string, session *MigrationSession) error {
	return writeJSONFile(filepath.Join(a.UserDir(userID), "migration-session.json"), session, true)
}

func (a *Archive) PasswordRestored(userID string) (bool, error) {
	_, err := os.Stat(filepath.Join(a.UserDir(userID), "password-restored.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (a *Archive) MarkPasswordRestored(userID string) error {
	return writeJSONFile(filepath.Join(a.UserDir(userID), "password-restored.json"), struct{}{}, true)
}
