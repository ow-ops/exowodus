package migrate

import (
	"context"
	"errors"
	"fmt"

	"exodus/internal/mx"
)

// RecoverLogin verifies an existing destination password and saves it for import.
func (im *Importer) RecoverLogin(ctx context.Context, userID, password string) error {
	if password == "" {
		return errors.New("destination password is empty")
	}
	u, err := im.Archive.ReadUser(userID)
	if err != nil {
		return err
	}
	if u.UserID != userID || mx.ServerName(userID) != im.Archive.Manifest.ServerName {
		return errors.New("account differs from the archived local user")
	}
	if u.Deactivated || u.Guest || u.Passwordless {
		return errors.New("passwordless, guest and ID-only accounts use --adopt-existing-user during import")
	}
	session, err := im.migrationSession(ctx, u)
	if err != nil {
		return err
	}
	c, err := mx.LoginDevice(ctx, im.Dest, userID, password, session.DeviceID)
	if err != nil {
		return fmt.Errorf("verify destination login for %s: %w", userID, err)
	}
	if string(c.UserID) != userID || string(c.DeviceID) != session.DeviceID {
		return errors.New("destination login returned a different user or device; credentials were not saved")
	}
	session.Legacy = false
	_, _, err = im.saveMigrationSession(u, session, c, password)
	return err
}
