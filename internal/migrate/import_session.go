package migrate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"maunium.net/go/mautrix"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func (im *Importer) migrationSession(u *archive.User) (*archive.MigrationSession, error) {
	session, err := im.Archive.ReadMigrationSession(u.UserID)
	if err != nil {
		return nil, err
	}
	if !session.Owned && im.Appservice != nil && mx.ServerName(im.Appservice.Bot) == im.Archive.Manifest.ServerName && mx.ServerName(u.UserID) == im.Archive.Manifest.ServerName {
		state, err := im.Archive.ReadImportState(u.UserID)
		if err != nil {
			return nil, err
		}
		if state.DestUserID == u.UserID {
			session.UserID, session.Owned, session.Legacy = u.UserID, true, true
			if err := im.Archive.WriteMigrationSession(u.UserID, session); err != nil {
				return nil, err
			}
		}
	}
	devices := map[string]bool{}
	for _, device := range u.Devices {
		devices[device.ID] = true
	}
	if u.Dehydrated != nil {
		devices[u.Dehydrated.DeviceID] = true
	}
	secrets, err := im.Archive.ReadSecrets(u.UserID)
	if err != nil {
		return nil, err
	}
	if secrets != nil {
		for _, device := range secrets.Devices {
			devices[device] = true
		}
		for _, token := range secrets.Tokens {
			devices[token.DeviceID] = true
		}
	}
	if session.Owned && (session.UserID == "" || mx.Localpart(session.UserID) != mx.Localpart(u.UserID)) {
		return nil, errors.New("migration account differs from source account")
	}
	if session.Owned && im.Appservice != nil && session.UserID != mx.WithServer(u.UserID, mx.ServerName(im.Appservice.Bot)) {
		return nil, errors.New("migration account belongs to a different destination")
	}
	if session.DeviceID == "" || devices[session.DeviceID] {
		for {
			session.DeviceID = "EXODUS_" + rand.Text()
			if !devices[session.DeviceID] {
				break
			}
		}
		session.Token = ""
		if err := im.Archive.WriteMigrationSession(u.UserID, session); err != nil {
			return nil, err
		}
	}
	return session, nil
}

func (im *Importer) saveMigrationSession(u *archive.User, session *archive.MigrationSession, client *mautrix.Client, password string) (*mautrix.Client, string, error) {
	if client.AccessToken == "" || mx.Localpart(string(client.UserID)) != mx.Localpart(u.UserID) || string(client.DeviceID) != session.DeviceID || session.Owned && string(client.UserID) != session.UserID {
		return nil, "", fmt.Errorf("destination returned a different migration user or device for %s", u.UserID)
	}
	if im.Appservice != nil && string(client.UserID) != mx.WithServer(u.UserID, mx.ServerName(im.Appservice.Bot)) {
		return nil, "", errors.New("destination returned a different migration account")
	}
	if password != "" && im.DestPassword == "" {
		if err := im.Archive.AddCredential(archive.Credential{SourceUserID: u.UserID, DestUserID: string(client.UserID), Password: password}); err != nil {
			return nil, "", err
		}
	}
	session.UserID, session.Token, session.Owned = string(client.UserID), client.AccessToken, true
	if err := im.Archive.WriteMigrationSession(u.UserID, session); err != nil {
		return nil, "", err
	}
	return client, password, nil
}

func (im *Importer) resumeLegacyPassword(ctx context.Context, u *archive.User, session *archive.MigrationSession) (*mautrix.Client, string, error) {
	restored, err := im.Archive.PasswordRestored(u.UserID)
	if err != nil {
		return nil, "", err
	}
	pending, err := im.Archive.PendingPasswords()
	if err != nil {
		return nil, "", err
	}
	secrets, err := im.Archive.ReadSecrets(u.UserID)
	if err != nil {
		return nil, "", err
	}
	if !restored && pending[session.UserID].Hash == "" && secrets != nil && secrets.PasswordHash != "" {
		credentials, err := im.Archive.Credentials()
		if err != nil {
			return nil, "", err
		}
		password := credentials[u.UserID].Password
		if password == "" {
			return nil, "", errors.New("legacy password migration state is unknown: generated credentials are missing")
		}
		client, err := mx.LoginDevice(ctx, im.Dest, mx.Localpart(u.UserID), password, session.DeviceID)
		if err != nil {
			if mx.IsCode(err, "M_FORBIDDEN") {
				return nil, "", errors.New("legacy password migration state is unknown: destination password differs from generated credentials; verify prior password restoration before resuming")
			}
			return nil, "", err
		}
		session.Legacy = false
		return im.saveMigrationSession(u, session, client, password)
	}
	session.Legacy = false
	return nil, "", im.Archive.WriteMigrationSession(u.UserID, session)
}
