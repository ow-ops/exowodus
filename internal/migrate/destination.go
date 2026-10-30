package migrate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/mx"

	"maunium.net/go/mautrix"
)

func (im *Importer) registrationClient() *mautrix.Client {
	if im.Appservice != nil {
		return im.Appservice.client
	}
	return im.Dest
}

// SetAdoptExistingUsers limits explicit recovery to accounts in this import.
func (im *Importer) SetAdoptExistingUsers(users []*archive.User, ids []string) error {
	im.AdoptExistingUsers = map[string]bool{}
	for _, userID := range ids {
		if im.Admin == nil || im.Admin.ServerName() != im.Archive.Manifest.ServerName {
			return errors.New("--adopt-existing-user requires --to-admin-token and the original server name")
		}
		found := false
		for _, user := range users {
			if user.UserID == userID && mx.ServerName(userID) == im.Archive.Manifest.ServerName {
				if !(user.Passwordless || user.Guest || user.Deactivated && im.DeactivatedIDOnly) {
					return fmt.Errorf("%s: --adopt-existing-user applies only to passwordless, guest or ID-only accounts", userID)
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("--adopt-existing-user %s is not an imported local account", userID)
		}
		im.AdoptExistingUsers[userID] = true
	}
	return nil
}

// CheckDestination checks account APIs before creating users or restoring rooms.
func (im *Importer) CheckDestination(ctx context.Context, users []*archive.User) error {
	im.registrationNeeded = false
	if im.DestToken != "" || len(users) == 0 {
		return nil
	}
	password, appservice := false, false
	var pending []*archive.User
	for _, u := range users {
		state, err := im.Archive.ReadImportState(u.UserID)
		if err != nil {
			return err
		}
		if state.Status && (u.Deactivated || u.Locked || u.Suspended) {
			continue
		}
		asAccount := u.Guest || u.Passwordless || u.Deactivated && im.DeactivatedIDOnly
		password = password || !asAccount
		secrets, err := im.Archive.ReadSecrets(u.UserID)
		if err != nil {
			return err
		}
		appservice = appservice || asAccount || len(u.Devices) > 0 || secrets != nil && len(secrets.Devices)+len(secrets.Tokens) > 0
		migration, err := im.Archive.ReadMigrationSession(u.UserID)
		if err != nil {
			return err
		}
		if state.DestUserID == "" && !migration.Owned && !im.AdoptExistingUsers[u.UserID] {
			pending = append(pending, u)
		}
	}
	if !password && !appservice {
		return nil
	}
	var login struct {
		Flows []struct {
			Type string `json:"type"`
		} `json:"flows"`
	}
	if err := im.checkDestinationRequest(ctx, im.Dest.BuildClientURL("v3", "login"), &login); err != nil {
		return fmt.Errorf("destination login discovery failed: %w; Exowodus requires legacy login APIs; check global.oauth.compatibility_mode and delegated OIDC settings", err)
	}
	types := map[string]bool{}
	for _, flow := range login.Flows {
		types[flow.Type] = true
	}
	var failures []error
	if password && !types[string(mautrix.AuthTypePassword)] {
		failures = append(failures, errors.New("destination does not offer m.login.password"))
	}
	if appservice && !types[string(mautrix.AuthTypeAppservice)] {
		failures = append(failures, errors.New("destination does not offer m.login.application_service; device and passwordless-account restoration require it"))
	}
	if len(failures) > 0 {
		return fmt.Errorf("%w; enable legacy login APIs before import (global.oauth.compatibility_mode=hybrid; delegated global.oauth.oidc forces exclusive mode)", errors.Join(failures...))
	}
	registration := false
	for _, u := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		endpoint, err := url.Parse(im.Dest.BuildClientURL("v3", "register", "available"))
		if err != nil {
			return err
		}
		params := endpoint.Query()
		params.Set("username", mx.Localpart(u.UserID))
		endpoint.RawQuery = params.Encode()
		err = im.checkDestinationRequest(ctx, endpoint.String(), nil)
		switch {
		case mx.IsCode(err, "M_INVALID_USERNAME"):
			failures = append(failures, fmt.Errorf("destination rejects archived ID %s; its original spelling must be preserved: %w", u.UserID, err))
		case mx.IsCode(err, "M_USER_IN_USE"):
			// Existing accounts still need authenticated ownership during login.
		case err != nil:
			if !mx.IsCode(err, "M_EXCLUSIVE") {
				return fmt.Errorf("check destination username %s: %w", u.UserID, err)
			}
		}
		registration = registration || !mx.IsCode(err, "M_USER_IN_USE") && !(u.Guest || u.Passwordless || u.Deactivated && im.DeactivatedIDOnly)
	}
	im.registrationNeeded = registration
	return errors.Join(failures...)
}

// CheckRegistration discovers UIAA requirements using the migration appservice.
func (im *Importer) CheckRegistration(ctx context.Context) error {
	if im.registrationNeeded && im.Admin != nil {
		// The existing server bot cannot be created again. No authentication
		// stages are submitted; this only discovers registration requirements.
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, auth, err := im.registrationClient().Register(probeCtx, &mautrix.ReqRegister[any]{Username: mx.Localpart(im.Admin.bot), InhibitLogin: true})
		cancel()
		switch {
		case auth != nil:
			return mx.CheckRegistrationFlow(auth, im.RegistrationToken != "")
		case mx.IsCode(err, "M_USER_IN_USE"):
		case err != nil:
			return fmt.Errorf("destination registration is unavailable; check registration_token and supported authentication flows: %w", err)
		default:
			return errors.New("destination returned an unexpected registration probe response")
		}
	}
	return nil
}

func (im *Importer) checkDestinationRequest(ctx context.Context, endpoint string, response any) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, err := im.Dest.MakeRequest(ctx, http.MethodGet, endpoint, nil, response)
	return err
}
