package migrate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"exodus/internal/archive"
)

// FilterBridgeAccounts also handles archives made before ghost filtering existed.
func (im *Importer) FilterBridgeAccounts(ctx context.Context, users []*archive.User, server *archive.Server) ([]*archive.User, error) {
	if server == nil {
		return users, nil
	}
	var bridges []*Bridge
	seen := map[string]bool{}
	protected := map[string]bool{}
	senders := map[string]bool{}
	for _, raw := range server.AppserviceRegistrations {
		b, err := parseBridge([]byte(raw), nil)
		if err != nil {
			return nil, err
		}
		if seen[b.ID] || b.sender == "" {
			return nil, fmt.Errorf("invalid or duplicate archived appservice %s", b.ID)
		}
		seen[b.ID] = true
		bridges = append(bridges, b)
		senders["@"+b.sender+":"+im.Archive.Manifest.ServerName] = true
	}
	im.protectedDeactivated = protected
	candidates := map[string]bool{}
	for _, user := range users {
		if user.Deactivated {
			candidates[user.UserID] = true
		}
	}
	if len(candidates) == 0 {
		return users, nil
	}
	dir := filepath.Join(im.Archive.Dir, "source", "tuwunel")
	if _, err := os.Stat(filepath.Join(dir, "userid_password.txt")); errors.Is(err, os.ErrNotExist) {
		for user := range senders {
			protected[user] = true
		}
		for user := range candidates {
			for _, b := range bridges {
				if b.owns(user) {
					protected[user] = true
				}
			}
		}
		return users, nil
	} else if err != nil {
		return nil, err
	}
	devices := map[string]bool{}
	for _, name := range []string{"userid_password", "token_userdeviceid", "userdeviceid_refresh", "userdeviceid_metadata", "onetimekeyid4225_otk", "onetimekeyid_onetimekeys", "userdeviceidalgorithm_fallback", "senderkey_pusher"} {
		err := walkTuwunelScan(ctx, filepath.Join(dir, name+".txt"), func(key string, value []byte, _ tuwunelValueRef) error {
			user, _, ok := strings.Cut(key, "\xff")
			switch name {
			case "userid_password":
				if candidates[key] && len(value) > 0 && string(value) != "*" {
					protected[key] = true
				}
				return nil
			case "token_userdeviceid":
				raw, _, found := bytes.Cut(value, []byte{0xff})
				user, ok = string(raw), found
			}
			if !ok {
				return errors.New("invalid Tuwunel login or device record")
			}
			if candidates[user] {
				switch name {
				case "userdeviceid_metadata":
					devices[key] = true
				case "onetimekeyid4225_otk", "onetimekeyid_onetimekeys":
					_, device, _, err := tuwunelDeviceKey(key)
					if err != nil {
						return err
					}
					// Older databases can retain prekeys after deleting a device.
					if !devices[user+"\xff"+device] {
						return nil
					}
				}
				protected[user] = true
			}
			return nil
		})
		optional := name == "userdeviceid_refresh" || name == "onetimekeyid_onetimekeys"
		if err != nil && !(optional && errors.Is(err, os.ErrNotExist)) {
			return nil, fmt.Errorf("classify archived appservice accounts: %w", err)
		}
	}
	im.protectedDeactivated = protected
	ghostProtected := map[string]bool{}
	for user := range protected {
		ghostProtected[user] = true
	}
	for user := range senders {
		ghostProtected[user] = true
	}
	var selected []*archive.User
	for _, user := range users {
		if !user.Deactivated || !isBridgeGhost(user.UserID, bridges, ghostProtected, im.Archive.Manifest.ServerName) || user.Admin || len(user.ExternalIDs) > 0 || len(user.Devices) > 0 || user.CrossSigning != nil || user.Dehydrated != nil || len(user.Verified) > 0 || len(user.Rooms) > 0 {
			selected = append(selected, user)
			continue
		}
		secrets, err := im.Archive.ReadSecrets(user.UserID)
		if err != nil {
			return nil, err
		}
		if secrets != nil && (secrets.PasswordHash != "" || len(secrets.Tokens)+len(secrets.Devices)+len(secrets.OneTimeKeys)+len(secrets.FallbackKeys)+len(secrets.Pushers) > 0) {
			selected = append(selected, user)
			continue
		}
		if _, err := os.Stat(filepath.Join(im.Archive.UserDir(user.UserID), "key_backup.json")); err == nil {
			selected = append(selected, user)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		im.bridgeAccounts = append(im.bridgeAccounts, user.UserID)
		delete(im.Migrated, user.UserID)
	}
	return selected, nil
}
