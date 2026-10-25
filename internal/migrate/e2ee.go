package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"maunium.net/go/mautrix"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

const maxSessionsPerRequest = 1000
const maxBackupBatchBytes = 4 << 20

func exportKeyBackup(ctx context.Context, c *mautrix.Client) (*archive.KeyBackup, error) {
	var version struct {
		Algorithm string          `json:"algorithm"`
		AuthData  json.RawMessage `json:"auth_data"`
		Version   string          `json:"version"`
	}
	_, err := c.MakeRequest(ctx, http.MethodGet, c.BuildClientURL("v3", "room_keys", "version"), nil, &version)
	if mx.IsCode(err, "M_NOT_FOUND") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kb := &archive.KeyBackup{Algorithm: version.Algorithm, AuthData: version.AuthData}
	var keys struct {
		Rooms map[string]json.RawMessage `json:"rooms"`
	}
	u := c.BuildURLWithQuery(mautrix.ClientURLPath{"v3", "room_keys", "keys"}, map[string]string{"version": version.Version})
	if _, err := c.MakeRequest(ctx, http.MethodGet, u, nil, &keys); err != nil {
		return nil, err
	}
	kb.Rooms = keys.Rooms
	return kb, nil
}

// exportKeys excludes only devices created for the export session.
func exportKeys(ctx context.Context, c *mautrix.Client, userID string, ephemeral bool) (*archive.CrossSigning, []archive.Device, error) {
	var resp struct {
		Devices     map[string]map[string]json.RawMessage `json:"device_keys"`
		Master      map[string]json.RawMessage            `json:"master_keys"`
		SelfSigning map[string]json.RawMessage            `json:"self_signing_keys"`
		UserSigning map[string]json.RawMessage            `json:"user_signing_keys"`
	}
	body := map[string]any{"device_keys": map[string][]string{userID: {}}}
	if err := queryKeys(ctx, c, body, &resp); err != nil {
		return nil, nil, err
	}
	var cs *archive.CrossSigning
	if master, ok := resp.Master[userID]; ok {
		cs = &archive.CrossSigning{Master: master, SelfSigning: resp.SelfSigning[userID], UserSigning: resp.UserSigning[userID]}
	}

	list, err := c.GetDevicesInfo(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("devices: %w", err)
	}
	who, err := c.Whoami(ctx)
	if err != nil {
		return nil, nil, err
	}
	var devices []archive.Device
	for _, d := range list.Devices {
		if ephemeral && d.DeviceID == who.DeviceID {
			continue
		}
		deviceID := string(d.DeviceID)
		devices = append(devices, archive.Device{ID: deviceID, DisplayName: d.DisplayName, Keys: resp.Devices[userID][deviceID]})
	}
	return cs, devices, nil
}

var dehydratedDevicePath = mautrix.ClientURLPath{"unstable", "org.matrix.msc3814.v1", "dehydrated_device"}

func exportDehydrated(ctx context.Context, c *mautrix.Client, userID string) (*archive.Dehydrated, error) {
	var d struct {
		DeviceID   string          `json:"device_id"`
		DeviceData json.RawMessage `json:"device_data"`
	}
	_, err := c.MakeRequest(ctx, http.MethodGet, c.BuildURL(dehydratedDevicePath), nil, &d)
	if mx.IsStatus(err, http.StatusNotFound) || mx.IsCode(err, "M_UNRECOGNIZED") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var resp struct {
		Devices map[string]map[string]json.RawMessage `json:"device_keys"`
	}
	body := map[string]any{"device_keys": map[string][]string{userID: {d.DeviceID}}}
	if err := queryKeys(ctx, c, body, &resp); err != nil {
		return nil, err
	}
	return &archive.Dehydrated{DeviceID: d.DeviceID, DeviceData: d.DeviceData, Keys: resp.Devices[userID][d.DeviceID]}, nil
}

func importDehydrated(ctx context.Context, c *mautrix.Client, d *archive.Dehydrated, secrets *archive.Secrets) error {
	body := map[string]any{
		"device_id":                   d.DeviceID,
		"device_data":                 d.DeviceData,
		"initial_device_display_name": "Dehydrated device",
		"device_keys":                 d.Keys,
		"one_time_keys":               map[string]json.RawMessage{},
		"fallback_keys":               map[string]json.RawMessage{},
	}
	if secrets != nil {
		if otks := secrets.OneTimeKeys[d.DeviceID]; otks != nil {
			body["one_time_keys"] = otks
		}
		if fallback := secrets.FallbackKeys[d.DeviceID]; fallback != nil {
			body["fallback_keys"] = fallback
		}
	}
	_, err := c.MakeRequest(ctx, http.MethodPut, c.BuildURL(dehydratedDevicePath), body, nil)
	return err
}

// exportVerifications keeps only this user's signature on each master key.
func exportVerifications(ctx context.Context, c *mautrix.Client, userID string, cs *archive.CrossSigning, users []string) (map[string]json.RawMessage, error) {
	if cs == nil || len(cs.UserSigning) == 0 || len(users) == 0 {
		return nil, nil
	}
	uskID, err := keyID(cs.UserSigning)
	if err != nil {
		return nil, err
	}
	verified := map[string]json.RawMessage{}
	for chunk := range slices.Chunk(users, 100) {
		query := map[string][]string{}
		for _, u := range chunk {
			query[u] = []string{}
		}
		var resp struct {
			Master map[string]map[string]json.RawMessage `json:"master_keys"`
		}
		if err := queryKeys(ctx, c, map[string]any{"device_keys": query}, &resp); err != nil {
			return nil, err
		}
		for u, key := range resp.Master {
			var sigs map[string]map[string]string
			_ = json.Unmarshal(key["signatures"], &sigs)
			sig, ok := sigs[userID][uskID]
			if !ok {
				continue
			}
			key["signatures"], _ = json.Marshal(map[string]map[string]string{userID: {uskID: sig}})
			delete(key, "unsigned")
			if verified[u], err = json.Marshal(key); err != nil {
				return nil, err
			}
		}
	}
	return verified, nil
}

func keyID(raw json.RawMessage) (string, error) {
	var key struct {
		Keys map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		return "", err
	}
	for id := range key.Keys {
		return id, nil
	}
	return "", errors.New("cross-signing key has no key")
}

// importVerifications only applies when the user ID is unchanged.
func importVerifications(ctx context.Context, c *mautrix.Client, verified map[string]json.RawMessage) error {
	body := map[string]map[string]json.RawMessage{}
	for u, key := range verified {
		id, err := keyID(key)
		if err != nil {
			return err
		}
		// Cross-signing keys are indexed by their public key, unprefixed.
		body[u] = map[string]json.RawMessage{strings.TrimPrefix(id, "ed25519:"): key}
	}
	var resp struct {
		Failures map[string]map[string]json.RawMessage `json:"failures"`
	}
	if _, err := c.MakeRequest(ctx, http.MethodPost, c.BuildClientURL("v3", "keys", "signatures", "upload"), body, &resp); err != nil {
		return err
	}
	if len(resp.Failures) > 0 {
		raw, _ := json.Marshal(resp.Failures)
		return fmt.Errorf("rejected signatures: %s", raw)
	}
	return nil
}

// importKeyBackup reuses the original auth data so the recovery key still works.
func importKeyBackup(ctx context.Context, dest *mautrix.Client, kb *archive.KeyBackupReader, state *archive.ImportState, save func() error) error {
	if state.KeyBackup == "" {
		var resp struct {
			Version string `json:"version"`
		}
		body := map[string]any{"algorithm": kb.Algorithm, "auth_data": kb.AuthData}
		if _, err := dest.MakeRequest(ctx, http.MethodPost, dest.BuildClientURL("v3", "room_keys", "version"), body, &resp); err != nil {
			return fmt.Errorf("create backup version: %w", err)
		}
		state.KeyBackup = resp.Version
		if err := save(); err != nil {
			return err
		}
	}

	keysURL := dest.BuildURLWithQuery(mautrix.ClientURLPath{"v3", "room_keys", "keys"}, map[string]string{"version": state.KeyBackup})
	batch := map[string]map[string]map[string]json.RawMessage{}
	sessions := 0
	batchBytes := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := dest.MakeRequest(ctx, http.MethodPut, keysURL, map[string]any{"rooms": batch}, nil)
		batch, sessions, batchBytes = map[string]map[string]map[string]json.RawMessage{}, 0, 0
		return err
	}
	for session, err := range kb.Sessions(ctx) {
		if err != nil {
			return err
		}
		size := len(session.RoomID) + len(session.SessionID) + len(session.Data)
		if sessions > 0 && (sessions >= maxSessionsPerRequest || batchBytes+size > maxBackupBatchBytes) {
			if err := flush(); err != nil {
				return err
			}
		}
		if batch[session.RoomID] == nil {
			batch[session.RoomID] = map[string]map[string]json.RawMessage{"sessions": {}}
		}
		batch[session.RoomID]["sessions"][session.SessionID] = session.Data
		sessions++
		batchBytes += size
	}
	if err := flush(); err != nil {
		return err
	}
	state.KeysDone = true
	return save()
}

// importCrossSigning only applies when the user ID is unchanged.
func importCrossSigning(ctx context.Context, acct destAccount, as *Appservice, cs *archive.CrossSigning) error {
	master := map[string]json.RawMessage{}
	if err := json.Unmarshal(cs.Master, &master); err != nil {
		return err
	}
	if _, ok := master["signatures"]; !ok {
		// Continuwuity drops others' signatures on keys without this field.
		master["signatures"] = json.RawMessage("{}")
	}
	body := map[string]any{"master_key": master}
	if len(cs.SelfSigning) > 0 {
		body["self_signing_key"] = cs.SelfSigning
	}
	if len(cs.UserSigning) > 0 {
		body["user_signing_key"] = cs.UserSigning
	}
	if as != nil {
		// Appservices are exempt from user-interactive auth here.
		c := as.As(acct.id)
		_, err := c.MakeRequest(ctx, http.MethodPost, c.BuildClientURL("v3", "keys", "device_signing", "upload"), body, nil)
		return err
	}

	if acct.password == "" {
		return errors.New("password unknown for user-interactive auth; pass --to-admin-token")
	}
	c := acct.client
	return mx.DoWithPassword(ctx, c, http.MethodPost, c.BuildClientURL("v3", "keys", "device_signing", "upload"), body, acct.id, acct.password)
}

// queryKeys keeps signed key objects verbatim.
func queryKeys(ctx context.Context, c *mautrix.Client, body, out any) error {
	_, err := c.MakeRequest(ctx, http.MethodPost, c.BuildClientURL("v3", "keys", "query"), body, out)
	return err
}
