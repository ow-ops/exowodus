package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"exodus/internal/archive"
)

const maxAccountRecoveryBytes = 32 << 20

func recoverTuwunelAccount(ctx context.Context, a *archive.Archive, dir, user string) (*archive.User, *archive.Secrets, *archive.KeyBackup, error) {
	d := &TuwunelDump{maps: map[string]map[string][]byte{}}
	used := 0
	for _, table := range append(slices.Clone(accountCheckpointTables), accountRecoveryTables...) {
		rows := map[string][]byte{}
		err := walkTuwunelScan(ctx, filepath.Join(dir, table+".txt"), func(key string, value []byte, _ tuwunelValueRef) error {
			if table != "pushkey_deviceid" && accountRowUser(table, key, value) != user {
				return nil
			}
			used += len(key) + len(value) + 128
			if used > maxAccountRecoveryBytes {
				return errors.New("account recovery exceeds the 32 MiB per-account limit; no account files were changed")
			}
			if _, exists := rows[key]; exists {
				return errors.New("duplicate account recovery record")
			}
			rows[key] = bytes.Clone(value)
			return nil
		})
		if err != nil {
			return nil, nil, nil, err
		}
		d.maps[table] = rows
	}
	d.passwords, d.tokens, d.refresh = d.maps["userid_password"], d.maps["token_userdeviceid"], d.maps["userdeviceid_refresh"]
	if password, exists := d.passwords[user]; !exists || len(password) != 0 {
		return nil, nil, nil, errors.New("account is not passwordless in the original backup")
	}
	secrets, err := d.Secrets(user)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(secrets.Devices) == 0 {
		return nil, nil, nil, errors.New("account has no live devices; ID-only restoration must remain explicit")
	}
	for _, token := range secrets.Tokens {
		if !slices.Contains(secrets.Devices, token.DeviceID) {
			return nil, nil, nil, errors.New("login token references a missing device")
		}
	}
	for _, pusher := range secrets.Pushers {
		if !slices.Contains(secrets.Devices, pusher.DeviceID) {
			return nil, nil, nil, errors.New("pusher references a missing device")
		}
	}
	for device := range secrets.OneTimeKeys {
		if !slices.Contains(secrets.Devices, device) {
			delete(secrets.OneTimeKeys, device)
		}
	}
	for device := range secrets.FallbackKeys {
		if !slices.Contains(secrets.Devices, device) {
			return nil, nil, nil, errors.New("fallback keys reference a missing device")
		}
	}
	u, err := a.ReadUser(user)
	if err != nil {
		return nil, nil, nil, err
	}
	u.Deactivated, u.Passwordless = false, true
	_, u.Locked = d.maps["userid_locked"][user]
	_, u.Suspended = d.maps["userid_suspended"][user]
	u.Devices = nil
	for _, device := range secrets.Devices {
		key := user + "\xff" + device
		var metadata struct {
			DisplayName string `json:"display_name"`
		}
		if err := json.Unmarshal(d.maps["userdeviceid_metadata"][key], &metadata); err != nil {
			return nil, nil, nil, errors.New("invalid device metadata")
		}
		keys := d.maps["keyid_key"][key]
		if len(keys) > 0 {
			var identity struct {
				UserID   string `json:"user_id"`
				DeviceID string `json:"device_id"`
			}
			if err := json.Unmarshal(keys, &identity); err != nil || identity.UserID != user || identity.DeviceID != device {
				return nil, nil, nil, errors.New("device key identity differs from device metadata")
			}
		}
		u.Devices = append(u.Devices, archive.Device{ID: device, DisplayName: metadata.DisplayName, Keys: keys})
	}
	cs := &archive.CrossSigning{}
	for _, field := range []struct {
		table, usage string
		dest         *json.RawMessage
	}{
		{"userid_masterkeyid", "master", &cs.Master},
		{"userid_selfsigningkeyid", "self_signing", &cs.SelfSigning},
		{"userid_usersigningkeyid", "user_signing", &cs.UserSigning},
	} {
		pointer := d.maps[field.table][user]
		if pointer == nil {
			continue
		}
		key := d.maps["keyid_key"][string(pointer)]
		var identity struct {
			UserID string   `json:"user_id"`
			Usage  []string `json:"usage"`
		}
		if err := json.Unmarshal(key, &identity); err != nil || identity.UserID != user || !slices.Equal(identity.Usage, []string{field.usage}) {
			return nil, nil, nil, fmt.Errorf("invalid %s cross-signing key", field.usage)
		}
		*field.dest = key
	}
	if len(cs.Master) > 0 {
		u.CrossSigning = cs
	} else if len(cs.SelfSigning)+len(cs.UserSigning) > 0 {
		return nil, nil, nil, errors.New("cross-signing master key missing")
	}
	if raw := d.maps["userid_dehydrateddevice"][user]; raw != nil {
		var dehydrated archive.Dehydrated
		if err := json.Unmarshal(raw, &dehydrated); err != nil || !slices.Contains(secrets.Devices, dehydrated.DeviceID) || !json.Valid(dehydrated.DeviceData) {
			return nil, nil, nil, errors.New("invalid dehydrated device")
		}
		dehydrated.Keys = d.maps["keyid_key"][user+"\xff"+dehydrated.DeviceID]
		u.Dehydrated = &dehydrated
	}
	u.ProfileFields = map[string]json.RawMessage{}
	for key, value := range d.maps["useridprofilekey_value"] {
		_, name, _ := strings.Cut(key, "\xff")
		if !json.Valid(value) {
			return nil, nil, nil, errors.New("invalid profile field")
		}
		switch name {
		case "displayname":
			if err := json.Unmarshal(value, &u.DisplayName); err != nil {
				return nil, nil, nil, err
			}
		case "avatar_url":
			if err := json.Unmarshal(value, &u.AvatarURL); err != nil {
				return nil, nil, nil, err
			}
		default:
			u.ProfileFields[name] = value
		}
	}
	if err := recoverAccountRooms(ctx, a, d, u); err != nil {
		return nil, nil, nil, err
	}
	if err := recoverVerifications(ctx, dir, u); err != nil {
		return nil, nil, nil, err
	}
	if err := recoverAccountAvatar(a, u); err != nil {
		return nil, nil, nil, err
	}
	backup, err := recoverAccountBackup(d, user)
	if err != nil {
		return nil, nil, nil, err
	}
	return u, secrets, backup, nil
}

func recoverAccountRooms(ctx context.Context, a *archive.Archive, d *TuwunelDump, u *archive.User) error {
	rooms := map[string]*archive.Room{}
	for key := range d.maps["userroomid_joinedcount"] {
		_, roomID, _ := strings.Cut(key, "\xff")
		if a.IsRoomSkipped(roomID) {
			continue
		}
		member, err := recoveredRoomMember(ctx, a, roomID, u.UserID)
		if err != nil {
			return err
		}
		rooms[roomID] = &archive.Room{RoomID: roomID, Member: member, AccountData: map[string]json.RawMessage{}}
	}
	u.AccountData = map[string]json.RawMessage{}
	for key, pointer := range d.maps["roomusertype_roomuserdataid"] {
		room, rest, _ := strings.Cut(key, "\xff")
		_, typ, ok := strings.Cut(rest, "\xff")
		prefix := room + "\xff" + u.UserID + "\xff"
		if !ok || !bytes.HasPrefix(pointer, []byte(prefix)) || len(pointer) < len(prefix)+9 || pointer[len(prefix)+8] != 0xff || string(pointer[len(prefix)+9:]) != typ {
			return errors.New("invalid account-data pointer")
		}
		var data struct {
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(d.maps["roomuserdataid_accountdata"][string(pointer)], &data); err != nil || data.Type != typ || !json.Valid(data.Content) {
			return errors.New("missing or invalid account-data event")
		}
		if room == "" {
			if typ == "m.push_rules" {
				u.PushRules = data.Content
			} else {
				u.AccountData[typ] = data.Content
			}
		} else if r := rooms[room]; r != nil {
			r.AccountData[typ] = data.Content
		}
	}
	u.Rooms = nil
	for _, room := range slices.Sorted(maps.Keys(rooms)) {
		u.Rooms = append(u.Rooms, *rooms[room])
	}
	u.Invites, u.Knocks = nil, nil
	for _, table := range []string{"userroomid_invitestate", "userroomid_knockedstate"} {
		for key, raw := range d.maps[table] {
			_, room, _ := strings.Cut(key, "\xff")
			if a.IsRoomSkipped(room) {
				continue
			}
			var state []struct {
				Type     string `json:"type"`
				StateKey string `json:"state_key"`
				Sender   string `json:"sender"`
				Content  struct {
					Reason string `json:"reason"`
				} `json:"content"`
			}
			if err := json.Unmarshal(raw, &state); err != nil {
				return errors.New("invalid invitation or knock state")
			}
			for _, event := range state {
				if event.Type != "m.room.member" || event.StateKey != u.UserID {
					continue
				}
				if table == "userroomid_invitestate" {
					u.Invites = append(u.Invites, archive.Invite{RoomID: room, Inviter: event.Sender})
				} else {
					u.Knocks = append(u.Knocks, archive.Knock{RoomID: room, Reason: event.Content.Reason})
				}
			}
		}
	}
	return nil
}

func recoverAccountBackup(d *TuwunelDump, user string) (*archive.KeyBackup, error) {
	var latest uint64
	var algorithm []byte
	for key, raw := range d.maps["backupid_algorithm"] {
		_, version, _ := strings.Cut(key, "\xff")
		n, err := strconv.ParseUint(version, 10, 64)
		if err != nil {
			return nil, errors.New("invalid key-backup version")
		}
		if algorithm == nil || n > latest {
			latest, algorithm = n, raw
		}
	}
	if algorithm == nil {
		return nil, nil
	}
	backup := &archive.KeyBackup{Rooms: map[string]json.RawMessage{}}
	if err := json.Unmarshal(algorithm, backup); err != nil || backup.Algorithm == "" || !json.Valid(backup.AuthData) {
		return nil, errors.New("invalid key-backup metadata")
	}
	rooms := map[string]map[string]json.RawMessage{}
	prefix := user + "\xff" + strconv.FormatUint(latest, 10) + "\xff"
	for key, raw := range d.maps["backupkeyid_backup"] {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		room, session, ok := strings.Cut(strings.TrimPrefix(key, prefix), "\xff")
		if !ok || room == "" || session == "" || !json.Valid(raw) {
			return nil, errors.New("invalid backed-up room key")
		}
		if rooms[room] == nil {
			rooms[room] = map[string]json.RawMessage{}
		}
		rooms[room][session] = raw
	}
	for room, sessions := range rooms {
		raw, err := json.Marshal(map[string]any{"sessions": sessions})
		if err != nil {
			return nil, err
		}
		backup.Rooms[room] = raw
	}
	return backup, nil
}

func recoverVerifications(ctx context.Context, dir string, u *archive.User) error {
	if u.CrossSigning == nil || len(u.CrossSigning.UserSigning) == 0 {
		return nil
	}
	keyID, err := keyID(u.CrossSigning.UserSigning)
	if err != nil {
		return err
	}
	u.Verified = map[string]json.RawMessage{}
	used := 0
	return walkTuwunelScan(ctx, filepath.Join(dir, "keyid_key.txt"), func(_ string, raw []byte, _ tuwunelValueRef) error {
		var key struct {
			UserID     string                       `json:"user_id"`
			Usage      []string                     `json:"usage"`
			Signatures map[string]map[string]string `json:"signatures"`
		}
		if err := json.Unmarshal(raw, &key); err != nil {
			return errors.New("invalid device or cross-signing key")
		}
		signature := key.Signatures[u.UserID][keyID]
		if !slices.Equal(key.Usage, []string{"master"}) || signature == "" {
			return nil
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
		body["signatures"], _ = json.Marshal(map[string]map[string]string{u.UserID: {keyID: signature}})
		delete(body, "unsigned")
		used += len(raw) + 128
		if used > maxAccountRecoveryBytes {
			return errors.New("account verifications exceed the 32 MiB recovery limit")
		}
		u.Verified[key.UserID], err = json.Marshal(body)
		return err
	})
}

func recoveredRoomMember(ctx context.Context, a *archive.Archive, room, user string) (json.RawMessage, error) {
	f, err := os.Open(filepath.Join(a.RoomDir(room), "room.json"))
	if err != nil {
		return nil, fmt.Errorf("joined room %s missing from archive: %w", room, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if key != "state" {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		for dec.More() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var event struct {
				Type     string          `json:"type"`
				StateKey string          `json:"state_key"`
				Content  json.RawMessage `json:"content"`
			}
			if err := dec.Decode(&event); err != nil {
				return nil, err
			}
			if event.Type == "m.room.member" && event.StateKey == user {
				return event.Content, nil
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("joined room %s has no archived membership for %s", room, user)
}

func recoverAccountAvatar(a *archive.Archive, u *archive.User) error {
	if u.AvatarURL == "" || slices.ContainsFunc(u.Media, func(m archive.Media) bool { return m.MXC == u.AvatarURL }) {
		return nil
	}
	server, err := a.ReadServer()
	if err != nil || server == nil {
		return err
	}
	for _, media := range server.Media {
		if media.MXC != u.AvatarURL {
			continue
		}
		media.File, err = filepath.Rel(a.UserDir(u.UserID), filepath.Join(a.Dir, media.File))
		if err != nil {
			return err
		}
		u.Media = append(u.Media, media)
		break
	}
	return nil
}
