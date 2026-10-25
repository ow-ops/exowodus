package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
)

func (im *Importer) VerifySessions(ctx context.Context, users []*archive.User) []Failure {
	sessions, err := im.Archive.Sessions()
	if err != nil {
		return []Failure{{Step: "sessions", Error: err.Error()}}
	}
	var failures []Failure
	checked := map[string]error{}
	for _, user := range users {
		secrets, err := im.Archive.ReadSecrets(user.UserID)
		if err != nil || secrets == nil {
			failures = append(failures, Failure{Step: "sessions", Target: user.UserID, Error: "source login data unavailable"})
			continue
		}
		for _, token := range secrets.Tokens {
			session, ok := sessions[token.Token]
			target := user.UserID + "/" + token.DeviceID
			if !ok || session.UserID != user.UserID || session.DeviceID != token.DeviceID || session.Refresh != token.Refresh || session.Token == "" {
				failures = append(failures, Failure{Step: "sessions", Target: target, Error: "source token has no matching proxy session"})
				continue
			}
			key := target + "\x00" + session.Token
			if _, ok := checked[key]; !ok {
				who, err := mx.WithToken(im.Dest, session.Token).Whoami(ctx)
				if err == nil && (string(who.UserID) != user.UserID || string(who.DeviceID) != token.DeviceID) {
					err = errors.New("destination session belongs to a different user or device")
				}
				checked[key] = err
			}
			if err := checked[key]; err != nil {
				failures = append(failures, Failure{Step: "sessions", Target: target, Error: "destination session verification failed"})
			}
		}
	}
	return failures
}

// Empty tables still require a scan file.
func (d *TuwunelDump) CheckLosslessMaps() error {
	if err := d.CheckRelayMaps(); err != nil {
		return err
	}
	for _, name := range []string{"userdeviceid_metadata", "onetimekeyid4225_otk", "userdeviceidalgorithm_fallback", "senderkey_pusher", "pushkey_deviceid", "todeviceid_events", "bannedroomids", "alias_roomid", "servercurrentevent_data", "servernameevent_data", "mediaid_file", "mediaid_lazy", "mediaid_lazycontent", "readreceiptid_readreceipt", "roomuserid_privateread"} {
		if d.maps[name] == nil {
			return fmt.Errorf("--require-lossless requires %s.txt, including when the table is empty", name)
		}
	}
	return nil
}

// CheckLosslessImport runs before creating accounts or changing the target.
func (im *Importer) CheckLosslessImport(users []*archive.User, rooms []*archive.ArchivedRoom, server *archive.Server, hasRelay bool) error {
	slog.Info("checking import preservation", "users", len(users), "rooms", len(rooms))
	var failures []error
	for _, room := range rooms {
		if im.Archive.IsRoomSkipped(room.RoomID) {
			continue
		}
		if len(room.OmittedEvents) > 0 && (server == nil || !server.HistoryAtCheckpoint) {
			failures = append(failures, fmt.Errorf("%s: omitted events require checkpoint history", room.RoomID))
		}
		im.recordOmittedEvents(room)
	}
	if !im.Archive.Manifest.RequireLossless {
		failures = append(failures, errors.New("archive lacks preservation checks; re-export with --require-lossless"))
	}
	if im.Admin == nil {
		return errors.New("--require-lossless requires --to-admin-token")
	}
	if im.DestPassword != "" || im.DestToken != "" {
		failures = append(failures, errors.New("preserving source passwords requires generated credentials; omit --to-password and --to-token"))
	}
	if im.Admin.ServerName() != im.Archive.Manifest.ServerName {
		failures = append(failures, errors.New("lossless import requires the same server name"))
	}
	if len(rooms) > 0 && !hasRelay {
		failures = append(failures, errors.New("lossless room import requires --relay-name"))
	}
	for _, u := range users {
		if u.Deactivated {
			failures = append(failures, fmt.Errorf("%s: full deactivated-account data restoration is not implemented", u.UserID))
		}
		if !u.Deactivated {
			if secrets, err := im.Archive.ReadSecrets(u.UserID); err != nil || secrets == nil {
				failures = append(failures, fmt.Errorf("%s: database secrets required: %v", u.UserID, err))
			}
		}
		for _, r := range u.Rooms {
			if im.Archive.IsRoomSkipped(r.RoomID) {
				continue
			}
			if _, omitted := im.omittedEvents[r.RoomID][r.PrivateReceipt]; r.PrivateReceipt != "" && !omitted {
				failures = append(failures, fmt.Errorf("%s: private receipt in %s cannot be preserved on backfilled events", u.UserID, r.RoomID))
			}
		}
		if len(u.Emails) > 1 {
			failures = append(failures, fmt.Errorf("%s: destination supports only one email", u.UserID))
		}
	}
	for i, room := range rooms {
		if im.Archive.IsRoomSkipped(room.RoomID) {
			continue
		}
		if room.ArchiveOnly {
			failures = append(failures, fmt.Errorf("%s: rooms without joined local users cannot currently be restored", room.RoomID))
			continue
		}
		slog.Info("checking original room events", "room", room.RoomID, "position", i+1, "rooms", len(rooms))
		var data relay.RoomData
		ok, err := im.Archive.ReadRoomPDUs(room.RoomID, &data)
		if err != nil || !ok {
			failures = append(failures, fmt.Errorf("%s: original PDUs required: %v", room.RoomID, err))
			continue
		}
		if !relay.SupportsVersion(room.Version) || checkEventIDs(data.Events, room.Version) != 0 {
			failures = append(failures, fmt.Errorf("%s: original event IDs cannot be preserved", room.RoomID))
		}
	}
	if server != nil {
		for _, limitation := range server.Limitations {
			failures = append(failures, errors.New(limitation))
		}
		for _, message := range server.ToDevice {
			if !strings.HasSuffix(message.Sender, ":"+im.Archive.Manifest.ServerName) {
				if err := archive.ValidateProxyInboxMessage(message, im.Archive.Manifest.ServerName); err != nil {
					failures = append(failures, err)
				}
			}
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("lossless import blocked: %w", errors.Join(failures...))
	}
	slog.Info("import preservation checks passed")
	return nil
}

func (im *Importer) recordOmittedEvents(room *archive.ArchivedRoom) {
	if len(room.OmittedEvents) == 0 {
		return
	}
	if im.omittedEvents == nil {
		im.omittedEvents = map[string]map[string]string{}
	}
	im.omittedEvents[room.RoomID] = room.OmittedEvents
}

func hasThreadReceipt(v any) bool {
	switch value := v.(type) {
	case map[string]any:
		if thread, ok := value["thread_id"].(string); ok && thread != "" && thread != "main" {
			return true
		}
		for _, child := range value {
			if hasThreadReceipt(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if hasThreadReceipt(child) {
				return true
			}
		}
	}
	return false
}

// Redactions preserve event IDs, so compare content as well.
func originalEventFields(raw json.RawMessage) (map[string]any, error) {
	var event map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&event); err != nil {
		return nil, err
	}
	fields := map[string]any{}
	for _, k := range []string{"type", "sender", "origin_server_ts", "state_key", "content", "redacts"} {
		if v, ok := event[k]; ok {
			fields[k] = v
		}
	}
	// Client APIs duplicate redacts in content.redacts for compatibility.
	if fields["type"] == "m.room.redaction" {
		content, ok := fields["content"].(map[string]any)
		if !ok {
			return fields, nil
		}
		top, hasTop := fields["redacts"].(string)
		nested, hasNested := content["redacts"].(string)
		if value, exists := fields["redacts"]; exists && value != nil && !hasTop {
			return nil, errors.New("redaction target must be a string")
		}
		if value, exists := content["redacts"]; exists && value != nil && !hasNested {
			return nil, errors.New("redaction target must be a string")
		}
		if hasTop && hasNested && top != nested {
			return nil, errors.New("redaction event has conflicting targets")
		}
		if hasNested {
			fields["redacts"] = nested
			delete(content, "redacts")
		}
	}
	return fields, nil
}
