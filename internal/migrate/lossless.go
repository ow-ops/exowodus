package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
		if user.Deactivated && im.DeactivatedIDOnly {
			continue
		}
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
	return im.CheckLosslessImportContext(context.Background(), users, rooms, server, hasRelay)
}

func (im *Importer) CheckLosslessImportContext(ctx context.Context, users []*archive.User, rooms []*archive.ArchivedRoom, server *archive.Server, hasRelay bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	im.SetArchiveOnlyRooms(rooms)
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
	if !hasRelay {
		for _, room := range rooms {
			if !room.ArchiveOnly && !im.Archive.IsRoomSkipped(room.RoomID) {
				failures = append(failures, errors.New("lossless room import requires --relay-name"))
				break
			}
		}
	}
	for _, u := range users {
		if u.Deactivated {
			if !im.DeactivatedIDOnly {
				failures = append(failures, fmt.Errorf("%s: full deactivated-account data restoration is not implemented; use --deactivated-id-only to reserve its ID without restoring account data", u.UserID))
			} else {
				secrets, err := im.Archive.ReadSecrets(u.UserID)
				hasSecrets := secrets != nil && (secrets.PasswordHash != "" || len(secrets.Tokens)+len(secrets.Devices)+len(secrets.OneTimeKeys)+len(secrets.FallbackKeys)+len(secrets.Pushers) > 0)
				_, backupErr := os.Stat(filepath.Join(im.Archive.UserDir(u.UserID), "key_backup.json"))
				hasBackup := !errors.Is(backupErr, os.ErrNotExist)
				if err != nil || hasBackup || hasSecrets || im.protectedDeactivated[u.UserID] || len(u.Devices) > 0 || u.CrossSigning != nil || u.Dehydrated != nil {
					failures = append(failures, fmt.Errorf("%s: deactivated account has login or device data; ID-only restoration refused; run repair-tuwunel-accounts with the original backup for passwordless Tuwunel accounts", u.UserID))
				}
			}
		}
		if !u.Deactivated {
			if secrets, err := im.Archive.ReadSecrets(u.UserID); err != nil || secrets == nil {
				failures = append(failures, fmt.Errorf("%s: database secrets required: %v", u.UserID, err))
			}
		}
		for _, r := range u.Rooms {
			if im.roomLeftInArchive(r.RoomID) {
				continue
			}
			if _, omitted := im.omittedEvents[r.RoomID][r.PrivateReceipt]; r.PrivateReceipt != "" && !omitted && !im.SkipPrivateReceipts {
				failures = append(failures, fmt.Errorf("%s: private receipt in %s cannot be preserved on backfilled events", u.UserID, r.RoomID))
			}
		}
		if len(u.Emails) > 1 {
			failures = append(failures, fmt.Errorf("%s: destination supports only one email", u.UserID))
		}
	}
	for i, room := range rooms {
		if err := ctx.Err(); err != nil {
			return err
		}
		if im.Archive.IsRoomSkipped(room.RoomID) {
			continue
		}
		if room.ArchiveOnly {
			if !im.ArchiveDepartedRooms {
				failures = append(failures, fmt.Errorf("%s: rooms without joined local users cannot currently be restored; use --archive-departed-rooms to retain them offline", room.RoomID))
			}
			continue
		}
		slog.Info("checking original room events", "room", room.RoomID, "position", i+1, "rooms", len(rooms))
		if err := im.checkArchivedEventIDs(ctx, room); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures = append(failures, fmt.Errorf("%s: original event IDs cannot be preserved: %w", room.RoomID, err))
		}
	}
	if server != nil {
		for _, limitation := range server.Limitations {
			if table, count, ok := outgoingLimitation(limitation); ok && im.outboxSummary != nil && im.outboxSummary.Rows[table] == count {
				continue
			}
			if im.SkipPrivateReceipts && limitation == "private read receipts on backfilled events cannot currently be restored" {
				continue
			}
			if im.SkipThreadedReceipts && limitation == threadedReceiptLimitation {
				continue
			}
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

func (im *Importer) checkArchivedEventIDs(ctx context.Context, room *archive.ArchivedRoom) error {
	if !relay.SupportsVersion(room.Version) {
		return fmt.Errorf("unsupported room version %q", room.Version)
	}
	seen := map[string]bool{}
	for raw, err := range im.Archive.RoomPDUEvents(ctx, room.RoomID) {
		if err != nil {
			return err
		}
		var event relay.EventJSON
		if err := json.Unmarshal(raw, &event); err != nil {
			return err
		}
		if event.EventID == "" || seen[event.EventID] {
			return errors.New("missing or duplicate original event ID")
		}
		if err := checkEventID(event, room.Version); err != nil {
			return err
		}
		seen[event.EventID] = true
	}
	if len(seen) == 0 {
		return errors.New("room has no original events")
	}
	return nil
}

func (im *Importer) SetArchiveOnlyRooms(rooms []*archive.ArchivedRoom) {
	im.archiveOnlyRooms = map[string]bool{}
	if im.ArchiveDepartedRooms {
		for _, room := range rooms {
			if room.ArchiveOnly {
				im.archiveOnlyRooms[room.RoomID] = true
			}
		}
	}
}

func (im *Importer) roomLeftInArchive(roomID string) bool {
	return im.Archive.IsRoomSkipped(roomID) || im.archiveOnlyRooms[roomID]
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
