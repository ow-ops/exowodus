package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"exowodus/internal/archive"

	"maunium.net/go/mautrix"
)

// Synapse refuses /sync for appservice accounts. Read their account data and
// pending memberships without logging into an existing encryption device.
func (d *SynapseDB) appserviceSync(ctx context.Context, userID string) (*mautrix.RespSync, error) {
	var global []any
	rooms := map[string]any{}
	roomEvents := map[string][]any{}
	if err := d.eachRow(ctx, `SELECT account_data_type, content FROM account_data WHERE user_id = $1`, func(rows *sql.Rows) error {
		var typ string
		var content string
		if err := rows.Scan(&typ, &content); err != nil {
			return err
		}
		global = append(global, map[string]any{"type": typ, "content": json.RawMessage(content)})
		return nil
	}, userID); err != nil {
		return nil, fmt.Errorf("bridge account data: %w", err)
	}
	if err := d.eachRow(ctx, `SELECT room_id, account_data_type, content FROM room_account_data WHERE user_id = $1`, func(rows *sql.Rows) error {
		var room, typ string
		var content string
		if err := rows.Scan(&room, &typ, &content); err != nil {
			return err
		}
		roomEvents[room] = append(roomEvents[room], map[string]any{"type": typ, "content": json.RawMessage(content)})
		return nil
	}, userID); err != nil {
		return nil, fmt.Errorf("bridge room account data: %w", err)
	}
	tags := map[string]map[string]json.RawMessage{}
	if err := d.eachRow(ctx, `SELECT room_id, tag, content FROM room_tags WHERE user_id = $1`, func(rows *sql.Rows) error {
		var room, tag string
		var content string
		if err := rows.Scan(&room, &tag, &content); err != nil {
			return err
		}
		if tags[room] == nil {
			tags[room] = map[string]json.RawMessage{}
		}
		tags[room][tag] = json.RawMessage(content)
		return nil
	}, userID); err != nil {
		return nil, fmt.Errorf("bridge room tags: %w", err)
	}
	for room, data := range tags {
		roomEvents[room] = append(roomEvents[room], map[string]any{"type": "m.tag", "content": map[string]any{"tags": data}})
	}
	for room, events := range roomEvents {
		rooms[room] = map[string]any{"account_data": map[string]any{"events": events}}
	}
	receipts := map[string]map[string]map[string]map[string]json.RawMessage{}
	if err := d.eachRow(ctx, `SELECT room_id, receipt_type, event_id, data FROM receipts_linearized WHERE user_id = $1 AND receipt_type IN ('m.read', 'm.read.private') AND (thread_id IS NULL OR thread_id = 'main')`, func(rows *sql.Rows) error {
		var room, typ, eventID string
		var data string
		if err := rows.Scan(&room, &typ, &eventID, &data); err != nil {
			return err
		}
		if receipts[room] == nil {
			receipts[room] = map[string]map[string]map[string]json.RawMessage{}
		}
		if receipts[room][eventID] == nil {
			receipts[room][eventID] = map[string]map[string]json.RawMessage{}
		}
		receipts[room][eventID][typ] = map[string]json.RawMessage{userID: json.RawMessage(data)}
		return nil
	}, userID); err != nil {
		return nil, fmt.Errorf("bridge read positions: %w", err)
	}
	for room, content := range receipts {
		if rooms[room] == nil {
			rooms[room] = map[string]any{}
		}
		rooms[room].(map[string]any)["ephemeral"] = map[string]any{"events": []any{map[string]any{"type": "m.receipt", "content": content}}}
	}
	invites, knocks := map[string]any{}, map[string]any{}
	if err := d.eachRow(ctx, `SELECT m.room_id, m.membership, e.json FROM local_current_membership m JOIN event_json e ON e.event_id = m.event_id WHERE m.user_id = $1 AND m.membership IN ('invite', 'knock')`, func(rows *sql.Rows) error {
		var room, membership string
		var raw string
		if err := rows.Scan(&room, &membership, &raw); err != nil {
			return err
		}
		if membership == "invite" {
			invites[room] = map[string]any{"invite_state": map[string]any{"events": []json.RawMessage{json.RawMessage(raw)}}}
		} else {
			knocks[room] = map[string]any{"knock_state": map[string]any{"events": []json.RawMessage{json.RawMessage(raw)}}}
		}
		return nil
	}, userID); err != nil {
		return nil, fmt.Errorf("bridge pending memberships: %w", err)
	}
	raw, err := json.Marshal(map[string]any{"account_data": map[string]any{"events": global}, "rooms": map[string]any{"join": rooms, "invite": invites, "knock": knocks}})
	if err != nil {
		return nil, err
	}
	var result mautrix.RespSync
	err = json.Unmarshal(raw, &result)
	return &result, err
}

// RecoverSynapseBridgeAccounts adds missing bot/device accounts without
// rewriting exported room history or existing imported accounts.
func RecoverSynapseBridgeAccounts(ctx context.Context, a *archive.Archive, admin *mautrix.Client, db *SynapseDB, bridges []*Bridge) (int, error) {
	lock, err := a.LockImport()
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	lock, err = a.LockAccountRepair()
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	if err := a.CheckExport(); err != nil {
		return 0, err
	}
	if admin == nil || admin.UserID.Homeserver() != a.Manifest.ServerName || db == nil || len(bridges) == 0 {
		return 0, errors.New("bridge account recovery requires the original Synapse server, its database and bridge registrations")
	}
	seen := map[string]bool{}
	for _, b := range bridges {
		if b == nil || b.sender == "" || seen[b.ID] {
			return 0, errors.New("bridge recovery requires distinct registrations with sender_localpart")
		}
		seen[b.ID] = true
	}
	users, err := SelectSynapseUsers(ctx, admin, nil, false, bridges...)
	if err != nil {
		return 0, err
	}
	server, err := a.ReadServer()
	if err != nil {
		return 0, err
	}
	if server == nil {
		server = &archive.Server{}
	}
	for _, b := range bridges {
		found := false
		for _, raw := range server.AppserviceRegistrations {
			old, err := parseBridge([]byte(raw), nil)
			if err != nil {
				return 0, err
			}
			if old.ID == b.ID {
				if !b.MatchesRegistration(old.registration) {
					return 0, fmt.Errorf("appservice %s differs from the archived registration", b.ID)
				}
				found = true
			}
		}
		if !found {
			server.AppserviceRegistrations = append(server.AppserviceRegistrations, b.registration)
		}
	}
	// Recovery may append to an archive containing other services. Verify all
	// archived queues before marking the source snapshot as drained.
	allBridges := make([]*Bridge, 0, len(server.AppserviceRegistrations))
	for _, raw := range server.AppserviceRegistrations {
		b, err := parseBridge([]byte(raw), nil)
		if err != nil {
			return 0, err
		}
		allBridges = append(allBridges, b)
	}
	if err := db.CheckAppserviceQueues(ctx, allBridges); err != nil {
		return 0, err
	}
	server.BridgeQueuesDrained = true
	exp := &Exporter{Archive: a, Admin: admin, DB: db}
	count := 0
	for _, u := range users {
		i := slices.IndexFunc(bridges, func(b *Bridge) bool { return b.ID == u.AppserviceID })
		if u.AppserviceID == "" || i < 0 {
			continue
		}
		if u.Deactivated {
			return count, fmt.Errorf("bridge account %s is deactivated on the source", u.UserID)
		}
		if old, err := a.ReadUser(u.UserID); err == nil {
			if old.AppserviceID != u.AppserviceID {
				return count, fmt.Errorf("%s already exists in the archive; refusing to replace its account data", u.UserID)
			}
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return count, err
		}
		err = func() error {
			if u.Locked {
				relock, err := UnlockTemporarily(ctx, admin, u.UserID)
				if err != nil {
					return err
				}
				defer relock()
			}
			sess, err := bridges[i].SourceSession(ctx, u)
			if err != nil {
				return err
			}
			_, err = exp.ExportUser(ctx, sess)
			return err
		}()
		if err != nil {
			return count, fmt.Errorf("recover bridge account %s: %w", u.UserID, err)
		}
		count++
	}
	return count, a.WriteServer(server)
}
