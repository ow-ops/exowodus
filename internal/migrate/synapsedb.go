package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"exowodus/internal/archive"
	"exowodus/internal/relay"
)

// SynapseDB reads what no Synapse API exposes.
type SynapseDB struct {
	db *sql.DB
}

func OpenSynapseDB(ctx context.Context, dsn string) (*SynapseDB, error) {
	driver, source := "sqlite", "file:"+dsn+"?mode=ro&_pragma=busy_timeout(10000)"
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		driver, source = "pgx", dsn
	}
	db, err := sql.Open(driver, source)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("synapse database: %w", err)
	}
	return &SynapseDB{db: db}, nil
}

func (d *SynapseDB) Close() error { return d.db.Close() }

func (d *SynapseDB) eachRow(ctx context.Context, query string, scan func(*sql.Rows) error, args ...any) error {
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (d *SynapseDB) Secrets(ctx context.Context, userID string) (*archive.Secrets, error) {
	s := &archive.Secrets{}
	var hash sql.NullString
	err := d.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE name = $1`, userID).Scan(&hash)
	if err != nil {
		return nil, fmt.Errorf("password hash: %w", err)
	}
	s.PasswordHash = hash.String

	now := time.Now().UnixMilli()
	queries := []struct {
		refresh bool
		query   string
	}{
		// Tokens minted by the admin "login as user" API have puppets_user_id.
		{false, `SELECT token, device_id FROM access_tokens
			WHERE user_id = $1 AND device_id IS NOT NULL AND puppets_user_id IS NULL
			AND (valid_until_ms IS NULL OR valid_until_ms > $2)`},
		{true, `SELECT token, device_id FROM refresh_tokens
			WHERE user_id = $1 AND next_token_id IS NULL
			AND (expiry_ts IS NULL OR expiry_ts > $2)`},
	}
	for _, q := range queries {
		err := d.eachRow(ctx, q.query, func(rows *sql.Rows) error {
			t := archive.Token{Refresh: q.refresh}
			if err := rows.Scan(&t.Token, &t.DeviceID); err != nil {
				return err
			}
			s.Tokens = append(s.Tokens, t)
			return nil
		}, userID, now)
		if err != nil {
			return nil, fmt.Errorf("tokens: %w", err)
		}
	}
	err = d.eachRow(ctx, `SELECT COALESCE(p.device_id, a.device_id), p.kind, p.app_id, p.app_display_name,
			p.device_display_name, p.pushkey, p.profile_tag, p.lang, p.data
		FROM pushers p LEFT JOIN access_tokens a ON a.id = p.access_token
		WHERE p.user_name = $1 AND COALESCE(p.enabled, TRUE)`, func(rows *sql.Rows) error {
		var device, lang, data sql.NullString
		var kind, appID, appName, deviceName, pushkey, profileTag string
		if err := rows.Scan(&device, &kind, &appID, &appName, &deviceName, &pushkey, &profileTag, &lang, &data); err != nil {
			return err
		}
		body := map[string]any{
			"kind": kind, "app_id": appID, "app_display_name": appName, "device_display_name": deviceName,
			"pushkey": pushkey, "profile_tag": profileTag, "lang": lang.String, "data": json.RawMessage("{}"),
		}
		if data.Valid && data.String != "" {
			body["data"] = json.RawMessage(data.String)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		s.Pushers = append(s.Pushers, archive.Pusher{DeviceID: device.String, Body: raw})
		return nil
	}, userID)
	if err != nil {
		return nil, fmt.Errorf("pushers: %w", err)
	}
	err = d.eachRow(ctx, `SELECT device_id FROM devices WHERE user_id = $1 AND NOT hidden`, func(rows *sql.Rows) error {
		var deviceID string
		if err := rows.Scan(&deviceID); err != nil {
			return err
		}
		s.Devices = append(s.Devices, deviceID)
		return nil
	}, userID)
	if err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}
	if s.OneTimeKeys, err = d.deviceKeys(ctx, `SELECT device_id, algorithm, key_id, key_json FROM e2e_one_time_keys_json WHERE user_id = $1`, userID); err != nil {
		return nil, fmt.Errorf("one-time keys: %w", err)
	}
	if s.FallbackKeys, err = d.deviceKeys(ctx, `SELECT device_id, algorithm, key_id, key_json FROM e2e_fallback_keys_json WHERE user_id = $1 AND NOT used`, userID); err != nil {
		return nil, fmt.Errorf("fallback keys: %w", err)
	}
	return s, nil
}

func (d *SynapseDB) deviceKeys(ctx context.Context, query, userID string) (map[string]map[string]json.RawMessage, error) {
	keys := map[string]map[string]json.RawMessage{}
	err := d.eachRow(ctx, query, func(rows *sql.Rows) error {
		var device, algorithm, keyID, keyJSON string
		if err := rows.Scan(&device, &algorithm, &keyID, &keyJSON); err != nil {
			return err
		}
		if keys[device] == nil {
			keys[device] = map[string]json.RawMessage{}
		}
		keys[device][algorithm+":"+keyID] = json.RawMessage(keyJSON)
		return nil
	}, userID)
	return keys, err
}

// RoomRelayData returns non-rejected events oldest first, with Synapse's
// resolved state after each.
func (d *SynapseDB) RoomRelayData(ctx context.Context, roomID string) (*relay.RoomData, error) {
	data := &relay.RoomData{EventGroups: map[string]int64{}, Groups: map[int64]relay.Group{}, CurrentState: map[string]string{}}
	queries := []struct {
		query string
		scan  func(*sql.Rows) error
	}{
		{`SELECT j.event_id, j.json FROM event_json j
			JOIN events e ON e.event_id = j.event_id
			LEFT JOIN rejections r ON r.event_id = j.event_id
			WHERE j.room_id = $1 AND r.event_id IS NULL AND e.rejection_reason IS NULL
			ORDER BY e.topological_ordering, e.stream_ordering`,
			func(rows *sql.Rows) error {
				var eventID, raw string
				if err := rows.Scan(&eventID, &raw); err != nil {
					return err
				}
				data.Events = append(data.Events, relay.EventJSON{EventID: eventID, PDU: json.RawMessage(raw)})
				return nil
			}},
		{`SELECT s.event_id, s.state_group FROM event_to_state_groups s JOIN events e ON e.event_id = s.event_id WHERE e.room_id = $1`,
			func(rows *sql.Rows) error {
				var eventID string
				var g int64
				if err := rows.Scan(&eventID, &g); err != nil {
					return err
				}
				data.EventGroups[eventID] = g
				return nil
			}},
		{`SELECT state_group, type, state_key, event_id FROM state_groups_state WHERE room_id = $1`,
			func(rows *sql.Rows) error {
				var g int64
				var typ, key, eventID string
				if err := rows.Scan(&g, &typ, &key, &eventID); err != nil {
					return err
				}
				grp := data.Groups[g]
				if grp.State == nil {
					grp.State = map[string]string{}
				}
				grp.State[relay.StateKey(typ, key)] = eventID
				data.Groups[g] = grp
				return nil
			}},
		{`SELECT e.state_group, e.prev_state_group FROM state_group_edges e JOIN state_groups g ON g.id = e.state_group WHERE g.room_id = $1`,
			func(rows *sql.Rows) error {
				var g, prev int64
				if err := rows.Scan(&g, &prev); err != nil {
					return err
				}
				grp := data.Groups[g]
				grp.Prev = prev
				data.Groups[g] = grp
				return nil
			}},
		{`SELECT event_id FROM event_forward_extremities WHERE room_id = $1`,
			func(rows *sql.Rows) error {
				var eventID string
				if err := rows.Scan(&eventID); err != nil {
					return err
				}
				data.Extremities = append(data.Extremities, eventID)
				return nil
			}},
		{`SELECT type, state_key, event_id FROM current_state_events WHERE room_id = $1`,
			func(rows *sql.Rows) error {
				var typ, key, eventID string
				if err := rows.Scan(&typ, &key, &eventID); err != nil {
					return err
				}
				data.CurrentState[relay.StateKey(typ, key)] = eventID
				return nil
			}},
	}
	for _, q := range queries {
		if err := d.eachRow(ctx, q.query, q.scan, roomID); err != nil {
			return nil, fmt.Errorf("room %s: %w", roomID, err)
		}
	}
	return data, nil
}

// ServerKeys returns the key responses Synapse cached for other servers.
func (d *SynapseDB) ServerKeys(ctx context.Context) (map[string][]json.RawMessage, error) {
	keys := map[string][]json.RawMessage{}
	err := d.eachRow(ctx, `SELECT server_name, key_json FROM server_keys_json`, func(rows *sql.Rows) error {
		var server string
		var raw []byte
		if err := rows.Scan(&server, &raw); err != nil {
			return err
		}
		keys[server] = append(keys[server], json.RawMessage(raw))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("server keys: %w", err)
	}
	return keys, nil
}

func (d *SynapseDB) Aliases(ctx context.Context) (map[string]string, error) {
	aliases := map[string]string{}
	err := d.eachRow(ctx, `SELECT room_alias, room_id FROM room_aliases`, func(rows *sql.Rows) error {
		var alias, room string
		if err := rows.Scan(&alias, &room); err != nil {
			return err
		}
		aliases[alias] = room
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("aliases: %w", err)
	}
	return aliases, nil
}

func (d *SynapseDB) BlockedRooms(ctx context.Context) ([]string, error) {
	var rooms []string
	err := d.eachRow(ctx, `SELECT room_id FROM blocked_rooms`, func(rows *sql.Rows) error {
		var roomID string
		if err := rows.Scan(&roomID); err != nil {
			return err
		}
		rooms = append(rooms, roomID)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("blocked rooms: %w", err)
	}
	return rooms, nil
}

// Reports tolerates older Synapse versions without room and user report tables.
func (d *SynapseDB) Reports(ctx context.Context) ([]archive.Report, error) {
	queries := []struct{ kind, query string }{
		{"event", `SELECT id, received_ts, user_id, room_id, event_id, '', COALESCE(reason, ''), COALESCE(content, '') FROM event_reports ORDER BY id`},
		{"room", `SELECT id, received_ts, user_id, room_id, '', '', reason, '' FROM room_reports ORDER BY id`},
		{"user", `SELECT id, received_ts, user_id, '', '', target_user_id, reason, '' FROM user_reports ORDER BY id`},
	}
	var reports []archive.Report
	for _, q := range queries {
		err := d.eachRow(ctx, q.query, func(rows *sql.Rows) error {
			r := archive.Report{Kind: q.kind}
			var content string
			if err := rows.Scan(&r.ID, &r.ReceivedTS, &r.Reporter, &r.RoomID, &r.EventID, &r.TargetUserID, &r.Reason, &content); err != nil {
				return err
			}
			if r.Reason == "" && content != "" {
				var c struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal([]byte(content), &c)
				r.Reason = c.Reason
			}
			reports = append(reports, r)
			return nil
		})
		if err != nil && !missingTable(err) {
			return nil, fmt.Errorf("%s reports: %w", q.kind, err)
		}
	}
	return reports, nil
}

func missingTable(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such table") || strings.Contains(msg, "does not exist")
}

// ToDevice includes messages queued for remote servers.
func (d *SynapseDB) ToDevice(ctx context.Context) ([]archive.ToDevice, error) {
	var out []archive.ToDevice
	err := d.eachRow(ctx, `SELECT stream_id, user_id, device_id, message_json FROM device_inbox ORDER BY stream_id`, func(rows *sql.Rows) error {
		var stream int64
		var raw string
		m := archive.ToDevice{}
		if err := rows.Scan(&stream, &m.Recipient, &m.DeviceID, &raw); err != nil {
			return err
		}
		var msg struct {
			Sender  string          `json:"sender"`
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			return fmt.Errorf("message %d: %w", stream, err)
		}
		m.Key = fmt.Sprintf("inbox/%d/%s/%s", stream, m.Recipient, m.DeviceID)
		m.Sender, m.Type, m.Content = msg.Sender, msg.Type, msg.Content
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("device inbox: %w", err)
	}
	err = d.eachRow(ctx, `SELECT stream_id, destination, messages_json FROM device_federation_outbox ORDER BY stream_id`, func(rows *sql.Rows) error {
		var stream int64
		var dest, raw string
		if err := rows.Scan(&stream, &dest, &raw); err != nil {
			return err
		}
		var edu struct {
			Sender   string                                `json:"sender"`
			Type     string                                `json:"type"`
			Messages map[string]map[string]json.RawMessage `json:"messages"`
		}
		if err := json.Unmarshal([]byte(raw), &edu); err != nil {
			return fmt.Errorf("message %d: %w", stream, err)
		}
		for _, user := range slices.Sorted(maps.Keys(edu.Messages)) {
			for _, device := range slices.Sorted(maps.Keys(edu.Messages[user])) {
				out = append(out, archive.ToDevice{
					Key:    fmt.Sprintf("outbox/%s/%d/%s/%s", dest, stream, user, device),
					Sender: edu.Sender, Type: edu.Type, Recipient: user, DeviceID: device,
					Content: edu.Messages[user][device],
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("device outbox: %w", err)
	}
	return out, nil
}
