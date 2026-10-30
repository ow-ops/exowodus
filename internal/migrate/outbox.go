package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"exowodus/internal/archive"
	"exowodus/internal/outbox"
	"exowodus/internal/relay"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

var outgoingTables = []string{"servercurrentevent_data", "servernameevent_data"}

func outgoingLimitation(s string) (string, int, bool) {
	for _, table := range outgoingTables {
		var count int
		if _, err := fmt.Sscanf(s, table+" has %d pending deliveries; source queues must drain before lossless cutover", &count); err == nil && count > 0 && s == fmt.Sprintf("%s has %d pending deliveries; source queues must drain before lossless cutover", table, count) {
			return table, count, true
		}
	}
	return "", 0, false
}

// PrepareOutbox reuses the retained dump; the source server is not contacted.
func (im *Importer) PrepareOutbox(ctx context.Context, server *archive.Server, rooms []*archive.ArchivedRoom) error {
	if server == nil {
		return nil
	}
	needed := false
	for _, limitation := range server.Limitations {
		if _, _, ok := outgoingLimitation(limitation); ok {
			needed = true
		}
	}
	if !needed {
		return nil
	}
	if im.Admin == nil || im.Admin.ServerName() != im.Archive.Manifest.ServerName {
		return errors.New("pending federation deliveries require the same server name and --to-admin-token")
	}
	keyText, err := im.Archive.SigningKey()
	if err != nil {
		return err
	}
	key, err := federation.ParseSynapseKey(strings.TrimSpace(keyText))
	if err != nil {
		return fmt.Errorf("pending federation deliveries require the source signing key: %w", err)
	}
	var keys federation.ServerKeyResponse
	if _, err := im.Dest.MakeRequest(ctx, http.MethodGet, im.Dest.BuildURL(mautrix.BaseURLPath{"_matrix", "key", "v2", "server"}), nil, &keys); err != nil {
		return fmt.Errorf("check destination signing key: %w", err)
	}
	if keys.ServerName != im.Archive.Manifest.ServerName || keys.VerifyKeys[key.ID].Key != key.Pub {
		return errors.New("pending federation deliveries require the original server signing key on Continuwuity; stop Continuwuity, run exowodus restore-signing-key, restart it, and retry import with the same archive")
	}
	if err := keys.VerifySelfSignature(); err != nil {
		return fmt.Errorf("destination signing key response: %w", err)
	}
	store, err := outbox.Open(im.Archive.Dir)
	if err != nil {
		return err
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	hash := sha256.New()
	for _, table := range outgoingTables {
		hash.Write([]byte(table + "\x00"))
		f, err := os.Open(filepath.Join(im.Archive.Dir, "source", "tuwunel", table+".txt"))
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(hash, f)
		if err := errors.Join(copyErr, f.Close()); err != nil {
			return err
		}
	}
	sourceHash := hex.EncodeToString(hash.Sum(nil))
	if summary == nil {
		slog.Info("preparing pending federation deliveries")
		err = store.Prepare(ctx, func(tx *sql.Tx) (*outbox.Summary, error) {
			summary, err := im.buildOutbox(ctx, tx, rooms)
			if err == nil {
				summary.ServerName = im.Archive.Manifest.ServerName
				summary.SourceHash = sourceHash
			}
			return summary, err
		})
		if err != nil {
			return err
		}
		summary, err = store.Summary(ctx)
		if err != nil {
			return err
		}
	}
	if summary.ServerName != im.Archive.Manifest.ServerName || summary.SourceHash != sourceHash {
		return errors.New("federation outbox belongs to a different source checkpoint")
	}
	for _, limitation := range server.Limitations {
		if table, count, ok := outgoingLimitation(limitation); ok && summary.Rows[table] != count {
			return fmt.Errorf("%s: archived delivery count changed; expected %d, found %d", table, count, summary.Rows[table])
		}
	}
	if err := im.Archive.UpgradeFormat(); err != nil {
		return err
	}
	im.outboxSummary = summary
	pending, err := store.Pending(ctx)
	if err != nil {
		return err
	}
	slog.Info("pending federation deliveries retained for proxy retry", "pending", pending, "expired_typing", summary.ExpiredTyping)
	return nil
}

func (im *Importer) buildOutbox(ctx context.Context, tx *sql.Tx, rooms []*archive.ArchivedRoom) (*outbox.Summary, error) {
	dir := filepath.Join(im.Archive.Dir, "source", "tuwunel")
	summary := &outbox.Summary{Rows: map[string]int{}}
	pending := map[string][]string{}
	for _, table := range outgoingTables {
		err := walkTuwunelScan(ctx, filepath.Join(dir, table+".txt"), func(key string, value []byte, _ tuwunelValueRef) error {
			summary.Rows[table]++
			destination, tail, ok := strings.Cut(key, "\xff")
			if !ok || destination == "" || tail == "" || strings.ContainsAny(destination, "+$/?#@ \r\n") {
				return errors.New("outbound queue contains an invalid or unsupported non-federation destination")
			}
			if len(value) == 0 {
				pending[tail] = append(pending[tail], destination)
				return nil
			}
			var edu struct {
				Type    string          `json:"edu_type"`
				Content json.RawMessage `json:"content"`
			}
			if err := json.Unmarshal(value, &edu); err != nil || edu.Type == "" || len(edu.Content) == 0 || bytes.TrimSpace(edu.Content)[0] != '{' {
				return errors.New("outbound queue contains an invalid federation EDU")
			}
			if edu.Type == "m.typing" {
				summary.ExpiredTyping++
				return nil
			}
			return outbox.Enqueue(ctx, tx, destination, "EDU", "", value)
		})
		if err != nil {
			return nil, err
		}
	}
	versions := map[string]string{}
	omitted := map[string]map[string]string{}
	for _, room := range rooms {
		versions[room.RoomID] = room.Version
		omitted[room.RoomID] = room.OmittedEvents
	}
	// Keep payloads on disk while collecting room versions from create events.
	for _, table := range []string{"pduid_pdu", "eventid_outlierpdu"} {
		err := walkTuwunelScan(ctx, filepath.Join(dir, table+".txt"), func(key string, raw []byte, _ tuwunelValueRef) error {
			destinations := pending[key]
			if table != "pduid_pdu" {
				destinations = nil
			}
			if len(destinations) == 0 && !bytes.Contains(raw, []byte(`"m.room.create"`)) {
				return nil
			}
			var event struct {
				EventID string `json:"event_id"`
				RoomID  string `json:"room_id"`
				Type    string `json:"type"`
				Content struct {
					Version string `json:"room_version"`
				} `json:"content"`
			}
			if err := json.Unmarshal(raw, &event); err != nil {
				return err
			}
			if event.Type == "m.room.create" {
				version := event.Content.Version
				if version == "" {
					version = "1"
				}
				if event.RoomID == "" && id.RoomVersion(version).RoomIDIsCreateEventID() {
					eventID := event.EventID
					if eventID == "" && table == "eventid_outlierpdu" {
						eventID = key
					}
					if strings.HasPrefix(eventID, "$") {
						event.RoomID = "!" + strings.TrimPrefix(eventID, "$")
					}
				}
				if previous := versions[event.RoomID]; previous != "" && previous != version {
					return errors.New("queued event room version disagrees with archive")
				}
				versions[event.RoomID] = version
			}
			if len(destinations) == 0 {
				return nil
			}
			if event.EventID == "" || event.RoomID == "" {
				return errors.New("queued PDU has no event or room ID")
			}
			if _, skip := omitted[event.RoomID][event.EventID]; skip {
				summary.OmittedEvents += len(destinations)
				delete(pending, key)
				return nil
			}
			for _, destination := range destinations {
				if err := outbox.Enqueue(ctx, tx, destination, "PDU", event.EventID, raw); err != nil {
					return err
				}
			}
			delete(pending, key)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("%d queued PDUs are absent from the retained database checkpoint", len(pending))
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,event_id,payload FROM deliveries WHERE kind='PDU' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row int64
		var eventID string
		var raw []byte
		if err := rows.Scan(&row, &eventID, &raw); err != nil {
			return nil, err
		}
		var event struct {
			RoomID string `json:"room_id"`
			Type   string `json:"type"`
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, err
		}
		version := versions[event.RoomID]
		if event.RoomID == "" && event.Type == "m.room.create" {
			version = versions["!"+strings.TrimPrefix(eventID, "$")]
		}
		if err := checkEventID(relay.EventJSON{EventID: eventID, PDU: raw}, version); err != nil {
			return nil, fmt.Errorf("queued event %s could not be verified: %w", eventID, err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		delete(wire, "event_id")
		delete(wire, "unsigned")
		if event.Type == "m.room.create" && id.RoomVersion(version).RoomIDIsCreateEventID() {
			delete(wire, "room_id")
		}
		payload, err := json.Marshal(wire)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET payload=? WHERE id=?`, payload, row); err != nil {
			return nil, err
		}
	}
	return summary, rows.Err()
}
