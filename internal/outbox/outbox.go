// Package outbox retains federation deliveries across a homeserver migration.
package outbox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
	_ "modernc.org/sqlite"
)

const FileName = "federation-outbox.sqlite"

type Store struct{ db *sql.DB }

type Summary struct {
	ServerName    string         `json:"server_name"`
	SourceHash    string         `json:"source_hash"`
	Rows          map[string]int `json:"rows"`
	ExpiredTyping int            `json:"expired_typing"`
	OmittedEvents int            `json:"omitted_events"`
}

func Open(dir string) (*Store, error) {
	path, err := filepath.Abs(filepath.Join(dir, FileName))
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if filepath.VolumeName(path) != "" && u.Path[0] != '/' {
		u.Path = "/" + u.Path
	}
	db, err := sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(10000)&_pragma=synchronous(FULL)&_pragma=journal_mode(WAL)&_pragma=cache_size(-2048)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries (id INTEGER PRIMARY KEY, destination TEXT NOT NULL, kind TEXT NOT NULL, event_id TEXT NOT NULL, payload BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS deliveries_destination ON deliveries(destination, id);
CREATE INDEX IF NOT EXISTS deliveries_destination_kind ON deliveries(destination, kind DESC, id);
CREATE TABLE IF NOT EXISTS destinations (name TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, transaction_id TEXT, request BLOB, entries TEXT, last_error TEXT);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Summary(ctx context.Context) (*Summary, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='ready'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var summary Summary
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

// Prepare publishes the queue only after every source record has been checked.
func (s *Store) Prepare(ctx context.Context, build func(*sql.Tx) (*Summary, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	summary, err := build(tx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO destinations(name) SELECT DISTINCT destination FROM deliveries`); err != nil {
		return err
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES ('ready',?)`, string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

func Enqueue(ctx context.Context, tx *sql.Tx, destination, kind, eventID string, payload []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO deliveries(destination,kind,event_id,payload) VALUES (?,?,?,?)`, destination, kind, eventID, payload)
	return err
}

type Batch struct {
	Request federation.ReqSendTransaction
	entries []int64
	pduIDs  []id.EventID
}

// Next saves the transaction before sending, so a lost response reuses its ID.
func (s *Store) Next(ctx context.Context, origin string, now time.Time) (*Batch, error) {
	var destination string
	var txnID, raw, entries sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT name,transaction_id,request,entries FROM destinations WHERE next_attempt<=? AND EXISTS(SELECT 1 FROM deliveries WHERE destination=name) ORDER BY next_attempt,name LIMIT 1`, now.UnixMilli()).Scan(&destination, &txnID, &raw, &entries)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b := &Batch{}
	if txnID.Valid {
		if err := json.Unmarshal([]byte(raw.String), &b.Request); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(entries.String), &b.entries); err != nil {
			return nil, err
		}
		b.Request.TxnID = txnID.String
		return b, s.loadPDUEventIDs(ctx, b)
	}
	b.Request = federation.ReqSendTransaction{Destination: destination, Origin: origin, OriginServerTS: jsontime.UM(now), PDUs: []federation.PDU{}}
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,event_id,payload FROM deliveries WHERE destination=? ORDER BY kind DESC,id LIMIT 50`, destination)
	if err != nil {
		return nil, err
	}
	size := 0
	for rows.Next() {
		var entryID int64
		var kind, eventID string
		var payload []byte
		if err := rows.Scan(&entryID, &kind, &eventID, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		if size+len(payload) > 512<<10 && len(b.entries) > 0 {
			break
		}
		b.entries = append(b.entries, entryID)
		size += len(payload)
		if kind == "PDU" {
			b.pduIDs = append(b.pduIDs, id.EventID(eventID))
			b.Request.PDUs = append(b.Request.PDUs, json.RawMessage(payload))
		} else {
			b.Request.EDUs = append(b.Request.EDUs, json.RawMessage(payload))
		}
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	if len(b.entries) == 0 {
		return nil, errors.New("empty pending federation transaction")
	}
	b.Request.TxnID = "exowodus-" + rand.Text()
	request, err := json.Marshal(b.Request)
	if err != nil {
		return nil, err
	}
	ids, err := json.Marshal(b.entries)
	if err != nil {
		return nil, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE destinations SET transaction_id=?,request=?,entries=? WHERE name=?`, b.Request.TxnID, request, string(ids), destination)
	return b, err
}

func (s *Store) loadPDUEventIDs(ctx context.Context, b *Batch) error {
	if len(b.entries) == 0 {
		return errors.New("pending federation transaction has no queue entries")
	}
	args := make([]any, len(b.entries))
	for i, entry := range b.entries {
		args[i] = entry
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	rows, err := s.db.QueryContext(ctx, `SELECT event_id FROM deliveries WHERE kind='PDU' AND id IN (`+placeholders+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var eventID id.EventID
		if err := rows.Scan(&eventID); err != nil {
			return err
		}
		b.pduIDs = append(b.pduIDs, eventID)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(b.pduIDs) != len(b.Request.PDUs) {
		return errors.New("pending federation transaction no longer matches its queued PDUs")
	}
	return nil
}

func (s *Store) Acknowledge(ctx context.Context, b *Batch) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range b.entries {
		if _, err := tx.ExecContext(ctx, `DELETE FROM deliveries WHERE id=?`, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE destinations SET transaction_id=NULL,request=NULL,entries=NULL,attempts=0,next_attempt=0,last_error=NULL WHERE name=?`, b.Request.Destination); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Retry(ctx context.Context, b *Batch, now time.Time, cause error, rejected bool) error {
	var attempts int
	if err := s.db.QueryRowContext(ctx, `SELECT attempts FROM destinations WHERE name=?`, b.Request.Destination).Scan(&attempts); err != nil {
		return err
	}
	delay := min(time.Minute*time.Duration(1<<min(attempts, 6)), time.Hour)
	txnID := b.Request.TxnID
	// A returned PDU error may be cached under the old transaction ID.
	if rejected {
		txnID = "exowodus-" + rand.Text()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE destinations SET transaction_id=?,attempts=attempts+1,next_attempt=?,last_error=? WHERE name=?`, txnID, now.Add(delay).UnixMilli(), cause.Error(), b.Request.Destination)
	return err
}

func (s *Store) Pending(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deliveries`).Scan(&count)
	return count, err
}

type Sender interface {
	SendTransaction(context.Context, *federation.ReqSendTransaction) (*federation.RespSendTransaction, error)
}

func (s *Store) Deliver(ctx context.Context, origin string, sender Sender) (bool, error) {
	b, err := s.Next(ctx, origin, time.Now())
	if err != nil || b == nil {
		return false, err
	}
	slog.Info("sending archived federation transaction", "server", b.Request.Destination, "pdus", len(b.Request.PDUs), "edus", len(b.Request.EDUs))
	attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
	response, sendErr := sender.SendTransaction(attempt, &b.Request)
	cancel()
	rejected := false
	if sendErr == nil {
		if response == nil {
			sendErr = errors.New("empty federation response")
		} else {
			for _, eventID := range b.pduIDs {
				if _, ok := response.PDUs[eventID]; !ok {
					sendErr = fmt.Errorf("event %s: missing federation acknowledgement", eventID)
					rejected = true
					break
				}
			}
			for event, result := range response.PDUs {
				if result.Error != "" {
					sendErr = fmt.Errorf("event %s: %s", event, result.Error)
					rejected = true
					break
				}
			}
		}
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if sendErr != nil {
		if err := s.Retry(ctx, b, time.Now(), sendErr, rejected); err != nil {
			return false, err
		}
		return false, fmt.Errorf("federation delivery to %s retained for retry: %w", b.Request.Destination, sendErr)
	}
	err = s.Acknowledge(ctx, b)
	return err == nil, err
}
