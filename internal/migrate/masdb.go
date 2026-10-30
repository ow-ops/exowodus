package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

type MASDB struct {
	db *sql.DB
}

func OpenMASDB(ctx context.Context, dsn string) (*MASDB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("MAS database: %w", err)
	}
	return &MASDB{db: db}, nil
}

func (d *MASDB) Close() error { return d.db.Close() }

func (d *MASDB) addSecrets(ctx context.Context, userID string, s *archive.Secrets) error {
	username := mx.Localpart(userID)
	var hash sql.NullString
	var version sql.NullInt64
	err := d.db.QueryRowContext(ctx, `SELECT p.hashed_password, p.version FROM user_passwords p JOIN users u ON u.user_id = p.user_id
		WHERE u.username = $1 ORDER BY p.created_at DESC LIMIT 1`, username).Scan(&hash, &version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("password hash: %w", err)
	}
	if hash.Valid {
		s.PasswordHash, s.PasswordScheme, s.PasswordVersion = hash.String, archive.SchemeMAS, int(version.Int64)
	}

	queries := []struct {
		refresh, oauth bool
		query          string
	}{
		{false, false, `SELECT t.access_token, c.device_id FROM compat_access_tokens t
			JOIN compat_sessions c ON c.compat_session_id = t.compat_session_id
			JOIN users u ON u.user_id = c.user_id
			WHERE u.username = $1 AND c.finished_at IS NULL AND c.device_id IS NOT NULL
			AND (t.expires_at IS NULL OR t.expires_at > now())`},
		{true, false, `SELECT r.refresh_token, c.device_id FROM compat_refresh_tokens r
			JOIN compat_sessions c ON c.compat_session_id = r.compat_session_id
			JOIN users u ON u.user_id = c.user_id
			WHERE u.username = $1 AND c.finished_at IS NULL AND c.device_id IS NOT NULL AND r.consumed_at IS NULL`},
		{false, true, `SELECT t.access_token, array_to_string(s.scope_list, ' ') FROM oauth2_access_tokens t
			JOIN oauth2_sessions s ON s.oauth2_session_id = t.oauth2_session_id
			JOIN users u ON u.user_id = s.user_id
			WHERE u.username = $1 AND s.finished_at IS NULL AND t.revoked_at IS NULL
			AND (t.expires_at IS NULL OR t.expires_at > now())`},
		{true, true, `SELECT r.refresh_token, array_to_string(s.scope_list, ' ') FROM oauth2_refresh_tokens r
			JOIN oauth2_sessions s ON s.oauth2_session_id = r.oauth2_session_id
			JOIN users u ON u.user_id = s.user_id
			WHERE u.username = $1 AND s.finished_at IS NULL AND r.consumed_at IS NULL AND r.revoked_at IS NULL`},
	}
	for _, q := range queries {
		rows, err := d.db.QueryContext(ctx, q.query, username)
		if err != nil {
			return fmt.Errorf("sessions: %w", err)
		}
		if err := scanTokens(rows, q.refresh, q.oauth, s); err != nil {
			return fmt.Errorf("sessions: %w", err)
		}
	}
	return nil
}

func oauthDevice(scopes string) string {
	for _, scope := range strings.Fields(scopes) {
		for _, prefix := range []string{"urn:matrix:client:device:", "urn:matrix:org.matrix.msc2967.client:device:"} {
			if deviceID, ok := strings.CutPrefix(scope, prefix); ok {
				return deviceID
			}
		}
	}
	return ""
}

func scanTokens(rows *sql.Rows, refresh, oauth bool, s *archive.Secrets) error {
	defer rows.Close()
	for rows.Next() {
		t := archive.Token{Refresh: refresh, OAuth: oauth}
		var device string
		if err := rows.Scan(&t.Token, &device); err != nil {
			return err
		}
		if oauth {
			device = oauthDevice(device)
		}
		if t.DeviceID = device; t.DeviceID != "" {
			s.Tokens = append(s.Tokens, t)
		}
	}
	return rows.Err()
}
