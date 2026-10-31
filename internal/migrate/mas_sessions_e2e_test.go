//go:build e2e

package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"exowodus/internal/mx"
)

func TestRefreshMASSessionsPostgres(t *testing.T) {
	dsn := os.Getenv("EXOWODUS_MAS_TEST_DB")
	if dsn == "" {
		t.Skip("set EXOWODUS_MAS_TEST_DB to a PostgreSQL test database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// All fixture tables belong to this connection and disappear on close.
	db.SetMaxOpenConns(1)
	_, err = db.ExecContext(ctx, `
CREATE TEMP TABLE users (user_id text, username text);
CREATE TEMP TABLE compat_sessions (compat_session_id text, user_id text, device_id text, finished_at timestamptz);
CREATE TEMP TABLE compat_access_tokens (access_token text, compat_session_id text, expires_at timestamptz);
CREATE TEMP TABLE compat_refresh_tokens (refresh_token text, compat_session_id text, consumed_at timestamptz);
CREATE TEMP TABLE oauth2_sessions (oauth2_session_id text, user_id text, scope_list text[], finished_at timestamptz);
CREATE TEMP TABLE oauth2_access_tokens (access_token text, oauth2_session_id text, expires_at timestamptz, revoked_at timestamptz);
CREATE TEMP TABLE oauth2_refresh_tokens (refresh_token text, oauth2_session_id text, consumed_at timestamptz, revoked_at timestamptz);
INSERT INTO users VALUES ('alice', 'alice'), ('bob', 'bob');
INSERT INTO compat_sessions VALUES ('compat', 'alice', 'PHONE', NULL);
INSERT INTO compat_access_tokens VALUES ('compat-access', 'compat', now() + interval '1 hour'), ('compat-expired', 'compat', now() - interval '1 hour');
INSERT INTO compat_refresh_tokens VALUES ('compat-refresh', 'compat', NULL), ('compat-consumed', 'compat', now());
INSERT INTO oauth2_sessions VALUES
 ('oauth', 'alice', ARRAY['urn:matrix:client:api:*', 'urn:matrix:client:device:PHONE'], NULL),
 ('ended', 'alice', ARRAY['urn:matrix:client:device:PHONE'], now()),
 ('no-device', 'alice', ARRAY['openid'], NULL),
 ('other-user', 'bob', ARRAY['urn:matrix:client:device:PHONE'], NULL);
INSERT INTO oauth2_access_tokens VALUES
 ('oauth-access', 'oauth', now() + interval '1 hour', NULL),
 ('oauth-expired', 'oauth', now() - interval '1 hour', NULL),
 ('oauth-revoked', 'oauth', NULL, now()),
 ('ended-access', 'ended', NULL, NULL);
INSERT INTO oauth2_refresh_tokens VALUES
 ('oauth-refresh', 'oauth', NULL, NULL),
 ('oauth-consumed', 'oauth', now(), NULL),
 ('oauth-revoked', 'oauth', NULL, now()),
 ('ended-refresh', 'ended', NULL, NULL),
 ('no-device-refresh', 'no-device', NULL, NULL),
 ('other-user-refresh', 'other-user', NULL, NULL);
`)
	if err != nil {
		t.Fatal(err)
	}
	a := masRecoveryArchive(t)
	checks := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/_matrix/client/v3/account/whoami" || r.Header.Get("Authorization") != "Bearer destination-token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		checks++
		fmt.Fprintf(w, `{"user_id":%q,"device_id":"PHONE"}`, masRecoveryUser)
	}))
	defer api.Close()
	mas := &MASDB{db: db}
	for _, want := range []int{4, 0} {
		updated, failures, err := RefreshMASSessions(ctx, a, mx.MustNew(api.URL, ""), mas)
		if err != nil || updated != want || len(failures) != 0 {
			t.Fatalf("updated=%d failures=%v err=%v", updated, failures, err)
		}
	}
	sessions, err := a.Sessions()
	if err != nil || len(sessions) != 4 || checks != 2 {
		t.Fatalf("sessions=%d checks=%d err=%v", len(sessions), checks, err)
	}
	for _, token := range []string{"compat-access", "compat-refresh", "oauth-access", "oauth-refresh"} {
		if sessions[token].Token != "destination-token" {
			t.Fatalf("missing mapping for %s", token)
		}
	}
	if !sessions["oauth-refresh"].OAuth || !sessions["oauth-refresh"].Refresh || sessions["compat-refresh"].OAuth || !sessions["compat-refresh"].Refresh {
		t.Fatal("token types changed during recovery")
	}
}
