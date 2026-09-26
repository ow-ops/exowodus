//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"exodus/internal/migrate"
	"exodus/internal/mx"
)

const (
	massynURL = "http://127.0.0.1:38014"
	masURL    = "http://127.0.0.1:38015"
)

// TestMigrateFromMAS migrates a user of a Synapse that delegates auth to MAS.
func TestMigrateFromMAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	masAdmin := masAdminToken(t, ctx)
	synapseAdmin := masPersonalToken(t, ctx, masAdmin, "madmin", "urn:matrix:client:api:* urn:synapse:admin:*")
	mira := mx.MustNew(massynURL, masPersonalToken(t, ctx, masAdmin, "mira", "urn:matrix:client:api:*"))

	must(t, do(ctx, mira, http.MethodPut, urlPath("/_matrix/client/v3/profile", "@mira:massyn", "displayname"), nil,
		map[string]string{"displayname": "Mira"}, nil))
	room := createRoom(t, ctx, mira, map[string]any{"preset": "private_chat", "name": "Mira's room"})
	putAccountData(t, ctx, mira, "@mira:massyn", "com.example.mas", map[string]string{"from": "mas"})
	mas := mx.MustNew(masURL, masAdmin)
	var miraMAS struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	must(t, do(ctx, mas, http.MethodGet, "/api/admin/v1/users/by-username/mira", nil, nil, &miraMAS))
	must(t, do(ctx, mas, http.MethodPost, "/api/admin/v1/user-emails", nil,
		map[string]string{"user_id": miraMAS.Data.ID, "email": "mira@example.org"}, nil))
	var masToken struct {
		Data struct {
			Attributes struct {
				Token string `json:"token"`
			} `json:"attributes"`
		} `json:"data"`
	}
	must(t, do(ctx, mas, http.MethodPost, "/api/admin/v1/user-registration-tokens", nil, map[string]int{"usage_limit": 2}, &masToken))

	// A legacy client session, created by MAS's compatibility login.
	legacy, err := mx.Login(ctx, mx.MustNew(masURL, ""), "mira", "mira-password")
	must(t, err)
	legacyWho, err := mx.MustNew(massynURL, legacy.AccessToken).Whoami(ctx)
	must(t, err)
	if legacyWho.UserID != "@mira:massyn" {
		t.Fatalf("legacy session is %s", legacyWho.UserID)
	}

	cadmin := login(t, ctx, mx.MustNew(continuURL, ""), "cadmin")
	dir := t.TempDir()
	out := exodus(t, "migrate", "--mas-db", "postgres://postgres:mas@127.0.0.1:38016/mas",
		"--from", massynURL, "--from-admin-token", synapseAdmin, "--from-mas-url", masURL, "--from-mas-token", masAdmin,
		"--users", "@mira:massyn",
		"--to", continuURL, "--registration-token", regToken, "--to-admin-token", cadmin.AccessToken, "--archive", dir)
	for _, want := range []string{
		"@mira:massyn -> @mira:continuwuity: 1/1 rooms joined, 0 failures",
		"registration token " + masToken.Data.Attributes.Token + " is now ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	adm, err := migrate.NewContinuwuityAdmin(ctx, cadmin)
	must(t, err)
	email, err := adm.Run(ctx, "!admin users get-email @mira:continuwuity")
	must(t, err)
	if !strings.Contains(email, "mira@example.org") {
		t.Fatalf("email not migrated: %s", email)
	}

	var secrets struct {
		PasswordScheme string        `json:"password_scheme"`
		Tokens         []accessToken `json:"tokens"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "users", url.PathEscape("@mira:massyn"), "secrets.json"))
	must(t, err)
	must(t, json.Unmarshal(raw, &secrets))
	if secrets.PasswordScheme != "mas" || !slices.ContainsFunc(secrets.Tokens, func(tok accessToken) bool {
		return tok.Token == legacy.AccessToken
	}) {
		t.Fatalf("MAS secrets not exported: %s", raw)
	}

	newMira, err := mx.Login(ctx, mx.MustNew(continuURL, ""), "mira", password(t, dir, "@mira:massyn"))
	must(t, err)

	// The proxy sets the MAS password on first login.
	masConfig := filepath.Join(workDir(t), "mas", "config.yaml")
	stop := startProxy(t, dir, "127.0.0.1:38017", continuURL, "--mas-config", masConfig)
	defer stop()
	if _, err := mx.Login(ctx, mx.MustNew("http://127.0.0.1:38017", ""), "mira", "mira-password"); err != nil {
		t.Fatalf("login with the MAS password through the proxy: %v", err)
	}
	if _, err := mx.Login(ctx, mx.MustNew(continuURL, ""), "mira", "mira-password"); err != nil {
		t.Fatalf("MAS password not set on Continuwuity: %v", err)
	}
	var profile struct {
		DisplayName string `json:"displayname"`
	}
	must(t, do(ctx, newMira, http.MethodGet, urlPath("/_matrix/client/v3/profile", "@mira:continuwuity"), nil, nil, &profile))
	joined := joinedRooms(t, ctx, newMira)
	if profile.DisplayName != "Mira" || !slices.Contains(joined, room) {
		t.Fatalf("profile = %+v, rooms = %v", profile, joined)
	}
	var data map[string]string
	must(t, do(ctx, newMira, http.MethodGet, urlPath("/_matrix/client/v3/user", "@mira:continuwuity", "account_data", "com.example.mas"), nil, nil, &data))
	if data["from"] != "mas" {
		t.Fatalf("account data = %v", data)
	}

	var sessions struct {
		Data []struct {
			Attributes struct {
				HumanName string  `json:"human_name"`
				RevokedAt *string `json:"revoked_at"`
			} `json:"attributes"`
		} `json:"data"`
	}
	must(t, do(ctx, mas, http.MethodGet, "/api/admin/v1/personal-sessions", nil, nil, &sessions))
	for _, s := range sessions.Data {
		if s.Attributes.HumanName == "exodus migration" && s.Attributes.RevokedAt == nil {
			t.Fatal("exodus left its MAS personal session active")
		}
	}
}

func masAdminToken(t *testing.T, ctx context.Context) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"urn:mas:admin"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, masURL+"/oauth2/token", strings.NewReader(form.Encode()))
	must(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("01J9Z000000000000000000000", "e2e-mas-client-secret")
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	must(t, json.NewDecoder(resp.Body).Decode(&tok))
	if tok.AccessToken == "" {
		t.Fatalf("no MAS admin token (HTTP %d)", resp.StatusCode)
	}
	return tok.AccessToken
}

func masPersonalToken(t *testing.T, ctx context.Context, admin, username, scope string) string {
	t.Helper()
	mas := mx.MustNew(masURL, admin)
	var user struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	must(t, do(ctx, mas, http.MethodGet, urlPath("/api/admin/v1/users/by-username", username), nil, nil, &user))
	var session struct {
		Data struct {
			Attributes struct {
				AccessToken string `json:"access_token"`
			} `json:"attributes"`
		} `json:"data"`
	}
	must(t, do(ctx, mas, http.MethodPost, "/api/admin/v1/personal-sessions", nil,
		map[string]any{"actor_user_id": user.Data.ID, "human_name": "e2e " + username, "scope": scope}, &session))
	return session.Data.Attributes.AccessToken
}

type accessToken struct {
	Token string `json:"token"`
}
