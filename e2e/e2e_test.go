//go:build e2e

// Run with: ./e2e/up.sh && go test -tags e2e ./e2e/ ; ./e2e/down.sh
package e2e

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"exowodus/internal/migrate"
	"exowodus/internal/mx"

	"maunium.net/go/mautrix"
)

const (
	synapseURL  = "http://127.0.0.1:38008"
	continuURL  = "http://127.0.0.1:38009"
	regToken    = "e2e-registration-token"
	avatarBytes = "\x89PNG\r\n\x1a\nfake-avatar"
)

func TestMigrateNewServerName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	src := mx.MustNew(synapseURL, "")
	admin := login(t, ctx, src, "admin")
	alice := login(t, ctx, src, "alice")
	bob := login(t, ctx, src, "bob")

	must(t, do(ctx, alice, http.MethodPut, urlPath("/_matrix/client/v3/profile", "@alice:synapse", "displayname"), nil,
		map[string]string{"displayname": "Alice Liddell"}, nil))
	avatar := upload(t, ctx, alice, avatarBytes, "image/png")
	must(t, do(ctx, alice, http.MethodPut, urlPath("/_matrix/client/v3/profile", "@alice:synapse", "avatar_url"), nil,
		map[string]string{"avatar_url": avatar}, nil))
	upload(t, ctx, alice, "some notes", "text/plain")

	priv := createRoom(t, ctx, alice, map[string]any{"preset": "private_chat", "name": "Private", "invite": []string{"@bob:synapse"}})
	dm := createRoom(t, ctx, alice, map[string]any{"preset": "trusted_private_chat", "is_direct": true, "invite": []string{"@bob:synapse"}})
	for _, r := range []string{priv, dm} {
		must(t, do(ctx, bob, http.MethodPost, urlPath("/_matrix/client/v3/join", r), nil, struct{}{}, nil))
	}

	putAccountData(t, ctx, alice, "@alice:synapse", "m.direct", map[string][]string{"@bob:synapse": {dm}})
	putAccountData(t, ctx, alice, "@alice:synapse", "com.example.test", map[string]string{"hello": "world"})
	putAccountData(t, ctx, alice, "@alice:synapse", "m.ignored_user_list", map[string]any{"ignored_users": map[string]any{"@eve:elsewhere": map[string]any{}}})
	must(t, do(ctx, alice, http.MethodPut, urlPath("/_matrix/client/v3/user", "@alice:synapse", "rooms", priv, "tags", "m.favourite"), nil,
		map[string]float64{"order": 0.5}, nil))
	must(t, do(ctx, alice, http.MethodPut, urlPath("/_matrix/client/v3/user", "@alice:synapse", "rooms", priv, "account_data", "com.example.room"), nil,
		map[string]int{"r": 1}, nil))
	must(t, do(ctx, alice, http.MethodPut, "/_matrix/client/v3/pushrules/global/content/cake", nil,
		map[string]any{"actions": []string{"notify"}, "pattern": "cake"}, nil))
	must(t, do(ctx, alice, http.MethodPut, "/_matrix/client/v3/pushrules/global/override/.m.rule.suppress_notices/enabled", nil,
		map[string]bool{"enabled": false}, nil))
	must(t, do(ctx, alice, http.MethodPut, urlPath("/_matrix/client/v3/directory/room", "#priv:synapse"), nil,
		map[string]string{"room_id": priv}, nil))
	aliceMsg := send(t, ctx, alice, priv, "m.room.message", map[string]any{"msgtype": "m.text", "body": "read up to here"})
	must(t, do(ctx, alice, http.MethodPost, urlPath("/_matrix/client/v3/rooms", priv, "read_markers"), nil,
		map[string]string{"m.fully_read": aliceMsg}, nil))
	backup := createKeyBackup(t, ctx, alice, priv)
	must(t, do(ctx, alice, http.MethodPost, urlPath("/_matrix/client/v3/rooms", priv, "report", aliceMsg), nil,
		map[string]string{"reason": "reported before the move"}, nil))

	dir := t.TempDir()
	cadmin := login(t, ctx, mx.MustNew(continuURL, ""), "cadmin")
	synapseDB := filepath.Join(workDir(t), "synapse", "homeserver.db")
	args := []string{"migrate", "--synapse-db", synapseDB,
		"--from", synapseURL, "--from-admin-token", admin.AccessToken, "--users", "@admin:synapse,@alice:synapse,@bob:synapse",
		"--to", continuURL, "--registration-token", regToken, "--to-admin-token", cadmin.AccessToken, "--archive", dir}
	var out string
	for run := 1; run <= 2; run++ {
		out = exowodus(t, args...)
		for _, u := range []string{"alice", "bob"} {
			want := "@" + u + ":synapse -> @" + u + ":continuwuity: 2/2 rooms joined, 0 failures"
			if !strings.Contains(out, want) {
				t.Fatalf("run %d: output missing %q:\n%s", run, want, out)
			}
		}
		if strings.Contains(out, "Restore server admin rights") {
			t.Fatalf("run %d: admin rights were not granted:\n%s", run, out)
		}
	}
	if !isServerAdmin(t, ctx, cadmin, "@admin:continuwuity") {
		t.Fatal("@admin:continuwuity is not a server admin")
	}
	if reports := adminRoomText(t, ctx, cadmin); !strings.Contains(reports, "event report received from @alice:continuwuity") ||
		!strings.Contains(reports, "reported before the move (reported on") {
		t.Fatalf("report not filed again:\n%s\nimport output:\n%s", reports, out)
	}

	for _, r := range []string{priv, dm} {
		var jr struct {
			JoinRule string `json:"join_rule"`
		}
		must(t, do(ctx, alice, http.MethodGet, urlPath("/_matrix/client/v3/rooms", r, "state", "m.room.join_rules"), nil, nil, &jr))
		if jr.JoinRule != "invite" {
			t.Fatalf("join rule of %s = %q, want invite restored", r, jr.JoinRule)
		}
	}

	dst := mx.MustNew(continuURL, "")
	newAlice, err := mx.Login(ctx, dst, "alice", password(t, dir, "@alice:synapse"))
	must(t, err)
	assertKeyBackup(t, ctx, newAlice, priv, backup)

	resolved := resolveAlias(t, ctx, newAlice, "#priv:continuwuity")
	if resolved != priv {
		t.Fatalf("#priv:continuwuity -> %s, want %s", resolved, priv)
	}
	var marker struct {
		EventID string `json:"event_id"`
	}
	must(t, do(ctx, newAlice, http.MethodGet, urlPath("/_matrix/client/v3/user", "@alice:continuwuity", "rooms", priv, "account_data", "m.fully_read"), nil, nil, &marker))
	if marker.EventID != aliceMsg {
		t.Fatalf("read marker = %s, want %s", marker.EventID, aliceMsg)
	}

	// The proxy sets the Synapse password on first login.
	stop := startProxy(t, dir, "127.0.0.1:38012", continuURL)
	defer stop()
	if _, err := mx.Login(ctx, mx.MustNew("http://127.0.0.1:38012", ""), "alice", "alice-password"); err != nil {
		t.Fatalf("login with the Synapse password through the proxy: %v", err)
	}
	if _, err := mx.Login(ctx, dst, "alice", "alice-password"); err != nil {
		t.Fatalf("Synapse password not set on Continuwuity: %v", err)
	}

	// Without upstream, the proxy serves the retired server's media.
	stopMedia := startProxy(t, dir, "127.0.0.1:38013", "")
	defer stopMedia()
	_, avatarID, _ := mx.ParseMXC(avatar)
	resp, err := http.Get("http://127.0.0.1:38013/_matrix/federation/v1/media/download/" + avatarID)
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), avatarBytes) {
		t.Fatalf("retired media: %d %q", resp.StatusCode, body)
	}

	var profile struct {
		DisplayName string `json:"displayname"`
		AvatarURL   string `json:"avatar_url"`
	}
	must(t, do(ctx, newAlice, http.MethodGet, urlPath("/_matrix/client/v3/profile", "@alice:continuwuity"), nil, nil, &profile))
	if profile.DisplayName != "Alice Liddell" || !strings.HasPrefix(profile.AvatarURL, "mxc://continuwuity/") {
		t.Fatalf("profile = %+v", profile)
	}
	avatarFile := filepath.Join(t.TempDir(), "avatar")
	_, _, err = mx.Download(ctx, newAlice, profile.AvatarURL, avatarFile)
	must(t, err)
	if got, _ := os.ReadFile(avatarFile); string(got) != avatarBytes {
		t.Fatalf("avatar content = %q", got)
	}

	joined := joinedRooms(t, ctx, newAlice)
	if !slices.Contains(joined, priv) || !slices.Contains(joined, dm) {
		t.Fatalf("joined rooms = %v, want %s and %s", joined, priv, dm)
	}

	var pl struct {
		Users map[string]int `json:"users"`
	}
	must(t, do(ctx, newAlice, http.MethodGet, urlPath("/_matrix/client/v3/rooms", priv, "state", "m.room.power_levels"), nil, nil, &pl))
	if pl.Users["@alice:continuwuity"] != 100 {
		t.Fatalf("power levels = %v", pl.Users)
	}

	assertAccountData(t, ctx, newAlice, "m.direct", map[string][]string{"@bob:continuwuity": {dm}})
	assertAccountData(t, ctx, newAlice, "com.example.test", map[string]string{"hello": "world"})
	assertAccountData(t, ctx, newAlice, "m.ignored_user_list", map[string]any{"ignored_users": map[string]any{"@eve:elsewhere": map[string]any{}}})

	var roomData map[string]int
	must(t, do(ctx, newAlice, http.MethodGet, urlPath("/_matrix/client/v3/user", "@alice:continuwuity", "rooms", priv, "account_data", "com.example.room"), nil, nil, &roomData))
	if roomData["r"] != 1 {
		t.Fatalf("room account data = %v", roomData)
	}
	var tags struct {
		Tags map[string]json.RawMessage `json:"tags"`
	}
	must(t, do(ctx, newAlice, http.MethodGet, urlPath("/_matrix/client/v3/user", "@alice:continuwuity", "rooms", priv, "tags"), nil, nil, &tags))
	if _, ok := tags.Tags["m.favourite"]; !ok {
		t.Fatalf("tags = %v", tags.Tags)
	}

	var rule struct {
		Pattern string `json:"pattern"`
	}
	must(t, do(ctx, newAlice, http.MethodGet, "/_matrix/client/v3/pushrules/global/content/cake", nil, nil, &rule))
	if rule.Pattern != "cake" {
		t.Fatalf("push rule = %+v", rule)
	}
	var enabled struct {
		Enabled bool `json:"enabled"`
	}
	must(t, do(ctx, newAlice, http.MethodGet, "/_matrix/client/v3/pushrules/global/override/.m.rule.suppress_notices/enabled", nil, nil, &enabled))
	if enabled.Enabled {
		t.Fatal(".m.rule.suppress_notices should be disabled")
	}
}

// TestMigrateSingleUser covers a user without admin access, as on matrix.org.
func TestMigrateSingleUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	src := mx.MustNew(synapseURL, "")
	admin := login(t, ctx, src, "admin")
	must(t, do(ctx, admin, http.MethodPut, "/_synapse/admin/v2/users/@carol:synapse", nil,
		map[string]any{"password": "carol-password", "displayname": "Carol"}, nil))
	carol := login(t, ctx, src, "carol")
	room := createRoom(t, ctx, carol, map[string]any{"preset": "private_chat", "name": "Carol's room"})

	out := exowodus(t, "migrate", "--from", synapseURL, "--from-token", carol.AccessToken,
		"--to", continuURL, "--to-password", "new-carol-password", "--registration-token", regToken,
		"--archive", t.TempDir())
	if want := "@carol:synapse -> @carol:continuwuity: 1/1 rooms joined, 0 failures"; !strings.Contains(out, want) {
		t.Fatalf("output missing %q:\n%s", want, out)
	}

	newCarol, err := mx.Login(ctx, mx.MustNew(continuURL, ""), "carol", "new-carol-password")
	must(t, err)
	var profile struct {
		DisplayName string `json:"displayname"`
	}
	must(t, do(ctx, newCarol, http.MethodGet, urlPath("/_matrix/client/v3/profile", "@carol:continuwuity"), nil, nil, &profile))
	joined := joinedRooms(t, ctx, newCarol)
	if profile.DisplayName != "Carol" || !slices.Contains(joined, room) {
		t.Fatalf("profile = %+v, rooms = %v", profile, joined)
	}
}

func TestExportSingleUser(t *testing.T) {
	ctx := context.Background()
	bob := login(t, ctx, mx.MustNew(synapseURL, ""), "bob")
	solo := createRoom(t, ctx, bob, map[string]any{"preset": "private_chat", "name": "Solo"})
	send(t, ctx, bob, solo, "m.room.message", map[string]any{"msgtype": "m.text", "body": "only here"})
	dir := t.TempDir()
	exowodus(t, "export", "--from", synapseURL, "--from-token", bob.AccessToken, "--archive", dir)
	history, err := os.ReadFile(filepath.Join(dir, "rooms", url.PathEscape(solo), "events.jsonl"))
	must(t, err)
	if !strings.Contains(string(history), "only here") {
		t.Fatalf("local-only room history not exported without admin access: %s", history)
	}

	var u struct {
		UserID string            `json:"user_id"`
		Rooms  []json.RawMessage `json:"rooms"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "users", url.PathEscape("@bob:synapse"), "user.json"))
	must(t, err)
	must(t, json.Unmarshal(data, &u))
	if u.UserID != "@bob:synapse" || len(u.Rooms) == 0 {
		t.Fatalf("exported user = %s", data)
	}
}

func isServerAdmin(t *testing.T, ctx context.Context, cadmin *mautrix.Client, userID string) bool {
	t.Helper()
	adm, err := migrate.NewContinuwuityAdmin(ctx, cadmin)
	must(t, err)
	out, err := adm.Run(ctx, "!admin users list-joined-rooms "+userID)
	must(t, err)
	return strings.Contains(out, resolveAlias(t, ctx, cadmin, "#admins:"+mx.ServerName(userID)))
}

func exowodus(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(exowodusBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("exowodus %v: %v\n%s\n%s", args[0], err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func login(t *testing.T, ctx context.Context, c *mautrix.Client, user string) *mautrix.Client {
	t.Helper()
	lc, err := mx.Login(ctx, c, user, user+"-password")
	must(t, err)
	return lc
}

func upload(t *testing.T, ctx context.Context, c *mautrix.Client, content, contentType string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file")
	must(t, os.WriteFile(path, []byte(content), 0o600))
	mxc, err := mx.Upload(ctx, c, path, contentType, "file")
	must(t, err)
	return mxc
}

func createRoom(t *testing.T, ctx context.Context, c *mautrix.Client, body map[string]any) string {
	t.Helper()
	var resp struct {
		RoomID string `json:"room_id"`
	}
	must(t, do(ctx, c, http.MethodPost, "/_matrix/client/v3/createRoom", nil, body, &resp))
	return resp.RoomID
}

func putAccountData(t *testing.T, ctx context.Context, c *mautrix.Client, userID, typ string, content any) {
	t.Helper()
	must(t, do(ctx, c, http.MethodPut, urlPath("/_matrix/client/v3/user", userID, "account_data", typ), nil, content, nil))
}

func assertAccountData(t *testing.T, ctx context.Context, c *mautrix.Client, typ string, want any) {
	t.Helper()
	var got any
	must(t, c.GetAccountData(ctx, typ, &got))
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatalf("%s = %s, want %s", typ, gotJSON, wantJSON)
	}
}

func password(t *testing.T, dir, sourceID string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "credentials.csv"))
	must(t, err)
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	must(t, err)
	for _, r := range records {
		if r[0] == sourceID {
			return r[2]
		}
	}
	t.Fatalf("no credentials for %s", sourceID)
	return ""
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
