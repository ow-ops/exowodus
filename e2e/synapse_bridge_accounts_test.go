//go:build e2e

package e2e

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"exowodus/internal/mx"
	"maunium.net/go/mautrix/id"
)

// The source must be disposable, configured with the test registration and
// bridge-fixture-shared-secret. The target must have the same server name.
func TestSynapseBridgeAccountsLive(t *testing.T) {
	source, container, registration := os.Getenv("EXOWODUS_BRIDGE_SOURCE"), os.Getenv("EXOWODUS_BRIDGE_SOURCE_CONTAINER"), os.Getenv("EXOWODUS_BRIDGE_REGISTRATION")
	target := os.Getenv("EXOWODUS_BRIDGE_TARGET")
	if source == "" || container == "" || registration == "" || target == "" {
		t.Skip("set disposable bridge source, container, registration and target variables")
	}
	ctx := t.Context()
	c := mx.MustNew(source, "")
	var nonce struct {
		Nonce string `json:"nonce"`
	}
	must(t, do(ctx, c, http.MethodGet, "/_synapse/admin/v1/register", nil, nil, &nonce))
	mac := hmac.New(sha1.New, []byte("bridge-fixture-shared-secret"))
	_, _ = mac.Write([]byte(nonce.Nonce + "\x00cadmin\x00cadmin-password\x00admin"))
	err := do(ctx, c, http.MethodPost, "/_synapse/admin/v1/register", nil, map[string]any{"nonce": nonce.Nonce, "username": "cadmin", "password": "cadmin-password", "admin": true, "mac": hex.EncodeToString(mac.Sum(nil))}, nil)
	if err != nil && !mx.IsCode(err, "M_USER_IN_USE") {
		t.Fatal(err)
	}
	admin := login(t, ctx, c, "cadmin")
	as := mx.MustNew(source, "source-bridge-as")
	err = do(ctx, as, http.MethodPost, "/_matrix/client/v3/register", nil, map[string]any{"type": "m.login.application_service", "username": "bridgebot", "inhibit_login": true}, nil)
	if err != nil && !mx.IsCode(err, "M_USER_IN_USE") {
		t.Fatal(err)
	}
	var session struct {
		Token  string `json:"access_token"`
		User   string `json:"user_id"`
		Device string `json:"device_id"`
	}
	must(t, do(ctx, as, http.MethodPost, "/_matrix/client/v3/login", nil, map[string]any{"type": "m.login.application_service", "identifier": map[string]string{"type": "m.id.user", "user": "@bridgebot:bridge.test"}, "device_id": "ORIGINAL"}, &session))
	bot := mx.MustNew(source, session.Token)
	crypto := newBridgeCrypto(t, ctx, bot, session.User, session.Device)
	const ghostID = "@ghost_cached:bridge.test"
	must(t, do(ctx, as, http.MethodPost, "/_matrix/client/v3/register", nil, map[string]any{"type": "m.login.application_service", "username": "ghost_cached", "inhibit_login": true}, nil))
	ghost := mx.As(as, ghostID)
	must(t, do(ctx, ghost, http.MethodPut, urlPath("/_matrix/client/v3/profile", ghostID, "displayname"), nil, map[string]string{"displayname": "Cached puppet profile"}, nil))
	pending := crypto.encrypt(t, ctx, bot, "encrypted before migration")
	must(t, do(ctx, bot, http.MethodPut, "/_matrix/client/v3/sendToDevice/m.room.encrypted/before", nil, map[string]any{"messages": map[string]map[string]json.RawMessage{session.User: {session.Device: pending}}}, nil))
	must(t, do(ctx, bot, http.MethodPut, urlPath("/_matrix/client/v3/user", session.User, "account_data", "com.example.bridge"), nil, map[string]bool{"preserved": true}, nil))
	backup := "/data/bridge-recovery-snapshot.db"
	if out, err := exec.Command("docker", "exec", container, "python", "-c", `import sqlite3; sqlite3.connect('/data/homeserver.db').backup(sqlite3.connect('/data/bridge-recovery-snapshot.db'))`).CombinedOutput(); err != nil {
		t.Fatalf("snapshot: %v: %s", err, out)
	}
	database := filepath.Join(t.TempDir(), "source.db")
	if out, err := exec.Command("docker", "cp", container+":"+backup, database).CombinedOutput(); err != nil {
		t.Fatalf("copy snapshot: %v: %s", err, out)
	}
	db, err := migrate.OpenSynapseDB(ctx, database)
	must(t, err)
	defer db.Close()
	b, err := migrate.LoadBridge(registration, c)
	must(t, err)
	a, err := archive.Create(t.TempDir(), "bridge.test")
	must(t, err)
	must(t, a.FinishExport(nil))
	count, err := migrate.RecoverSynapseBridgeAccounts(ctx, a, admin, db, []*migrate.Bridge{b})
	must(t, err)
	if count != 2 {
		t.Fatalf("recovered %d accounts", count)
	}
	u, err := a.ReadUser(session.User)
	must(t, err)
	var accountData struct {
		Preserved bool `json:"preserved"`
	}
	must(t, json.Unmarshal(u.AccountData["com.example.bridge"], &accountData))
	if u.AppserviceID != b.ID || len(u.Devices) != 1 || u.Devices[0].ID != "ORIGINAL" || !accountData.Preserved {
		t.Fatal("lost bridge identity, device or account data")
	}
	ghostUser, err := a.ReadUser(ghostID)
	must(t, err)
	if ghostUser.DisplayName != "Cached puppet profile" || len(ghostUser.Devices) != 0 || ghostUser.AppserviceID != b.ID {
		t.Fatal("device-less puppet profile was omitted")
	}
	count, err = migrate.RecoverSynapseBridgeAccounts(ctx, a, admin, db, []*migrate.Bridge{b})
	must(t, err)
	if count != 0 {
		t.Fatal("recovery overwrote existing account")
	}
	srv, err := a.ReadServer()
	must(t, err)
	srv.ToDevice, err = db.ToDevice(ctx)
	must(t, err)
	if len(srv.ToDevice) != 1 {
		t.Fatalf("source inbox has %d messages", len(srv.ToDevice))
	}
	must(t, a.WriteServer(srv))
	destAdmin := login(t, ctx, mx.MustNew(target, ""), "cadmin")
	targetAdmin, err := migrate.NewContinuwuityAdmin(ctx, destAdmin)
	must(t, err)
	must(t, b.Hold(ctx, targetAdmin))
	room := createRoom(t, ctx, destAdmin, map[string]any{"preset": "private_chat", "invite": []string{session.User}})
	targetBot := mx.As(mx.MustNew(target, "source-bridge-as"), session.User)
	must(t, do(ctx, targetBot, http.MethodPost, urlPath("/_matrix/client/v3/join", room), nil, struct{}{}, nil))
	must(t, a.WriteUser(&archive.User{UserID: "@recipient:bridge.test", Passwordless: true, Invites: []archive.Invite{{RoomID: room, Inviter: session.User}}}))
	out := exowodus(t, "import", "--archive", a.Dir, "--to", target, "--to-admin-token", destAdmin.AccessToken)
	t.Log(out)
	profile, err := targetBot.GetProfile(ctx, id.UserID(ghostID))
	must(t, err)
	if profile.DisplayName != "Cached puppet profile" {
		t.Fatal("device-less puppet profile was not restored")
	}
	var scoped struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
	}
	must(t, do(ctx, targetBot, http.MethodGet, "/_matrix/client/v3/account/whoami", url.Values{"user_id": {session.User}, "device_id": {session.Device}}, nil, &scoped))
	if scoped.UserID != session.User || scoped.DeviceID != session.Device {
		t.Fatal("native appservice device masquerading was not preserved")
	}
	state, err := a.ReadImportState(session.User)
	must(t, err)
	serverState, err := a.ReadServerState()
	must(t, err)
	if !state.Devices["ORIGINAL"] || !serverState.ToDevice[srv.ToDevice[0].Key] {
		t.Fatal("bot device or pending delivery was not restored")
	}
	var queried struct {
		Devices map[string]map[string]struct {
			Keys map[string]string `json:"keys"`
		} `json:"device_keys"`
	}
	must(t, do(ctx, targetBot, http.MethodPost, "/_matrix/client/v3/keys/query", nil, map[string]any{"device_keys": map[string][]string{session.User: {"ORIGINAL"}}}, &queried))
	if queried.Devices[session.User]["ORIGINAL"].Keys["ed25519:ORIGINAL"] != string(crypto.ed) || queried.Devices[session.User]["ORIGINAL"].Keys["curve25519:ORIGINAL"] != string(crypto.curve) {
		t.Fatal("original public encryption key changed")
	}
	mappings, err := a.Sessions()
	must(t, err)
	mapped := mx.MustNew(target, mappings[session.Token].Token)
	var sync struct {
		NextBatch string `json:"next_batch"`
		ToDevice  struct {
			Events []struct {
				Type    string          `json:"type"`
				Content json.RawMessage `json:"content"`
			} `json:"events"`
		} `json:"to_device"`
	}
	must(t, do(ctx, mapped, http.MethodGet, "/_matrix/client/v3/sync", nil, nil, &sync))
	if len(sync.ToDevice.Events) != 1 || sync.ToDevice.Events[0].Type != "m.room.encrypted" {
		t.Fatal("pending message was not delivered to the original device")
	}
	if crypto.decrypt(t, sync.ToDevice.Events[0].Content) != "encrypted before migration" {
		t.Fatal("retained private account could not decrypt the migrated message")
	}
	fresh := crypto.encrypt(t, ctx, targetBot, "encrypted after migration")
	must(t, do(ctx, targetBot, http.MethodPut, "/_matrix/client/v3/sendToDevice/m.room.encrypted/after", nil, map[string]any{"messages": map[string]map[string]json.RawMessage{session.User: {session.Device: fresh}}}, nil))
	var next = sync
	must(t, do(ctx, mapped, http.MethodGet, "/_matrix/client/v3/sync", url.Values{"since": {sync.NextBatch}}, nil, &next))
	if len(next.ToDevice.Events) != 1 || crypto.decrypt(t, next.ToDevice.Events[0].Content) != "encrypted after migration" {
		t.Fatal("retained private account could not decrypt new messages using migrated one-time keys")
	}
	var membership struct {
		Membership string `json:"membership"`
	}
	must(t, do(ctx, destAdmin, http.MethodGet, urlPath("/_matrix/client/v3/rooms", room, "state", "m.room.member", "@recipient:bridge.test"), nil, nil, &membership))
	if membership.Membership != "invite" {
		t.Fatal("bridge's pending invitation was not restored")
	}
}
