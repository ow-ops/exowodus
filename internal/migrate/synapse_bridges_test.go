package migrate

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestBridgeMigrationRequiresRecordedOwnership(t *testing.T) {
	for _, owner := range []string{"example-bridge", "other-bridge", ""} {
		t.Run("owner="+owner, func(t *testing.T) {
			calls := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "Bearer bridge-test-token" {
					t.Error("used another service to claim the account")
				}
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/whoami") {
					_, _ = w.Write([]byte(`{"user_id":"@shared_device:example.org"}`))
				} else if strings.HasSuffix(r.URL.Path, "/register") {
					_, _ = w.Write([]byte(`{"user_id":"@shared_device:example.org"}`))
				} else {
					t.Errorf("unexpected %s", r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			c := mx.MustNew(api.URL, "")
			b, err := parseBridge([]byte(testBridgeRegistration), c)
			if err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Dest: c, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}, Bridges: []*Bridge{b}}
			s, err := im.bridgeAccount(t.Context(), &archive.User{UserID: "@shared_device:example.org", Passwordless: true, AppserviceID: owner})
			switch owner {
			case "example-bridge":
				if err != nil || s.id != "@shared_device:example.org" || s.ephemeral || s.client.DeviceID != "" || calls != 2 {
					t.Fatalf("matching bridge ownership failed: session=%v calls=%d error=%v", s, calls, err)
				}
			case "other-bridge":
				if err == nil || calls != 0 {
					t.Fatal("another bridge claimed the account")
				}
			default:
				if err == nil || calls != 0 {
					t.Fatal("subscription alone granted account ownership")
				}
			}
		})
	}
}

func TestSelectSynapseUsersKeepsAppserviceAccounts(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appservice_id":"example-bridge"}`))
	}))
	defer api.Close()
	admin := mx.MustNew(api.URL, "admin")
	admin.UserID = "@admin:example.org"
	b, err := parseBridge([]byte(testBridgeRegistration), admin)
	if err != nil {
		t.Fatal(err)
	}
	users, err := SelectSynapseUsers(t.Context(), admin, []string{"@puppet_bot:example.org", "@puppet_empty:example.org", "@puppet_device:example.org"}, false, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[0].UserID != "@puppet_bot:example.org" || users[1].UserID != "@puppet_empty:example.org" || users[2].UserID != "@puppet_device:example.org" {
		t.Fatalf("users=%v", users)
	}
	for _, u := range users {
		if !u.Passwordless || u.AppserviceID != b.ID {
			t.Fatal("lost appservice ownership")
		}
	}
}

func TestBridgeSourceSessionDoesNotUseExistingDevice(t *testing.T) {
	for _, device := range []string{"", "ORIGINAL"} {
		t.Run("device="+device, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/whoami") || r.Header.Get("Authorization") != "Bearer bridge-test-token" || r.URL.Query().Get("user_id") != "@puppet_bot:example.org" || r.URL.Query().Has("device_id") {
					t.Error("source bot session used ordinary login, a device, or the wrong appservice")
				}
				fmt.Fprintf(w, `{"user_id":"@puppet_bot:example.org","device_id":%q}`, device)
			}))
			defer api.Close()
			b, err := parseBridge([]byte(testBridgeRegistration), mx.MustNew(api.URL, ""))
			if err != nil {
				t.Fatal(err)
			}
			s, err := b.SourceSession(t.Context(), SynapseUser{UserID: "@puppet_bot:example.org", AppserviceID: b.ID})
			if device != "" {
				if err == nil {
					t.Fatal("existing encryption device used for export")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s.Close(t.Context())
		})
	}
}

func TestSynapseAppserviceSnapshot(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`CREATE TABLE account_data (user_id TEXT, account_data_type TEXT, content TEXT)`,
		`CREATE TABLE room_account_data (user_id TEXT, room_id TEXT, account_data_type TEXT, content TEXT)`,
		`CREATE TABLE room_tags (user_id TEXT, room_id TEXT, tag TEXT, content TEXT)`,
		`CREATE TABLE receipts_linearized (user_id TEXT, room_id TEXT, receipt_type TEXT, event_id TEXT, data TEXT, thread_id TEXT)`,
		`CREATE TABLE local_current_membership (user_id TEXT, room_id TEXT, event_id TEXT, membership TEXT)`,
		`CREATE TABLE event_json (event_id TEXT, json TEXT)`,
		`INSERT INTO account_data VALUES ('@bot:test','com.example.bridge','{"preserved":true}')`,
		`INSERT INTO account_data VALUES ('@other:test','private','{"must_not_copy":true}')`,
		`INSERT INTO room_account_data VALUES ('@bot:test','!room:test','com.example.room','{"room":true}')`,
		`INSERT INTO room_tags VALUES ('@bot:test','!room:test','m.favourite','{"order":0.5}')`,
		`INSERT INTO receipts_linearized VALUES ('@bot:test','!room:test','m.read','$read','{"ts":1}',NULL)`,
		`INSERT INTO receipts_linearized VALUES ('@bot:test','!room:test','m.read.private','$private','{"ts":2}',NULL)`,
		`INSERT INTO receipts_linearized VALUES ('@bot:test','!room:test','m.read','$thread','{"ts":3}','$root')`,
		`INSERT INTO event_json VALUES ('$invite','{"type":"m.room.member","sender":"@inviter:test","state_key":"@bot:test","content":{"membership":"invite"}}')`,
		`INSERT INTO local_current_membership VALUES ('@bot:test','!invite:test','$invite','invite')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	sync, err := (&SynapseDB{db: db}).appserviceSync(t.Context(), "@bot:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(sync.AccountData.Events) != 1 || sync.AccountData.Events[0].Type.Type != "com.example.bridge" {
		t.Fatal("copied another account or lost bot data")
	}
	joined := sync.Rooms.Join[id.RoomID("!room:test")]
	if joined == nil || len(joined.AccountData.Events) != 2 || ownReceipt(joined.Ephemeral.Events, "@bot:test", "m.read") != "$read" || ownReceipt(joined.Ephemeral.Events, "@bot:test", "m.read.private") != "$private" {
		t.Fatal("lost room data, tags or read positions")
	}
	if !slices.ContainsFunc(joined.AccountData.Events, func(e *event.Event) bool { return e.Type.Type == "m.tag" }) {
		t.Fatal("room tags omitted")
	}
	if invite := sync.Rooms.Invite[id.RoomID("!invite:test")]; invite == nil || len(invite.State.Events) != 1 {
		t.Fatal("pending invite omitted")
	}
	if raw, err := json.Marshal(sync); err != nil || strings.Contains(string(raw), "must_not_copy") {
		t.Fatal("snapshot leaked another user")
	}
}
