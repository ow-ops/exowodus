package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
)

func TestRestoreArchivedBridges(t *testing.T) {
	var commands []string
	homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/send/"):
			var message struct{ Body string }
			if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
				t.Error(err)
			}
			commands = append(commands, message.Body)
			_, _ = w.Write([]byte(`{"event_id":"$command"}`))
		case strings.HasSuffix(r.URL.Path, "/messages"):
			_, _ = w.Write([]byte(`{"chunk":[{"type":"m.room.message","sender":"@conduit:example.org","content":{"msgtype":"m.text","body":"Registered appservice","m.relates_to":{"m.in_reply_to":{"event_id":"$command"}}}}]}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer homeserver.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	dest := mx.MustNew(homeserver.URL, "")
	im := &Importer{Archive: a, Dest: dest, Admin: &ContinuwuityAdmin{
		client: mx.WithToken(dest, "admin"), room: "!admin:example.org", bot: "@conduit:example.org",
	}}
	server := &archive.Server{AppserviceRegistrations: []string{testBridgeRegistration}}
	if err := im.RestoreBridges(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	b := im.bridgeFor("@puppet_123:example.org")
	if len(commands) != 1 || commands[0] != "!admin appservices register\n```yaml\n"+strings.TrimRight(testBridgeRegistration, "\n")+"\n```" ||
		b == nil || b.client.AccessToken != "bridge-test-token" {
		t.Fatal("archived registration or replay credentials were not restored")
	}
	if err := im.RestoreBridges(t.Context(), server); err != nil || len(commands) != 1 {
		t.Fatalf("duplicate bridge registration: %v", err)
	}
	im.Bridges = nil
	im.Admin.bot = "@conduit:other.org"
	if err := im.RestoreBridges(t.Context(), server); err == nil || len(commands) != 1 {
		t.Fatal("appservice restored on another server name")
	}
	im.Admin = nil
	if err := im.RestoreBridges(t.Context(), server); err == nil || len(commands) != 1 {
		t.Fatal("appservice restoration without admin accepted")
	}
}

func TestRelayMembersIncludesBridgeGhosts(t *testing.T) {
	ghost := "@puppet_123:example.org"
	other := "@remote:elsewhere.org"
	r := &replay{
		im:      &Importer{Migrated: map[string]bool{}},
		puppets: map[string]bool{ghost: true},
		final: map[string]roomEvent{
			relay.StateKey("m.room.member", ghost): {Type: "m.room.member", StateKey: &ghost, Content: json.RawMessage(`{"membership":"join"}`)},
			relay.StateKey("m.room.member", other): {Type: "m.room.member", StateKey: &other, Content: json.RawMessage(`{"membership":"join"}`)},
		},
	}
	owner, members := r.relayMembers()
	if owner != ghost || len(members) != 1 || members[0] != ghost {
		t.Fatalf("owner=%s members=%v", owner, members)
	}
}
