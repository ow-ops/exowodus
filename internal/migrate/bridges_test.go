package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/relay"
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
	registration := testBridgeRegistration + "receive_ephemeral: true\norg.matrix.msc3202: true\n"
	server := &archive.Server{AppserviceRegistrations: []string{registration}}
	if err := im.RestoreBridges(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	b := im.bridgeFor("@puppet_123:example.org")
	if len(commands) != 1 || b == nil || b.client.AccessToken != "bridge-test-token" || !b.held || b.registration != registration {
		t.Fatal("archived registration or replay credentials were not restored")
	}
	_, raw, _ := strings.Cut(commands[0], "```yaml\n")
	raw, _, _ = strings.Cut(raw, "```")
	var held, original map[string]any
	if err := yaml.Unmarshal([]byte(raw), &held); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(registration), &original); err != nil {
		t.Fatal(err)
	}
	if held["url"] != "http://127.0.0.1:0" {
		t.Fatal("bridge delivery was enabled during history replay")
	}
	held["url"] = original["url"]
	if !reflect.DeepEqual(held, original) {
		t.Fatal("holding delivery changed bridge credentials or namespaces")
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

func TestBridgePuppetUsesItsOwnRegistration(t *testing.T) {
	var registered int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bridge-test-token" {
			t.Error("puppet registered through another appservice")
		}
		registered++
		_, _ = w.Write([]byte(`{"user_id":"@puppet_123:example.org","device_id":"","access_token":""}`))
	}))
	defer api.Close()
	b, err := parseBridge([]byte(testBridgeRegistration), mx.MustNew(api.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	r := &replay{im: &Importer{Archive: &archive.Archive{Manifest: archive.Manifest{ServerName: "example.org"}}, Bridges: []*Bridge{b}}, room: &archive.ArchivedRoom{Ghosts: []string{"@puppet_123:example.org"}}, puppets: map[string]bool{"@puppet_123:example.org": true}}
	if err := r.registerGhosts(t.Context()); err != nil {
		t.Fatal(err)
	}
	if registered != 1 {
		t.Fatalf("puppet registered %d times", registered)
	}
}
