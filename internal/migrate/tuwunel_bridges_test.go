package migrate

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

const testBridgeRegistration = `id: example-bridge
as_token: bridge-test-token
hs_token: homeserver-test-token
sender_localpart: puppet_bot
url: http://bridge:29317
namespaces:
  users:
    - regex: '^@puppet_.*:example\.org$'
      exclusive: true
    - regex: '^@shared_.*:example\.org$'
      exclusive: false
`

func TestTuwunelBridgeUsers(t *testing.T) {
	d := &TuwunelDump{
		passwords: map[string][]byte{
			"@alice:example.org": nil, "@puppet_snapshot:example.org": nil,
			"@puppet_password:example.org": []byte("$argon2id$hash"),
			"@puppet_disabled:example.org": []byte("*"),
		},
		tokens: map[string][]byte{"token": []byte("@puppet_token:example.org\xffDEVICE")},
		maps: map[string]map[string][]byte{
			"id_appserviceregistrations": {"example-bridge": []byte(testBridgeRegistration)},
			"userdeviceid_metadata":      {"@puppet_device:example.org\xffDEVICE": []byte(`{}`)},
		},
	}
	users := map[string]bool{}
	for _, localpart := range []string{"alice", "puppet_new", "puppet_bot", "puppet_password", "puppet_disabled", "puppet_token", "puppet_device", "shared_user", "discord_123"} {
		users["@"+localpart+":example.org"] = true
	}
	users["@puppet_remote:elsewhere.org"] = true
	skipped, err := d.BridgeUsers(users, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"@puppet_disabled:example.org", "@puppet_new:example.org", "@puppet_snapshot:example.org"}
	if got := slices.Sorted(maps.Keys(skipped)); !reflect.DeepEqual(got, want) {
		t.Fatalf("skipped = %v, want %v", got, want)
	}
	// A snapshot-only ghost and a live-only ghost must not block inventory checks.
	local := map[string]bool{"@alice:example.org": true, "@puppet_password:example.org": true}
	if err := d.CheckUserInventory(local, "@conduit:example.org", skipped); err != nil {
		t.Fatal(err)
	}
	local["@discord_123:example.org"] = true
	if err := d.CheckUserInventory(local, "@conduit:example.org", skipped); err == nil {
		t.Fatal("unregistered username prefix bypassed inventory validation")
	}
	delete(d.maps, "id_appserviceregistrations")
	if skipped, err := d.BridgeUsers(users, "example.org"); err != nil || len(skipped) != 0 {
		t.Fatalf("missing registrations: skipped=%v err=%v", skipped, err)
	}
}

func TestTuwunelDumpBridgeRegistrationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"userid_password", "token_userdeviceid"} {
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	scan := fmt.Sprintf("0x%x ==> 0x%x\n", "example-bridge", testBridgeRegistration)
	if err := os.WriteFile(filepath.Join(dir, "id_appserviceregistrations.txt"), []byte(scan), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := OpenTuwunelDump(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_synapse/admin/v1/registration_tokens" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"registration_tokens":[]}`))
	}))
	defer homeserver.Close()
	exp := &Exporter{Archive: a, Admin: mx.MustNew(homeserver.URL, "admin"), TuwunelDump: d, AllUsers: true}
	if err := exp.ExportServer(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := a.ReadServer()
	if err != nil || !reflect.DeepEqual(got.AppserviceRegistrations, []string{testBridgeRegistration}) {
		t.Fatalf("registration changed: %v", err)
	}
	info, err := os.Stat(filepath.Join(a.Dir, "server.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("registration tokens must stay private")
	}
	exp.AllUsers = false
	if err := exp.ExportServer(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err = a.ReadServer()
	if err != nil || len(got.AppserviceRegistrations) != 0 {
		t.Fatal("single-account export included unrelated appservices")
	}
	for _, raw := range []string{strings.Replace(testBridgeRegistration, "id: example-bridge", "id: another", 1), strings.Replace(testBridgeRegistration, "^@puppet_.*:example\\.org$", "[", 1)} {
		d.maps["id_appserviceregistrations"]["example-bridge"] = []byte(raw)
		if _, err := d.BridgeUsers(map[string]bool{"@puppet_new:example.org": true}, "example.org"); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
}

func TestTuwunelBridgeUsersKeepCredentialsAndDevices(t *testing.T) {
	const user = "@puppet_123:example.org"
	for _, table := range []string{"userdeviceid_metadata", "onetimekeyid4225_otk", "onetimekeyid_onetimekeys", "userdeviceidalgorithm_fallback", "senderkey_pusher", "userdeviceid_refresh", "token_userdeviceid"} {
		t.Run(table, func(t *testing.T) {
			d := &TuwunelDump{
				passwords: map[string][]byte{user: nil},
				tokens:    map[string][]byte{}, refresh: map[string][]byte{},
				maps: map[string]map[string][]byte{"id_appserviceregistrations": {"example-bridge": []byte(testBridgeRegistration)}},
			}
			switch table {
			case "token_userdeviceid":
				d.tokens["token"] = []byte(user + "\xffDEVICE")
			case "userdeviceid_refresh":
				d.refresh[user+"\xffDEVICE"] = []byte("refresh")
			default:
				d.maps[table] = map[string][]byte{user + "\xffDEVICE": []byte(`{}`)}
			}
			skipped, err := d.BridgeUsers(map[string]bool{user: true}, "example.org")
			if err != nil || skipped[user] {
				t.Fatalf("account with %s was filtered: skipped=%v err=%v", table, skipped, err)
			}
		})
	}
	registration := strings.ReplaceAll(testBridgeRegistration, "sender_localpart: puppet_bot", "sender_localpart: unrelated_bot")
	d := &TuwunelDump{passwords: map[string][]byte{"@unrelated_bot:example.org": nil}, maps: map[string]map[string][]byte{"id_appserviceregistrations": {"example-bridge": []byte(registration)}}}
	skipped, err := d.BridgeUsers(map[string]bool{"@unrelated_bot:example.org": true}, "example.org")
	if err != nil || skipped["@unrelated_bot:example.org"] {
		t.Fatalf("bridge sender was filtered: skipped=%v err=%v", skipped, err)
	}
}
