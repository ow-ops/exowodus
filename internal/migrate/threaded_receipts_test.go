package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"maunium.net/go/mautrix/event"
)

func TestSkipThreadedReceipts(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	u := &archive.User{UserID: "@alice:example.org", Rooms: []archive.Room{{RoomID: "!thread:example.org", Receipt: "$thread"}, {RoomID: "!main:example.org", Receipt: "$main"}}}
	if err := a.WriteSecrets(u.UserID, &archive.Secrets{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(a.Dir, "source", "tuwunel")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var raw strings.Builder
	for _, item := range []struct{ room, event, thread string }{{"!thread:example.org", "$thread", "$root"}, {"!main:example.org", "$main", "main"}} {
		receipt := fmt.Sprintf(`{"room_id":%q,"content":{%q:{"m.read":{%q:{"ts":1,"thread_id":%q}}}}}`, item.room, item.event, u.UserID, item.thread)
		fmt.Fprintf(&raw, "0x%x ==> 0x%x\n", item.room+"\xffcounter\xff"+u.UserID, receipt)
	}
	if err := os.WriteFile(filepath.Join(dir, "readreceiptid_readreceipt.txt"), []byte(raw.String()), 0600); err != nil {
		t.Fatal(err)
	}
	srv := &archive.Server{Limitations: []string{threadedReceiptLimitation}}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, SkipPrivateReceipts: true}
	if err := im.CheckLosslessImport([]*archive.User{u}, nil, srv, false); err == nil {
		t.Fatal("private receipt option bypassed threaded receipt guard")
	}
	im.SkipThreadedReceipts = true
	if err := im.LoadThreadedReceipts(t.Context(), []*archive.User{u}, srv); err != nil {
		t.Fatal(err)
	}
	if err := im.CheckLosslessImport([]*archive.User{u}, nil, srv, false); err != nil {
		t.Fatal(err)
	}
	var markers []map[string]string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		markers = append(markers, body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer api.Close()
	account := destAccount{id: u.UserID, client: mx.MustNew(api.URL, "token")}
	for _, room := range u.Rooms {
		im.restoreReadMarker(t.Context(), account, room, room.RoomID, &Report{})
	}
	if len(markers) != 1 || markers[0]["m.read"] != "$main" {
		t.Fatalf("threaded marker was flattened or main marker lost: %v", markers)
	}
	public := json.RawMessage(`{"$pub":{"m.read":{"@alice:example.org":{"ts":1}}},"$thread":{"m.read":{"@alice:example.org":{"ts":2,"thread_id":"$root"}}}}`)
	events := []*event.Event{{Type: event.EphemeralEventReceipt, Content: event.Content{VeryRaw: public}}}
	if got := ownReceipt(events, u.UserID, "m.read"); got != "$pub" {
		t.Fatal("new exports still flatten threaded receipts")
	}
}

func TestDeactivatedOrphanPrekeysDoNotCreateDevices(t *testing.T) {
	a, _, _ := accountRecoveryFixture(t)
	user := &archive.User{UserID: "@deleted:example.org", Deactivated: true}
	path := filepath.Join(a.Dir, "source", "tuwunel", "onetimekeyid4225_otk.txt")
	key := user.UserID + "\xffREMOVED\xff" + string(make([]byte, 8)) + "\xffsigned_curve25519:old"
	if err := os.WriteFile(path, []byte(fmt.Sprintf("0x%x ==> 0x%x\n", key, `{"key":"orphan"}`)), 0600); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, DeactivatedIDOnly: true}
	users, err := im.FilterBridgeAccounts(t.Context(), []*archive.User{user}, &archive.Server{})
	if err != nil {
		t.Fatal(err)
	}
	if err := im.CheckLosslessImport(users, nil, nil, false); err != nil {
		t.Fatalf("deleted device prekeys blocked ID-only restoration: %v", err)
	}
	secrets, _ := a.ReadSecrets(user.UserID)
	if len(user.Devices) != 0 || secrets != nil {
		t.Fatal("orphan prekeys created a device")
	}
}
