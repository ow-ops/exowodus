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

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

func TestImportAcceptedLimitsKeepPreservationChecks(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	u := &archive.User{UserID: "@alice:example.org", Rooms: []archive.Room{{RoomID: "!gone:example.org", PrivateReceipt: "$read"}}}
	if err := a.WriteSecrets(u.UserID, &archive.Secrets{}); err != nil {
		t.Fatal(err)
	}
	srv := &archive.Server{Limitations: []string{"private read receipts on backfilled events cannot currently be restored"}}
	rooms := []*archive.ArchivedRoom{{RoomID: "!gone:example.org", ArchiveOnly: true}}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, SkipPrivateReceipts: true, ArchiveDepartedRooms: true}
	if err := im.CheckLosslessImport([]*archive.User{u}, rooms, srv, true); err != nil {
		t.Fatal(err)
	}
	im.SkipPrivateReceipts = false
	if err := im.CheckLosslessImport([]*archive.User{u}, rooms, srv, true); err == nil {
		t.Fatal("private receipt loss was accepted without its option")
	}
	im.SkipPrivateReceipts = true
	im.ArchiveDepartedRooms = false
	if err := im.CheckLosslessImport([]*archive.User{u}, rooms, srv, true); err == nil {
		t.Fatal("archive-only room accepted without its option")
	}
	im.ArchiveDepartedRooms = true
	im.Admin.bot = "@conduit:other.org"
	if err := im.CheckLosslessImport([]*archive.User{u}, rooms, srv, true); err == nil {
		t.Fatal("partial metadata options bypassed server identity checks")
	}
	var sent []map[string]string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		sent = append(sent, body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer api.Close()
	room := archive.Room{RoomID: "!room:example.org", Receipt: "$public", PrivateReceipt: "$private"}
	im.restoreReadMarker(t.Context(), destAccount{client: mx.MustNew(api.URL, "token")}, room, room.RoomID, &Report{})
	if len(sent) != 1 || sent[0]["m.read"] != "$public" || sent[0]["m.read.private"] != "" {
		t.Fatalf("read markers=%v", sent)
	}
}

func TestArchivedBridgeAccountsAndDeactivatedIDs(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(a.Dir, "source", "tuwunel")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"userid_password", "token_userdeviceid", "userdeviceid_metadata", "onetimekeyid4225_otk", "userdeviceidalgorithm_fallback", "senderkey_pusher"} {
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	const ghost = "@puppet_empty:example.org"
	const protected = "@puppet_device:example.org"
	const inactive = "@deleted:example.org"
	passwords := fmt.Sprintf("0x%x ==> 0x\n0x%x ==> 0x\n0x%x ==> 0x\n", ghost, protected, inactive)
	if err := os.WriteFile(filepath.Join(dir, "userid_password.txt"), []byte(passwords), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "userdeviceid_metadata.txt"), []byte(fmt.Sprintf("0x%x ==> 0x%x\n", protected+"\xffDEVICE", "{}")), 0600); err != nil {
		t.Fatal(err)
	}
	users := []*archive.User{{UserID: ghost, Deactivated: true}, {UserID: protected, Deactivated: true}, {UserID: inactive, Deactivated: true}}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Migrated: map[string]bool{ghost: true, protected: true, inactive: true}, DeactivatedIDOnly: true}
	selected, err := im.FilterBridgeAccounts(t.Context(), users, &archive.Server{AppserviceRegistrations: []string{testBridgeRegistration}})
	if err != nil || len(selected) != 2 || im.Migrated[ghost] || !im.protectedDeactivated[protected] {
		t.Fatalf("selected=%v protected=%v err=%v", selected, im.protectedDeactivated, err)
	}
	if err := im.CheckLosslessImport(selected, nil, nil, false); err == nil || !strings.Contains(err.Error(), "login or device data") {
		t.Fatalf("device-bearing account discarded: %v", err)
	}
	if err := im.CheckLosslessImport(selected[1:], nil, nil, false); err != nil {
		t.Fatalf("deactivated ID rejected: %v", err)
	}
	if failures := im.VerifySessions(t.Context(), selected[1:]); len(failures) != 0 {
		t.Fatal("deactivated ID required a login")
	}
}
