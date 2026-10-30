package migrate

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/relay"
)

func TestSkippedRoomDoesNotExportOrImport(t *testing.T) {
	const roomID = "!broken:example.org"
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	if err := a.SetSkippedRooms([]string{roomID}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoom(&archive.ArchivedRoom{RoomID: roomID, ArchiveOnly: true}); err != nil {
		t.Fatal(err)
	}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Errorf("skipped room triggered request %s", r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := mx.MustNew(srv.URL, "token")
	c.UserID = "@alice:example.org"
	exp := &Exporter{Archive: a, Admin: c}
	if err := exp.ExportRoom(t.Context(), roomID, nil, nil); err != nil {
		t.Fatal(err)
	}
	rooms, err := a.Rooms()
	if err != nil || len(rooms) != 0 {
		t.Fatalf("skipped artifacts were selected for import: %v", err)
	}
	u := &archive.User{UserID: string(c.UserID), Rooms: []archive.Room{{RoomID: roomID, PrivateReceipt: "$missing", Via: []string{"remote.example"}}}, Invites: []archive.Invite{{RoomID: roomID}}, Knocks: []archive.Knock{{RoomID: roomID}}}
	if err := a.WriteSecrets(u.UserID, &archive.Secrets{}); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Dest: c, RequireLossless: true, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Appservice: &Appservice{}, sessions: map[string]destAccount{u.UserID: {id: u.UserID, client: c}}}
	if err := im.CheckLosslessImport([]*archive.User{u}, []*archive.ArchivedRoom{{RoomID: roomID, ArchiveOnly: true}}, nil, true); err != nil {
		t.Fatal(err)
	}
	reports, rest := im.RelayRooms(t.Context(), []*archive.ArchivedRoom{{RoomID: roomID}}, relay.New("relay.test", "example.org", nil, nil))
	if len(reports) != 0 || len(rest) != 0 {
		t.Fatal("skipped room entered relay import")
	}
	if got := im.ReplayRooms(t.Context(), []*archive.ArchivedRoom{{RoomID: roomID}}); len(got) != 0 {
		t.Fatal("skipped room entered replay import")
	}
	state, err := a.ReadImportState(u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	job := &UserJob{User: u, state: state, acct: destAccount{id: u.UserID, client: c}, Report: &Report{}}
	rep, err := im.FinishUser(t.Context(), job, nil)
	if err != nil || len(rep.Failures) != 0 || !reflect.DeepEqual(rep.SkippedRooms, []string{roomID}) || state.Rooms[roomID] {
		t.Fatalf("skipped membership was restored: report=%+v error=%v", rep, err)
	}
	if failures := im.RestoreInvites(t.Context(), []*archive.User{u}); len(failures) != 0 {
		t.Fatal(failures)
	}
	if failures := im.RestoreKnocks(t.Context(), []*archive.User{u}); len(failures) != 0 {
		t.Fatal(failures)
	}
	if err := a.WriteServer(&archive.Server{Aliases: map[string]string{"#broken:example.org": roomID}, Reports: []archive.Report{{RoomID: roomID}}}); err != nil {
		t.Fatal(err)
	}
	notes, failures := im.ImportServer(t.Context())
	if len(failures) != 0 || !slices.ContainsFunc(notes, func(s string) bool { return strings.Contains(s, "Skipped room "+roomID) }) {
		t.Fatalf("skip missing from import report: %v %v", notes, failures)
	}
	if requests != 0 {
		t.Fatal("skipped room triggered network activity")
	}
	if err := a.SetSkippedRooms(nil); err != nil {
		t.Fatal(err)
	}
	if err := im.CheckLosslessImport([]*archive.User{u}, []*archive.ArchivedRoom{{RoomID: roomID, ArchiveOnly: true}}, nil, true); err == nil {
		t.Fatal("removing exclusion bypassed preservation checks")
	}
}

func TestSkippedRoomReceiptLimitations(t *testing.T) {
	const roomID = "!broken:example.org"
	d := &TuwunelDump{maps: map[string]map[string][]byte{
		"roomuserid_privateread":    {roomID + "\xff@alice:example.org": {}},
		"readreceiptid_readreceipt": {roomID + "\xffcount": []byte(`{"thread_id":"$thread"}`)},
	}}
	skip := func(id string) bool { return id == roomID }
	s := &archive.Server{}
	if err := d.addServer(s, "example.org", skip); err != nil || len(s.Limitations) != 0 {
		t.Fatalf("skipped receipts blocked import: %v %v", s.Limitations, err)
	}
	s = &archive.Server{}
	if err := d.AddServer(s, "example.org"); err != nil || len(s.Limitations) != 2 {
		t.Fatalf("unskipped limitations lost: %v %v", s.Limitations, err)
	}
}
