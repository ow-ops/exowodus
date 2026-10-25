package migrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestDeviceUploadFailureRetries(t *testing.T) {
	uploads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/whoami") {
			_, _ = w.Write([]byte(`{"user_id":"@alice:example.org","device_id":"DEVICE"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = w.Write([]byte(`{"access_token":"dest-token","user_id":"@alice:example.org","device_id":"DEVICE"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/keys/upload") {
			uploads++
			if uploads > 1 {
				_, _ = w.Write([]byte(`{}`))
				return
			}
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"injected upload failure"}`))
			return
		}
		t.Errorf("unexpected request: %s", r.URL.Path)
	}))
	defer server.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	state, err := a.ReadImportState("@alice:example.org")
	if err != nil {
		t.Fatal(err)
	}
	c := mx.MustNew(server.URL, "as-token")
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{client: c}}
	job := &UserJob{User: &archive.User{UserID: "@alice:example.org", Devices: []archive.Device{{ID: "DEVICE", Keys: json.RawMessage(`{}`)}}}, state: state, acct: destAccount{id: "@alice:example.org"}, Report: &Report{}}
	if err := im.importDevices(context.Background(), job, nil); err != nil {
		t.Fatal(err)
	}
	saved, err := a.ReadImportState(job.User.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Report.Failures) != 1 || saved.Devices["DEVICE"] {
		t.Fatalf("failed device must remain pending: failure=%v checkpoint=%v", job.Report.Failures, saved.Devices)
	}
	job.state = saved
	if err := im.importDevices(context.Background(), job, nil); err != nil {
		t.Fatal(err)
	}
	if uploads != 2 || !job.state.Devices["DEVICE"] {
		t.Fatalf("device retry did not finish: uploads=%d state=%v", uploads, job.state.Devices)
	}

}

func TestReplayFailureDoesNotAdvance(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		attempts++
		if attempts == 1 {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
			return
		}
		_, _ = w.Write([]byte(`{"event_id":"$new"}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	st, err := a.ReadRoomState("!room:example.org")
	if err != nil {
		t.Fatal(err)
	}
	st.NewRoomID = "!room:example.org"
	c := mx.MustNew(srv.URL, "token")
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}, Migrated: map[string]bool{"@alice:example.org": true}, rooms: map[string]string{}}
	r := &replay{im: im, room: &archive.ArchivedRoom{RoomID: st.NewRoomID}, st: st, rep: &RoomReport{}, owner: "@alice:example.org", joined: map[string]bool{"@alice:example.org": true}, events: []json.RawMessage{json.RawMessage(`{"event_id":"$old","sender":"@alice:example.org","type":"m.room.message","content":{"msgtype":"m.text","body":"hello"}}`)}}
	if err := r.Create(t.Context()); err == nil {
		t.Fatal("failed send must fail replay")
	}
	if r.st.Replayed != 0 {
		t.Fatalf("advanced past failed event: %d", r.st.Replayed)
	}
	if err := r.Create(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.st.Replayed != 1 || r.st.Events["$old"] != "$new" {
		t.Fatalf("retry did not restore event: %+v", r.st)
	}
}

func TestFinalizeFailureRemainsPending(t *testing.T) {
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "GET" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		writes++
		if writes == 1 {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
			return
		}
		_, _ = w.Write([]byte(`{"event_id":"$topic"}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	st, err := a.ReadRoomState("!room:example.org")
	if err != nil {
		t.Fatal(err)
	}
	st.NewRoomID = "!room:example.org"
	c := mx.MustNew(srv.URL, "token")
	key := ""
	r := &replay{im: &Importer{Archive: a, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}, room: &archive.ArchivedRoom{RoomID: st.NewRoomID}, st: st, rep: &RoomReport{}, owner: "@alice:example.org", final: map[string]roomEvent{"topic": {Type: "m.room.topic", StateKey: &key, Content: json.RawMessage(`{"topic":"restored"}`)}}}
	if err := r.Finalize(t.Context()); err == nil {
		t.Fatal("failed state write must fail finalization")
	}
	if st.Done {
		t.Fatal("failed finalization marked complete")
	}
	if err := r.Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !st.Done || writes != 2 {
		t.Fatal("finalization was not retried")
	}
}

func TestRoomDataFailureRetries(t *testing.T) {
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(req.URL.Path, "/account_data/") {
			writes++
			if writes == 1 {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	st, err := a.ReadImportState("@alice:example.org")
	if err != nil {
		t.Fatal(err)
	}
	c := mx.MustNew(srv.URL, "token")
	c.UserID = "@alice:example.org"
	u := &archive.User{UserID: string(c.UserID), Rooms: []archive.Room{{RoomID: "!room:example.org", Via: []string{"other.org"}, AccountData: map[string]json.RawMessage{"custom": json.RawMessage(`{}`)}}}}
	im := &Importer{Archive: a, Dest: c}
	job := &UserJob{User: u, state: st, acct: destAccount{id: u.UserID, client: c}, Report: &Report{}}
	if _, err := im.FinishUser(t.Context(), job, nil); err != nil {
		t.Fatal(err)
	}
	if st.Rooms["!room:example.org"] {
		t.Fatal("failed room data marked complete")
	}
	job.Report = &Report{}
	if _, err := im.FinishUser(t.Context(), job, nil); err != nil {
		t.Fatal(err)
	}
	if !st.Rooms["!room:example.org"] || writes != 2 {
		t.Fatal("room data was not retried")
	}
}

func TestPowerTransferNeedsSourceUntilSuccessful(t *testing.T) {
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/m.room.power_levels/") || strings.HasSuffix(r.URL.Path, "/m.room.power_levels") {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"users":{"@alice:old.org":100}}`))
				return
			}
			writes++
			if writes == 1 {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "old.org")
	if err != nil {
		t.Fatal(err)
	}
	st, err := a.ReadImportState("@alice:old.org")
	if err != nil {
		t.Fatal(err)
	}
	c := mx.MustNew(srv.URL, "dest")
	c.UserID = "@alice:new.org"
	im := &Importer{Archive: a, Dest: c}
	u := &archive.User{UserID: "@alice:old.org", Rooms: []archive.Room{{RoomID: "!room:old.org", Via: []string{"other.org"}}}}
	source := &Session{UserID: u.UserID, Client: mx.MustNew(srv.URL, "source")}
	job := &UserJob{User: u, acct: destAccount{id: string(c.UserID), client: c}, state: st, Report: &Report{}}
	for _, src := range []*Session{source, nil} {
		job.Report = &Report{}
		if _, err := im.FinishUser(t.Context(), job, src); err != nil {
			t.Fatal(err)
		}
		if st.Rooms["!room:old.org"] || !st.PowerPending["!room:old.org"] || len(job.Report.Failures) != 1 {
			t.Fatalf("lost pending transfer: state=%+v report=%+v", st, job.Report)
		}
	}
	job.Report = &Report{}
	if _, err := im.FinishUser(t.Context(), job, source); err != nil {
		t.Fatal(err)
	}
	if !st.Rooms["!room:old.org"] || st.PowerPending["!room:old.org"] || writes != 2 {
		t.Fatalf("power transfer not restored: %+v writes=%d", st, writes)
	}
}

func TestCompletedRoomRejoinsWhenMembershipIsMissing(t *testing.T) {
	joins, leaves := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/state/m.room.member/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND"}`))
		case strings.HasSuffix(r.URL.Path, "/leave"):
			leaves++
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/invite"):
			_, _ = w.Write([]byte(`{}`))
		case strings.Contains(r.URL.Path, "/join/"):
			joins++
			_, _ = w.Write([]byte(`{"room_id":"!room:old.org"}`))
		case strings.HasSuffix(r.URL.Path, "/m.room.power_levels/") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"users":{"@alice:old.org":100}}`))
		case strings.HasSuffix(r.URL.Path, "/m.room.power_levels/") && r.Method == http.MethodPut:
			_, _ = w.Write([]byte(`{"event_id":"$power"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "old.org")
	if err != nil {
		t.Fatal(err)
	}
	st, err := a.ReadImportState("@alice:old.org")
	if err != nil {
		t.Fatal(err)
	}
	st.Rooms["!room:old.org"] = true
	dest := mx.MustNew(srv.URL, "dest")
	dest.UserID = "@alice:new.org"
	u := &archive.User{UserID: "@alice:old.org", Rooms: []archive.Room{{RoomID: "!room:old.org", Via: []string{"other.org"}}}}
	job := &UserJob{User: u, acct: destAccount{id: string(dest.UserID), client: dest}, state: st, Report: &Report{}}
	source := &Session{UserID: u.UserID, Client: mx.MustNew(srv.URL, "source")}
	if _, err := (&Importer{Archive: a, Dest: dest}).FinishUser(t.Context(), job, source); err != nil {
		t.Fatal(err)
	}
	if leaves != 1 || joins != 1 || job.Report.RoomsJoined != 1 {
		t.Fatalf("leaves=%d joins=%d report=%+v", leaves, joins, job.Report)
	}
}
