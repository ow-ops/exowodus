package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestBackfillRequiresCompleteHistory(t *testing.T) {
	for _, tc := range []struct {
		name, chunk string
		wantError   bool
	}{
		{"empty", `[]`, true},
		{"missing create", `[{"event_id":"$message","type":"m.room.message"}]`, true},
		{"missing message", `[{"event_id":"$create","type":"m.room.create"}]`, true},
		{"complete", `[{"event_id":"$create","type":"m.room.create"},{"event_id":"$message","type":"m.room.message"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"chunk":` + tc.chunk + `}`)) }))
			defer srv.Close()
			events := []json.RawMessage{json.RawMessage(`{"event_id":"$create"}`), json.RawMessage(`{"event_id":"$message"}`)}
			_, err := backfillRoom(t.Context(), mx.MustNew(srv.URL, "token"), "!room:example.org", events)
			if (err != nil) != tc.wantError {
				t.Fatalf("backfill error = %v", err)
			}
		})
	}
}

func TestExportKeepsExistingDevice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/keys/query"):
			_, _ = w.Write([]byte(`{"device_keys":{"@alice:example.org":{"DEVICE":{"device_id":"DEVICE"}}}}`))
		case strings.HasSuffix(r.URL.Path, "/devices"):
			_, _ = w.Write([]byte(`{"devices":[{"device_id":"DEVICE","display_name":"Phone"}]}`))
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			_, _ = w.Write([]byte(`{"user_id":"@alice:example.org","device_id":"DEVICE"}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	for _, tc := range []struct {
		name      string
		ephemeral bool
		want      int
	}{{"existing", false, 1}, {"temporary", true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			_, devices, err := exportKeys(t.Context(), mx.MustNew(srv.URL, "token"), "@alice:example.org", tc.ephemeral)
			if err != nil {
				t.Fatal(err)
			}
			if len(devices) != tc.want {
				t.Fatalf("devices = %+v", devices)
			}
			if len(devices) > 0 && len(devices[0].Keys) == 0 {
				t.Fatal("signed keys omitted")
			}
		})
	}
}

func TestMediaDownloadFailureFailsExport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			_, _ = w.Write([]byte(`{"versions":["v1.11"]}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"missing media"}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	exp := &Exporter{Archive: a}
	_, err = exp.exportMedia(t.Context(), &Session{UserID: "@alice:example.org", Client: mx.MustNew(srv.URL, "token")}, "mxc://example.org/missing")
	if err == nil || !strings.Contains(err.Error(), "mxc://example.org/missing") {
		t.Fatalf("download failure lost: %v", err)
	}
}

func TestDepartedRoomInventory(t *testing.T) {
	pages := 0
	state := `[{"event_id":"$create","type":"m.room.create","sender":"@alice:example.org","state_key":"","content":{"room_version":"10"}},{"event_id":"$leave","type":"m.room.member","sender":"@alice:example.org","state_key":"@alice:example.org","content":{"membership":"leave"}}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_synapse/admin/v1/rooms":
			pages++
			if r.URL.Query().Get("from") == "" {
				_, _ = w.Write([]byte(`{"rooms":[{"room_id":"!active:example.org","joined_local_members":1}],"next_token":1}`))
			} else {
				_, _ = w.Write([]byte(`{"rooms":[{"room_id":"!closed:example.org","joined_local_members":0}]}`))
			}
		case strings.Contains(r.URL.Path, "!active"):
			t.Error("active room exported as departed")
		case strings.HasSuffix(r.URL.Path, "/state"):
			_, _ = w.Write([]byte(`{"state":` + state + `}`))
		case strings.HasSuffix(r.URL.Path, "/messages"):
			_, _ = w.Write([]byte(`{"chunk":` + state + `}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	exp := &Exporter{Archive: a, Admin: mx.MustNew(srv.URL, "token"), AllUsers: true}
	if err := exp.ExportDepartedRooms(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	rooms, err := a.Rooms()
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 || len(rooms) != 1 || !rooms[0].ArchiveOnly {
		t.Fatalf("inventory: pages=%d rooms=%+v", pages, rooms)
	}
	events, err := a.RoomEvents(rooms[0].RoomID)
	if err != nil || len(events) != 2 {
		t.Fatalf("history missing: %v %v", events, err)
	}
	im := &Importer{Archive: a}
	reports := im.ReplayRooms(t.Context(), rooms)
	if len(reports) != 1 || !reports[0].ArchiveOnly || len(reports[0].Failures) > 0 {
		t.Fatalf("closed room was replayed: %+v", reports)
	}
}

func TestPusherFailureRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pushers/set") {
			attempts++
			if attempts == 1 {
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
	uid := "@alice:example.org"
	st, err := a.ReadImportState(uid)
	if err != nil {
		t.Fatal(err)
	}
	st.Devices["DEVICE"] = true
	st.DeviceTokens["DEVICE"] = "token"
	if err := a.WriteImportState(uid, st); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSecrets(uid, &archive.Secrets{Pushers: []archive.Pusher{{DeviceID: "DEVICE", Body: json.RawMessage(`{"kind":"http","app_id":"app","pushkey":"push","data":{}}`)}}}); err != nil {
		t.Fatal(err)
	}
	c := mx.MustNew(srv.URL, "token")
	c.UserID = "@alice:example.org"
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{client: c}, sessions: map[string]destAccount{uid: {id: uid, client: c}}}
	u := &archive.User{UserID: uid, Devices: []archive.Device{{ID: "DEVICE"}}}
	job, err := im.PrepareUser(t.Context(), u)
	if err != nil {
		t.Fatal(err)
	}
	if job.state.Pushers {
		t.Fatal("failed pusher marked complete")
	}
	job, err = im.PrepareUser(t.Context(), u)
	if err != nil {
		t.Fatal(err)
	}
	if !job.state.Pushers || attempts != 2 {
		t.Fatalf("pusher not retried: %d", attempts)
	}
}
