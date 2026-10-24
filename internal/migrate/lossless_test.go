package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
)

func TestOriginalRedactionFields(t *testing.T) {
	for _, tc := range []struct {
		name, original, served string
		match                  bool
	}{
		{"old room API copy", `"redacts":"$target","content":{"reason":"spam"}`, `"redacts":"$target","content":{"reason":"spam","redacts":"$target"}`, true},
		{"new room API copy", `"content":{"reason":"spam","redacts":"$target"}`, `"redacts":"$target","content":{"reason":"spam","redacts":"$target"}`, true},
		{"changed target", `"redacts":"$target","content":{}`, `"redacts":"$other","content":{"redacts":"$other"}`, false},
		{"conflicting target", `"redacts":"$target","content":{}`, `"redacts":"$target","content":{"redacts":"$other"}`, false},
		{"invalid top target", `"redacts":"$target","content":{}`, `"redacts":42,"content":{"redacts":"$target"}`, false},
		{"invalid nested target", `"redacts":"$target","content":{}`, `"redacts":"$target","content":{"redacts":42}`, false},
		{"changed reason", `"redacts":"$target","content":{"reason":"spam"}`, `"redacts":"$target","content":{"reason":"changed","redacts":"$target"}`, false},
		{"removed content", `"redacts":"$target","content":{"reason":"spam"}`, `"redacts":"$target","content":{"redacts":"$target"}`, false},
		{"custom content", `"redacts":"$target","content":{"custom":"keep"}`, `"redacts":"$target","content":{"custom":"keep","redacts":"$target"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := originalEventFields(json.RawMessage(`{"type":"m.room.redaction",` + tc.original + `}`))
			if err != nil {
				t.Fatal(err)
			}
			got, err := originalEventFields(json.RawMessage(`{"type":"m.room.redaction",` + tc.served + `}`))
			if match := err == nil && reflect.DeepEqual(want, got); match != tc.match {
				t.Fatalf("match=%t want=%t error=%v", match, tc.match, err)
			}
		})
	}
	message, err := originalEventFields(json.RawMessage(`{"type":"m.room.message","content":{"redacts":"$target"}}`))
	if err != nil || message["content"].(map[string]any)["redacts"] != "$target" {
		t.Fatal("normalized a non-redaction event")
	}
}

func TestLosslessRejectsDestinationCredentials(t *testing.T) {
	for _, credential := range []string{"password", "token"} {
		t.Run(credential, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.RequireLossless(); err != nil {
				t.Fatal(err)
			}
			u := &archive.User{UserID: "@alice:example.org"}
			if err := a.WriteSecrets(u.UserID, &archive.Secrets{PasswordHash: "source-hash"}); err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
			if err := im.CheckLosslessImport([]*archive.User{u}, nil, nil, false); err != nil {
				t.Fatal(err)
			}
			if credential == "password" {
				im.DestPassword = "destination-password"
			} else {
				im.DestToken = "destination-token"
			}
			if err := im.CheckLosslessImport([]*archive.User{u}, nil, nil, false); err == nil || !strings.Contains(err.Error(), "preserving source passwords") {
				t.Fatalf("destination credentials bypassed source password restoration: %v", err)
			}
		})
	}
}

func TestVerifyOriginalRoomChecksContent(t *testing.T) {
	source := json.RawMessage(`{"event_id":"$original","room_id":"!room:example.org","sender":"@alice:example.org","origin_server_ts":1234,"type":"m.room.message","content":{"msgtype":"m.text","body":"original"}}`)
	for _, tc := range []struct {
		name, body string
		fails      bool
	}{
		{"exact", string(source), false},
		{"same ID different content", `{"event_id":"$original","sender":"@alice:example.org","origin_server_ts":1234,"type":"m.room.message","content":{"body":"changed","msgtype":"m.text"}}`, true},
		{"same ID different sender", `{"event_id":"$original","sender":"@exodus:example.org","origin_server_ts":1234,"type":"m.room.message","content":{"body":"original","msgtype":"m.text"}}`, true},
		{"same ID different timestamp", `{"event_id":"$original","sender":"@alice:example.org","origin_server_ts":9999,"type":"m.room.message","content":{"body":"original","msgtype":"m.text"}}`, true},
		{"missing", `{"event_id":"$other","type":"m.room.message","content":{}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"chunk":[` + tc.body + `]}`)) }))
			defer srv.Close()
			err := verifyOriginalRoom(t.Context(), mx.MustNew(srv.URL, "token"), "!room:example.org", []json.RawMessage{source})
			if (err != nil) != tc.fails {
				t.Fatalf("verification error = %v", err)
			}
		})
	}
}

func TestLosslessRejectsKnownLoss(t *testing.T) {
	for _, tc := range []struct {
		name        string
		user        *archive.User
		rooms       []*archive.ArchivedRoom
		server      *archive.Server
		destination string
	}{
		{name: "remote inbox", server: &archive.Server{ToDevice: []archive.ToDevice{{Key: "remote", Sender: "@remote:other.org"}}}},
		{name: "pending queue", server: &archive.Server{Limitations: []string{"pending deliveries"}}},
		{name: "archive only", rooms: []*archive.ArchivedRoom{{RoomID: "!room:example.org", ArchiveOnly: true}}},
		{name: "new identity", destination: "new.example.org"},
		{name: "missing secrets", user: &archive.User{UserID: "@alice:example.org"}},
		{name: "deactivated data", user: &archive.User{UserID: "@gone:example.org", Deactivated: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.RequireLossless(); err != nil {
				t.Fatal(err)
			}
			destination := tc.destination
			if destination == "" {
				destination = "example.org"
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:" + destination}}
			var users []*archive.User
			if tc.user != nil {
				users = append(users, tc.user)
			}
			if err := im.CheckLosslessImport(users, tc.rooms, tc.server, true); err == nil {
				t.Fatal("loss accepted")
			}
		})
	}
}

func TestLosslessRelayNeverFallsBackToReplay(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, RequireLossless: true, Appservice: &Appservice{}}
	reports, rest := im.RelayRooms(t.Context(), []*archive.ArchivedRoom{{RoomID: "!room:example.org", Version: "10"}}, relay.New("relay.test", "example.org", nil, nil))
	if len(rest) != 0 || len(reports) != 1 || len(reports[0].Failures) != 1 {
		t.Fatal("lossless relay silently fell back to replay")
	}
}

func TestLosslessRequirementPersists(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	b, err := archive.Open(a.Dir)
	if err != nil || !b.Manifest.RequireLossless {
		t.Fatal("lossless requirement not persisted")
	}
}

func TestLosslessAllowsRetryableKnocks(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	u := &archive.User{UserID: "@alice:example.org", Knocks: []archive.Knock{{RoomID: "!room:remote.org", Reason: "let me in", Via: []string{"remote.org"}}}}
	if err := a.WriteSecrets(u.UserID, &archive.Secrets{}); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
	if err := im.CheckLosslessImport([]*archive.User{u}, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct {
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Reason != "let me in" {
			t.Error("knock reason not preserved")
		}
		if requests == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"remote unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"room_id":"!room:remote.org"}`))
	}))
	defer srv.Close()
	c := mx.MustNew(srv.URL, "token")
	c.DefaultHTTPRetries = 0
	im.sessions = map[string]destAccount{u.UserID: {id: u.UserID, client: c}}
	if failures := im.RestoreKnocks(t.Context(), []*archive.User{u}); len(failures) != 1 {
		t.Fatalf("failures = %v", failures)
	}
	state, err := a.ReadImportState(u.UserID)
	if err != nil || state.Knocks[u.Knocks[0].RoomID] {
		t.Fatal("failed knock marked complete")
	}
	if failures := im.RestoreKnocks(t.Context(), []*archive.User{u}); len(failures) != 0 {
		t.Fatalf("retry failed: %v", failures)
	}
	if failures := im.RestoreKnocks(t.Context(), []*archive.User{u}); len(failures) != 0 || requests != 2 {
		t.Fatal("completed knock was sent again")
	}
}

func TestLosslessReadMarkerRemainsPending(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["m.fully_read"] != "$original" || body["m.read.private"] != "" {
			t.Error("strict import changed source receipt state")
		}
		if requests == 1 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"not backfilled yet"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	im := &Importer{RequireLossless: true}
	acct := destAccount{client: mx.MustNew(srv.URL, "token")}
	r := archive.Room{RoomID: "!room:example.org", AccountData: map[string]json.RawMessage{"m.fully_read": json.RawMessage(`{"event_id":"$original"}`)}}
	rep := &Report{}
	im.restoreReadMarker(t.Context(), acct, r, r.RoomID, rep)
	if len(rep.Failures) != 1 {
		t.Fatal("missing event silently accepted")
	}
	retry := &Report{}
	im.restoreReadMarker(t.Context(), acct, r, r.RoomID, retry)
	if len(retry.Failures) != 0 || requests != 2 {
		t.Fatalf("retry failed: %v", retry.Failures)
	}
}

func TestReadMarkersForOmittedEvents(t *testing.T) {
	var bodies []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	im := &Importer{RequireLossless: true}
	im.recordOmittedEvents(&archive.ArchivedRoom{RoomID: "!room:example.org", OmittedEvents: map[string]string{"$invalid": "hash mismatch"}})
	acct := destAccount{client: mx.MustNew(srv.URL, "token")}
	r := archive.Room{RoomID: "!room:example.org", Receipt: "$kept", PrivateReceipt: "$invalid", AccountData: map[string]json.RawMessage{"m.fully_read": json.RawMessage(`{"event_id":"$invalid"}`)}}
	rep := &Report{}
	im.restoreReadMarker(t.Context(), acct, r, r.RoomID, rep)
	if len(rep.Failures) != 0 || !reflect.DeepEqual(bodies, []map[string]string{{"m.read": "$kept"}}) {
		t.Fatalf("read markers=%v failures=%v", bodies, rep.Failures)
	}
	r.Receipt = "$invalid"
	im.restoreReadMarker(t.Context(), acct, r, r.RoomID, rep)
	if len(bodies) != 1 {
		t.Fatal("sent marker for omitted event")
	}
}

func TestVerifySessions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		session  archive.Session
		response string
		status   int
		fails    bool
	}{
		{"valid", archive.Session{UserID: "@alice:example.org", DeviceID: "PHONE", Token: "destination"}, `{"user_id":"@alice:example.org","device_id":"PHONE"}`, 200, false},
		{"missing mapping", archive.Session{}, `{}`, 200, true},
		{"wrong mapping", archive.Session{UserID: "@other:example.org", DeviceID: "PHONE", Token: "destination"}, `{}`, 200, true},
		{"wrong device", archive.Session{UserID: "@alice:example.org", DeviceID: "PHONE", Token: "destination"}, `{"user_id":"@alice:example.org","device_id":"OTHER"}`, 200, true},
		{"revoked", archive.Session{UserID: "@alice:example.org", DeviceID: "PHONE", Token: "destination"}, `{"errcode":"M_UNKNOWN_TOKEN","error":"revoked"}`, 401, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			u := &archive.User{UserID: "@alice:example.org"}
			if err := a.WriteSecrets(u.UserID, &archive.Secrets{Tokens: []archive.Token{{Token: "source", DeviceID: "PHONE"}, {Token: "refresh", DeviceID: "PHONE", Refresh: true}}}); err != nil {
				t.Fatal(err)
			}
			refresh := tc.session
			refresh.Refresh = true
			if err := a.WriteSessions(map[string]archive.Session{"source": tc.session, "refresh": refresh}); err != nil {
				t.Fatal(err)
			}
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Header.Get("Authorization") != "Bearer destination" {
					t.Error("wrong destination token")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer srv.Close()
			im := &Importer{Archive: a, Dest: mx.MustNew(srv.URL, "")}
			failures := im.VerifySessions(t.Context(), []*archive.User{u})
			if (len(failures) != 0) != tc.fails {
				t.Fatalf("failures = %v", failures)
			}
			if !tc.fails && requests != 1 {
				t.Fatalf("shared access/refresh session verified %d times", requests)
			}
		})
	}
}
