package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/migrate"
	"exodus/internal/mx"
)

type reportCheckingWriter struct {
	t     *testing.T
	path  string
	wrote bool
}

func (w *reportCheckingWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	if _, err := os.Stat(w.path); err != nil {
		w.t.Errorf("summary printed before report was saved: %v", err)
	}
	w.wrote = true
	return len(p), nil
}

func TestCanceledImportSavesReportWithoutFinalNetworkChecks(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("canceled finalization sent %s %s", r.Method, r.URL.Path)
		w.WriteHeader(400)
	}))
	defer api.Close()
	im := &migrate.Importer{Archive: a, Dest: mx.MustNew(api.URL, ""), RequireLossless: true}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	user := &archive.User{UserID: "@alice:example.org", Locked: true}
	reports := []*migrate.Report{{SourceUserID: user.UserID, DestUserID: user.UserID, Failures: []migrate.Failure{{Step: "room", Error: "relay unavailable"}}}}
	out := &reportCheckingWriter{t: t, path: filepath.Join(a.Dir, "import-report.json")}
	err = finishImport(ctx, out, im, a, []*archive.User{user}, reports, nil)
	if !errors.Is(err, context.Canceled) || !out.wrote {
		t.Fatalf("error=%v summary printed=%t", err, out.wrote)
	}
	raw, err := os.ReadFile(out.path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Complete bool              `json:"complete"`
		Users    []*migrate.Report `json:"users"`
		Failures []migrate.Failure `json:"failures"`
		Notes    []string          `json:"notes"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Complete || len(report.Users) != 1 || len(report.Users[0].Failures) != 1 || len(report.Failures) != 0 || !strings.Contains(strings.Join(report.Notes, "\n"), "interrupted") {
		t.Fatalf("canceled report=%+v", report)
	}
}

func TestTuwunelSourceSkipsDumpBridgeGhosts(t *testing.T) {
	dir := t.TempDir()
	for _, table := range []string{
		"userid_password", "token_userdeviceid", "global", "server_signingkeys", "pduid_pdu", "eventid_outlierpdu",
		"shorteventid_eventid", "shortstatekey_statekey", "shorteventid_shortstatehash", "roomid_shortstatehash", "shortstatehash_statediff", "roomid_pduleaves",
		"userdeviceid_metadata", "onetimekeyid4225_otk", "userdeviceidalgorithm_fallback", "senderkey_pusher", "pushkey_deviceid", "todeviceid_events",
		"bannedroomids", "alias_roomid", "servercurrentevent_data", "servernameevent_data", "mediaid_file", "mediaid_lazy", "mediaid_lazycontent", "readreceiptid_readreceipt", "roomuserid_privateread",
	} {
		if err := os.WriteFile(filepath.Join(dir, table+".txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	passwords := fmt.Sprintf("0x%x ==> 0x\n0x%x ==> 0x\n", "@admin:example.org", "@ghost_old:example.org")
	if err := os.WriteFile(filepath.Join(dir, "userid_password.txt"), []byte(passwords), 0600); err != nil {
		t.Fatal(err)
	}
	registration := "id: bridge\nas_token: test\nhs_token: test\nsender_localpart: bridgebot\nnamespaces:\n  users:\n    - regex: '^@ghost_.*:example\\.org$'\n      exclusive: true\n"
	scan := fmt.Sprintf("0x%x ==> 0x%x\n", "bridge", registration)
	if err := os.WriteFile(filepath.Join(dir, "id_appserviceregistrations.txt"), []byte(scan), 0600); err != nil {
		t.Fatal(err)
	}
	liveUser := "@ghost_new:example.org"
	homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			_, _ = w.Write([]byte(`{"user_id":"@admin:example.org"}`))
		case r.URL.Path == "/_synapse/admin/v2/users":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]string{{"name": "@admin:example.org"}, {"name": liveUser}}})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer homeserver.Close()
	f := sourceFlags{kind: "tuwunel", allUsers: true, serverUser: "conduit", tuwunelDump: dir, adminToken: "admin", url: homeserver.URL}
	source, err := f.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if len(source.users) != 1 || source.users[0].UserID != "@admin:example.org" {
		t.Fatalf("selected users = %v", source.users)
	}
	liveUser = "@real_new:example.org"
	if _, err := f.open(t.Context()); err == nil || !strings.Contains(err.Error(), liveUser) {
		t.Fatalf("real account absent from checkpoint accepted: %v", err)
	}
}

func TestExportStartupFailurePreservesReport(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"failed export", errors.New("previous export failed")}, {"complete export", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.FinishExport(tc.err); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(a.Dir, "export-report.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cmd := newExportCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--from", "http://127.0.0.1:1", "--from-type", "tuwunel", "--all-users", "--from-admin-token", "test", "--archive", a.Dir})
			err = cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "export did not start; export-report.json was not updated") {
				t.Fatalf("startup error: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("startup failure overwrote the previous report: %v", err)
			}
		})
	}
}

func TestTuwunelPreservationDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags sourceFlags
		want  bool
	}{
		{"whole server", sourceFlags{kind: "tuwunel", allUsers: true}, true},
		{"individual account", sourceFlags{kind: "tuwunel"}, false},
		{"Synapse", sourceFlags{kind: "synapse", allUsers: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.flags.preservationDefault()
			if tc.flags.requireLossless != tc.want {
				t.Fatalf("preservation = %v, want %v", tc.flags.requireLossless, tc.want)
			}
		})
	}
}

func TestCheckpointHistoryRequiresNativeWholeServerExport(t *testing.T) {
	for _, args := range [][]string{
		{"--from-type", "synapse", "--all-users"},
		{"--from-type", "tuwunel", "--tuwunel-dump", "unused"},
		{"--from-type", "tuwunel", "--all-users"},
	} {
		cmd := newExportCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"--from", "http://127.0.0.1:1", "--history-at-checkpoint"}, args...))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--history-at-checkpoint requires") {
			t.Fatalf("invalid checkpoint history options accepted: %v", err)
		}
	}
}

func TestTuwunelDefaultRejectsIncompleteExportBeforeAPI(t *testing.T) {
	cmd := newExportCmd()
	cmd.SetArgs([]string{"--from", "http://127.0.0.1:1", "--from-type", "tuwunel", "--all-users", "--from-admin-token", "test"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "preservation requires") {
		t.Fatalf("incomplete whole-server export was not rejected: %v", err)
	}
}

func TestTuwunelCannotDisablePreservation(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN","error":"test token"}`))
	}))
	defer srv.Close()
	cmd := newExportCmd()
	cmd.SetArgs([]string{"--from", srv.URL, "--from-type", "tuwunel", "--all-users", "--from-admin-token", "test", "--require-lossless=false"})
	if err := cmd.Execute(); err == nil || requests != 0 || !strings.Contains(err.Error(), "preservation requires") {
		t.Fatalf("whole-server preservation was bypassed: %v", err)
	}
}

func TestTuwunelStaleSnapshotCannotOmitJoinedRoom(t *testing.T) {
	dir := t.TempDir()
	for _, table := range []string{"userid_password", "token_userdeviceid", "global", "server_signingkeys", "pduid_pdu", "eventid_outlierpdu", "shorteventid_eventid", "shortstatekey_statekey", "shorteventid_shortstatehash", "roomid_shortstatehash", "shortstatehash_statediff", "roomid_pduleaves"} {
		if err := os.WriteFile(filepath.Join(dir, table+".txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dump, err := migrate.OpenTuwunelDump(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	requested := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/state"):
			requested = true
			_, _ = w.Write([]byte(`{"state":[]}`))
		case strings.HasSuffix(r.URL.Path, "/messages"):
			_, _ = w.Write([]byte(`{"chunk":[]}`))
		case r.URL.Path == "/_synapse/admin/v1/rooms":
			_, _ = w.Write([]byte(`{"rooms":[]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	exp := &migrate.Exporter{Archive: a, Admin: mx.MustNew(srv.URL, "admin"), AllUsers: true, TuwunelDump: dump}
	users := []*archive.User{{UserID: "@alice:example.org", Rooms: []archive.Room{{RoomID: "!new:example.org", Via: []string{"remote.example.org"}}}}}
	err = exportRooms(t.Context(), exp, users, nil)
	if !requested || err == nil {
		t.Fatal("joined room created after checkpoint was silently omitted")
	}
	requested = false
	exp.HistoryAtCheckpoint = true
	if err := exportRooms(t.Context(), exp, users, nil); err != nil || requested {
		t.Fatalf("checkpoint export requested a newer room: %v", err)
	}
}

func TestTuwunelBulkSource(t *testing.T) {
	logouts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_matrix/client/v3/account/whoami":
			_, _ = w.Write([]byte(`{"user_id":"@admin:example.org","device_id":"ADMIN"}`))
		case "/_synapse/admin/v2/users":
			if r.URL.Query().Get("user_id") != ":example.org" {
				t.Error("local user filter missing")
			}
			if r.URL.Query().Get("deactivated") != "true" || r.URL.Query().Get("locked") != "true" {
				t.Error("account status filters omitted")
			}
			if r.URL.Query().Get("from") == "" {
				_, _ = w.Write([]byte(`{"users":[{"name":"@remote:elsewhere.org"},{"name":"@conduit:example.org"},{"name":"@admin:example.org"}],"next_token":"3"}`))
			} else {
				_, _ = w.Write([]byte(`{"users":[{"name":"@alice:example.org"},{"name":"@gone:example.org"}]}`))
			}
		case "/_synapse/admin/v2/users/@gone:example.org":
			_, _ = w.Write([]byte(`{"deactivated":true}`))
		case "/_synapse/admin/v2/users/@conduit:example.org", "/_synapse/admin/v2/users/@admin:example.org":
			_, _ = w.Write([]byte(`{"admin":true}`))
		case "/_synapse/admin/v2/users/@alice:example.org":
			_, _ = w.Write([]byte(`{}`))
		case "/_synapse/admin/v1/users/@alice:example.org/login":
			var body map[string]int64
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["valid_until_ms"] == 0 {
				t.Error("impersonation expiry missing")
			}
			_, _ = w.Write([]byte(`{"access_token":"temporary"}`))
		case "/_matrix/client/v3/logout":
			if r.Header.Get("Authorization") != "Bearer temporary" {
				t.Error("revoking wrong token")
			}
			logouts++
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	f := sourceFlags{url: srv.URL, kind: "tuwunel", serverUser: "conduit", adminToken: "admin-token", allUsers: true}
	s, err := f.openAPI(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.users) != 2 || len(s.deactivated) != 1 || s.userIDs()["@conduit:example.org"] {
		t.Fatalf("source = %+v", s)
	}
	if err := s.each(t.Context(), func(sess *migrate.Session) error {
		if sess.UserID == "@admin:example.org" && !sess.Admin {
			t.Error("admin status lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if logouts != 1 {
		t.Fatalf("temporary logouts = %d", logouts)
	}
}

func TestTuwunelSourceValidation(t *testing.T) {
	for _, f := range []sourceFlags{
		{kind: "unknown"}, {kind: "tuwunel", db: "database"},
		{kind: "tuwunel", signingKey: "key"}, {kind: "synapse", tuwunelDump: "dump"},
		{kind: "tuwunel", tuwunelDump: "dump", masURL: "https://mas.example.org"},
	} {
		if _, err := f.open(t.Context()); err == nil {
			t.Fatalf("invalid flags accepted: %+v", f)
		}
	}
}

func TestTuwunelSingleSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/whoami") || r.Header.Get("Authorization") != "Bearer user-token" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"user_id":"@alice:example.org","device_id":"PHONE"}`))
	}))
	defer srv.Close()
	f := sourceFlags{kind: "tuwunel", url: srv.URL, token: "user-token"}
	s, err := f.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.single == nil || s.single.UserID != "@alice:example.org" || len(s.userIDs()) != 1 {
		t.Fatalf("source = %+v", s)
	}
}

func TestMigrationFailures(t *testing.T) {
	f := migrate.Failure{Step: "injected", Error: "failure"}
	for _, tc := range []struct {
		name      string
		users     []*migrate.Report
		rooms     []*migrate.RoomReport
		failures  []migrate.Failure
		wantError bool
	}{
		{name: "success"},
		{name: "user", users: []*migrate.Report{{Failures: []migrate.Failure{f}}}, wantError: true},
		{name: "room", rooms: []*migrate.RoomReport{{Failures: []migrate.Failure{f}}}, wantError: true},
		{name: "server", failures: []migrate.Failure{f}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := migrationFailures(tc.users, tc.rooms, tc.failures); (err != nil) != tc.wantError {
				t.Fatalf("result=%v", err)
			}
		})
	}
}

func TestImportRejectsIncompleteArchive(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.BeginExport(); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"import", "--archive", a.Dir, "--to", "http://127.0.0.1:1"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("incomplete archive accepted")
	}
}

func TestImportCommandFailsOnReportedStepFailure(t *testing.T) {
	joins := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/whoami") {
			_, _ = w.Write([]byte(`{"user_id":"@alice:example.org","device_id":"DEVICE"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/join/") {
			joins++
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"injected"}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteUser(&archive.User{UserID: "@alice:example.org", DisplayName: "Alice", Rooms: []archive.Room{{RoomID: "!room:example.org"}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"import", "--archive", a.Dir, "--to", srv.URL, "--to-token", "token"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "migration incomplete") {
		t.Fatalf("step failure did not fail the command: %v", err)
	}
	if joins != 0 {
		t.Fatal("room import continued after account preparation failed")
	}
}

func TestRelayNameValidation(t *testing.T) {
	for _, name := range []string{"", "relay.example.org", "relay.example.org:8448", "[::1]:8448"} {
		if err := validateRelayName(name); err != nil {
			t.Errorf("valid name %q: %v", name, err)
		}
	}
	for _, name := range []string{"https://relay.example.org", "relay.example.org/path", "relay.example.org?x=y", "relay.example.org:", "relay.example.org:99999", "user@relay.example.org", "relay.example.org\n", "::1"} {
		if err := validateRelayName(name); err == nil {
			t.Errorf("invalid name accepted: %q", name)
		}
	}
}

func TestImportPreflightReplacesStaleReport(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = w.Write([]byte(`{"flows":[]}`))
			return
		}
		posts++
		w.WriteHeader(400)
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteUser(&archive.User{UserID: "@alice:example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteImportReport(map[string]any{"users": []string{"old report"}}); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"import", "--archive", a.Dir, "--to", srv.URL})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("error=%v", err)
	}
	raw, err := os.ReadFile(filepath.Join(a.Dir, "import-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Failures []migrate.Failure
		Users    []json.RawMessage
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if posts != 0 || len(report.Users) != 0 || len(report.Failures) != 1 || report.Failures[0].Step != "preflight" {
		t.Fatalf("posts=%d report=%+v", posts, report)
	}
}
