package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/migrate"
)

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/whoami") {
			_, _ = w.Write([]byte(`{"user_id":"@alice:example.org","device_id":"DEVICE"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"injected"}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteUser(&archive.User{UserID: "@alice:example.org", DisplayName: "Alice"}); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"import", "--archive", a.Dir, "--to", srv.URL, "--to-token", "token"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "migration incomplete") {
		t.Fatalf("step failure did not fail the command: %v", err)
	}
}
