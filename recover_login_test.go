package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
)

func TestRecoverLoginCommand(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Device   string `json:"device_id"`
			Password string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Password != "current destination password" {
			t.Error("password input changed")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user_id":"@lea:example.org","device_id":%q,"access_token":"migration-token"}`, req.Device)
	}))
	defer api.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteUser(&archive.User{UserID: "@lea:example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader("current destination password\n"))
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"recover-login", "--archive", a.Dir, "--to", api.URL, "--user", "@lea:example.org"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Verified destination login") || strings.Contains(out.String(), "current destination password") {
		t.Fatal("recovery confirmation missing or password echoed")
	}
}

func TestReadRecoveryPassword(t *testing.T) {
	for _, input := range []string{" spaced password \n", " spaced password \r\n"} {
		password, err := readRecoveryPassword(t.Context(), strings.NewReader(input), &bytes.Buffer{})
		if err != nil || string(password) != " spaced password " {
			t.Fatal("password whitespace was not preserved")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readRecoveryPassword(ctx, strings.NewReader("password"), &bytes.Buffer{}); err != context.Canceled {
		t.Fatal("canceled recovery read input")
	}
}

func TestPreparationSummaryDefersRoomsAndOmitsEmptyAdminHint(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	users := []*archive.User{{UserID: "@lea:example.org", Admin: true}, {UserID: "@test:example.org", Rooms: []archive.Room{{RoomID: "!room:example.org"}}}}
	reports := []*migrate.Report{
		{SourceUserID: users[0].UserID, PreparationOnly: true, Failures: []migrate.Failure{{Step: "prepare", Error: "existing account"}}},
		{SourceUserID: users[1].UserID, DestUserID: users[1].UserID, PreparationOnly: true},
	}
	var out bytes.Buffer
	printSummary(&out, a, users, reports, nil, nil)
	if !strings.Contains(out.String(), "account prepared; room import deferred") || !strings.Contains(out.String(), "account preparation failed") {
		t.Fatal("preparation was presented as a completed room import")
	}
	if strings.Contains(out.String(), "rooms joined") || strings.Contains(out.String(), "make-user-admin") || strings.Contains(out.String(), "Per-user details") {
		t.Fatal("summary included incomplete phase counts or an empty admin command")
	}
}
