package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestRecoverExistingLogin(t *testing.T) {
	const user = "@lea:example.org"
	for _, tc := range []struct {
		name, password, returnedUser string
		wrongDevice                  bool
		shadow                       bool
		wantError                    bool
	}{
		{name: "valid", password: "current destination password", returnedUser: user},
		{name: "wrong password", password: "incorrect", returnedUser: user, wantError: true},
		{name: "shadow account", password: "current destination password", returnedUser: user, shadow: true, wantError: true},
		{name: "wrong identity", password: "current destination password", returnedUser: "@other:example.org", wantError: true},
		{name: "wrong device", password: "current destination password", returnedUser: user, wrongDevice: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var device string
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/whoami") {
					fmt.Fprintf(w, `{"user_id":%q,"device_id":%q}`, user, device)
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/login") {
					t.Error("recovery must only authenticate")
					w.WriteHeader(400)
					return
				}
				var req struct {
					Password   string
					Device     string `json:"device_id"`
					Identifier struct{ User string }
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
				}
				if req.Identifier.User != user {
					t.Error("different user requested")
				}
				if tc.shadow {
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"This user cannot log in with a password."}`))
					return
				}
				if req.Password != "current destination password" {
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
					return
				}
				device = req.Device
				if device == "PHONE" || device == "" {
					t.Error("preserved device was reused")
				}
				if tc.wrongDevice {
					device = "PHONE"
				}
				fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":"verified-migration-token"}`, tc.returnedUser, device)
			}))
			defer api.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			u := &archive.User{UserID: user, Devices: []archive.Device{{ID: "PHONE"}}}
			if err := a.WriteUser(u); err != nil {
				t.Fatal(err)
			}
			if err := a.AddCredential(archive.Credential{SourceUserID: user, Password: "previous generated password"}); err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Dest: mx.MustNew(api.URL, "")}
			err = im.RecoverLogin(t.Context(), user, tc.password)
			if (err != nil) != tc.wantError {
				t.Fatalf("recovery=%v", err)
			}
			if tc.shadow && !strings.Contains(err.Error(), "--convert-to-local-account") {
				t.Fatal("shadow account conversion guidance missing")
			}
			credentials, err := a.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			session, err := a.ReadMigrationSession(user)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantError {
				if credentials[user].Password != "previous generated password" || session.Owned {
					t.Fatal("unverified credentials or ownership were saved")
				}
				return
			}
			if credentials[user].Password != tc.password || credentials[user].DestUserID != user || !session.Owned || session.Legacy {
				t.Fatal("verified credentials were not recorded")
			}
			if _, _, err := im.login(t.Context(), u); err != nil {
				t.Fatalf("import cannot reuse recovered login: %v", err)
			}
		})
	}
}

func TestRecoveredLoginPreservesSourcePasswordMigration(t *testing.T) {
	const user = "@lea:example.org"
	var device string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/login") {
			var req struct {
				Device string `json:"device_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			device = req.Device
			fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":"migration-token"}`, user, device)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/whoami") {
			fmt.Fprintf(w, `{"user_id":%q,"device_id":%q}`, user, device)
			return
		}
		t.Error("unexpected account change")
		w.WriteHeader(400)
	}))
	defer api.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	u := &archive.User{UserID: user}
	if err := a.WriteUser(u); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSecrets(user, &archive.Secrets{PasswordHash: "original-source-hash", PasswordScheme: archive.SchemeTuwunel}); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Dest: mx.MustNew(api.URL, "")}
	if err := im.RecoverLogin(t.Context(), user, "current destination password"); err != nil {
		t.Fatal(err)
	}
	bulk := &Importer{Archive: a, Dest: im.Dest}
	job, err := bulk.PrepareUser(t.Context(), u)
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Report.Failures) > 0 {
		t.Fatal(job.Report.Failures)
	}
	pending, err := a.PendingPasswords()
	if err != nil {
		t.Fatal(err)
	}
	if pending[user].Hash != "original-source-hash" {
		t.Fatal("existing password recovery disabled source password restoration")
	}
}
