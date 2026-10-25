package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestMigrationDeviceAvoidsPreservedID(t *testing.T) {
	const user = "@bot:example.org"
	var mu sync.Mutex
	tokens := map[string]string{}
	keys := map[string]bool{}
	logins := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			fmt.Fprintf(w, `{"user_id":%q}`, user)
		case strings.HasSuffix(r.URL.Path, "/login"):
			var req struct {
				Device string `json:"device_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			logins++
			token := fmt.Sprintf("destination-%d", logins)
			tokens[req.Device] = token
			fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":%q}`, user, req.Device, token)
		case strings.HasSuffix(r.URL.Path, "/keys/upload"):
			for device, token := range tokens {
				if r.Header.Get("Authorization") == "Bearer "+token {
					keys[device] = true
				}
			}
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			for device, token := range tokens {
				if r.Header.Get("Authorization") == "Bearer "+token {
					fmt.Fprintf(w, `{"user_id":%q,"device_id":%q}`, user, device)
					return
				}
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN"}`))
		case strings.HasSuffix(r.URL.Path, "/logout"):
			for device, token := range tokens {
				if r.Header.Get("Authorization") == "Bearer "+token {
					delete(tokens, device)
					delete(keys, device)
					_, _ = w.Write([]byte(`{}`))
					return
				}
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN"}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer api.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	u := &archive.User{UserID: user, Passwordless: true, Devices: []archive.Device{{ID: "EXODUS", Keys: json.RawMessage(`{"user_id":"@bot:example.org","device_id":"EXODUS","keys":{}}`)}}}
	secrets := &archive.Secrets{Devices: []string{"EXODUS"}, Tokens: []archive.Token{{Token: "original", DeviceID: "EXODUS"}}}
	if err := a.WriteSecrets(user, secrets); err != nil {
		t.Fatal(err)
	}
	client := mx.MustNew(api.URL, "as-token")
	makeImporter := func() *Importer {
		return &Importer{Archive: a, Dest: client, Appservice: &Appservice{Bot: "@exodus:example.org", client: client}}
	}
	im := makeImporter()
	account, err := im.destSession(t.Context(), u)
	if err != nil {
		t.Fatal(err)
	}
	state, err := a.ReadImportState(user)
	if err != nil {
		t.Fatal(err)
	}
	job := &UserJob{User: u, acct: account, state: state, Report: &Report{}}
	if err := im.importDevices(t.Context(), job, secrets); err != nil {
		t.Fatal(err)
	}
	if failures := im.VerifySessions(t.Context(), []*archive.User{u}); len(failures) != 0 {
		t.Fatalf("first migration did not produce a valid mappedtoken: %v", failures)
	}
	im.Close(t.Context())
	retry := makeImporter()
	account, err = retry.destSession(t.Context(), u)
	if err != nil {
		t.Fatal(err)
	}
	state, err = a.ReadImportState(user)
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.importDevices(t.Context(), &UserJob{User: u, acct: account, state: state, Report: &Report{}}, secrets); err != nil {
		t.Fatal(err)
	}
	if failures := retry.VerifySessions(t.Context(), []*archive.User{u}); len(failures) != 0 {
		t.Fatalf("retry revoked preserved device: %v", failures)
	}
	retry.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if !keys["EXODUS"] || tokens["EXODUS"] == "" {
		t.Fatal("cleanup deleted preserved EXODUS device")
	}

}

func TestCompletedDeviceRebuildsSessionMap(t *testing.T) {
	const user = "@alice:example.org"
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	u := &archive.User{UserID: user, Devices: []archive.Device{{ID: "PHONE"}}}
	secrets := &archive.Secrets{Devices: []string{"PHONE"}, Tokens: []archive.Token{{Token: "original", DeviceID: "PHONE"}}}
	if err := a.WriteSecrets(user, secrets); err != nil {
		t.Fatal(err)
	}
	state, err := a.ReadImportState(user)
	if err != nil {
		t.Fatal(err)
	}
	state.Devices["PHONE"] = true
	state.DeviceTokens["PHONE"] = "valid-destination-device-token"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user_id":%q,"device_id":"PHONE"}`, user)
	}))
	defer api.Close()
	im := &Importer{Archive: a, Dest: mx.MustNew(api.URL, "")}
	job := &UserJob{User: u, acct: destAccount{id: user}, state: state, Report: &Report{}}
	if err := im.importDevices(t.Context(), job, secrets); err != nil {
		t.Fatal(err)
	}
	sessions, err := a.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if sessions["original"].Token != state.DeviceTokens["PHONE"] {
		t.Fatal("completed checkpoint did not reconstruct original token mapping")
	}
	if failures := im.VerifySessions(t.Context(), []*archive.User{u}); len(failures) != 0 {
		t.Fatal(failures)
	}

}

func TestRecoveredDehydratedDeviceRemainsDehydrated(t *testing.T) {
	a, database, _ := accountRecoveryFixture(t)
	for _, table := range []string{"token_userdeviceid", "userdeviceid_refresh"} {
		if err := os.WriteFile(filepath.Join(database, table+".txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dehydrated := `{"device_id":"DEVICE","device_data":{"algorithm":"org.matrix.msc3814.v1.olm","device_pickle":"encrypted"}}`
	row := fmt.Sprintf("0x%x ==> 0x%x\n", recoveryUser, dehydrated)
	if err := os.WriteFile(filepath.Join(database, "userid_dehydrateddevice.txt"), []byte(row), 0600); err != nil {
		t.Fatal(err)
	}
	u, secrets, _, err := recoverTuwunelAccount(t.Context(), a, database, recoveryUser, false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Dehydrated == nil || len(u.Devices) != 0 {
		t.Fatal("dehydrated ID leaked into recovered hydrated device list")
	}
	u.Devices = append(u.Devices, archive.Device{ID: u.Dehydrated.DeviceID})
	var hydrated bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			hydrated = true
			fmt.Fprintf(w, `{"user_id":%q,"device_id":"DEVICE","access_token":"destination"}`, recoveryUser)
		case strings.Contains(r.URL.Path, "dehydrated_device"):
			if hydrated {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"errcode":"M_INVALID_PARAM","error":"A hydrated device already exists with that ID"}`))
			} else {
				_, _ = w.Write([]byte(`{}`))
			}
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "as-token")
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{client: c}}
	state, err := a.ReadImportState(recoveryUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := im.importDevices(t.Context(), &UserJob{User: u, state: state, acct: destAccount{id: recoveryUser}, Report: &Report{}}, secrets); err != nil {
		t.Fatal(err)
	}
	if err := importDehydrated(t.Context(), c, u.Dehydrated, secrets); err != nil {
		t.Fatal(err)
	}
	if hydrated {
		t.Fatal("dehydrated ID was logged in as a hydrated device")
	}

}

func TestRegistrationResponseLossAndPasswordChangeResume(t *testing.T) {
	const user = "@alice:example.org"
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	password := ""
	tokens := map[string]string{}
	registrations, appserviceLogins := 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var request struct {
			Type     string `json:"type"`
			Password string `json:"password"`
			DeviceID string `json:"device_id"`
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			credentials, err := a.Credentials()
			if err != nil || credentials[user].Password != request.Password || request.Password == "" {
				t.Error("registration preceded durable credential intent")
			}
			registrations++
			password = request.Password
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"response lost after account creation"}`))
		case strings.HasSuffix(r.URL.Path, "/login"):
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.Type == "m.login.application_service" {
				appserviceLogins++
			} else if password == "" || request.Password != password {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
				return
			}
			token := fmt.Sprintf("temporary-%d", len(tokens)+appserviceLogins)
			tokens[token] = request.DeviceID
			fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":%q}`, user, request.DeviceID, token)
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			device, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN"}`))
				return
			}
			fmt.Fprintf(w, `{"user_id":%q,"device_id":%q}`, user, device)
		case strings.HasSuffix(r.URL.Path, "/logout"):
			delete(tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "")
	c.DefaultHTTPRetries = 0
	makeImporter := func() *Importer {
		asClient := mx.WithToken(c, "as-token")
		asClient.DefaultHTTPRetries = 0
		return &Importer{Archive: a, Dest: c, Appservice: &Appservice{Bot: "@exodus:example.org", client: asClient}}
	}
	u := &archive.User{UserID: user}
	if _, err := makeImporter().destSession(t.Context(), u); !mx.IsStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("lost response: %v", err)
	}
	retry := makeImporter()
	account, err := retry.destSession(t.Context(), u)
	if err != nil || account.password == "" {
		t.Fatalf("resume after registration: %v", err)
	}
	cached := makeImporter()
	if account, err := cached.destSession(t.Context(), u); err != nil || account.password == "" {
		t.Fatalf("cached session lost password for UIA: %v", err)
	}
	retry.Close(t.Context())
	mu.Lock()
	password = "restored source password"
	mu.Unlock()
	if err := a.MarkPasswordRestored(user); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSecrets(user, &archive.Secrets{PasswordHash: "archived hash"}); err != nil {
		t.Fatal(err)
	}
	resumed := makeImporter()
	if _, err := resumed.PrepareUser(t.Context(), u); err != nil {
		t.Fatalf("resume after proxy password restoration: %v", err)
	}
	pending, err := a.PendingPasswords()
	if err != nil || len(pending) != 0 {
		t.Fatal("resume queued an already restored source password")
	}
	mu.Lock()
	defer mu.Unlock()
	if registrations != 1 || appserviceLogins != 1 {
		t.Fatalf("registration=%d appservice login=%d", registrations, appserviceLogins)
	}
}

func TestFinalizedRestrictedAccountResume(t *testing.T) {
	for _, status := range []string{"locked", "suspended", "deactivated"} {
		t.Run(status, func(t *testing.T) {
			u := &archive.User{UserID: "@alice:example.org", Locked: status == "locked", Suspended: status == "suspended", Deactivated: status == "deactivated"}
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			state, err := a.ReadImportState(u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			state.DestUserID, state.Status = u.UserID, true
			if err := a.WriteImportState(u.UserID, state); err != nil {
				t.Fatal(err)
			}
			if err := a.WriteSecrets(u.UserID, &archive.Secrets{Tokens: []archive.Token{{Token: "old", DeviceID: "PHONE"}}}); err != nil {
				t.Fatal(err)
			}
			if err := a.WriteSessions(map[string]archive.Session{"old": {UserID: u.UserID, DeviceID: "PHONE", Token: "verified-before-lock"}}); err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, DeactivatedIDOnly: true}
			job, err := im.PrepareUser(t.Context(), u)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := im.FinishUser(t.Context(), job, nil); err != nil {
				t.Fatal(err)
			}
			if failures := im.VerifySessions(t.Context(), []*archive.User{u}); len(failures) != 0 {
				t.Fatal(failures)
			}
		})
	}
}

func TestLegacyMigrationOwnershipResume(t *testing.T) {
	const user = "@alice:example.org"
	for _, checkpoint := range []string{user, "@other:example.org", "@alice:other.example", ""} {
		t.Run("checkpoint="+checkpoint, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			state, err := a.ReadImportState(user)
			if err != nil {
				t.Fatal(err)
			}
			state.DestUserID = checkpoint
			if err := a.WriteImportState(user, state); err != nil {
				t.Fatal(err)
			}
			appserviceLogins := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/register") {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"errcode":"M_USER_IN_USE"}`))
					return
				}
				var request struct {
					Type     string `json:"type"`
					DeviceID string `json:"device_id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if request.Type != "m.login.application_service" {
					t.Error("unexpected password login")
				}
				session, err := a.ReadMigrationSession(user)
				if err != nil || !session.Owned || session.UserID != user || session.DeviceID != request.DeviceID {
					t.Error("appservice used before durable account ownership")
				}
				appserviceLogins++
				fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":"temporary"}`, user, request.DeviceID)
			}))
			defer api.Close()
			c := mx.MustNew(api.URL, "")
			im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{Bot: "@exodus:example.org", client: mx.WithToken(c, "as-token")}}
			_, err = im.destSession(t.Context(), &archive.User{UserID: user})
			if checkpoint == user {
				if err != nil || appserviceLogins != 1 {
					t.Fatalf("legacy resume: %v, logins %d", err, appserviceLogins)
				}
			} else if err == nil || appserviceLogins != 0 {
				t.Fatal("unrelated checkpoint authorized appservice login")
			}
		})
	}
}

func TestUnownedAppserviceAccountsAreRefused(t *testing.T) {
	for _, kind := range []string{"guest", "passwordless", "deactivated"} {
		t.Run(kind, func(t *testing.T) {
			logins := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/login") {
					logins++
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errcode":"M_USER_IN_USE"}`))
			}))
			defer api.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			c := mx.MustNew(api.URL, "as-token")
			im := &Importer{Archive: a, Dest: c, DeactivatedIDOnly: true, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}
			u := &archive.User{UserID: "@existing:example.org", Guest: kind == "guest", Passwordless: kind == "passwordless", Deactivated: kind == "deactivated"}
			if _, err := im.destSession(t.Context(), u); err == nil || !strings.Contains(err.Error(), "refusing to take ownership") || logins != 0 {
				t.Fatalf("unowned account: %v, logins=%d", err, logins)
			}
			session, err := a.ReadMigrationSession(u.UserID)
			if err != nil || session.Owned {
				t.Fatal("existing account was marked owned")
			}
		})
	}
}

func TestAppserviceRegistrationOwnershipSurvivesLoginFailure(t *testing.T) {
	const user = "@bot:example.org"
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	registrations, logins := 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/register") {
			registrations++
			fmt.Fprintf(w, `{"user_id":%q}`, user)
			return
		}
		logins++
		session, err := a.ReadMigrationSession(user)
		if err != nil || !session.Owned {
			t.Error("login preceded durable registration ownership")
		}
		if logins == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
			return
		}
		fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":"temporary"}`, user, session.DeviceID)
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "as-token")
	makeImporter := func() *Importer {
		return &Importer{Archive: a, Dest: c, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}
	}
	u := &archive.User{UserID: user, Passwordless: true}
	if _, err := makeImporter().destSession(t.Context(), u); err == nil {
		t.Fatal("first login should fail")
	}
	if _, err := makeImporter().destSession(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	if registrations != 1 || logins != 2 {
		t.Fatalf("registrations=%d logins=%d", registrations, logins)
	}
}

func TestLegacyUnknownPasswordStateIsRefused(t *testing.T) {
	const user = "@alice:example.org"
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	state, err := a.ReadImportState(user)
	if err != nil {
		t.Fatal(err)
	}
	state.DestUserID = user
	if err := a.WriteImportState(user, state); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSecrets(user, &archive.Secrets{PasswordHash: "source hash"}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddCredential(archive.Credential{SourceUserID: user, DestUserID: user, Password: "old generated password"}); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if !strings.HasSuffix(r.URL.Path, "/login") || body.Type != "m.login.password" {
			t.Error("ambiguous legacy account used an appservice or changed password")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "")
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{Bot: "@exodus:example.org", client: mx.WithToken(c, "as-token")}}
	if _, err := im.PrepareUser(t.Context(), &archive.User{UserID: user}); err == nil || !strings.Contains(err.Error(), "legacy password migration state is unknown") {
		t.Fatalf("ambiguous legacy password: %v", err)
	}
	pending, err := a.PendingPasswords()
	if err != nil || len(pending) != 0 {
		t.Fatal("legacy source hash was silently requeued")
	}
}

func TestIncompleteDeviceRenewsRevokedToken(t *testing.T) {
	const user = "@alice:example.org"
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	logins, uploads := 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN"}`))
		case strings.HasSuffix(r.URL.Path, "/login"):
			logins++
			fmt.Fprintf(w, `{"user_id":%q,"device_id":"PHONE","access_token":"renewed"}`, user)
		case strings.HasSuffix(r.URL.Path, "/keys/upload"):
			if r.Header.Get("Authorization") != "Bearer renewed" {
				t.Error("revoked token reused")
			}
			uploads++
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer api.Close()
	state, err := a.ReadImportState(user)
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceTokens["PHONE"] = "revoked"
	c := mx.MustNew(api.URL, "as-token")
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{client: c}}
	u := &archive.User{UserID: user, Devices: []archive.Device{{ID: "PHONE", Keys: json.RawMessage(`{"user_id":"@alice:example.org","device_id":"PHONE"}`)}}}
	job := &UserJob{User: u, acct: destAccount{id: user}, state: state, Report: &Report{}}
	if err := im.importDevices(t.Context(), job, &archive.Secrets{Tokens: []archive.Token{{Token: "original", DeviceID: "PHONE"}}}); err != nil {
		t.Fatal(err)
	}
	if logins != 1 || uploads != 1 || !state.Devices["PHONE"] || len(job.Report.Failures) != 0 {
		t.Fatalf("login=%d upload=%d state=%v failures=%v", logins, uploads, state.Devices, job.Report.Failures)
	}
}
