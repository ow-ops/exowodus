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

func TestDestinationPreflight(t *testing.T) {
	for _, tc := range []struct {
		name, flows, failure string
		invalid, blocked     bool
	}{
		{name: "ready", flows: `[{"type":"m.login.password"},{"type":"m.login.application_service"}]`},
		{name: "exclusive OAuth", flows: `[]`, failure: "legacy login"},
		{name: "appservice disabled", flows: `[{"type":"m.login.password"}]`, failure: "m.login.application_service"},
		{name: "historical IDs", flows: `[{"type":"m.login.password"},{"type":"m.login.application_service"}]`, invalid: true, failure: "original spelling"},
		{name: "registration rejected", flows: `[{"type":"m.login.password"},{"type":"m.login.application_service"}]`, blocked: true, failure: "registration is unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posts, names := 0, 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/login"):
					fmt.Fprintf(w, `{"flows":%s}`, tc.flows)
				case strings.HasSuffix(r.URL.Path, "/register/available"):
					names++
					if tc.invalid {
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"errcode":"M_INVALID_USERNAME","error":"uppercase rejected"}`))
						return
					}
					_, _ = w.Write([]byte(`{"available":true}`))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/register"):
					posts++
					if r.Header.Get("Authorization") != "Bearer as-token" {
						t.Error("registration probe lost appservice authentication")
					}
					var req struct {
						Username, Password string
						Inhibit            bool `json:"inhibit_login"`
						Auth               any
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
					}
					if req.Username != "conduit" || req.Password != "" || req.Auth != nil || !req.Inhibit {
						t.Error("registration probe could create a new account")
					}
					if tc.blocked {
						w.WriteHeader(403)
						_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"registrations disabled"}`))
						return
					}
					w.WriteHeader(401)
					_, _ = w.Write([]byte(`{"session":"probe","flows":[{"stages":["m.login.registration_token"]}]}`))
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer api.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			c := mx.MustNew(api.URL, "")
			im := &Importer{Archive: a, Dest: c, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org", client: mx.WithToken(c, "admin-token")}, RegistrationToken: "registration-token"}
			im.Appservice = &Appservice{Bot: "@exodus:example.org", client: mx.WithToken(c, "as-token")}
			users := []*archive.User{{UserID: "@alice:example.org", Devices: []archive.Device{{ID: "PHONE"}}}, {UserID: "@Guest:example.org", Guest: true}}
			err = im.CheckDestination(t.Context(), users)
			if err == nil {
				err = im.CheckRegistration(t.Context())
			}
			if tc.failure == "" && err != nil || tc.failure != "" && (err == nil || !strings.Contains(err.Error(), tc.failure)) {
				t.Fatalf("preflight=%v", err)
			}
			if tc.name == "ready" && (posts != 1 || names != 2) {
				t.Fatalf("probes=%d names=%d", posts, names)
			}
			if strings.Contains(tc.failure, "login") && posts != 0 {
				t.Fatal("registration reached after failed login discovery")
			}
			if tc.invalid && (err == nil || !strings.Contains(err.Error(), "@alice:example.org") || !strings.Contains(err.Error(), "@Guest:example.org")) {
				t.Fatal("username failures were not aggregated")
			}
		})
	}
}

func TestOrdinaryRegistrationUsesAppserviceAuthentication(t *testing.T) {
	registrations := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/register") || r.Header.Get("Authorization") != "Bearer as-token" {
			t.Error("ordinary registration requires appservice authentication")
			w.WriteHeader(403)
			return
		}
		var req struct {
			Username, Password, Type string
			Device                   string `json:"device_id"`
			Auth                     map[string]string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Username != "alice" || req.Password == "" || req.Device == "" || req.Type != "" {
			t.Error("ordinary account was not registered with a password and separate device")
		}
		registrations++
		if req.Auth == nil {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"session":"registration","flows":[{"stages":["m.login.registration_token"]}]}`))
			return
		}
		if req.Auth["token"] != "registration-token" {
			t.Error("registration token flow was bypassed")
		}
		fmt.Fprintf(w, `{"user_id":"@alice:example.org","device_id":%q,"access_token":"new-user-token"}`, req.Device)
	}))
	defer api.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	c := mx.MustNew(api.URL, "")
	im := &Importer{Archive: a, Dest: c, Admin: &ContinuwuityAdmin{client: mx.WithToken(c, "admin-token"), bot: "@conduit:example.org"}, RegistrationToken: "registration-token"}
	im.Appservice = &Appservice{Bot: "@exodus:example.org", client: mx.WithToken(c, "as-token")}
	client, _, err := im.login(t.Context(), &archive.User{UserID: "@alice:example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || client.AccessToken != "new-user-token" || string(client.UserID) != "@alice:example.org" {
		t.Fatal("registered session does not belong to the new user")
	}
}

func TestAdoptExistingPasswordlessAccount(t *testing.T) {
	const user = "@whatsappbot:example.org"
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprint(wrong), func(t *testing.T) {
			logins := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/whoami"):
					if r.URL.Query().Get("user_id") != user {
						t.Error("existing identity was not checked")
					}
					id := user
					if wrong {
						id = "@other:example.org"
					}
					fmt.Fprintf(w, `{"user_id":%q}`, id)
				case strings.HasSuffix(r.URL.Path, "/login"):
					logins++
					var req struct {
						Device string `json:"device_id"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
					}
					if req.Device == "PHONE" || req.Device == "" {
						t.Error("existing device was reused")
					}
					fmt.Fprintf(w, `{"user_id":%q,"device_id":%q,"access_token":"migration-token"}`, user, req.Device)
				default:
					t.Error("adoption tried registering an existing account")
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			c := mx.MustNew(api.URL, "as-token")
			im := &Importer{Archive: a, Dest: c, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}
			u := &archive.User{UserID: user, Passwordless: true, Devices: []archive.Device{{ID: "PHONE"}}}
			if err := im.SetAdoptExistingUsers([]*archive.User{u}, []string{user}); err != nil {
				t.Fatal(err)
			}
			_, _, err = im.login(t.Context(), u)
			if wrong && (err == nil || logins != 0) {
				t.Fatalf("wrong identity accepted: %v", err)
			}
			if !wrong && (err != nil || logins != 1) {
				t.Fatalf("adoption failed: %v", err)
			}
			state, stateErr := a.ReadMigrationSession(user)
			if stateErr != nil || state.Owned == wrong {
				t.Fatalf("ownership=%+v error=%v", state, stateErr)
			}
			if err := im.SetAdoptExistingUsers([]*archive.User{u}, []string{"@not-exported:example.org"}); err == nil {
				t.Fatal("unarchived account accepted")
			}
		})
	}
}
