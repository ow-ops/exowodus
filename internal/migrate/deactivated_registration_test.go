package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

func TestDeactivatedIDRestorationWithRegistrationDisabled(t *testing.T) {
	const userID = "@deleted:example.org"
	var registered, loggedIn, deactivated int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			var body struct {
				Type         string `json:"type"`
				Username     string `json:"username"`
				Password     string `json:"password"`
				InhibitLogin bool   `json:"inhibit_login"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if r.Header.Get("Authorization") != "Bearer as-token" || body.Type != "m.login.application_service" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"registration disabled"}`))
				return
			}
			if body.Username != "deleted" || body.Password != "" || !body.InhibitLogin {
				t.Error("ID-only registration created password credentials")
			}
			registered++
			fmt.Fprintf(w, `{"user_id":%q}`, userID)
		case strings.HasSuffix(r.URL.Path, "/login"):
			var body struct {
				Type string `json:"type"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if r.Header.Get("Authorization") != "Bearer as-token" || body.Type != "m.login.application_service" {
				t.Error("ID-only restoration did not use its appservice session")
			}
			loggedIn++
			fmt.Fprintf(w, `{"user_id":%q,"device_id":"EXODUS","access_token":"migration"}`, userID)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/send/"):
			var body struct {
				Body string `json:"body"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if r.Header.Get("Authorization") != "Bearer admin" || body.Body != "!admin users deactivate --no-leave-rooms "+userID {
				t.Error("restored ID was not deactivated through the admin API")
			}
			deactivated++
			_, _ = w.Write([]byte(`{"event_id":"$command"}`))
		case strings.HasSuffix(r.URL.Path, "/messages"):
			_, _ = w.Write([]byte(`{"chunk":[{"type":"m.room.message","sender":"@conduit:example.org","content":{"msgtype":"m.text","body":"Deactivated user","m.relates_to":{"m.in_reply_to":{"event_id":"$command"}}}}]}`))
		default:
			t.Errorf("unexpected ID-only restoration request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer api.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	dest := mx.MustNew(api.URL, "")
	im := &Importer{Archive: a, Dest: dest, DeactivatedIDOnly: true,
		Appservice: &Appservice{Bot: "@exodus:example.org", client: mx.WithToken(dest, "as-token")},
		Admin:      &ContinuwuityAdmin{client: mx.WithToken(dest, "admin"), room: "!admins:example.org", bot: "@conduit:example.org"},
	}
	user := &archive.User{UserID: userID, Deactivated: true, DisplayName: "not restored in ID-only mode"}
	job, err := im.PrepareUser(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	if job.acct.generated || job.acct.password != "" || !user.Deactivated {
		t.Fatal("ID-only restoration changed account status or generated password credentials")
	}
	if _, err := im.FinishUser(t.Context(), job, nil); err != nil {
		t.Fatal(err)
	}
	if failures := im.ApplyStatus(t.Context(), []*archive.User{user}); len(failures) > 0 {
		t.Fatal(failures)
	}
	credentials, err := a.Credentials()
	if err != nil || len(credentials) != 0 || registered != 1 || loggedIn != 1 || deactivated != 1 {
		t.Fatal("ID-only restoration did not finish without password credentials")
	}
	state, err := a.ReadImportState(userID)
	if err != nil || !state.Status || state.DestUserID != userID {
		t.Fatal("deactivated status was not checkpointed")
	}
}

func TestIDOnlyOptionKeepsPasswordRegistration(t *testing.T) {
	for _, deactivated := range []bool{false, true} {
		t.Run(fmt.Sprintf("deactivated=%t", deactivated), func(t *testing.T) {
			var requests int
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Type     string `json:"type"`
					Password string `json:"password"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if !strings.HasSuffix(r.URL.Path, "/register") || body.Type != "" || body.Password == "" || r.Header.Get("Authorization") != "Bearer as-token" {
					t.Error("normal account did not use authenticated password registration")
				}
				requests++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"registration disabled"}`))
			}))
			defer api.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			dest := mx.MustNew(api.URL, "")
			im := &Importer{Archive: a, Dest: dest, DeactivatedIDOnly: !deactivated,
				Appservice: &Appservice{Bot: "@exodus:example.org", client: mx.WithToken(dest, "as-token")},
			}
			_, err = im.destSession(t.Context(), &archive.User{UserID: "@alice:example.org", Deactivated: deactivated})
			if !mx.IsStatus(err, http.StatusForbidden) || requests != 1 {
				t.Fatalf("normal registration policy changed: requests=%d err=%v", requests, err)
			}
		})
	}
}
