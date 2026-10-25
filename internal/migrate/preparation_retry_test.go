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

func TestProfileAvatarKeepsRemoteURI(t *testing.T) {
	for _, tc := range []struct {
		name, avatar, mapped, want string
		fails                      bool
	}{
		{name: "remote", avatar: "mxc://maunium.net/avatar", want: "mxc://maunium.net/avatar"},
		{name: "local missing", avatar: "mxc://example.org/avatar", fails: true},
		{name: "local uploaded", avatar: "mxc://example.org/avatar", mapped: "mxc://destination.org/upload", want: "mxc://destination.org/upload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/avatar_url") {
					t.Error("unexpected avatar request")
				}
				var body struct {
					Avatar string `json:"avatar_url"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body.Avatar != tc.want {
					t.Errorf("avatar=%s", body.Avatar)
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			defer api.Close()
			state := &archive.ImportState{Media: map[string]string{}}
			if tc.mapped != "" {
				state.Media[tc.avatar] = tc.mapped
			}
			report := &Report{}
			importProfile(t.Context(), mx.MustNew(api.URL, "token"), &archive.User{UserID: "@bot:example.org", AvatarURL: tc.avatar}, state, report)
			if (len(report.Failures) > 0) != tc.fails || tc.fails && calls != 0 || !tc.fails && calls != 1 {
				t.Fatalf("requests=%d failures=%+v", calls, report.Failures)
			}
		})
	}
}

func TestAlreadyJoinedAdminRequiresVerifiedPrivileges(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		status      int
		html        bool
		fails       bool
		checks      int
	}{
		{name: "existing admin", reply: "Command failed with error: User is already joined in the admin room", status: 200, checks: 1},
		{name: "joined without privileges", reply: "Command failed with error: User is already joined in the admin room", status: 403, fails: true, checks: 1},
		{name: "wrong proxy route", reply: "Command failed with error: User is already joined in the admin room", status: 200, html: true, fails: true, checks: 1},
		{name: "unrelated failure", reply: "Command failed with error: permission denied", fails: true},
		{name: "new grant", reply: "Granted administrator privileges"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/send/"):
					_, _ = w.Write([]byte(`{"event_id":"$grant"}`))
				case strings.HasSuffix(r.URL.Path, "/messages"):
					fmt.Fprintf(w, `{"chunk":[{"type":"m.room.message","sender":"@conduit:example.org","content":{"msgtype":"m.text","body":%q,"m.relates_to":{"m.in_reply_to":{"event_id":"$grant"}}}}]}`, tc.reply)
				case r.URL.Path == "/_continuwuity/admin/rooms/list":
					checks++
					if r.Header.Get("Authorization") != "Bearer target-user-token" {
						t.Error("admin verification used the operator's identity")
					}
					if tc.html {
						w.Header().Set("Content-Type", "text/html")
					}
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(`{"rooms":[]}`))
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			admin := &ContinuwuityAdmin{client: mx.MustNew(api.URL, "operator-token"), bot: "@conduit:example.org", room: "!admins:example.org"}
			err := admin.EnsureUserAdmin(t.Context(), mx.MustNew(api.URL, "target-user-token"), "@lea:example.org")
			if (err != nil) != tc.fails || checks != tc.checks {
				t.Fatalf("error=%v checks=%d", err, checks)
			}
		})
	}
}

func TestKeyBackupResumeReconcilesCurrentVersion(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		owned                               bool
		differentKey, missing, race, denied bool
		wantCreates                         int
		wantErr                             bool
	}{
		{name: "resume owned version", owned: true},
		{name: "retain matching newer version", wantCreates: 1},
		{name: "retain different key", differentKey: true, wantCreates: 1},
		{name: "deleted version", missing: true, wantCreates: 1},
		{name: "version changes during upload", race: true, owned: true, wantCreates: 1},
		{name: "permission failure", denied: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, user := keyBackupImportFixture(t, 2, 16)
			reader, err := a.OpenKeyBackup(t.Context(), user)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			latest, creates, uploads := "newer", 0, 0
			if tc.owned {
				latest = "old-version"
			}
			seen := map[string]bool{}
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					if tc.denied {
						w.WriteHeader(403)
						_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
						return
					}
					if tc.missing && creates == 0 {
						w.WriteHeader(404)
						_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND"}`))
						return
					}
					auth := reader.AuthData
					if tc.differentKey && creates == 0 {
						auth = json.RawMessage(`{"public_key":"different destination key"}`)
					}
					fmt.Fprintf(w, `{"version":%q,"algorithm":%q,"auth_data":%s}`, latest, reader.Algorithm, auth)
				case http.MethodPost:
					creates++
					latest = fmt.Sprintf("restored-%d", creates)
					var body struct {
						Algorithm string
						AuthData  json.RawMessage `json:"auth_data"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Algorithm != reader.Algorithm || !strings.Contains(string(body.AuthData), `"original"`) {
						t.Error("recovery metadata was replaced")
					}
					fmt.Fprintf(w, `{"version":%q}`, latest)
				case http.MethodPut:
					uploads++
					if !tc.owned && r.URL.Query().Get("version") == "newer" {
						t.Error("a newer destination backup was overwritten")
					}
					if r.URL.Query().Get("version") != latest {
						t.Error("upload used a stale version")
					}
					if tc.race && uploads == 1 {
						latest = "raced"
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"errcode":"M_INVALID_PARAM","error":"You may only manipulate the most recently created version of the backup."}`))
						return
					}
					var body struct {
						Rooms map[string]struct{ Sessions map[string]json.RawMessage }
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					for key, data := range body.Rooms["!room:example.org"].Sessions {
						seen[key] = true
						if !strings.Contains(string(data), strings.Repeat("x", 16)) {
							t.Error("encrypted key data changed")
						}
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Error("existing backups must not be deleted")
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			state := &archive.ImportState{KeyBackup: "old-version"}
			err = importKeyBackup(t.Context(), mx.MustNew(api.URL, "token"), reader, state, func() error { return a.WriteImportState(user, state) })
			if (err != nil) != tc.wantErr || creates != tc.wantCreates {
				t.Fatalf("error=%v created=%d", err, creates)
			}
			if !tc.wantErr && (!state.KeysDone || state.KeyBackup != latest || len(seen) != 2) {
				t.Fatalf("version=%s complete=%v keys=%d", state.KeyBackup, state.KeysDone, len(seen))
			}
			if tc.denied && (state.KeysDone || uploads != 0) {
				t.Fatal("permission failure advanced backup checkpoint")
			}
		})
	}
}
