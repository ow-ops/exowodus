package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func keyBackupImportFixture(t *testing.T, count, keyBytes int) (*archive.Archive, string) {
	t.Helper()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	const user = "@alice:example.org"
	sessions := map[string]json.RawMessage{}
	for i := range count {
		sessions[fmt.Sprintf("session%d", i)] = json.RawMessage(`{"first_message_index":10,"forwarded_count":1,"is_verified":false,"session_data":{"ciphertext":"` + strings.Repeat("x", keyBytes) + `"}}`)
	}
	raw, err := json.Marshal(map[string]any{"sessions": sessions})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteKeyBackup(user, &archive.KeyBackup{Algorithm: "m.megolm_backup.v1.curve25519-aes-sha2", AuthData: json.RawMessage(`{"public_key":"original"}`), Rooms: map[string]json.RawMessage{"!room:example.org": raw}}); err != nil {
		t.Fatal(err)
	}
	return a, user
}

func TestKeyBackupImportStreamsSingleSessions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		size  int
	}{
		{name: "session count", count: 2101, size: 64},
		{name: "payload bytes", count: 9, size: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, user := keyBackupImportFixture(t, tc.count, tc.size)
			reader, err := a.OpenKeyBackup(t.Context(), user)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			creates := 0
			seen := map[string]bool{}
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND"}`))
					return
				}
				if r.Method == http.MethodPost {
					creates++
					var body struct {
						Algorithm string `json:"algorithm"`
						AuthData  struct {
							PublicKey string `json:"public_key"`
						} `json:"auth_data"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Algorithm != reader.Algorithm || body.AuthData.PublicKey != "original" {
						t.Error("backup recovery metadata changed")
					}
					_, _ = w.Write([]byte(`{"version":"new-version"}`))
					return
				}
				if r.URL.Query().Get("version") != "new-version" {
					t.Error("keys uploaded to a different backup version")
				}
				prefix := "/_matrix/client/v3/room_keys/keys/!room:example.org/"
				if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, prefix) {
					t.Errorf("unexpected key upload: %s %s", r.Method, r.URL.Path)
				}
				var body struct {
					SessionData struct{ Ciphertext string } `json:"session_data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body.SessionData.Ciphertext != strings.Repeat("x", tc.size) {
					t.Error("encrypted session data changed")
				}
				key := strings.TrimPrefix(r.URL.Path, prefix)
				if seen[key] {
					t.Error("key uploaded twice without a retry")
				}
				seen[key] = true
				_, _ = w.Write([]byte(`{}`))
			}))
			defer api.Close()
			state := &archive.ImportState{}
			if err := importKeyBackup(t.Context(), mx.MustNew(api.URL, "token"), reader, state, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if creates != 1 || len(seen) != tc.count || !state.KeysDone {
				t.Fatalf("versions=%d keys=%d complete=%t", creates, len(seen), state.KeysDone)
			}
		})
	}
}

func TestKeyBackupImportRetryKeepsVersion(t *testing.T) {
	a, user := keyBackupImportFixture(t, 1001, 10)
	reader, err := a.OpenKeyBackup(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	versions, uploads := 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			if versions == 0 {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND"}`))
				return
			}
			fmt.Fprintf(w, `{"version":"saved-version","algorithm":%q,"auth_data":%s}`, reader.Algorithm, reader.AuthData)
			return
		}
		if r.Method == http.MethodPost {
			versions++
			_, _ = w.Write([]byte(`{"version":"saved-version"}`))
			return
		}
		uploads++
		if uploads == 2 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"injected failure"}`))
			return
		}
		if r.URL.Query().Get("version") != "saved-version" {
			t.Error("retry changed the backup version")
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer api.Close()
	state := &archive.ImportState{}
	c := mx.MustNew(api.URL, "token")
	save := func() error { return a.WriteImportState(user, state) }
	if err := importKeyBackup(t.Context(), c, reader, state, save); err == nil || state.KeysDone {
		t.Fatal("failed backup upload was marked complete")
	}
	state, err = a.ReadImportState(user)
	if err != nil || state.KeyBackup != "saved-version" || state.KeysDone {
		t.Fatal("failed upload lost the version checkpoint")
	}
	if err := importKeyBackup(t.Context(), c, reader, state, save); err != nil {
		t.Fatal(err)
	}
	if versions != 1 || uploads != 1003 || !state.KeysDone {
		t.Fatal("backup retry created another version or skipped pending keys")
	}
}

func TestCompletedKeyBackupIsNotRead(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	user := &archive.User{UserID: "@alice:example.org"}
	if err := a.WriteImportState(user.UserID, &archive.ImportState{KeysDone: true, KeyBackup: "complete"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.UserDir(user.UserID), "key_backup.json"), []byte("invalid JSON must not be read"), 0600); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("completed backup made an HTTP request") }))
	defer api.Close()
	c := mx.MustNew(api.URL, "token")
	im := &Importer{Archive: a, sessions: map[string]destAccount{user.UserID: {id: user.UserID, client: c}}}
	job, err := im.PrepareUser(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := im.FinishUser(t.Context(), job, nil); err != nil {
		t.Fatalf("completed backup was opened again: %v", err)
	}
}

func TestBackupConflictDoesNotBlockRoomImport(t *testing.T) {
	a, userID := keyBackupImportFixture(t, 2, 16)
	const roomID = "!room:example.org"
	user := &archive.User{UserID: userID, Rooms: []archive.Room{{RoomID: roomID}}}
	compatible := false
	metadataReads, keyUploads, roomWrites := 0, 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/room_keys/version"):
			metadataReads++
			if roomWrites == 0 {
				t.Error("backup restoration ran before room import")
			}
			key := "destination-key"
			if compatible {
				key = "original"
			}
			fmt.Fprintf(w, `{"version":"525","algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":%q}}`, key)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/room_keys/keys/"):
			keyUploads++
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/rooms/"+roomID+"/account_data/"):
			roomWrites++
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "token")
	im := &Importer{Archive: a, Dest: c, rooms: map[string]string{roomID: roomID}, sessions: map[string]destAccount{userID: {id: userID, client: c}}}
	user.Rooms[0].AccountData = map[string]json.RawMessage{"custom": json.RawMessage(`{"test":true}`)}
	job, err := im.PrepareUser(t.Context(), user)
	if err != nil || len(job.Report.Failures) != 0 || metadataReads != 0 {
		t.Fatalf("preparation error=%v report=%+v backup reads=%d", err, job, metadataReads)
	}
	report, err := im.FinishUser(t.Context(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.PreparationOnly || report.RoomsJoined != 1 || len(report.Failures) != 1 || report.Failures[0].Step != "key_backup" || metadataReads != 1 || keyUploads != 0 {
		t.Fatalf("report=%+v reads=%d uploads=%d", report, metadataReads, keyUploads)
	}
	state, err := a.ReadImportState(userID)
	if err != nil || !state.Rooms[roomID] || state.KeysDone {
		t.Fatalf("state=%+v error=%v", state, err)
	}
	if backup, err := a.ReadKeyBackup(userID); err != nil || backup == nil || !strings.Contains(string(backup.AuthData), `"original"`) {
		t.Fatal("backup conflict changed the archived recovery metadata")
	}

	compatible = true
	job, err = im.PrepareUser(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	report, err = im.FinishUser(t.Context(), job, nil)
	if err != nil || len(report.Failures) != 0 || report.RoomsJoined != 1 || keyUploads != 2 || roomWrites != 1 {
		t.Fatalf("retry error=%v report=%+v uploads=%d room writes=%d", err, report, keyUploads, roomWrites)
	}
	state, err = a.ReadImportState(userID)
	if err != nil || !state.KeysDone || state.KeyBackup != "525" {
		t.Fatalf("restored backup state=%+v error=%v", state, err)
	}
}
