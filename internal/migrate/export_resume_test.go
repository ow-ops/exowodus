package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestResumeCompletedRoom(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			const room = "!room:example.org"
			const first = `{"event_id":"$first","sender":"@alice:example.org","type":"m.room.message","content":{"body":"first"}}`
			const last = `{"event_id":"$last","sender":"@alice:example.org","type":"m.room.message","content":{"body":"last"}}`
			var history, state, head atomic.Int32
			var sourceChanged atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/state"):
					state.Add(1)
					_, _ = fmt.Fprint(w, `{"state":[{"type":"m.room.create","content":{"room_version":"10"}},{"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join"}}]}`)
				case strings.HasSuffix(r.URL.Path, "/messages"):
					if r.URL.Query().Get("dir") == "b" {
						head.Add(1)
						if sourceChanged.Load() {
							_, _ = fmt.Fprint(w, `{"chunk":[{"event_id":"$new"}]}`)
						} else {
							_, _ = fmt.Fprintf(w, `{"chunk":[%s]}`, last)
						}
					} else {
						history.Add(1)
						_, _ = fmt.Fprintf(w, `{"chunk":[%s,%s]}`, first, last)
					}
				default:
					_, _ = fmt.Fprint(w, `{}`)
				}
			}))
			defer server.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			source := archive.ExportSource{Fingerprint: "source", Dump: map[string]string{}}
			resume, err := a.OpenExportResume(t.Context(), source, false)
			if err != nil {
				t.Fatal(err)
			}
			client := mx.MustNew(server.URL, "token")
			e := Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{}, Resume: resume}
			if err := e.ExportRoom(t.Context(), room, nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := resume.Close(); err != nil {
				t.Fatal(err)
			}
			sourceChanged.Store(changed)
			resume, err = a.OpenExportResume(t.Context(), source, false)
			if err != nil {
				t.Fatal(err)
			}
			defer resume.Close()
			e = Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{}, Resume: resume}
			err = e.ExportRoom(t.Context(), room, nil, nil)
			if changed {
				if err == nil || !strings.Contains(err.Error(), "changed since export") {
					t.Fatalf("source change=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if state.Load() != 1 || history.Load() != 1 || head.Load() != 1 {
				t.Fatalf("state=%d history=%d head=%d", state.Load(), history.Load(), head.Load())
			}
		})
	}
}

func TestResumeCorruptHistory(t *testing.T) {
	const room = "!room:example.org"
	var histories atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/state"):
			_, _ = fmt.Fprint(w, `{"state":[{"type":"m.room.create","content":{"room_version":"10"}}]}`)
		case strings.HasSuffix(r.URL.Path, "/messages"):
			if r.URL.Query().Get("dir") != "b" {
				histories.Add(1)
			}
			_, _ = fmt.Fprint(w, `{"chunk":[{"event_id":"$message","sender":"@alice:example.org","type":"m.room.message","content":{}}]}`)

		default:
			_, _ = fmt.Fprint(w, `{}`)
		}
	}))
	defer server.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source", Dump: map[string]string{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	client := mx.MustNew(server.URL, "token")
	client.DefaultHTTPRetries = 0
	e := Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{}, Resume: resume}
	if err := e.Archive.WriteRoomEvents(room, []json.RawMessage{json.RawMessage(`{"event_id":"$message"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := e.saveHistoryExport(t.Context(), room, "$message"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.RoomDir(room), "events.jsonl"), []byte("corrupt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.ExportRoom(t.Context(), room, nil, nil); err != nil {
		t.Fatal(err)
	}
	if histories.Load() != 1 {
		t.Fatalf("corrupt history was reused: %d", histories.Load())
	}
}

func TestResumeExportMedia(t *testing.T) {
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			_, _ = fmt.Fprint(w, `{"versions":["v1.11"]}`)
			return
		}
		downloads.Add(1)
		w.Header().Set("Content-Type", "image/png")
		_, _ = fmt.Fprint(w, "media")
	}))
	defer server.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	e := Exporter{Archive: a, Resume: resume, TuwunelDump: &TuwunelDump{}}
	client := mx.MustNew(server.URL, "token")
	path := filepath.Join(a.Dir, "file")
	if _, _, err := e.downloadExportMedia(t.Context(), client, "mxc://remote.org/file", path); err == nil {
		t.Fatal("remote media download accepted")
	}
	if downloads.Load() != 0 {
		t.Fatal("remote media request reached the source")
	}
	for i := 0; i < 2; i++ {
		if _, _, err := e.downloadExportMedia(t.Context(), client, "mxc://example.org/file", path); err != nil {
			t.Fatal(err)
		}
	}
	if downloads.Load() != 1 {
		t.Fatalf("downloaded %d times", downloads.Load())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.downloadExportMedia(t.Context(), client, "mxc://example.org/file", path); err != nil {
		t.Fatal(err)
	}
	if downloads.Load() != 2 {
		t.Fatal("missing media not downloaded again")
	}
}

func TestResumeUserRequiresAllArtifacts(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	e := Exporter{Archive: a, Resume: resume, quarantined: map[string]bool{"mxc://example.org/blocked": true}}
	user := &archive.User{UserID: "@alice:example.org"}
	if err := a.WriteUser(user); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSecrets(user.UserID, &archive.Secrets{}); err != nil {
		t.Fatal(err)
	}
	if err := e.saveUserExport(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	e = Exporter{Archive: a, Resume: resume}
	cached, err := e.ResumeUser(t.Context(), user.UserID)
	if err != nil || cached == nil {
		t.Fatalf("user=%+v error=%v", cached, err)
	}
	if !e.quarantined["mxc://example.org/blocked"] {
		t.Fatal("quarantine lost on resume")
	}
	if err := os.Remove(filepath.Join(a.UserDir(user.UserID), "secrets.json")); err != nil {
		t.Fatal(err)
	}
	cached, err = e.ResumeUser(t.Context(), user.UserID)
	if err != nil || cached != nil {
		t.Fatalf("incomplete user reused: %+v %v", cached, err)
	}
}

func TestResumeRoomAfterMediaFailure(t *testing.T) {
	const room = "!room:example.org"
	const event = `{"event_id":"$message","type":"m.room.message","content":{"url":"mxc://example.org/file"}}`
	var histories, downloads atomic.Int32
	var missing atomic.Bool
	missing.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			_, _ = fmt.Fprint(w, `{"versions":["v1.11"]}`)
		case strings.Contains(r.URL.Path, "/download/"):
			downloads.Add(1)
			if missing.Load() {
				w.WriteHeader(404)
				_, _ = fmt.Fprint(w, `{"errcode":"M_NOT_FOUND","error":"missing"}`)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			_, _ = fmt.Fprint(w, "media")
		case strings.HasSuffix(r.URL.Path, "/state"):
			_, _ = fmt.Fprint(w, `{"state":[{"type":"m.room.create","content":{"room_version":"10"}}]}`)
		case strings.HasSuffix(r.URL.Path, "/messages"):
			if r.URL.Query().Get("dir") != "b" {
				histories.Add(1)
			}
			_, _ = fmt.Fprintf(w, `{"chunk":[%s]}`, event)
		default:
			_, _ = fmt.Fprint(w, `{}`)
		}
	}))
	defer server.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	client := mx.MustNew(server.URL, "token")
	client.DefaultHTTPRetries = 0
	e := Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{}, Resume: resume}
	if err := e.ExportRoom(t.Context(), room, nil, nil); err == nil {
		t.Fatal("media failure ignored")
	}
	if checkpoint, err := resume.Load(t.Context(), "rooms", room); err != nil || checkpoint != nil {
		t.Fatalf("failed room checkpoint=%+v error=%v", checkpoint, err)
	}
	missing.Store(false)
	e = Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{}, Resume: resume}
	if err := e.ExportRoom(t.Context(), room, nil, nil); err != nil {
		t.Fatal(err)
	}
	if histories.Load() != 1 || downloads.Load() != 2 {
		t.Fatalf("history=%d downloads=%d", histories.Load(), downloads.Load())
	}
	if err := os.Remove(filepath.Join(a.RoomDir(room), mediaFile("example.org", "file"))); err != nil {
		t.Fatal(err)
	}
	e = Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{}, Resume: resume}
	if err := e.ExportRoom(t.Context(), room, nil, nil); err != nil {
		t.Fatal(err)
	}
	if histories.Load() != 1 || downloads.Load() != 3 {
		t.Fatalf("history=%d downloads=%d", histories.Load(), downloads.Load())
	}
}

func TestResumeLegacyHistoryIsVerified(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			dumpDir := filepath.Join(a.Dir, "source", "tuwunel")
			if err := os.MkdirAll(dumpDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dumpDir, "global.txt"), []byte("source"), 0600); err != nil {
				t.Fatal(err)
			}
			hashes, err := archive.HashExportDump(t.Context(), dumpDir)
			if err != nil {
				t.Fatal(err)
			}
			d := tuwunelRoomsFixture(1, 0)
			if err := d.indexRelayData(t.Context()); err != nil {
				t.Fatal(err)
			}
			raw := json.RawMessage(`{"event_id":"$create0","room_id":"!room0:example.org","type":"m.room.create","state_key":"","content":{}}`)
			if !valid {
				raw = json.RawMessage(`{"event_id":"$create0","type":"m.room.create","state_key":"","content":{"changed":true}}`)
			}
			if err := a.WriteRoomEvents("!room0:example.org", []json.RawMessage{raw}); err != nil {
				t.Fatal(err)
			}
			resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source", Dump: hashes}, true)
			if err != nil {
				t.Fatal(err)
			}
			defer resume.Close()
			e := Exporter{Archive: a, TuwunelDump: d, Resume: resume}
			ready, err := e.resumeHistory(t.Context(), "!room0:example.org")
			if err != nil {
				t.Fatal(err)
			}
			if ready != valid {
				t.Fatalf("ready=%t want=%t", ready, valid)
			}
		})
	}
}

func TestMismatchedHistoryIsNotCheckpointed(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	d := tuwunelRoomsFixture(1, 0)
	if err := d.indexRelayData(t.Context()); err != nil {
		t.Fatal(err)
	}
	e := Exporter{Archive: a, Resume: resume, TuwunelDump: d}
	const room = "!room0:example.org"
	raw := json.RawMessage(`{"event_id":"$create0","type":"m.room.create","state_key":"","content":{"changed":true}}`)
	if err := a.WriteRoomEvents(room, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	if err := e.saveHistoryExport(t.Context(), room, "$create0"); err == nil {
		t.Fatal("mismatched history accepted")
	}
	if checkpoint, err := resume.Load(t.Context(), "history", room); err != nil || checkpoint != nil {
		t.Fatalf("mismatched checkpoint=%+v error=%v", checkpoint, err)
	}
}

func TestResumeServerData(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, `{"registration_tokens":[]}`)
	}))
	defer server.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "source"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	e := Exporter{Archive: a, Admin: mx.MustNew(server.URL, "token"), Resume: resume, TuwunelDump: &TuwunelDump{}}
	for i := 0; i < 2; i++ {
		if err := e.ExportServer(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("server requested %d times", requests.Load())
	}
	if err := os.Remove(filepath.Join(a.Dir, "server.json")); err != nil {
		t.Fatal(err)
	}
	if err := e.ExportServer(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatal("missing server data was reused")
	}
}
