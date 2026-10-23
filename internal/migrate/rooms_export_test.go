package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestExportRoomPages(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "complete"
		if fail {
			name = "failed second page"
		}
		t.Run(name, func(t *testing.T) {
			const room = "!room:example.org"
			first := json.RawMessage(`{"event_id":"$first","sender":"@alice:example.org","type":"m.room.message","content":{"body":"first"}}`)
			second := json.RawMessage(`{"event_id":"$second","sender":"@bob:remote.org","type":"m.room.message","content":{"body":"second"}}`)
			var pages atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/state"):
					_, _ = w.Write([]byte(`{"state":[{"type":"m.room.create","content":{"room_version":"10"}},{"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join"}}]}`))
				case strings.HasSuffix(r.URL.Path, "/messages"):
					pages.Add(1)
					if r.URL.Query().Get("from") == "" {
						_ = json.NewEncoder(w).Encode(map[string]any{"chunk": []json.RawMessage{first}, "end": "next"})
					} else if fail {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"page failed"}`))
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"chunk": []json.RawMessage{second}})
					}
				case strings.Contains(r.URL.Path, "/users/"):
					_, _ = w.Write([]byte(`{"deactivated":false,"is_guest":false}`))
				default:
					_, _ = w.Write([]byte(`{"public":false}`))
				}
			}))
			defer server.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			old := json.RawMessage(`{"event_id":"$old"}`)
			if err := a.WriteRoomEvents(room, []json.RawMessage{old}); err != nil {
				t.Fatal(err)
			}
			exporter := Exporter{Archive: a, Admin: mx.MustNew(server.URL, "token")}
			err = exporter.ExportRoom(t.Context(), room, nil, nil)
			if (err != nil) != fail {
				t.Fatalf("export error=%v", err)
			}
			if pages.Load() != 2 {
				t.Fatalf("requested %d pages", pages.Load())
			}
			events, err := a.RoomEvents(room)
			if err != nil {
				t.Fatal(err)
			}
			if fail {
				if len(events) != 1 || string(events[0]) != string(old) {
					t.Fatal("failed export replaced timeline")
				}
				return
			}
			if len(events) != 2 || string(events[0]) != string(first) || string(events[1]) != string(second) {
				t.Fatalf("timeline=%s", events)
			}
			rooms, err := a.Rooms()
			if err != nil {
				t.Fatal(err)
			}
			if len(rooms) != 1 || rooms[0].ArchiveOnly || !rooms[0].RemoteParticipants {
				t.Fatalf("room metadata=%+v", rooms)
			}
		})
	}
}
