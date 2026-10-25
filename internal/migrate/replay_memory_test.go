package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exodus/internal/mx"
)

func TestReplayReloadsFinalStateAfterCreatingAllRooms(t *testing.T) {
	a, rooms := relayFailureFixture(t)
	for i, room := range rooms {
		room.Ghosts = nil
		child := json.RawMessage(fmt.Sprintf(`{"type":"m.space.child","state_key":%q,"sender":"@alice:example.org","content":{"via":["example.org"]}}`, rooms[1-i].RoomID))
		room.State = append(room.State, child)
		if err := a.WriteRoom(room); err != nil {
			t.Fatal(err)
		}
		events, err := a.RoomEvents(room.RoomID)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, json.RawMessage(fmt.Sprintf(`{"event_id":"$message%d","type":"m.room.message","sender":"@alice:example.org","content":{"msgtype":"m.text","body":"hello"}}`, i)))
		if err := a.WriteRoomEvents(room.RoomID, events); err != nil {
			t.Fatal(err)
		}
	}
	created, messages, links := 0, 0, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/createRoom"):
			fmt.Fprintf(w, `{"room_id":"!dest%d:example.org"}`, created)
			created++
		case strings.HasSuffix(r.URL.Path, "/joined_members"):
			fmt.Fprint(w, `{"joined":{"@alice:example.org":{}}}`)
		case strings.HasSuffix(r.URL.Path, "/state"):
			if created != 2 {
				t.Error("finalization started before both destination IDs were known")
			}
			fmt.Fprint(w, `[]`)
		case strings.Contains(r.URL.Path, "/send/m.room.message/"):
			messages++
			fmt.Fprintf(w, `{"event_id":"$sent%d"}`, messages)
		case strings.Contains(r.URL.Path, "/state/m.space.child/"):
			if !strings.Contains(r.URL.Path, "!dest") {
				t.Error("cross-room reference kept the source room ID")
			}
			links++
			fmt.Fprint(w, `{"event_id":"$link"}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "as-token")
	im := &Importer{Archive: a, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}, Migrated: map[string]bool{"@alice:example.org": true}}
	headers, err := a.RoomHeaders()
	if err != nil {
		t.Fatal(err)
	}
	reports := im.ReplayRooms(t.Context(), headers)
	if created != 2 || messages != 2 || links != 2 || len(reports) != 2 {
		t.Fatalf("created=%d messages=%d links=%d reports=%d", created, messages, links, len(reports))
	}
	for _, report := range reports {
		if len(report.Failures) > 0 {
			t.Fatal(report.Failures)
		}
		state, err := a.ReadRoomState(report.RoomID)
		if err != nil || !state.Done || state.Replayed != 3 {
			t.Fatal("reloading final state changed replay progress")
		}
	}
}
