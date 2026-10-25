package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
)

func relayFailureFixture(t *testing.T) (*archive.Archive, []*archive.ArchivedRoom) {
	t.Helper()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	var rooms []*archive.ArchivedRoom
	for i := range 2 {
		roomID := fmt.Sprintf("!room%d:example.org", i)
		create := json.RawMessage(fmt.Sprintf(`{"event_id":"$create%d","room_id":%q,"type":"m.room.create","state_key":"","sender":"@alice:example.org","content":{"creator":"@alice:example.org","room_version":"10"}}`, i, roomID))
		join := json.RawMessage(fmt.Sprintf(`{"event_id":"$join%d","room_id":%q,"type":"m.room.member","state_key":"@alice:example.org","sender":"@alice:example.org","content":{"membership":"join"}}`, i, roomID))
		room := &archive.ArchivedRoom{RoomID: roomID, Version: "10", State: []json.RawMessage{create, join}, Ghosts: []string{"@ghost:example.org"}}
		if err := a.WriteRoom(room); err != nil {
			t.Fatal(err)
		}
		if err := a.WriteRoomEvents(roomID, room.State); err != nil {
			t.Fatal(err)
		}
		data := relay.RoomData{Events: []relay.EventJSON{{EventID: fmt.Sprintf("$create%d", i), PDU: create}, {EventID: fmt.Sprintf("$join%d", i), PDU: join}}, CurrentState: map[string]string{relay.StateKey("m.room.create", ""): fmt.Sprintf("$create%d", i), relay.StateKey("m.room.member", "@alice:example.org"): fmt.Sprintf("$join%d", i)}}
		if err := a.WriteRoomPDUs(roomID, data); err != nil {
			t.Fatal(err)
		}
		rooms = append(rooms, room)
	}
	return a, rooms
}

func TestFailedRelayRoomsReleasedBeforeNextAttempt(t *testing.T) {
	a, rooms := relayFailureFixture(t)
	rl := relay.New("relay.test", "example.org", nil, nil)
	var calls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := calls % len(rooms)
		calls++
		if rl.Content(rooms[current].RoomID, "m.room.create", "") == nil {
			t.Error("current room was not loaded for the attempt")
		}
		if rl.Content(rooms[1-current].RoomID, "m.room.create", "") != nil {
			t.Error("previous failed room remains loaded while importing the next room")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"injected registration failure"}`))
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "as-token")
	im := &Importer{Archive: a, RequireLossless: true, Migrated: map[string]bool{"@alice:example.org": true}, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}
	original := map[string][]byte{}
	for _, room := range rooms {
		raw, err := os.ReadFile(filepath.Join(a.RoomDir(room.RoomID), "pdus.json"))
		if err != nil {
			t.Fatal(err)
		}
		original[room.RoomID] = raw
	}
	for range 2 {
		reports, rest := im.RelayRooms(t.Context(), rooms, rl)
		if len(rest) != 0 || len(reports) != len(rooms) {
			t.Fatal("failed preservation attempt fell back to replay")
		}
		for i, room := range rooms {
			if len(reports[i].Failures) != 1 || !im.roomFailures[room.RoomID] {
				t.Fatal("failed room was marked complete")
			}
			if rl.Content(room.RoomID, "m.room.create", "") != nil {
				t.Fatal("failed room remains loaded after the attempt")
			}
			raw, err := os.ReadFile(filepath.Join(a.RoomDir(room.RoomID), "pdus.json"))
			if err != nil || !bytes.Equal(raw, original[room.RoomID]) {
				t.Fatal("failed attempt modified the source archive")
			}
			state, err := a.ReadRoomState(room.RoomID)
			if err != nil || state.Done || state.NewRoomID != "" {
				t.Fatal("failed attempt advanced the room checkpoint")
			}
		}
	}
	if calls != 2*len(rooms) {
		t.Fatal("retry did not reload and attempt every failed room")
	}
}

func TestCanceledRelayReleasesRoomAndStops(t *testing.T) {
	a, rooms := relayFailureFixture(t)
	rl := relay.New("relay.test", "example.org", nil, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		cancel()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "as-token")
	im := &Importer{Archive: a, RequireLossless: true, Migrated: map[string]bool{"@alice:example.org": true}, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}
	reports, rest := im.RelayRooms(ctx, rooms, rl)
	if calls != 1 || len(reports) != 1 || len(rest) != 0 {
		t.Fatal("canceled import continued loading rooms")
	}
	for _, room := range rooms {
		if rl.Content(room.RoomID, "m.room.create", "") != nil {
			t.Fatal("canceled room remains loaded")
		}
	}
}
