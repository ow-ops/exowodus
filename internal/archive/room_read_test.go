package archive

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoomHeadersDoNotRetainState(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	room := &ArchivedRoom{RoomID: "!large:example.org", Version: "12", Public: true, Ghosts: []string{"@ghost:example.org"}, OmittedEvents: map[string]string{"$missing": "missing dependency"}}
	raw := json.RawMessage(`{"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join","padding":"` + strings.Repeat("x", 4096) + `"}}`)
	if err := a.WriteRoomWithState(room, func(yield func(json.RawMessage, error) bool) {
		for range 4096 {
			if !yield(raw, nil) {
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	rooms, err := a.RoomHeaders()
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if len(rooms) != 1 || rooms[0].State != nil || rooms[0].Version != "12" || !rooms[0].Public || len(rooms[0].Ghosts) != 1 || len(rooms[0].OmittedEvents) != 1 {
		t.Fatal("room headers lost metadata or retained state")
	}
	if after.HeapAlloc > before.HeapAlloc+(4<<20) {
		t.Fatalf("room headers retained %d bytes for a 16 MiB state array", after.HeapAlloc-before.HeapAlloc)
	}
	runtime.KeepAlive(rooms)
	count := 0
	for value, err := range a.RoomStateIter(t.Context(), room.RoomID) {
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(value) {
			t.Fatal("state iterator changed an event")
		}
		count++
	}
	if count != 4096 {
		t.Fatalf("state events = %d", count)
	}
}

func TestRoomStateReadFailures(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	room := &ArchivedRoom{RoomID: "!room:example.org", State: []json.RawMessage{json.RawMessage(`{"type":"m.room.name","content":{"name":"room"}}`)}}
	if err := a.WriteRoom(room); err != nil {
		t.Fatal(err)
	}
	full, err := a.Rooms()
	if err != nil || len(full) != 1 || len(full[0].State) != 1 {
		t.Fatal("full room loading lost its state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, err := range a.RoomStateIter(ctx, room.RoomID) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled state read: %v", err)
		}
	}
	path := filepath.Join(a.RoomDir(room.RoomID), "room.json")
	if err := os.WriteFile(path, []byte(`{"room_id":"!room:example.org","state":[{"type":"m.room.name"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RoomHeaders(); err == nil {
		t.Fatal("room headers accepted truncated state")
	}
	var failure error
	for _, err := range a.RoomStateIter(t.Context(), room.RoomID) {
		if err != nil {
			failure = err
		}
	}
	if failure == nil {
		t.Fatal("state iterator accepted a truncated array")
	}
}
