package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamRoomStateFailurePreservesRoom(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	room := &ArchivedRoom{RoomID: "!room:example.org", Version: "11", State: []json.RawMessage{json.RawMessage(`{"type":"m.room.create","content":{"room_version":"11"}}`)}}
	if err := a.WriteRoom(room); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.RoomDir(room.RoomID), "room.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("state read failed")
	state := func(yield func(json.RawMessage, error) bool) {
		if yield(room.State[0], nil) {
			yield(nil, failure)
		}
	}
	if err := a.WriteRoomWithState(room, state); !errors.Is(err, failure) {
		t.Fatalf("write error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed state export replaced the room")
	}
}
