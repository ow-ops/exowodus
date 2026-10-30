//go:build e2e

package migrate

import (
	"os"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

func TestTuwunelOriginalEventsLive(t *testing.T) {
	dir, target := os.Getenv("EXOWODUS_TUWUNEL_LIVE_ARCHIVE"), os.Getenv("EXOWODUS_TUWUNEL_LIVE_TARGET")
	if dir == "" || target == "" {
		t.Skip("set EXOWODUS_TUWUNEL_LIVE_ARCHIVE and EXOWODUS_TUWUNEL_LIVE_TARGET")
	}
	a, err := archive.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := a.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, s := range sessions {
		if !s.Refresh {
			token = s.Token
			break
		}
	}
	if token == "" {
		t.Fatal("no migrated device token available")
	}
	rooms, err := a.Rooms()
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms) == 0 {
		t.Fatal("no source rooms to verify")
	}
	c := mx.MustNew(target, token)
	for _, room := range rooms {
		if room.ArchiveOnly {
			t.Fatalf("room %s was not restored", room.RoomID)
		}
		events, err := a.RoomEvents(room.RoomID)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyOriginalRoom(t.Context(), c, room.RoomID, room.Version, events); err != nil {
			t.Fatal(err)
		}
		t.Logf("verified all %d original events in %s", len(events), room.RoomID)
	}
}
