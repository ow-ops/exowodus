package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"exodus/internal/mx"
	"exodus/internal/relay"
)

func TestOriginalEventFingerprintPreservesFields(t *testing.T) {
	for _, tc := range []struct {
		name, left, right string
		equal             bool
	}{
		{"map order", `{"type":"m.room.message","content":{"body":"same","n":1}}`, `{"content":{"n":1,"body":"same"},"type":"m.room.message"}`, true},
		{"number spelling", `{"type":"m.room.message","content":{"n":1}}`, `{"type":"m.room.message","content":{"n":1.0}}`, false},
		{"null and empty", `{"type":"m.room.message","content":{"n":null}}`, `{"type":"m.room.message","content":{"n":[]}}`, false},
		{"redaction copy", `{"type":"m.room.redaction","redacts":"$target","content":{"reason":"spam"}}`, `{"type":"m.room.redaction","redacts":"$target","content":{"reason":"spam","redacts":"$target"}}`, true},
		{"changed body", `{"type":"m.room.message","content":{"body":"first"}}`, `{"type":"m.room.message","content":{"body":"second"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, err := originalEventFingerprint(json.RawMessage(tc.left))
			if err != nil {
				t.Fatal(err)
			}
			right, err := originalEventFingerprint(json.RawMessage(tc.right))
			if err != nil {
				t.Fatal(err)
			}
			if (left == right) != tc.equal {
				t.Fatal("original field comparison changed")
			}
		})
	}
}

func TestRelayTimelineReadErrorsStopBeforeRequests(t *testing.T) {
	requests := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"chunk":[]}`))
	}))
	defer api.Close()
	c := mx.MustNew(api.URL, "token")
	c.DefaultHTTPRetries = 0
	failure := errors.New("timeline read interrupted")
	events := func(yield func(json.RawMessage, error) bool) {
		if yield(json.RawMessage(`{"event_id":"$first","type":"m.room.create","content":{}}`), nil) {
			yield(nil, failure)
		}
	}
	if err := verifyOriginalRoomEvents(t.Context(), c, "!room:example.org", events); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := backfillRoomEvents(t.Context(), c, "!room:example.org", events); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatal("timeline read failure was ignored before contacting destination")
	}
}

func TestRelayMalformedTimelineReleasesRoom(t *testing.T) {
	a, rooms := relayFailureFixture(t)
	room := rooms[0]
	broken := []byte("{\"event_id\":\"$broken\"\n")
	path := filepath.Join(a.RoomDir(room.RoomID), "events.jsonl")
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	rl := relay.New("relay.test", "example.org", nil, nil)
	im := &Importer{Archive: a, RequireLossless: true, Appservice: &Appservice{Bot: "@exodus:example.org"}}
	reports, rest := im.RelayRooms(t.Context(), rooms[:1], rl)
	if len(rest) != 0 || len(reports) != 1 || len(reports[0].Failures) != 1 {
		t.Fatal("malformed timeline was accepted or replayed")
	}
	if rl.Content(room.RoomID, "m.room.create", "") != nil {
		t.Fatal("malformed timeline kept a relay room loaded")
	}
	state, err := a.ReadRoomState(room.RoomID)
	if err != nil || state.Done {
		t.Fatal("malformed timeline advanced completion state")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(broken) {
		t.Fatal("failed import modified the archived timeline")
	}
}

func TestOriginalRoomVerificationKeepsFingerprints(t *testing.T) {
	const events = 4096
	body := strings.Repeat("x", 8192)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var growth int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtime.GC()
		var during runtime.MemStats
		runtime.ReadMemStats(&during)
		growth = int64(during.HeapAlloc) - int64(before.HeapAlloc)
		_, _ = w.Write([]byte(`{"chunk":[]}`))
	}))
	defer api.Close()
	stream := func(yield func(json.RawMessage, error) bool) {
		for i := range events {
			raw := json.RawMessage(fmt.Sprintf(`{"event_id":"$event%d","type":"m.room.message","sender":"@alice:example.org","origin_server_ts":1,"content":{"body":%q}}`, i, body))
			if !yield(raw, nil) {
				return
			}
		}
	}
	err := verifyOriginalRoomEvents(t.Context(), mx.MustNew(api.URL, "token"), "!room:example.org", stream)
	if err == nil || !strings.Contains(err.Error(), "original events absent") {
		t.Fatal("missing destination events were accepted")
	}
	if growth > 4<<20 {
		t.Fatalf("verification retained %d bytes for 32 MiB of event bodies", growth)
	}
	t.Logf("verification live heap growth for 32 MiB of event bodies: %d bytes", growth)
}
