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
	"maunium.net/go/mautrix"
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
	if err := verifyOriginalRoomEvents(t.Context(), []*mautrix.Client{c}, "!room:example.org", "11", events); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := backfillRoomEvents(t.Context(), []*mautrix.Client{c}, "!room:example.org", events); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatal("timeline read failure was ignored before contacting destination")
	}
}

func TestRelayBackfillRequiresCreateAndAllExportedEvents(t *testing.T) {
	create := json.RawMessage(`{"event_id":"$create","type":"m.room.create","content":{}}`)
	message := json.RawMessage(`{"event_id":"$message","type":"m.room.message","content":{"body":"original"}}`)
	for _, tc := range []struct {
		name    string
		pages   [][]json.RawMessage
		wantErr bool
	}{
		{"create before message", [][]json.RawMessage{{create}, {message}}, false},
		{"message before create", [][]json.RawMessage{{message}, {create}}, false},
		{"same page", [][]json.RawMessage{{create, message}}, false},
		{"missing message", [][]json.RawMessage{{create}}, true},
		{"missing create", [][]json.RawMessage{{message}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				page := requests
				requests++
				if page >= len(tc.pages) {
					t.Error("requested a page after pagination ended")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				from := ""
				if page > 0 {
					from = fmt.Sprintf("page%d", page)
				}
				if r.URL.Query().Get("from") != from {
					t.Error("pagination did not advance to the supplied token")
				}
				end := ""
				if page+1 < len(tc.pages) {
					end = fmt.Sprintf("page%d", page+1)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"chunk": tc.pages[page], "end": end})
			}))
			defer api.Close()
			_, err := backfillRoom(t.Context(), mx.MustNew(api.URL, "token"), "!room:example.org", []json.RawMessage{create, message})
			if (err != nil) != tc.wantErr {
				t.Fatalf("backfill error=%v", err)
			}
			if requests != len(tc.pages) {
				t.Fatalf("stopped after %d of %d available pages", requests, len(tc.pages))
			}
		})
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
	err := verifyOriginalRoomEvents(t.Context(), []*mautrix.Client{mx.MustNew(api.URL, "token")}, "!room:example.org", "11", stream)
	if err == nil || !strings.Contains(err.Error(), "original events absent") {
		t.Fatal("missing destination events were accepted")
	}
	if growth > 4<<20 {
		t.Fatalf("verification retained %d bytes for 32 MiB of event bodies", growth)
	}
	t.Logf("verification live heap growth for 32 MiB of event bodies: %d bytes", growth)
}

func TestRelayBackfillRetriesEmptyPages(t *testing.T) {
	create := json.RawMessage(`{"event_id":"$create","type":"m.room.create","content":{}}`)
	message := json.RawMessage(`{"event_id":"$message","type":"m.room.message","content":{"body":"original"}}`)
	for _, tc := range []struct {
		name    string
		empty   int
		wantErr bool
	}{
		// Continuwuity answered from another server, then from the relay.
		{name: "relay chosen after empty pages", empty: 3},
		{name: "history never arrives", empty: maxEmptyBackfillPages + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				from := r.URL.Query().Get("from")
				switch {
				case requests == 1:
					_ = json.NewEncoder(w).Encode(map[string]any{"chunk": []json.RawMessage{message}, "end": "oldest"})
				case from != "oldest":
					t.Errorf("retry did not repeat the oldest position: %q", from)
				case requests-1 <= tc.empty:
					_ = json.NewEncoder(w).Encode(map[string]any{"chunk": []json.RawMessage{}})
				default:
					_ = json.NewEncoder(w).Encode(map[string]any{"chunk": []json.RawMessage{create}, "end": "start"})
				}
			}))
			defer api.Close()
			_, err := backfillRoom(t.Context(), mx.MustNew(api.URL, "token"), "!room:example.org", []json.RawMessage{create, message})
			if (err != nil) != tc.wantErr {
				t.Fatalf("backfill error=%v after %d requests", err, requests)
			}
			if want := map[bool]int{false: tc.empty + 2, true: maxEmptyBackfillPages + 2}[tc.wantErr]; requests != want {
				t.Fatalf("requests = %d, want %d", requests, want)
			}
		})
	}
}

func TestRelayVerificationReadsAsEveryMember(t *testing.T) {
	create := json.RawMessage(`{"event_id":"$create","type":"m.room.create","sender":"@a:example.org","content":{}}`)
	early := json.RawMessage(`{"event_id":"$early","type":"m.room.message","sender":"@b:example.org","content":{"body":"before a joined"}}`)
	late := json.RawMessage(`{"event_id":"$late","type":"m.room.message","sender":"@a:example.org","content":{"body":"after"}}`)
	// History visibility hides $early from the first reader only.
	visible := map[string][]json.RawMessage{"Bearer first": {late, create}, "Bearer second": {late, early, create}}
	for _, tc := range []struct {
		name    string
		second  string
		wantErr string
	}{
		{name: "second member sees hidden events", second: "second"},
		{name: "second member not joined", second: "forbidden", wantErr: "$early"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				chunk, ok := visible[r.Header.Get("Authorization")]
				if !ok {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"You don't have permission to view this room."}`))
					return
				}
				if r.URL.Query().Get("from") != "" {
					chunk = nil
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"chunk": chunk, "end": "oldest"})
			}))
			defer api.Close()
			readers := []*mautrix.Client{mx.MustNew(api.URL, "first"), mx.MustNew(api.URL, tc.second)}
			events := []json.RawMessage{create, early, late}
			_, backfillErr := backfillRoomEvents(t.Context(), readers, "!room:example.org", roomEventSequence(events))
			verifyErr := verifyOriginalRoomEvents(t.Context(), readers, "!room:example.org", "11", roomEventSequence(events))
			for _, err := range []error{backfillErr, verifyErr} {
				if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
			}
		})
	}
}

func TestRelayVerificationAcceptsLaterRedactions(t *testing.T) {
	archived := json.RawMessage(`{"event_id":"$m","type":"m.room.member","sender":"@a:example.org","state_key":"@a:example.org","origin_server_ts":5,"content":{"membership":"join","displayname":"A"}}`)
	for _, tc := range []struct {
		name, destination string
		ok                bool
	}{
		{name: "unchanged", destination: `{"event_id":"$m","type":"m.room.member","sender":"@a:example.org","state_key":"@a:example.org","origin_server_ts":5,"content":{"membership":"join","displayname":"A"}}`, ok: true},
		{name: "redacted later", destination: `{"event_id":"$m","type":"m.room.member","sender":"@a:example.org","state_key":"@a:example.org","origin_server_ts":5,"content":{"membership":"join"},"unsigned":{"redacted_because":{"event_id":"$r","type":"m.room.redaction","sender":"@a:example.org","content":{}}}}`, ok: true},
		{name: "stripped without redaction", destination: `{"event_id":"$m","type":"m.room.member","sender":"@a:example.org","state_key":"@a:example.org","origin_server_ts":5,"content":{"membership":"join"}}`},
		{name: "redacted but altered", destination: `{"event_id":"$m","type":"m.room.member","sender":"@a:example.org","state_key":"@a:example.org","origin_server_ts":5,"content":{"membership":"leave"},"unsigned":{"redacted_because":{"event_id":"$r","type":"m.room.redaction","sender":"@a:example.org","content":{}}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"chunk":[%s]}`, tc.destination)
			}))
			defer api.Close()
			err := verifyOriginalRoom(t.Context(), mx.MustNew(api.URL, "token"), "!room:example.org", "11", []json.RawMessage{archived})
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
