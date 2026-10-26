package relay

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"maunium.net/go/mautrix/federation"
)

func TestBackfillFromDestinationEventsStartsAtArchiveHeads(t *testing.T) {
	const roomID = "!room:example.org"
	rl := New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	data := RoomData{Extremities: []string{"$b"}}
	for depth, e := range []struct{ id, prev string }{{"$create", ""}, {"$a", "$create"}, {"$b", "$a"}} {
		prev := []string{}
		if e.prev != "" {
			prev = append(prev, e.prev)
		}
		raw, _ := json.Marshal(map[string]any{"event_id": e.id, "room_id": roomID, "type": "m.room.message", "sender": "@alice:example.org", "content": map[string]any{}, "prev_events": prev, "depth": depth + 1})
		data.Events = append(data.Events, EventJSON{EventID: e.id, PDU: raw})
	}
	if err := rl.AddRoom(roomID, "11", data); err != nil {
		t.Fatal(err)
	}
	// Events the relay authors or receives must not replace the archive heads.
	rm := rl.room(roomID)
	rm.mu.Lock()
	rm.extremities = []string{"$relayJoin"}
	rm.mu.Unlock()
	backfill := func(from ...string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/?"+url.Values{"v": from, "limit": {"10"}}.Encode(), nil)
		req.SetPathValue("roomID", roomID)
		w := httptest.NewRecorder()
		rl.backfill(w, req)
		var resp struct {
			PDUs []struct {
				Prev []string `json:"prev_events"`
			} `json:"pdus"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err, w.Body.String())
		}
		var heads []string
		for _, p := range resp.PDUs {
			heads = append(heads, p.Prev...)
		}
		return heads
	}
	// $b, $a and $create are returned; their prev_events identify them.
	if got := backfill("$destinationJoin"); !slices.Equal(got, []string{"$a", "$create"}) {
		t.Fatalf("unknown destination anchor served %v", got)
	}
	if got := backfill("$a"); !slices.Equal(got, []string{"$create"}) {
		t.Fatalf("archived anchor served %v", got)
	}
}

func TestBackfillPagesDoNotSkipBranches(t *testing.T) {
	const roomID = "!room:example.org"
	// $root forks into $left and $right; $merge joins them, as dummy events do.
	data := RoomData{Extremities: []string{"$merge"}}
	for _, e := range []struct {
		id    string
		prev  []string
		depth int
	}{{"$root", nil, 1}, {"$left", []string{"$root"}, 2}, {"$right", []string{"$root"}, 2}, {"$merge", []string{"$left", "$right"}, 3}} {
		raw, _ := json.Marshal(map[string]any{"event_id": e.id, "room_id": roomID, "type": "m.room.message", "sender": "@alice:example.org", "content": map[string]any{}, "prev_events": append([]string{}, e.prev...), "depth": e.depth})
		data.Events = append(data.Events, EventJSON{EventID: e.id, PDU: raw})
	}
	rl := New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	if err := rl.AddRoom(roomID, "11", data); err != nil {
		t.Fatal(err)
	}
	rm := rl.room(roomID)
	// Continuwuity asks again from the last event of each page.
	var served []string
	from := []string{"$merge"}
	for range 4 {
		page := rm.backfill(from, 2)
		served = append(served, page...)
		from = page[len(page)-1:]
		if from[0] == "$root" {
			break
		}
	}
	slices.Sort(served)
	served = slices.Compact(served)
	if !slices.Equal(served, []string{"$left", "$merge", "$right", "$root"}) {
		t.Fatalf("served %v", served)
	}
}

func TestFileRoomServesSameEvents(t *testing.T) {
	const roomID = "!room:example.org"
	data := RoomData{Extremities: []string{"$merge"}, CurrentState: map[string]string{StateKey("m.room.topic", ""): "$left"}}
	for _, e := range []struct {
		id, typ string
		prev    []string
		depth   int
	}{{"$root", "m.room.message", nil, 1}, {"$left", "m.room.topic", []string{"$root"}, 2}, {"$right", "m.room.message", []string{"$root"}, 2}, {"$merge", "m.room.message", []string{"$left", "$right"}, 3}} {
		fields := map[string]any{"event_id": e.id, "room_id": roomID, "type": e.typ, "sender": "@alice:example.org", "content": map[string]any{"body": "<" + e.id + ">", "topic": "t"}, "prev_events": append([]string{}, e.prev...), "depth": e.depth, "unsigned": map[string]any{"transaction_id": "x"}}
		if e.typ == "m.room.topic" {
			fields["state_key"] = ""
		}
		raw, _ := json.Marshal(fields)
		data.Events = append(data.Events, EventJSON{EventID: e.id, PDU: raw})
	}
	// The archive writes pdus.json indented.
	path := filepath.Join(t.TempDir(), "pdus.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := jsonv2.MarshalWrite(f, data, json.DefaultOptionsV1(), jsontext.WithIndent("  ")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	memory := New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	if err := memory.AddRoom(roomID, "11", data); err != nil {
		t.Fatal(err)
	}
	file := New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	if err := file.AddRoomFile(roomID, "11", path); err != nil {
		t.Fatal(err)
	}
	ids := []string{"$merge", "$right", "$left", "$root"}
	want, err := memory.room(roomID).pdus(ids)
	if err != nil {
		t.Fatal(err)
	}
	got, err := file.room(roomID).pdus(ids)
	if err != nil || len(got) != len(want) {
		t.Fatalf("file room pdus: %v", err)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("event %s differs:\n%s\n%s", ids[i], got[i], want[i])
		}
	}
	if !slices.Equal(file.room(roomID).backfill([]string{"$unknown"}, 10), memory.room(roomID).backfill([]string{"$unknown"}, 10)) {
		t.Fatal("backfill order differs")
	}
	if file.Content(roomID, "m.room.topic", "")["topic"] != "t" {
		t.Fatal("state content unavailable from file")
	}
	rm := file.room(roomID)
	file.RemoveRoom(roomID)
	if _, err := rm.source.Stat(); err == nil {
		t.Fatal("room file left open")
	}
}
