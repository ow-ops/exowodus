package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type responseElement struct {
	raw    json.RawMessage
	before func() error
}

func (e responseElement) MarshalJSON() ([]byte, error) {
	if e.before != nil {
		if err := e.before(); err != nil {
			return nil, err
		}
	}
	return e.raw, nil
}

func TestRelayResponseStreamsBeforeLastElement(t *testing.T) {
	response := httptest.NewRecorder()
	first := json.RawMessage(fmt.Sprintf(`{"ciphertext":%q,"preserve":"<>&"}`, strings.Repeat("e", 64<<10)))
	last := responseElement{raw: json.RawMessage(`{"last":true}`), before: func() error {
		if response.Body.Len() == 0 {
			t.Error("response was buffered until the last element")
		}
		return nil
	}}
	writeJSON(response, []responseElement{{raw: first}, last})
	var got []json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || len(got) != 2 {
		t.Fatalf("invalid streamed response: %v", err)
	}
	if !strings.Contains(response.Body.String(), `\u003c\u003e\u0026`) {
		t.Fatal("streaming changed JSON escaping")
	}
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatal("streaming changed the response status or content type")
	}
}

func TestRelayResponseDoesNotAppendErrorAfterPartialWrite(t *testing.T) {
	response := httptest.NewRecorder()
	failure := errors.New("response encoding failed")
	last := responseElement{before: func() error {
		if response.Body.Len() == 0 {
			t.Error("failure did not follow a partial response")
		}
		return failure
	}}
	writeJSON(response, []responseElement{{raw: json.RawMessage(fmt.Sprintf(`{"ciphertext":%q}`, strings.Repeat("e", 64<<10)))}, last})
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "errcode") || strings.Contains(response.Body.String(), failure.Error()) {
		t.Fatal("encoding failure appended another response")
	}
}

func TestCachedEventKeepsFederationPayload(t *testing.T) {
	const roomID = "!room:example.org"
	encrypted := json.RawMessage(fmt.Sprintf(`{"type":"m.room.encrypted","sender":"@alice:example.org","room_id":%q,"depth":3,"content":{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":%q},"prev_events":["$power"],"auth_events":["$create","$power"],"hashes":{"sha256":"AQID"},"signatures":{"example.org":{"ed25519:original":"original-signature"}},"unsigned":{"age":123},"org.example.extension":{"keep":true}}`, roomID, strings.Repeat("encrypted", 32<<10)))
	power := json.RawMessage(`{"type":"m.room.power_levels","state_key":"","depth":2,"content":{"users":{"@alice:example.org":9007199254740993}},"prev_events":["$create"],"auth_events":["$create"]}`)
	rl := New("relay.example.org", "example.org", nil, nil)
	if err := rl.AddRoom(roomID, "11", RoomData{
		Events: []EventJSON{
			{EventID: "$create", PDU: json.RawMessage(`{"type":"m.room.create","state_key":"","depth":1,"content":{"room_version":"11"},"prev_events":[],"auth_events":[]}`)},
			{EventID: "$power", PDU: power},
			{EventID: "$encrypted", PDU: encrypted},
		},
		CurrentState: map[string]string{StateKey("m.room.power_levels", ""): "$power"},
	}); err != nil {
		t.Fatal(err)
	}
	content := rl.Content(roomID, "m.room.power_levels", "")
	users, ok := content["users"].(map[string]any)
	if !ok || users["@alice:example.org"] != json.Number("9007199254740993") {
		t.Fatal("reading cached content changed an integer")
	}
	r := rl.room(roomID)
	if got := r.before([]string{"$encrypted"}, 3, nil); !slices.Equal(got, []string{"$encrypted", "$power", "$create"}) {
		t.Fatalf("cached predecessors: %v", got)
	}
	if got := r.authChain([]string{"$encrypted"}); len(got) != 2 || !slices.Contains(got, "$create") || !slices.Contains(got, "$power") {
		t.Fatalf("cached auth chain: %v", got)
	}
	if got := r.maxDepth(); got != 3 {
		t.Fatalf("cached depth: %d", got)
	}
	request := httptest.NewRequest(http.MethodGet, "/?v=$encrypted&limit=1", nil)
	request.SetPathValue("roomID", roomID)
	response := httptest.NewRecorder()
	rl.backfill(response, request)
	var body struct {
		PDUs []json.RawMessage `json:"pdus"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want, err := federationPDU(encrypted, "11")
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(body.PDUs) != 1 || !bytes.Equal(body.PDUs[0], want) {
		t.Fatal("caching metadata changed the federation payload")
	}
	added := json.RawMessage(`{"type":"m.room.topic","state_key":"","depth":4,"content":{"topic":"after join"},"prev_events":["$encrypted"],"auth_events":["$create","$power"]}`)
	p, err := ParsePDU(added)
	if err != nil {
		t.Fatal(err)
	}
	r.add("$added", p, added)
	if got := rl.Content(roomID, "m.room.topic", ""); got["topic"] != "after join" {
		t.Fatal("new event content was not retained")
	}
	if got, err := r.pdus([]string{"$added"}); err != nil || len(got) != 1 || !bytes.Equal(got[0], added) {
		t.Fatal("new event wire bytes changed")
	}
}

func BenchmarkRelayEncryptedRoomMemory(b *testing.B) {
	for b.Loop() {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		rl := encryptedRoomForMemory(b)
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc)-float64(before.HeapAlloc), "retained-B")
		runtime.KeepAlive(rl)
	}
}

func encryptedRoomForMemory(b *testing.B) *Relay {
	b.Helper()
	const roomID = "!large:example.org"
	data := RoomData{}
	for i := range 32 {
		raw := json.RawMessage(fmt.Sprintf(`{"type":"m.room.encrypted","sender":"@alice:example.org","room_id":%q,"depth":%d,"content":{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":%q},"prev_events":[],"auth_events":[]}`, roomID, i, strings.Repeat("e", 256<<10)))
		data.Events = append(data.Events, EventJSON{EventID: fmt.Sprintf("$event%d", i), PDU: raw})
	}
	rl := New("relay.example.org", "example.org", nil, nil)
	if err := rl.AddRoom(roomID, "11", data); err != nil {
		b.Fatal(err)
	}
	return rl
}
