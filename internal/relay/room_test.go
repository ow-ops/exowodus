package relay

import (
	"encoding/json"
	"testing"
)

func TestTuwunelBeforeEventState(t *testing.T) {
	data := RoomData{
		Events: []EventJSON{
			{EventID: "$first", PDU: json.RawMessage(`{"type":"m.room.topic","state_key":"","content":{"topic":"old"},"prev_events":[]}`)},
			{EventID: "$second", PDU: json.RawMessage(`{"type":"m.room.topic","state_key":"","content":{"topic":"new"},"prev_events":["$first"]}`)},
			{EventID: "$message", PDU: json.RawMessage(`{"type":"m.room.message","content":{"body":"hi"},"prev_events":["$second"]}`)},
		},
		BeforeEventGroups: map[string]int64{"$first": 1, "$second": 2, "$message": 3},
		Groups:            map[int64]Group{1: {State: map[string]string{}}, 2: {State: map[string]string{StateKey("m.room.topic", ""): "$first"}}, 3: {State: map[string]string{StateKey("m.room.topic", ""): "$second"}}},
	}
	r, err := newRoom("!room:example.org", "10", data)
	if err != nil {
		t.Fatal(err)
	}
	k := StateKey("m.room.topic", "")
	if len(r.stateBefore("$first")) != 0 || r.stateBefore("$second")[k] != "$first" || r.stateAfter("$second")[k] != "$second" || r.stateAfter("$message")[k] != "$second" {
		t.Fatal("state before/after event was confused")
	}
	if r.groups[2].State[k] != "$first" {
		t.Fatal("historical snapshot was mutated")
	}
}

func TestStoredPDUConvertedToFederationWireShape(t *testing.T) {
	for _, version := range []string{"10", "12"} {
		wire, err := federationPDU(json.RawMessage(`{"event_id":"$original","room_id":"!room:example.org","type":"m.room.create","content":{"room_version":"10"},"signatures":{"example.org":{"ed25519:original":"original-signature"}},"unsigned":{"transaction_id":"private","age":123}}`), version)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(wire, &object); err != nil {
			t.Fatal(err)
		}
		if object["event_id"] != nil || version == "12" && object["room_id"] != nil {
			t.Fatal("stored-only fields sent over federation")
		}
		var unsigned map[string]json.RawMessage
		if err := json.Unmarshal(object["unsigned"], &unsigned); err != nil {
			t.Fatal(err)
		}
		if unsigned["transaction_id"] != nil || string(unsigned["age"]) != "123" || string(object["signatures"]) != `{"example.org":{"ed25519:original":"original-signature"}}` {
			t.Fatal("wire conversion changed original signature or unsigned metadata")
		}
	}
}
