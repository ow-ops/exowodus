package migrate

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"

	"exodus/internal/relay"
	"maunium.net/go/mautrix/federation"
)

func collectTuwunelRoom(ctx context.Context, d *TuwunelDump, roomID string) (*relay.RoomData, error) {
	data, err := d.roomRelayMetadata(ctx, roomID)
	if err != nil {
		return nil, err
	}
	for event, err := range d.roomEvents(ctx, roomID) {
		if err != nil {
			return nil, err
		}
		data.Events = append(data.Events, event)
	}
	return data, nil
}

func tuwunelRoomsFixture(rooms, messages int) *TuwunelDump {
	d := &TuwunelDump{maps: map[string]map[string][]byte{}}
	for _, name := range tuwunelRelayMaps {
		d.maps[name] = map[string][]byte{}
	}
	u64 := func(n int) string { return string(binary.BigEndian.AppendUint64(nil, uint64(n))) }
	d.maps["shortstatekey_statekey"][u64(1)] = []byte("m.room.create\xff")
	for i := 0; i < rooms; i++ {
		room := fmt.Sprintf("!room%d:example.org", i)
		create := fmt.Sprintf("$create%d", i)
		short := u64(i*(messages+1) + 1)
		group := u64(i + 1)
		d.maps["shorteventid_eventid"][short] = []byte(create)
		d.maps["roomid_shortstatehash"][room] = []byte(group)
		d.maps["shortstatehash_statediff"][group] = []byte(u64(0) + u64(1) + short)
		d.maps["pduid_pdu"][create] = []byte(fmt.Sprintf(`{"event_id":%q,"room_id":%q,"type":"m.room.create","state_key":"","content":{}}`, create, room))
		last := create
		for j := 0; j < messages; j++ {
			id := fmt.Sprintf("$message%d-%d", i, j)
			short := u64(i*(messages+1) + j + 2)
			d.maps["shorteventid_eventid"][short] = []byte(id)
			d.maps["shorteventid_shortstatehash"][short] = []byte(group)
			d.maps["pduid_pdu"][id] = []byte(fmt.Sprintf(`{"event_id":%q,"room_id":%q,"type":"m.room.message","content":{"body":"hello"},"auth_events":[%q]}`, id, room, create))
			last = id
		}
		d.maps["roomid_pduleaves"][room+"\xff"+last] = []byte(last)
	}
	return d
}

func TestTuwunelRelayIndexSeparatesRooms(t *testing.T) {
	d := tuwunelRoomsFixture(2, 3)
	d.maps["eventid_outlierpdu"]["$auth"] = []byte(`{"room_id":"!room0:example.org","type":"m.room.join_rules","state_key":"","content":{}}`)
	d.maps["eventid_outlierpdu"]["$outlier"] = []byte(`{"room_id":"!outlier:example.org","type":"m.room.create","content":{}}`)
	ids, err := d.RoomIDs(t.Context())
	if err != nil || len(ids) != 2 {
		t.Fatalf("rooms = %v, error = %v", ids, err)
	}
	for i, room := range ids {
		data, err := collectTuwunelRoom(t.Context(), d, room)
		if err != nil {
			t.Fatal(err)
		}
		want := 4
		if i == 0 {
			want++
		}
		if len(data.Events) != want || len(data.Timeline) != 4 || len(data.Extremities) != 1 {
			t.Fatalf("wrong room inventory: %+v", data)
		}
		for _, entry := range data.Events {
			var p struct {
				Room string `json:"room_id"`
			}
			if err := json.Unmarshal(entry.PDU, &p); err != nil || p.Room != room {
				t.Fatal("events leaked between rooms")
			}
		}
	}
}

func BenchmarkTuwunelRoomRelayData(b *testing.B) {
	for _, rooms := range []int{1, 100, 1000} {
		b.Run(fmt.Sprintf("rooms=%d", rooms), func(b *testing.B) {
			d := tuwunelRoomsFixture(rooms, 100)
			if err := d.indexRelayData(b.Context()); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for b.Loop() {
				if _, err := d.roomRelayMetadata(b.Context(), "!room0:example.org"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestTuwunelSigningKey(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// Ruma/ring's v2 PKCS#8 includes an explicitly tagged public key.
	ringPrefix, _ := hex.DecodeString("3053020101300506032b657004220420")
	ringPublic, _ := hex.DecodeString("a123032100")
	ring := append(append(append(ringPrefix, seed...), ringPublic...), key.Public().(ed25519.PublicKey)...)
	for _, encoded := range [][]byte{der, ring} {
		d := &TuwunelDump{maps: map[string]map[string][]byte{"global": {"keypair": append([]byte("original\xff"), encoded...)}}}
		raw, err := d.SigningKey()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := federation.ParseSynapseKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.Priv.Equal(key) || string(parsed.ID) != "ed25519:original" {
			t.Fatal("signing identity changed")
		}
	}
	ring[len(ring)-1] ^= 1
	d := &TuwunelDump{maps: map[string]map[string][]byte{"global": {"keypair": append([]byte("original\xff"), ring...)}}}
	if _, err := d.SigningKey(); err == nil {
		t.Fatal("mismatched public key accepted")
	}
}

func TestTuwunelHistoricalState(t *testing.T) {
	u64 := func(n uint64) string { return string(binary.BigEndian.AppendUint64(nil, n)) }
	pair := func(k, e uint64) []byte {
		return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, k), e)
	}
	d := &TuwunelDump{maps: map[string]map[string][]byte{}}
	for _, name := range tuwunelRelayMaps {
		d.maps[name] = map[string][]byte{}
	}
	d.maps["shorteventid_eventid"] = map[string][]byte{u64(1): []byte("$create"), u64(2): []byte("$first"), u64(3): []byte("$second"), u64(4): []byte("$message")}
	d.maps["shortstatekey_statekey"] = map[string][]byte{u64(8): []byte("m.room.create\xff"), u64(9): []byte("m.room.topic\xff")}
	d.maps["shortstatehash_statediff"][u64(10)] = append([]byte(u64(0)), pair(8, 1)...)
	d.maps["shortstatehash_statediff"][u64(11)] = append([]byte(u64(10)), pair(9, 2)...)
	d.maps["shortstatehash_statediff"][u64(12)] = append(append(append([]byte(u64(11)), pair(9, 3)...), []byte(u64(0))...), pair(9, 2)...)
	d.maps["roomid_shortstatehash"]["!room:example.org"] = []byte(u64(12))
	d.maps["shorteventid_shortstatehash"] = map[string][]byte{u64(2): []byte(u64(10)), u64(3): []byte(u64(11)), u64(4): []byte(u64(12))}
	d.maps["roomid_pduleaves"]["!room:example.org\xff$message"] = []byte("$message")
	d.maps["pduid_pdu"] = map[string][]byte{
		"a": []byte(`{"event_id":"$create","room_id":"!room:example.org","type":"m.room.create","state_key":"","content":{}}`),
		"b": []byte(`{"event_id":"$first","room_id":"!room:example.org","type":"m.room.topic","state_key":"","content":{"topic":"old"}}`),
		"c": []byte(`{"event_id":"$second","room_id":"!room:example.org","type":"m.room.topic","state_key":"","content":{"topic":"new"}}`),
		"d": []byte(`{"event_id":"$message","room_id":"!room:example.org","type":"m.room.message","content":{"body":"hi"},"auth_events":["$create"]}`),
	}
	data, err := collectTuwunelRoom(t.Context(), d, "!room:example.org")
	if err != nil {
		t.Fatal(err)
	}
	if data.Groups[12].Prev != 11 || len(data.Groups[12].State) != 1 {
		t.Fatal("replacement expanded into a full snapshot")
	}
	k := relay.StateKey("m.room.topic", "")
	if len(data.Events) != 4 || data.BeforeEventGroups["$create"] != 0 || data.BeforeEventGroups["$second"] != 11 || data.Groups[11].State[k] != "$first" || data.CurrentState[k] != "$second" || data.Extremities[0] != "$message" {
		t.Fatalf("room state = %+v", data)
	}
	for _, entry := range data.Events {
		var original map[string]any
		if err := json.Unmarshal(entry.PDU, &original); err != nil {
			t.Fatal(err)
		}
		if original["event_id"] != entry.EventID {
			t.Fatal("PDU changed during export")
		}
	}
	if data.Groups[11].Prev != 10 || len(data.Groups[11].State) != 1 {
		t.Fatal("expanded delta into full snapshot")
	}
	d.maps["shortstatehash_statediff"][u64(13)] = append(append([]byte(u64(12)), []byte(u64(0))...), pair(9, 3)...)
	d.maps["roomid_shortstatehash"]["!room:example.org"] = []byte(u64(13))
	removed, err := collectTuwunelRoom(t.Context(), d, "!room:example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := removed.CurrentState[k]; ok {
		t.Fatal("removed state retained")
	}
	if removed.CurrentState[relay.StateKey("m.room.create", "")] != "$create" {
		t.Fatal("removal lost inherited state")
	}
	d.maps["shortstatehash_statediff"][u64(10)] = []byte(u64(12))
	if _, err := collectTuwunelRoom(t.Context(), d, "!room:example.org"); err == nil {
		t.Fatal("state cycle accepted")
	}
}

func TestLosslessRequiresCompleteDump(t *testing.T) {
	d := &TuwunelDump{maps: map[string]map[string][]byte{}}
	for _, name := range tuwunelExtraMaps {
		d.maps[name] = map[string][]byte{}
	}
	if err := d.CheckLosslessMaps(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pduid_pdu", "shortstatehash_statediff", "onetimekeyid4225_otk", "servercurrentevent_data"} {
		missing := &TuwunelDump{maps: maps.Clone(d.maps)}
		delete(missing.maps, name)
		if err := missing.CheckLosslessMaps(); err == nil {
			t.Fatalf("missing %s accepted", name)
		}
	}
}

func TestTuwunelBackfillWithoutHistoricalState(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		backfilled, badMarker, badCount, extremity bool
		fail                                       bool
	}{
		{name: "backfilled", backfilled: true},
		{name: "forward", fail: true},
		{name: "invalid backfill marker", backfilled: true, badMarker: true, fail: true},
		{name: "positive backfill count", backfilled: true, badCount: true, fail: true},
		{name: "forward extremity without state", backfilled: true, extremity: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tuwunelRoomsFixture(1, 1)
			const room = "!room0:example.org"
			const message = "$message0-0"
			delete(d.maps["shorteventid_shortstatehash"], string(binary.BigEndian.AppendUint64(nil, 2)))
			if tc.backfilled {
				key := binary.BigEndian.AppendUint64(nil, 1)
				marker := uint64(0)
				if tc.badMarker {
					marker = 1
				}
				key = binary.BigEndian.AppendUint64(key, marker)
				count := ^uint64(0)
				if tc.badCount {
					count = 1
				}
				key = binary.BigEndian.AppendUint64(key, count)
				d.maps["pduid_pdu"][string(key)] = d.maps["pduid_pdu"][message]
				delete(d.maps["pduid_pdu"], message)
			}
			if !tc.extremity {
				delete(d.maps["roomid_pduleaves"], room+"\xff"+message)
				d.maps["roomid_pduleaves"][room+"\xff$create0"] = []byte("$create0")
			}
			data, err := d.roomRelayMetadata(t.Context(), room)
			if tc.fail {
				if err == nil {
					t.Fatal("missing forward state accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(data.StateUnavailable, []string{message}) || len(data.Timeline) != 2 {
				t.Fatalf("metadata=%+v", data)
			}
			if _, ok := data.BeforeEventGroups[message]; ok {
				t.Fatal("invented historical state")
			}
			events := func(yield func(json.RawMessage, error) bool) {
				for event, err := range d.roomEvents(t.Context(), room) {
					if !yield(event.PDU, err) || err != nil {
						return
					}
				}
			}
			if err := d.compareTimeline(t.Context(), room, events); err != nil {
				t.Fatal(err)
			}
		})
	}
}
