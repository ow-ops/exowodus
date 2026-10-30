package migrate

import (
	"encoding/binary"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/relay"
	"maunium.net/go/mautrix/id"
)

func storedTestEvent(t *testing.T, raw json.RawMessage, version string) relay.EventJSON {
	t.Helper()
	p, err := relay.ParsePDU(raw)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := p.GetEventID(id.RoomVersion(version))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = jsonv2.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["event_id"], _ = json.Marshal(eventID)
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return relay.EventJSON{EventID: string(eventID), PDU: raw}
}

func TestTuwunelDummyOmissionEligibility(t *testing.T) {
	for _, tc := range []struct {
		name, fields, typ string
		valid, omit       bool
	}{
		{name: "invalid dummy", omit: true},
		{name: "valid dummy", valid: true},
		{name: "historical state dependency"},
		{name: "auth dependency"},
		{name: "room head"},
		{name: "state event", fields: `,"state_key":""`},
		{name: "ordinary event", typ: "m.room.message"},
	} {
		for _, version := range []string{"11", "12"} {
			t.Run(tc.name+"/"+version, func(t *testing.T) {
				dump, timeline := checkpointFixture(t)
				const roomID = "!room:example.org"
				typ := tc.typ
				if typ == "" {
					typ = "org.matrix.dummy_event"
				}
				event := storedTestEvent(t, json.RawMessage(`{"type":"`+typ+`","room_id":"!room:example.org","sender":"@alice:example.org","content":{},"auth_events":[],"prev_events":["$older"],"depth":4,"origin_server_ts":123`+tc.fields+`}`), version)
				if !tc.valid {
					event.PDU = json.RawMessage(strings.Replace(string(event.PDU), event.EventID, "$invalid", 1))
					event.EventID = "$invalid"
				}
				if err := dump.indexRelayData(t.Context()); err != nil {
					t.Fatal(err)
				}
				index := dump.relayRooms[roomID]
				index.events[event.EventID] = event.PDU
				index.timeline[event.EventID] = true
				u64 := func(n uint64) string { return string(binary.BigEndian.AppendUint64(nil, n)) }
				dump.shortEvents[event.EventID] = u64(10)
				dump.maps["shorteventid_eventid"][u64(10)] = []byte(event.EventID)
				dump.maps["shorteventid_shortstatehash"][u64(10)] = []byte(u64(2))
				message, err := decodeEvent(timeline[2])
				if err != nil {
					t.Fatal(err)
				}
				switch tc.name {
				case "historical state dependency":
					delete(dump.disk, "shortstatehash_statediff")
					dump.maps["shortstatehash_statediff"][u64(1)] = []byte(u64(0) + u64(1) + u64(1))
					dump.maps["shortstatehash_statediff"][u64(2)] = []byte(u64(1) + u64(2) + u64(2))
					dump.maps["shortstatekey_statekey"][u64(3)] = []byte("m.room.name\xff")
					dump.maps["shortstatehash_statediff"][u64(3)] = []byte(u64(2) + u64(3) + u64(10))
					dump.maps["shortstatehash_statediff"][u64(4)] = []byte(u64(3) + u64(0) + u64(3) + u64(10))
					dump.maps["roomid_shortstatehash"][roomID] = []byte(u64(4))
					dump.maps["shorteventid_shortstatehash"][dump.shortEvents[message.EventID]] = []byte(u64(3))
				case "auth dependency":
					var object map[string]json.RawMessage
					if err := json.Unmarshal(timeline[2], &object); err != nil {
						t.Fatal(err)
					}
					object["auth_events"], _ = json.Marshal([]string{event.EventID})
					index.events[message.EventID], err = json.Marshal(object)
					if err != nil {
						t.Fatal(err)
					}
				case "room head":
					index.extremities = append(index.extremities, event.EventID)
				}
				data, err := dump.roomRelayMetadata(t.Context(), roomID)
				if err != nil {
					t.Fatal(err)
				}
				original := slices.Clone(event.PDU)
				omitted, err := dump.omitInvalidDummies(t.Context(), roomID, version, data)
				if err != nil {
					t.Fatal(err)
				}
				if (len(omitted) == 1) != tc.omit {
					t.Fatalf("omissions = %v", omitted)
				}
				if tc.omit {
					if data.required[event.EventID] != 0 || slices.Contains(data.Timeline, event.EventID) || slices.Contains(data.StateUnavailable, event.EventID) {
						t.Fatal("omitted event retained in export metadata")
					}
					if !reflect.DeepEqual(data.OmittedParents[event.EventID], []string{"$older"}) {
						t.Fatal(data.OmittedParents)
					}
				}
				if _, present := index.timeline[event.EventID]; !present || !reflect.DeepEqual(index.events[event.EventID], original) {
					t.Fatal("source index or PDU changed")
				}
			})
		}
	}
}

func TestCheckpointDummyOmissionAndResume(t *testing.T) {
	dump, timeline := checkpointFixture(t)
	const roomID = "!room:example.org"
	if err := dump.indexRelayData(t.Context()); err != nil {
		t.Fatal(err)
	}
	index := dump.relayRooms[roomID]
	dummy := json.RawMessage(`{"event_id":"$invalid","type":"org.matrix.dummy_event","room_id":"!room:example.org","sender":"@alice:example.org","content":{},"auth_events":[],"prev_events":[],"depth":4,"origin_server_ts":123}`)
	index.events["$invalid"] = dummy
	index.timeline["$invalid"] = false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "checkpoint", Dump: map[string]string{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	// A previous attempt saved history before failing PDU verification.
	if err := a.WriteRoomEvents(roomID, append(slices.Clone(timeline), dummy)); err != nil {
		t.Fatal(err)
	}
	if err := dump.exportRoomPDUs(t.Context(), a, roomID, "11"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("strict export accepted invalid dummy: %v", err)
	}
	if err := resume.Save(t.Context(), "history", roomID, []string{filepath.Join(a.RoomDir(roomID), "events.jsonl")}, archive.ExportCheckpoint{}); err != nil {
		t.Fatal(err)
	}
	e := &Exporter{Archive: a, TuwunelDump: dump, AllUsers: true, HistoryAtCheckpoint: true, Admin: mx.MustNew(srv.URL, "admin"), Resume: resume}
	if err := e.ExportRoom(t.Context(), roomID, nil, nil); err != nil {
		t.Fatal(err)
	}
	rooms, err := a.Rooms()
	if err != nil || len(rooms) != 1 || len(rooms[0].OmittedEvents) != 1 {
		t.Fatalf("rooms=%v error=%v", rooms, err)
	}
	events, err := a.RoomEvents(roomID)
	if err != nil || !reflect.DeepEqual(events, timeline) {
		t.Fatalf("remaining history changed: %v", err)
	}
	var pdus relay.RoomData
	if ok, err := a.ReadRoomPDUs(roomID, &pdus); err != nil || !ok || len(pdus.Events) != len(timeline) || checkEventIDs(pdus.Events, "11") != 0 {
		t.Fatalf("remaining PDUs: %v", err)
	}
	if _, ok := pdus.OmittedParents["$invalid"]; !ok {
		t.Fatal("omission links missing")
	}
	if ready, err := e.resumeHistory(t.Context(), roomID, rooms[0].OmittedEvents); err != nil || !ready {
		t.Fatalf("filtered history cannot resume: %v", err)
	}
	if err := e.ExportRoom(t.Context(), roomID, nil, nil); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
	if err := im.CheckLosslessImport(nil, rooms, &archive.Server{HistoryAtCheckpoint: true}, true); err != nil {
		t.Fatal(err)
	}
	if err := im.CheckLosslessImport(nil, rooms, &archive.Server{}, true); err == nil {
		t.Fatal("omissions accepted outside checkpoint mode")
	}
	if err := a.WriteServer(&archive.Server{HistoryAtCheckpoint: true}); err != nil {
		t.Fatal(err)
	}
	notes, failures := im.ImportServer(t.Context())
	if len(failures) != 0 || !slices.ContainsFunc(notes, func(note string) bool { return strings.Contains(note, "omitted event $invalid") }) {
		t.Fatalf("omission audit missing: notes=%v failures=%v", notes, failures)
	}
}
