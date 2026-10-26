package migrate

import (
	"encoding/binary"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
	"maunium.net/go/mautrix/id"
)

func checkpointFixture(t *testing.T) (*TuwunelDump, []json.RawMessage) {
	t.Helper()
	const roomID = "!room:example.org"
	makeEvent := func(typ string, stateKey *string, content any, auth []string, depth int) (string, json.RawMessage) {
		t.Helper()
		value := map[string]any{
			"room_id": roomID, "sender": "@alice:example.org", "type": typ,
			"content": content, "auth_events": auth, "prev_events": []string{}, "depth": depth, "origin_server_ts": depth,
		}
		if stateKey != nil {
			value["state_key"] = *stateKey
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		pdu, err := relay.ParsePDU(raw)
		if err != nil {
			t.Fatal(err)
		}
		eventID, err := pdu.GetEventID(id.RoomVersion("11"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err = jsonv2.Marshal(pdu)
		if err != nil {
			t.Fatal(err)
		}
		var stored map[string]json.RawMessage
		if err := json.Unmarshal(raw, &stored); err != nil {
			t.Fatal(err)
		}
		stored["event_id"], err = json.Marshal(eventID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		return string(eventID), raw
	}
	empty, alice := "", "@alice:example.org"
	createID, create := makeEvent("m.room.create", &empty, map[string]any{"room_version": "11"}, []string{}, 1)
	memberID, member := makeEvent("m.room.member", &alice, map[string]any{"membership": "join"}, []string{createID}, 2)
	messageID, message := makeEvent("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": "checkpoint message"}, []string{createID, memberID}, 3)
	outlierID, outlier := makeEvent("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": "outlier"}, []string{createID, memberID}, 4)
	u64 := func(n uint64) string { return string(binary.BigEndian.AppendUint64(nil, n)) }
	tables := map[string]map[string][]byte{}
	for _, name := range tuwunelRelayMaps {
		tables[name] = map[string][]byte{}
	}
	tables["global"]["version"] = tuwunelSchemaRow
	tables["userid_password"] = map[string][]byte{}
	tables["token_userdeviceid"] = map[string][]byte{}
	tables["pduid_pdu"][u64(1)+u64(1)] = create
	tables["pduid_pdu"][u64(1)+u64(2)] = member
	tables["pduid_pdu"][u64(1)+u64(3)] = message
	tables["eventid_outlierpdu"][outlierID] = outlier
	for i, eventID := range []string{createID, memberID, messageID} {
		tables["shorteventid_eventid"][u64(uint64(i+1))] = []byte(eventID)
	}
	tables["shortstatekey_statekey"][u64(1)] = []byte("m.room.create\xff")
	tables["shortstatekey_statekey"][u64(2)] = []byte("m.room.member\xff" + alice)
	tables["shortstatehash_statediff"][u64(1)] = []byte(u64(0) + u64(1) + u64(1))
	tables["shortstatehash_statediff"][u64(2)] = []byte(u64(1) + u64(2) + u64(2))
	tables["shorteventid_shortstatehash"][u64(2)] = []byte(u64(1))
	tables["shorteventid_shortstatehash"][u64(3)] = []byte(u64(2))
	tables["roomid_shortstatehash"][roomID] = []byte(u64(2))
	tables["roomid_pduleaves"][roomID+"\xff"+messageID] = nil
	dir := t.TempDir()
	for name, rows := range tables {
		var scan strings.Builder
		for _, key := range slices.Sorted(maps.Keys(rows)) {
			fmt.Fprintf(&scan, "0x%x ==> 0x%x\n", key, rows[key])
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(scan.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dump, err := OpenTuwunelDump(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return dump, []json.RawMessage{create, member, message}
}

func TestCheckpointRoomExportAndResume(t *testing.T) {
	for _, checkpoint := range []bool{false, true} {
		t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
			dump, timeline := checkpointFixture(t)
			var states, histories, details atomic.Int32
			homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/state"):
					states.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"state": timeline[:2]})
				case strings.HasSuffix(r.URL.Path, "/messages"):
					histories.Add(1)
					live := append(slices.Clone(timeline), json.RawMessage(`{"event_id":"$new","type":"m.room.message","content":{"body":"new"}}`))
					live[2] = json.RawMessage(strings.Replace(string(live[2]), "checkpoint message", "different API content", 1))
					_ = json.NewEncoder(w).Encode(map[string]any{"chunk": live})
				case strings.HasPrefix(r.URL.Path, "/_synapse/admin/v2/users/"):
					_, _ = w.Write([]byte(`{}`))
				case r.URL.Path == "/_synapse/admin/v1/registration_tokens":
					_, _ = w.Write([]byte(`{"registration_tokens":[]}`))
				default:
					details.Add(1)
					_, _ = w.Write([]byte(`{"public":false}`))
				}
			}))
			defer homeserver.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			resume, err := a.OpenExportResume(t.Context(), archive.ExportSource{Fingerprint: "checkpoint", Dump: map[string]string{}}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer resume.Close()
			client := mx.MustNew(homeserver.URL, "admin")
			exp := &Exporter{Archive: a, TuwunelDump: dump, AllUsers: true, HistoryAtCheckpoint: checkpoint, Admin: client, Resume: resume}
			err = exp.ExportRoom(t.Context(), "!room:example.org", nil, nil)
			if !checkpoint {
				if err == nil || !strings.Contains(err.Error(), "fields: content") {
					t.Fatalf("live drift accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			events, err := a.RoomEvents("!room:example.org")
			if err != nil || !reflect.DeepEqual(events, timeline) {
				t.Fatalf("checkpoint timeline changed: %v", err)
			}
			rooms, err := a.Rooms()
			if err != nil || len(rooms) != 1 || len(rooms[0].State) != 2 || rooms[0].Version != "11" || rooms[0].ArchiveOnly {
				t.Fatalf("checkpoint state not restored: %v", err)
			}
			if err := a.RequireLossless(); err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
			if err := im.CheckLosslessImport(nil, rooms, nil, true); err != nil {
				t.Fatalf("checkpoint room failed preservation checks: %v", err)
			}
			exp = &Exporter{Archive: a, TuwunelDump: dump, AllUsers: true, HistoryAtCheckpoint: true, Admin: client, Resume: resume}
			if err := exp.ExportRoom(t.Context(), "!room:example.org", nil, nil); err != nil {
				t.Fatal(err)
			}
			if states.Load() != 0 || histories.Load() != 0 || details.Load() != 1 {
				t.Fatalf("state=%d history=%d details=%d", states.Load(), histories.Load(), details.Load())
			}
			if err := exp.ExportServer(t.Context()); err != nil {
				t.Fatal(err)
			}
			srv, err := a.ReadServer()
			if err != nil || !srv.HistoryAtCheckpoint {
				t.Fatalf("checkpoint policy not recorded: %v", err)
			}
		})
	}
}

func TestCheckpointKeepsIntegrityChecks(t *testing.T) {
	for _, failure := range []string{"auth", "event ID", "historical state"} {
		t.Run(failure, func(t *testing.T) {
			dump, timeline := checkpointFixture(t)
			ev, err := decodeEvent(timeline[2])
			if err != nil {
				t.Fatal(err)
			}
			raw := timeline[2]
			if failure == "auth" {
				var value map[string]json.RawMessage
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				value["auth_events"] = json.RawMessage(`["$missing"]`)
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
			} else if failure == "historical state" {
				delete(dump.maps["shorteventid_shortstatehash"], dump.shortEvents[ev.EventID])
			} else {
				raw = json.RawMessage(strings.Replace(string(raw), `"origin_server_ts":3`, `"origin_server_ts":99`, 1))
			}
			dump.relayRooms["!room:example.org"].events[ev.EventID] = raw
			homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{}`))
			}))
			defer homeserver.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			exp := &Exporter{Archive: a, TuwunelDump: dump, AllUsers: true, HistoryAtCheckpoint: true, Admin: mx.MustNew(homeserver.URL, "admin")}
			if err := exp.ExportRoom(t.Context(), "!room:example.org", nil, nil); err == nil || !strings.Contains(err.Error(), failure) {
				t.Fatalf("%s check bypassed: %v", failure, err)
			}
			rooms, err := a.Rooms()
			if err != nil || len(rooms) != 0 {
				t.Fatal("invalid checkpoint room published")
			}
		})
	}
}

func TestCheckpointOmitsUnusedOutliers(t *testing.T) {
	dump, _ := checkpointFixture(t)
	const room = "!room:example.org"
	dump.relayRooms[room].events["$unused"] = json.RawMessage(`{"event_id":"$unused","room_id":"!room:example.org","type":"m.room.message","content":{},"auth_events":["$missing"]}`)
	homeserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer homeserver.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	exp := &Exporter{Archive: a, TuwunelDump: dump, AllUsers: true, HistoryAtCheckpoint: true, Admin: mx.MustNew(homeserver.URL, "admin")}
	if err := exp.ExportRoom(t.Context(), room, nil, nil); err != nil {
		t.Fatal(err)
	}
	var stored relay.RoomData
	if ok, err := a.ReadRoomPDUs(room, &stored); err != nil || !ok {
		t.Fatalf("read PDUs: %v", err)
	}
	if len(stored.Events) != 3 || len(stored.Timeline) != 3 {
		t.Fatalf("events=%d timeline=%d", len(stored.Events), len(stored.Timeline))
	}
	for _, event := range stored.Events {
		if event.EventID == "$unused" {
			t.Fatal("exported an unused outlier")
		}
	}
}

func TestCheckpointMembershipAndReceipts(t *testing.T) {
	dump, timeline := checkpointFixture(t)
	r := &archive.Room{RoomID: "!new:example.org"}
	if include, err := dump.checkpointUserRoom(t.Context(), "@alice:example.org", r); err != nil || include {
		t.Fatalf("new room accepted: %v", err)
	}
	r.RoomID = "!room:example.org"
	if include, err := dump.checkpointUserRoom(t.Context(), "@new:example.org", r); err != nil || include {
		t.Fatalf("new membership accepted: %v", err)
	}
	if include, err := dump.checkpointUserRoom(t.Context(), "@alice:example.org", r); err != nil || !include || string(r.Member) != `{"membership":"join"}` {
		t.Fatalf("checkpoint membership missing: %v", err)
	}
	message, err := decodeEvent(timeline[2])
	if err != nil {
		t.Fatal(err)
	}
	r.Receipt, r.PrivateReceipt = message.EventID, "$new"
	r.AccountData = map[string]json.RawMessage{"m.fully_read": json.RawMessage(`{"event_id":"$new"}`), "m.tag": json.RawMessage(`{}`)}
	dump.trimCheckpointReceipts(r)
	if r.Receipt != message.EventID || r.PrivateReceipt != "" || r.AccountData["m.fully_read"] != nil || r.AccountData["m.tag"] == nil {
		t.Fatal("checkpoint receipt filtering changed the wrong data")
	}
}
