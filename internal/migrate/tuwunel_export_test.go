package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/relay"
	"maunium.net/go/mautrix/id"
)

func TestTuwunelStreamArchive(t *testing.T) {
	d := diskRoomFixture(t, 10, 32)
	data, err := d.roomRelayMetadata(t.Context(), "!room0:example.org")
	if err != nil {
		t.Fatal(err)
	}
	if data.Events != nil {
		t.Fatal("metadata retained event bodies")
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	value := tuwunelRoomExport{RoomData: data, Events: tuwunelEventStream(d.roomEvents(t.Context(), "!room0:example.org"))}
	if err := a.WriteRoomPDUs("!room0:example.org", value); err != nil {
		t.Fatal(err)
	}
	var got relay.RoomData
	ok, err := a.ReadRoomPDUs("!room0:example.org", &got)
	if err != nil || !ok {
		t.Fatalf("read=%t err=%v", ok, err)
	}
	want, err := collectTuwunelRoom(t.Context(), d, "!room0:example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoomPDUs("!buffered:example.org", want); err != nil {
		t.Fatal(err)
	}
	var buffered relay.RoomData
	if _, err := a.ReadRoomPDUs("!buffered:example.org", &buffered); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, buffered) {
		t.Fatalf("streamed archive differs: got=%+v want=%+v", got, buffered)
	}
	failure := errors.New("event read failed")
	failed := tuwunelRoomExport{RoomData: data, Events: func(yield func(relay.EventJSON, error) bool) { yield(relay.EventJSON{}, failure) }}
	if err := a.WriteRoomPDUs("!room0:example.org", failed); !errors.Is(err, failure) {
		t.Fatalf("write error=%v", err)
	}
	var after relay.RoomData
	if _, err := a.ReadRoomPDUs("!room0:example.org", &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, got) {
		t.Fatal("failed export replaced complete archive")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	value.Events = tuwunelEventStream(d.roomEvents(ctx, "!room0:example.org"))
	if err := a.WriteRoomPDUs("!room0:example.org", value); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestTuwunelStreamTimelineChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []string
		fail   string
	}{
		{"exact", []string{`{"event_id":"$create0","room_id":"!room0:example.org","type":"m.room.create","state_key":"","content":{}}`}, ""},
		{"different content", []string{`{"event_id":"$create0","type":"m.room.create","state_key":"","content":{"changed":true}}`}, "fields: content"},
		{"duplicate", []string{`{"event_id":"$create0","type":"m.room.create","state_key":"","content":{}}`, `{"event_id":"$create0","type":"m.room.create","state_key":"","content":{}}`}, "duplicated"},
		{"missing", nil, "missing"},
		{"unknown", []string{`{"event_id":"$unknown","content":{}}`}, "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tuwunelRoomsFixture(1, 0)
			if err := d.indexRelayData(t.Context()); err != nil {
				t.Fatal(err)
			}
			events := func(yield func(json.RawMessage, error) bool) {
				for _, raw := range tc.events {
					if !yield(json.RawMessage(raw), nil) {
						return
					}
				}
			}
			err := d.compareTimeline(t.Context(), "!room0:example.org", events)
			if tc.fail == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.fail) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTuwunelTimelineRedactionCompatibility(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprint(nested), func(t *testing.T) {
			d := tuwunelRoomsFixture(1, 0)
			if err := d.indexRelayData(t.Context()); err != nil {
				t.Fatal(err)
			}
			const roomID = "!room0:example.org"
			original := json.RawMessage(`{"event_id":"$redaction","type":"m.room.redaction","redacts":"$target","content":{"reason":"spam"}}`)
			if nested {
				original = json.RawMessage(`{"event_id":"$redaction","type":"m.room.redaction","content":{"reason":"spam","redacts":"$target"}}`)
			}
			room := d.relayRooms[roomID]
			before := bytes.Clone(original)
			room.events["$redaction"] = original
			room.timeline["$redaction"] = true
			events := func(yield func(json.RawMessage, error) bool) {
				if yield(room.events["$create0"], nil) {
					yield(json.RawMessage(`{"event_id":"$redaction","type":"m.room.redaction","redacts":"$target","content":{"reason":"spam","redacts":"$target"}}`), nil)
				}
			}
			if err := d.compareTimeline(t.Context(), roomID, events); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(room.events["$redaction"], before) {
				t.Fatal("comparison changed the original PDU")
			}
		})
	}
}

func TestTuwunelStreamVerifiesEventIDs(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			d := tuwunelRoomsFixture(1, 0)
			const room = "!room0:example.org"
			old := "$create0"
			raw := d.maps["pduid_pdu"][old]
			if valid {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(raw, &object); err != nil {
					t.Fatal(err)
				}
				delete(object, "event_id")
				unsigned, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				p, err := relay.ParsePDU(unsigned)
				if err != nil {
					t.Fatal(err)
				}
				hash, err := p.GetEventID(id.RoomVersion("10"))
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := jsonv2.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(encoded, &object); err != nil {
					t.Fatal(err)
				}
				object["event_id"], err = json.Marshal(hash)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				d.maps["pduid_pdu"][old] = raw
				for key, eventID := range d.maps["shorteventid_eventid"] {
					if string(eventID) == old {
						d.maps["shorteventid_eventid"][key] = []byte(hash)
					}
				}
				delete(d.maps["roomid_pduleaves"], room+"\xff"+old)
				d.maps["roomid_pduleaves"][room+"\xff"+string(hash)] = []byte(hash)
			}
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.WriteRoomEvents(room, []json.RawMessage{raw}); err != nil {
				t.Fatal(err)
			}
			err = d.exportRoomPDUs(t.Context(), a, room, "10")
			if valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "ID could not be verified") {
				t.Fatalf("error=%v", err)
			}
			if !valid {
				if _, err := os.Stat(filepath.Join(a.RoomDir(room), "pdus.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid PDUs published: %v", err)
				}
			}
		})
	}
}

func diskRoomFixture(tb testing.TB, messages, bodySize int) *TuwunelDump {
	tb.Helper()
	memory := tuwunelRoomsFixture(1, messages)

	dir := tb.TempDir()
	tables := map[string]map[string][]byte{"userid_password": {}, "token_userdeviceid": {}}
	for name, rows := range memory.maps {
		tables[name] = rows
	}
	for name, rows := range tables {
		f, err := os.Create(filepath.Join(dir, name+".txt"))
		if err != nil {
			tb.Fatal(err)
		}
		for key, value := range rows {
			if name == "pduid_pdu" {
				value = []byte(strings.Replace(string(value), "hello", strings.Repeat("x", bodySize), 1))
			}
			if _, err := fmt.Fprintf(f, "0x%x ==> 0x%x\n", key, value); err != nil {
				tb.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			tb.Fatal(err)
		}
	}
	d, err := OpenTuwunelDump(tb.Context(), dir)
	if err != nil {
		tb.Fatal(err)
	}
	return d
}

func BenchmarkTuwunelRoomMemory(b *testing.B) {
	d := diskRoomFixture(b, 256, 64<<10)
	for _, buffered := range []bool{true, false} {
		name := "metadata"
		if buffered {
			name = "buffered"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var retained uint64
			for b.Loop() {
				b.StopTimer()
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				b.StartTimer()
				var data *relay.RoomData
				var err error
				if buffered {
					data, err = collectTuwunelRoom(b.Context(), d, "!room0:example.org")
				} else {
					data, err = d.roomRelayMetadata(b.Context(), "!room0:example.org")
				}
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				runtime.GC()
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				if after.HeapAlloc > before.HeapAlloc {
					retained += after.HeapAlloc - before.HeapAlloc
				}
				runtime.KeepAlive(data)
				b.StartTimer()
			}
			b.ReportMetric(float64(retained)/float64(b.N), "retained-B/op")
		})
	}
}

func TestTuwunelStreamWritesBeforeExhaustingEvents(t *testing.T) {
	d := diskRoomFixture(t, 32, 64<<10)
	const room = "!room0:example.org"
	data, err := d.roomRelayMetadata(t.Context(), room)
	if err != nil {
		t.Fatal(err)
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	wroteEarly := false
	events := func(yield func(relay.EventJSON, error) bool) {
		count := 0
		for event, err := range d.roomEvents(t.Context(), room) {
			if count == 8 {
				info, err := os.Stat(filepath.Join(a.RoomDir(room), "pdus.json.tmp"))
				if err != nil {
					yield(relay.EventJSON{}, err)
					return
				}
				wroteEarly = info.Size() > 0
			}
			if !yield(event, err) || err != nil {
				return
			}
			count++
		}
	}
	if err := a.WriteRoomPDUs(room, tuwunelRoomExport{RoomData: data, Events: events}); err != nil {
		t.Fatal(err)
	}
	if !wroteEarly {
		t.Fatal("encoder buffered the event stream")
	}
}

func TestTuwunelLargeRoomStream(t *testing.T) {
	if os.Getenv("EXODUS_MEMORY_STRESS") == "" {
		t.Skip("set EXODUS_MEMORY_STRESS to run the large-room memory test")
	}
	const room = "!room0:example.org"
	d := diskRoomFixture(t, 2048, 128<<10)
	data, err := d.roomRelayMetadata(t.Context(), room)
	if err != nil {
		t.Fatal(err)
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	events := func(yield func(json.RawMessage, error) bool) {
		for event, err := range d.roomEvents(t.Context(), room) {
			if !yield(event.PDU, err) || err != nil {
				return
			}
		}
	}
	if err := a.WriteRoomEventsFrom(room, events); err != nil {
		t.Fatal(err)
	}
	if err := d.compareTimeline(t.Context(), room, a.RoomEventsIter(room)); err != nil {
		t.Fatal(err)
	}
	value := tuwunelRoomExport{RoomData: data, Events: tuwunelEventStream(d.roomEvents(t.Context(), room))}
	if err := a.WriteRoomPDUs(room, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(a.RoomDir(room), "pdus.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < 256<<20 {
		t.Fatalf("archive too small: %d", info.Size())
	}
	t.Logf("wrote %d bytes of PDUs", info.Size())
	for _, name := range []string{"memory.peak", "memory.events"} {
		if raw, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", name)); err == nil {
			t.Logf("%s: %s", name, raw)
		}
	}
}
