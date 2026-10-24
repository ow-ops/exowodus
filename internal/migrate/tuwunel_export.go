package migrate

import (
	"cmp"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"exodus/internal/archive"
	"exodus/internal/relay"
)

func (r *tuwunelRoomIndex) hasEvent(id string) bool {
	_, memory := r.events[id]
	_, disk := r.diskEvents[id]
	return memory || disk
}

type tuwunelRoomReader struct {
	dump  *TuwunelDump
	room  *tuwunelRoomIndex
	files map[string]*os.File
}

func (r *tuwunelRoomReader) read(ctx context.Context, id string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if raw, ok := r.room.events[id]; ok {
		return raw, nil
	}
	ref, ok := r.room.diskEvents[id]
	if !ok {
		return nil, fmt.Errorf("Tuwunel event %s missing from dump", id)
	}
	f := r.files[ref.table]
	if f == nil {
		var err error
		f, err = os.Open(r.dump.disk[ref.table].path)
		if err != nil {
			return nil, err
		}
		r.files[ref.table] = f
	}
	return readTuwunelValue(f, ref.value)
}

func (r *tuwunelRoomReader) Close() error {
	var err error
	for _, f := range r.files {
		err = errors.Join(err, f.Close())
	}
	return err
}

func (d *TuwunelDump) roomEvents(ctx context.Context, roomID string) iter.Seq2[relay.EventJSON, error] {
	return func(yield func(relay.EventJSON, error) bool) {
		room := d.relayRooms[roomID]
		if room == nil {
			yield(relay.EventJSON{}, fmt.Errorf("Tuwunel room %s missing from dump", roomID))
			return
		}
		reader := tuwunelRoomReader{dump: d, room: room, files: map[string]*os.File{}}
		defer reader.Close()
		ids := slices.Collect(maps.Keys(room.events))
		for id := range room.diskEvents {
			if _, ok := room.events[id]; !ok {
				ids = append(ids, id)
			}
		}
		// Event array order has no timeline meaning. Read each table in file
		// order to avoid seeking by event ID through large dumps.
		slices.SortFunc(ids, func(a, b string) int {
			left, right := room.diskEvents[a], room.diskEvents[b]
			if order := cmp.Compare(left.table, right.table); order != 0 {
				return order
			}
			if order := cmp.Compare(left.value.offset, right.value.offset); order != 0 {
				return order
			}
			return cmp.Compare(a, b)
		})
		for _, id := range ids {
			raw, err := reader.read(ctx, id)
			if !yield(relay.EventJSON{EventID: id, PDU: raw}, err) || err != nil {
				return
			}
		}
	}
}

type tuwunelEventStream iter.Seq2[relay.EventJSON, error]

func (events tuwunelEventStream) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	for event, err := range events {
		if err != nil {
			return err
		}
		if err := jsonv2.MarshalEncode(enc, event); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndArray)
}

type tuwunelRoomExport struct {
	*relay.RoomData
	Events tuwunelEventStream `json:"events"`
}

func (d *TuwunelDump) compareTimeline(ctx context.Context, roomID string, events iter.Seq2[json.RawMessage, error]) error {
	room := d.relayRooms[roomID]
	if room == nil {
		return fmt.Errorf("Tuwunel room %s missing from dump", roomID)
	}
	remaining := maps.Clone(room.timeline)
	reader := tuwunelRoomReader{dump: d, room: room, files: map[string]*os.File{}}
	defer reader.Close()
	for raw, err := range events {
		if err != nil {
			return err
		}
		event, err := decodeEvent(raw)
		if err != nil {
			return err
		}
		if _, ok := remaining[event.EventID]; !ok {
			if _, present := room.timeline[event.EventID]; present {
				return fmt.Errorf("API event %s duplicated in room history", event.EventID)
			}
			return fmt.Errorf("API event %s absent from snapshot", event.EventID)
		}
		original, err := reader.read(ctx, event.EventID)
		if err != nil {
			return err
		}
		want, err := originalEventFields(original)
		if err != nil {
			return err
		}
		got, err := originalEventFields(raw)
		if err != nil {
			return fmt.Errorf("API event %s: %w", event.EventID, err)
		}
		if !reflect.DeepEqual(want, got) {
			var fields []string
			for key, value := range want {
				if actual, ok := got[key]; !ok || !reflect.DeepEqual(value, actual) {
					fields = append(fields, key)
				}
			}
			for key := range got {
				if _, ok := want[key]; !ok {
					fields = append(fields, key)
				}
			}
			slices.Sort(fields)
			return fmt.Errorf("event %s differs between API and snapshot (fields: %s)", event.EventID, strings.Join(fields, ", "))
		}
		delete(remaining, event.EventID)
	}
	if len(remaining) != 0 {
		return fmt.Errorf("%d database timeline events missing from API export", len(remaining))
	}
	return nil
}

func (d *TuwunelDump) exportRoomPDUs(ctx context.Context, a *archive.Archive, roomID, version string) error {
	slog.Info("reading original room state", "room", roomID)
	data, err := d.roomRelayMetadata(ctx, roomID)
	if err != nil {
		return err
	}
	slog.Info("verifying room timeline", "room", roomID)
	if err := d.compareTimeline(ctx, roomID, a.RoomEventsIter(roomID)); err != nil {
		return fmt.Errorf("room %s: source snapshot/API mismatch: %w", roomID, err)
	}
	events := func(yield func(relay.EventJSON, error) bool) {
		count := 0
		progress := time.Now()
		for event, err := range d.roomEvents(ctx, roomID) {
			if err != nil {
				yield(relay.EventJSON{}, err)
				return
			}
			if err := checkEventID(event, version); err != nil {
				yield(relay.EventJSON{}, fmt.Errorf("room %s: original Tuwunel event %s ID could not be verified: %w", roomID, event.EventID, err))
				return
			}
			if !yield(event, nil) {
				return
			}
			count++
			if time.Since(progress) >= 5*time.Second {
				slog.Info("exporting original room events", "room", roomID, "events", count)
				progress = time.Now()
			}
		}
	}
	slog.Info("exporting original room events", "room", roomID)
	return a.WriteRoomPDUs(roomID, tuwunelRoomExport{RoomData: data, Events: tuwunelEventStream(events)})
}
