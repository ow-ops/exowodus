package migrate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"slices"

	"exodus/internal/archive"
	"exodus/internal/relay"
)

func (d *TuwunelDump) roomStateEvents(ctx context.Context, roomID string, state map[string]string) iter.Seq2[json.RawMessage, error] {
	return func(yield func(json.RawMessage, error) bool) {
		reader := tuwunelRoomReader{dump: d, room: d.relayRooms[roomID], files: map[string]*os.File{}}
		defer reader.Close()
		for _, key := range slices.Sorted(maps.Keys(state)) {
			raw, err := reader.read(ctx, state[key])
			if !yield(raw, err) || err != nil {
				return
			}
		}
	}
}

func (d *TuwunelDump) checkpointTimeline(ctx context.Context, roomID string) iter.Seq2[json.RawMessage, error] {
	// ldb scans store timeline PDUs in stream order, with backfill first.
	return func(yield func(json.RawMessage, error) bool) {
		for event, err := range d.roomEvents(ctx, roomID) {
			if err != nil {
				yield(nil, err)
				return
			}
			if _, accepted := d.relayRooms[roomID].timeline[event.EventID]; accepted && !yield(event.PDU, nil) {
				return
			}
		}
	}
}

func (d *TuwunelDump) checkpointUserRoom(ctx context.Context, userID string, room *archive.Room) (bool, error) {
	index := d.relayRooms[room.RoomID]
	if index == nil || len(index.timeline) == 0 {
		return false, nil
	}
	current := d.maps["roomid_shortstatehash"][room.RoomID]
	if len(current) != 8 {
		return false, errors.New("Tuwunel room has no current state")
	}
	var stateFile *os.File
	if table := d.disk["shortstatehash_statediff"]; table != nil {
		var err error
		stateFile, err = os.Open(table.path)
		if err != nil {
			return false, err
		}
		defer stateFile.Close()
	}
	group := binary.BigEndian.Uint64(current)
	groups := map[int64]relay.Group{}
	if err := d.loadStateGroups(ctx, groups, group, stateFile); err != nil {
		return false, err
	}
	state, err := relay.ResolveStateContext(ctx, groups, int64(group))
	if err != nil {
		return false, err
	}
	eventID := state[relay.StateKey("m.room.member", userID)]
	if eventID == "" {
		return false, nil
	}
	reader := tuwunelRoomReader{dump: d, room: index, files: map[string]*os.File{}}
	defer reader.Close()
	raw, err := reader.read(ctx, eventID)
	if err != nil {
		return false, err
	}
	ev, err := decodeEvent(raw)
	if err != nil {
		return false, err
	}
	if ev.Type != "m.room.member" || memberTarget(ev) != userID {
		return false, fmt.Errorf("invalid checkpoint membership %s", eventID)
	}
	room.Member = ev.Content
	return membership(ev) == "join", nil
}

func (d *TuwunelDump) trimCheckpointReceipts(room *archive.Room) {
	timeline := d.relayRooms[room.RoomID].timeline
	if _, ok := timeline[room.Receipt]; !ok {
		room.Receipt = ""
	}
	if _, ok := timeline[room.PrivateReceipt]; !ok {
		room.PrivateReceipt = ""
	}
	var marker struct {
		EventID string `json:"event_id"`
	}
	if json.Unmarshal(room.AccountData["m.fully_read"], &marker) == nil {
		if _, ok := timeline[marker.EventID]; !ok {
			delete(room.AccountData, "m.fully_read")
		}
	}
}
