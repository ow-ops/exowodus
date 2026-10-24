package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"

	"exodus/internal/archive"
	"exodus/internal/relay"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const maxBackfillPages = 100000

// RelayRooms has Continuwuity backfill the original rooms from the relay. It
// returns the rooms that cannot be relayed.
func (im *Importer) RelayRooms(ctx context.Context, rooms []*archive.ArchivedRoom, rl *relay.Relay) ([]*RoomReport, []*archive.ArchivedRoom) {
	if im.Appservice == nil {
		return nil, rooms
	}
	if im.rooms == nil {
		im.rooms = map[string]string{}
	}
	if im.roomFailures == nil {
		im.roomFailures = map[string]bool{}
	}
	var reports []*RoomReport
	var rest []*archive.ArchivedRoom
	for _, room := range rooms {
		if room.ArchiveOnly {
			rep := &RoomReport{RoomID: room.RoomID, ArchiveOnly: true}
			if im.RequireLossless {
				rep.fail("lossless", room.RoomID, errors.New("archive-only retention does not restore the room"))
			}
			reports = append(reports, rep)
			continue
		}
		var data relay.RoomData
		ok, err := im.Archive.ReadRoomPDUs(room.RoomID, &data)
		if err != nil {
			slog.Warn("could not read the room's events, replaying it", "room", room.RoomID, "err", err)
		}
		if !ok {
			if im.RequireLossless {
				rep := &RoomReport{RoomID: room.RoomID}
				rep.fail("lossless", room.RoomID, errors.New("original PDUs unavailable; replay refused"))
				reports = append(reports, rep)
				im.roomFailures[room.RoomID] = true
				continue
			}
			rest = append(rest, room)
			continue
		}
		if err := rl.AddRoom(room.RoomID, room.Version, data); err != nil {
			if im.RequireLossless {
				rep := &RoomReport{RoomID: room.RoomID}
				rep.fail("lossless", room.RoomID, err)
				reports = append(reports, rep)
				im.roomFailures[room.RoomID] = true
				continue
			}
			slog.Warn("room cannot be relayed, replaying it", "room", room.RoomID, "err", err)
			rest = append(rest, room)
			continue
		}
		rep := &RoomReport{RoomID: room.RoomID, NewRoomID: room.RoomID, KeptRoomID: true}
		reports = append(reports, rep)
		slog.Info("moving room through the relay", "room", room.RoomID)
		if err := im.relayRoom(ctx, room, rl, rep); err != nil {
			rep.fail("relay", room.RoomID, err)
			im.roomFailures[room.RoomID] = true
			continue
		}
		rl.RemoveRoom(room.RoomID)
		delete(im.roomFailures, room.RoomID)
		im.rooms[room.RoomID] = room.RoomID
	}
	return reports, rest
}

func (im *Importer) relayRoom(ctx context.Context, room *archive.ArchivedRoom, rl *relay.Relay, rep *RoomReport) error {
	r, err := im.newReplay(ctx, room, rep)
	if err != nil {
		return err
	}
	rep.NewRoomID, rep.KeptRoomID = room.RoomID, true
	owner, members := r.relayMembers()
	if owner == "" {
		return errors.New("no migrated member is in the room")
	}
	if err := r.registerGhosts(ctx); err != nil {
		return err
	}
	if r.st.Done {
		if im.RequireLossless {
			return verifyOriginalRoom(ctx, r.as(r.mapUser(owner)), room.RoomID, r.events)
		}
		return nil
	}
	if err := rl.Enter(room.RoomID, owner); err != nil {
		return err
	}
	if err := r.relayHandOver(rl, owner, members); err != nil {
		return err
	}

	joiner := r.mapUser(owner)
	c := r.as(joiner)
	if _, err := c.JoinRoom(ctx, room.RoomID, &mautrix.ReqJoinRoom{Via: []string{rl.Name}}); err != nil {
		return fmt.Errorf("join through the relay: %w", err)
	}
	r.st.NewRoomID = room.RoomID
	if err := r.save(); err != nil {
		return err
	}

	backfilled, err := backfillRoom(ctx, c, room.RoomID, r.events)
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}
	rep.Replayed = backfilled
	if im.RequireLossless {
		if err := verifyOriginalRoom(ctx, c, room.RoomID, r.events); err != nil {
			return err
		}
	}

	before := len(rep.Failures)
	if err := r.loadJoined(ctx); err != nil {
		return err
	}
	for _, m := range members {
		if newID := r.mapUser(m); !r.joined[newID] {
			if _, err := r.as(newID).JoinRoomByID(ctx, id.RoomID(room.RoomID)); err != nil {
				rep.fail("membership", newID, err)
			}
		}
	}

	if err := failuresError(rep.Failures[before:]); err != nil {
		return err
	}

	if pl := rl.Content(room.RoomID, "m.room.power_levels", ""); pl != nil {
		if users, ok := pl["users"].(map[string]any); ok {
			delete(users, rl.UserID())
			if _, err := r.putState(ctx, joiner, "m.room.power_levels", "", pl, 0); err != nil {
				rep.fail("power_levels", room.RoomID, err)
			}
		}
	}
	if alias, err := decodeContent(r.final[relay.StateKey("m.room.canonical_alias", "")].Content); err == nil {
		r.createAliases(ctx, joiner, alias)
	}
	if room.Public {
		if err := publishRoom(ctx, c, room.RoomID); err != nil {
			rep.fail("directory", room.RoomID, err)
		}
	}
	if err := failuresError(rep.Failures[before:]); err != nil {
		return err
	}
	// Remove the relay only after history and all room restoration succeeded.
	if r.joined[rl.UserID()] {
		if _, err := r.putState(ctx, joiner, "m.room.member", rl.UserID(), map[string]string{"membership": "leave"}, 0); err != nil {
			return fmt.Errorf("remove relay member: %w", err)
		}
	}
	r.st.Done = true
	return r.save()
}

func verifyOriginalRoom(ctx context.Context, c *mautrix.Client, roomID string, events []json.RawMessage) error {
	expected := map[string]json.RawMessage{}
	for _, raw := range events {
		ev, err := decodeEvent(raw)
		if err != nil {
			return err
		}
		expected[ev.EventID] = raw
	}
	var mismatch error
	_, _, err := paginateBack(ctx, c, roomID, func(ev *event.Event) bool {
		want, ok := expected[string(ev.ID)]
		if !ok {
			return len(expected) == 0
		}
		wantFields, fieldErr := originalEventFields(want)
		if fieldErr != nil {
			mismatch = fieldErr
			return true
		}
		raw, marshalErr := json.Marshal(ev)
		if marshalErr != nil {
			mismatch = marshalErr
			return true
		}
		got, fieldErr := originalEventFields(raw)
		if fieldErr != nil || !reflect.DeepEqual(wantFields, got) {
			mismatch = fmt.Errorf("original event %s differs on the destination", ev.ID)
			return true
		}
		delete(expected, string(ev.ID))
		return len(expected) == 0
	})
	if err != nil {
		return err
	}
	if mismatch != nil {
		return mismatch
	}
	if len(expected) != 0 {
		return fmt.Errorf("%d original events absent on destination", len(expected))
	}
	return nil
}

// relayHandOver raises the relay's member above the default level so
// Continuwuity backfills from it. On a new server name, the new accounts get
// the old ones' levels.
func (r *replay) relayHandOver(rl *relay.Relay, owner string, members []string) error {
	roomID := r.room.RoomID
	for _, m := range members {
		if r.mapUser(m) == m {
			continue
		}
		if err := rl.Author(roomID, m, "m.room.member", r.mapUser(m), map[string]any{"membership": "invite"}); err != nil {
			return err
		}
	}
	pl := rl.Content(roomID, "m.room.power_levels", "")
	if pl == nil {
		return nil
	}
	content := maps.Clone(pl)
	users := map[string]any{}
	if orig, ok := pl["users"].(map[string]any); ok {
		maps.Copy(users, orig)
	}
	for _, m := range members {
		if level, ok := users[m]; ok {
			users[r.mapUser(m)] = level
		}
	}
	users[rl.UserID()] = powerValue(pl["users_default"]) + 1
	content["users"] = users
	return rl.Author(roomID, owner, "m.room.power_levels", "", content)
}

// relayMembers returns the most powerful joined local member, and all of them.
func (r *replay) relayMembers() (string, []string) {
	pl, _ := decodeContent(r.final[relay.StateKey("m.room.power_levels", "")].Content)
	users, _ := pl["users"].(map[string]any)
	var owner string
	var ownerLevel int64 = -1
	var members []string
	for _, ev := range r.final {
		if ev.Type != "m.room.member" || membership(ev) != "join" || (!r.im.Migrated[*ev.StateKey] && !r.puppets[*ev.StateKey]) {
			continue
		}
		userID := *ev.StateKey
		members = append(members, userID)
		level := powerValue(pl["users_default"])
		if v, ok := users[userID]; ok {
			level = powerValue(v)
		}
		if level > ownerLevel || level == ownerLevel && userID < owner {
			owner, ownerLevel = userID, level
		}
	}
	return owner, members
}

// paginateBack makes Continuwuity backfill until found or the room's start.
// It returns the number of events seen.
func paginateBack(ctx context.Context, c *mautrix.Client, roomID string, found func(*event.Event) bool) (int, bool, error) {
	var total int
	from := ""
	for range maxBackfillPages {
		page, err := c.Messages(ctx, id.RoomID(roomID), from, "", mautrix.DirectionBackward, nil, 500)
		if err != nil {
			return total, false, err
		}
		total += len(page.Chunk)
		complete := false
		for _, ev := range page.Chunk {
			complete = found(ev) || complete
		}
		if complete {
			return total, true, nil
		}
		if page.End == "" || page.End == from || len(page.Chunk) == 0 {
			break
		}
		from = page.End
	}
	return total, false, nil
}

// backfillRoom requires both the create event and every exported timeline event.
func backfillRoom(ctx context.Context, c *mautrix.Client, roomID string, events []json.RawMessage) (int, error) {
	missing := make(map[string]bool, len(events))
	for _, raw := range events {
		ev, err := decodeEvent(raw)
		if err != nil {
			return 0, err
		}
		missing[ev.EventID] = true
	}
	count, complete, err := paginateBack(ctx, c, roomID, func(ev *event.Event) bool {
		delete(missing, string(ev.ID))
		return ev.Type == event.StateCreate
	})
	if err != nil {
		return count, err
	}
	if !complete || len(missing) > 0 {
		return count, fmt.Errorf("incomplete backfill: reached create event: %t, %d exported events missing", complete, len(missing))
	}
	return count, nil
}
