package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

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
	var reports []*RoomReport
	var rest []*archive.ArchivedRoom
	for _, room := range rooms {
		var data relay.RoomData
		ok, err := im.Archive.ReadRoomPDUs(room.RoomID, &data)
		if err != nil {
			slog.Warn("could not read the room's events, replaying it", "room", room.RoomID, "err", err)
		}
		if !ok {
			rest = append(rest, room)
			continue
		}
		if err := rl.AddRoom(room.RoomID, room.Version, data); err != nil {
			slog.Warn("room cannot be relayed, replaying it", "room", room.RoomID, "err", err)
			rest = append(rest, room)
			continue
		}
		rep := &RoomReport{RoomID: room.RoomID, NewRoomID: room.RoomID, KeptRoomID: true}
		reports = append(reports, rep)
		slog.Info("moving room through the relay", "room", room.RoomID)
		if err := im.relayRoom(ctx, room, rl, rep); err != nil {
			rep.fail("relay", room.RoomID, err)
			continue
		}
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
	if r.st.Done {
		return nil
	}
	owner, members := r.relayMembers()
	if owner == "" {
		return errors.New("no migrated member is in the room")
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

	backfilled, _, err := paginateBack(ctx, c, room.RoomID, func(ev *event.Event) bool { return ev.Type == event.StateCreate })
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}
	rep.Replayed = backfilled

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

	// Removing the relay's member leaves the room only on Continuwuity.
	if _, err := r.putState(ctx, joiner, "m.room.member", rl.UserID(), map[string]string{"membership": "leave"}, 0); err != nil {
		rep.fail("membership", rl.UserID(), err)
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
	r.st.Done = true
	return r.save()
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

// relayMembers returns the most powerful joined migrated member, and all of them.
func (r *replay) relayMembers() (string, []string) {
	pl, _ := decodeContent(r.final[relay.StateKey("m.room.power_levels", "")].Content)
	users, _ := pl["users"].(map[string]any)
	var owner string
	var ownerLevel int64 = -1
	var members []string
	for _, ev := range r.final {
		if ev.Type != "m.room.member" || membership(ev) != "join" || !r.im.Migrated[*ev.StateKey] {
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
		if slices.ContainsFunc(page.Chunk, found) {
			return total, true, nil
		}
		if page.End == "" || len(page.Chunk) == 0 {
			break
		}
		from = page.End
	}
	return total, false, nil
}
