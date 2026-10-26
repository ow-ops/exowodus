package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"

	"exodus/internal/archive"
	"exodus/internal/relay"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

const maxBackfillPages = 100000

// Continuwuity asks one backfill server per request, picked from an unordered
// set; in federated rooms it may pick a server without the history.
const maxEmptyBackfillPages = 20

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
		if ctx.Err() != nil {
			break
		}
		if im.Archive.IsRoomSkipped(room.RoomID) {
			continue
		}
		if room.ArchiveOnly {
			rep := &RoomReport{RoomID: room.RoomID, ArchiveOnly: true}
			if im.RequireLossless && !im.ArchiveDepartedRooms {
				rep.fail("lossless", room.RoomID, errors.New("archive-only retention does not restore the room"))
			}
			reports = append(reports, rep)
			continue
		}
		err := rl.AddRoomFile(room.RoomID, room.Version, im.Archive.RoomPDUsPath(room.RoomID))
		if errors.Is(err, fs.ErrNotExist) {
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
		if err != nil {
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
		delete(im.roomFailures, room.RoomID)
		im.rooms[room.RoomID] = room.RoomID
	}
	return reports, rest
}

func (im *Importer) relayRoom(ctx context.Context, room *archive.ArchivedRoom, rl *relay.Relay, rep *RoomReport) error {
	defer rl.RemoveRoom(room.RoomID)
	r, err := im.loadReplay(ctx, room, rep, false)
	if err != nil {
		return err
	}
	rep.NewRoomID, rep.KeptRoomID = room.RoomID, true
	owner, members := r.relayMembers()
	if owner == "" {
		return errors.New("no migrated member is in the room")
	}
	handover := false
	for _, member := range members {
		if r.mapUser(member) != member {
			handover = true
			break
		}
	}
	if !r.st.Done {
		if err := rl.CheckEnter(room.RoomID, owner); err != nil {
			return fmt.Errorf("cannot invite the relay as %s: %w", owner, err)
		}
		if handover {
			if _, err := r.relayHandOverContent(rl, owner, members); err != nil {
				return err
			}
		}
	}
	if err := r.registerGhosts(ctx); err != nil {
		return err
	}
	if r.st.Done {
		if im.RequireLossless {
			return verifyOriginalRoomEvents(ctx, r.relayReaders(owner, members), room.RoomID, room.Version, im.Archive.RoomEventsIter(room.RoomID))
		}
		return nil
	}
	joiner := r.mapUser(owner)
	c := r.as(joiner)
	resumed, err := joinedOnDestination(ctx, c, room.RoomID, joiner)
	if err != nil {
		return err
	}
	if resumed {
		// An earlier attempt already admitted the relay's events. Authoring
		// them again would create events the destination never received.
		slog.Info("resuming room already joined on the destination", "room", room.RoomID, "user", joiner)
	} else {
		if err := rl.Enter(room.RoomID, owner); err != nil {
			return err
		}
		if handover {
			if err := r.relayHandOver(rl, owner, members); err != nil {
				return err
			}
		} else {
			slog.Info("using trusted relay for backfill", "room", room.RoomID, "server", rl.Name)
		}
		if _, err := c.JoinRoom(ctx, room.RoomID, &mautrix.ReqJoinRoom{Via: []string{rl.Name}}); err != nil {
			return fmt.Errorf("join through the relay: %w", err)
		}
	}
	if err := ensureRelayJoined(ctx, c, room.RoomID, rl); err != nil {
		return err
	}
	r.st.NewRoomID = room.RoomID
	if err := r.save(); err != nil {
		return err
	}

	readers := r.relayReaders(owner, members)
	backfilled, err := backfillRoomEvents(ctx, readers, room.RoomID, im.Archive.RoomEventsIter(room.RoomID))
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}
	rep.Replayed = backfilled
	if im.RequireLossless {
		if err := verifyOriginalRoomEvents(ctx, readers, room.RoomID, room.Version, im.Archive.RoomEventsIter(room.RoomID)); err != nil {
			return err
		}
	}

	before := len(rep.Failures)
	r.owner = joiner
	if err := r.loadJoined(ctx); err != nil {
		return err
	}
	for _, m := range members {
		if newID := r.mapUser(m); !r.joined[newID] {
			if err := r.joinMember(ctx, c, newID); err != nil {
				rep.fail("membership", newID, err)
			}
		}
	}

	if err := failuresError(rep.Failures[before:]); err != nil {
		return err
	}

	if handover {
		if err := removeRelayPower(ctx, r, c, joiner, rl.UserID()); err != nil {
			rep.fail("power_levels", room.RoomID, err)
		}
	}
	if alias, err := decodeContent(r.final[relay.StateKey("m.room.canonical_alias", "")].Content); err == nil {
		r.createAliases(ctx, joiner, alias)
	}
	if room.Public {
		publisher := c
		if im.Admin != nil {
			publisher = im.Admin.client
		}
		if err := publishRoom(ctx, publisher, room.RoomID); err != nil {
			rep.fail("directory", room.RoomID, err)
		}
	}
	if err := failuresError(rep.Failures[before:]); err != nil {
		return err
	}
	// Remove the relay only after history and all room restoration succeeded.
	if r.joined[rl.UserID()] {
		if err := rl.Leave(ctx, room.RoomID); err != nil {
			return fmt.Errorf("remove relay member: %w", err)
		}
		var member event.MemberEventContent
		if err := c.StateEvent(ctx, id.RoomID(room.RoomID), event.StateMember, rl.UserID(), &member); err != nil {
			return fmt.Errorf("verify relay departure: %w", err)
		}
		if member.Membership != event.MembershipLeave {
			return errors.New("relay departure did not update destination membership")
		}
	}
	r.st.Done = true
	return r.save()
}

// relayReaders returns the joining member first, then the other migrated members.
func (r *replay) relayReaders(owner string, members []string) []*mautrix.Client {
	readers := []*mautrix.Client{r.as(r.mapUser(owner))}
	for _, m := range members {
		if m != owner {
			readers = append(readers, r.as(r.mapUser(m)))
		}
	}
	return readers
}

// joinMember restores an archived join, inviting the member first when the
// destination's room state has no membership for it.
func (r *replay) joinMember(ctx context.Context, inviter *mautrix.Client, userID string) error {
	roomID := id.RoomID(r.room.RoomID)
	_, err := r.as(userID).JoinRoomByID(ctx, roomID)
	if !errors.Is(err, mautrix.MForbidden) {
		return err
	}
	if _, inviteErr := inviter.InviteUser(ctx, roomID, &mautrix.ReqInviteUser{UserID: id.UserID(userID)}); inviteErr != nil {
		return fmt.Errorf("%w; invitation by %s: %w", err, inviter.UserID, inviteErr)
	}
	_, err = r.as(userID).JoinRoomByID(ctx, roomID)
	return err
}

// joinedOnDestination reports whether an earlier attempt already joined the room.
func joinedOnDestination(ctx context.Context, c *mautrix.Client, roomID, userID string) (bool, error) {
	var member event.MemberEventContent
	err := c.StateEvent(ctx, id.RoomID(roomID), event.StateMember, userID, &member)
	if errors.Is(err, mautrix.MForbidden) || errors.Is(err, mautrix.MNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check destination membership: %w", err)
	}
	return member.Membership == event.MembershipJoin, nil
}

// removeRelayPower edits the destination's current power levels, which may
// include changes made after the relay's archived view.
func removeRelayPower(ctx context.Context, r *replay, c *mautrix.Client, sender, relayUser string) error {
	var raw json.RawMessage
	if err := c.StateEvent(ctx, id.RoomID(r.room.RoomID), event.StatePowerLevels, "", &raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var pl map[string]any
	if err := dec.Decode(&pl); err != nil {
		return err
	}
	users, ok := pl["users"].(map[string]any)
	if _, granted := users[relayUser]; !ok || !granted {
		return nil
	}
	delete(users, relayUser)
	_, err := r.putState(ctx, sender, "m.room.power_levels", "", pl, 0)
	return err
}

func ensureRelayJoined(ctx context.Context, c *mautrix.Client, roomID string, rl *relay.Relay) error {
	var member event.MemberEventContent
	err := c.StateEvent(ctx, id.RoomID(roomID), event.StateMember, rl.UserID(), &member)
	if err == nil && member.Membership == event.MembershipJoin {
		return nil
	}
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		return fmt.Errorf("check relay membership: %w", err)
	}
	slog.Info("rejoining relay to destination room", "room", roomID, "server", rl.Name)
	if err := rl.Join(ctx, roomID); err != nil {
		if !errors.Is(err, mautrix.MForbidden) {
			return fmt.Errorf("join relay to destination: %w", err)
		}
		if _, err := c.InviteUser(ctx, id.RoomID(roomID), &mautrix.ReqInviteUser{UserID: id.UserID(rl.UserID())}); err != nil {
			return fmt.Errorf("invite relay to destination: %w", err)
		}
		if err := rl.Join(ctx, roomID); err != nil {
			return fmt.Errorf("join invited relay to destination: %w", err)
		}
	}
	if err := c.StateEvent(ctx, id.RoomID(roomID), event.StateMember, rl.UserID(), &member); err != nil {
		return fmt.Errorf("verify relay membership: %w", err)
	}
	if member.Membership != event.MembershipJoin {
		return errors.New("relay join did not update destination membership")
	}
	return nil
}

func verifyOriginalRoom(ctx context.Context, c *mautrix.Client, roomID, version string, events []json.RawMessage) error {
	return verifyOriginalRoomEvents(ctx, []*mautrix.Client{c}, roomID, version, roomEventSequence(events))
}

// originalFingerprints holds an event's fields as exported, and as redacted.
type originalFingerprints struct{ full, redacted [sha256.Size]byte }

func verifyOriginalRoomEvents(ctx context.Context, readers []*mautrix.Client, roomID, version string, events iter.Seq2[json.RawMessage, error]) error {
	expected := map[string]originalFingerprints{}
	for raw, err := range events {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			return err
		}
		if _, duplicate := expected[ev.EventID]; ev.EventID == "" || duplicate {
			return errors.New("missing or duplicate exported event ID")
		}
		var want originalFingerprints
		if want.full, err = originalEventFingerprint(raw); err != nil {
			return err
		}
		if want.redacted, err = redactedEventFingerprint(raw, version); err != nil {
			return err
		}
		expected[ev.EventID] = want
	}
	if len(expected) == 0 {
		return errors.New("room has no exported events")
	}
	var mismatch error
	done := func() bool { return mismatch != nil || len(expected) == 0 }
	_, err := readRoom(ctx, readers, roomID, func(ev *event.Event) bool {
		want, ok := expected[string(ev.ID)]
		if !ok {
			return done()
		}
		raw, marshalErr := json.Marshal(ev)
		if marshalErr != nil {
			mismatch = marshalErr
			return true
		}
		got, fieldErr := originalEventFingerprint(raw)
		// A checkpoint export omits later redactions that other servers in
		// the room can still deliver.
		accepted := got == want.full || ev.Unsigned.RedactedBecause != nil && got == want.redacted
		if fieldErr == nil && !accepted {
			accepted, fieldErr = restoresOriginalContent(events, string(ev.ID), ev.Content.VeryRaw, got)
		}
		if fieldErr != nil || !accepted {
			mismatch = fmt.Errorf("original event %s differs on the destination", ev.ID)
			return true
		}
		delete(expected, string(ev.ID))
		return done()
	}, done)
	if err != nil {
		return err
	}
	if mismatch != nil {
		return mismatch
	}
	if len(expected) != 0 {
		missing := map[string]bool{}
		for eventID := range expected {
			missing[eventID] = true
		}
		return missingEventsError("original events absent on destination", missing)
	}
	return nil
}

// restoresOriginalContent reports whether the destination holds the original
// content of an archived event that the source had emptied: its other fields
// match and the content reproduces the archived content hash.
func restoresOriginalContent(events iter.Seq2[json.RawMessage, error], eventID string, content json.RawMessage, got [sha256.Size]byte) (bool, error) {
	for raw, err := range events {
		if err != nil {
			return false, err
		}
		var archived map[string]json.RawMessage
		if err := json.Unmarshal(raw, &archived); err != nil {
			return false, err
		}
		var archivedID string
		if err := json.Unmarshal(archived["event_id"], &archivedID); err != nil || archivedID != eventID {
			continue
		}
		archived["content"] = content
		candidate, err := json.Marshal(archived)
		if err != nil {
			return false, err
		}
		if fingerprint, err := originalEventFingerprint(candidate); err != nil || fingerprint != got {
			return false, err
		}
		delete(archived, "event_id")
		delete(archived, "unsigned")
		if candidate, err = json.Marshal(archived); err != nil {
			return false, err
		}
		p, err := relay.ParsePDU(candidate)
		if err != nil {
			return false, err
		}
		return p.Hashes != nil && p.VerifyContentHash(), nil
	}
	return false, nil
}

// redactedEventFingerprint applies the room version's redaction rules to content.
func redactedEventFingerprint(raw json.RawMessage, version string) ([sha256.Size]byte, error) {
	var event map[string]json.RawMessage
	if err := json.Unmarshal(raw, &event); err != nil {
		return [sha256.Size]byte{}, err
	}
	var typ string
	if err := json.Unmarshal(event["type"], &typ); err != nil {
		return [sha256.Size]byte{}, err
	}
	if content, ok := event["content"]; ok {
		event["content"] = json.RawMessage(pdu.RedactContent(typ, jsontext.Value(content), id.RoomVersion(version)))
	}
	redacted, err := json.Marshal(event)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return originalEventFingerprint(redacted)
}

func originalEventFingerprint(raw json.RawMessage) ([sha256.Size]byte, error) {
	fields, err := originalEventFields(raw)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(normalized), nil
}

// relayHandOver raises the relay's member above the default level so
// Continuwuity backfills from it. On a new server name, the new accounts get
// the old ones' levels.
func (r *replay) relayHandOver(rl *relay.Relay, owner string, members []string) error {
	content, err := r.relayHandOverContent(rl, owner, members)
	if err != nil {
		return err
	}
	roomID := r.room.RoomID
	for _, m := range members {
		if r.mapUser(m) == m {
			continue
		}
		if err := rl.Author(roomID, owner, "m.room.member", r.mapUser(m), map[string]any{"membership": "invite"}); err != nil {
			return err
		}
	}
	return rl.Author(roomID, owner, "m.room.power_levels", "", content)
}

func (r *replay) relayHandOverContent(rl *relay.Relay, owner string, members []string) (map[string]any, error) {
	roomID := r.room.RoomID
	for _, member := range members {
		if r.mapUser(member) == member {
			continue
		}
		if err := rl.CheckAuthor(roomID, owner, "m.room.member", r.mapUser(member), map[string]string{"membership": "invite"}); err != nil {
			return nil, fmt.Errorf("cannot invite migrated member %s: %w", member, err)
		}
	}
	pl := rl.Content(roomID, "m.room.power_levels", "")
	content := maps.Clone(pl)
	if content == nil {
		content = map[string]any{}
	}
	users := map[string]any{}
	if orig, ok := pl["users"].(map[string]any); ok {
		maps.Copy(users, orig)
	}
	if pl == nil && !id.RoomVersion(r.room.Version).PrivilegedRoomCreators() {
		users[r.final[relay.StateKey("m.room.create", "")].Sender] = 100
	}
	for _, m := range members {
		if level, ok := users[m]; ok {
			users[r.mapUser(m)] = level
		}
	}
	defaultLevel := powerValue(pl["users_default"])
	if defaultLevel >= 1<<53-1 {
		return nil, errors.New("cannot raise the relay above the room's default power level")
	}
	users[rl.UserID()] = defaultLevel + 1
	content["users"] = users
	if err := rl.CheckAuthor(roomID, owner, "m.room.power_levels", "", content); err != nil {
		return nil, fmt.Errorf("no migrated member can authorize relay backfill: %w", err)
	}
	return content, nil
}

// relayMembers returns the most powerful joined local member, and all of them.
func (r *replay) relayMembers() (string, []string) {
	powerEvent, hasPowerLevels := r.final[relay.StateKey("m.room.power_levels", "")]
	pl, _ := decodeContent(powerEvent.Content)
	users, _ := pl["users"].(map[string]any)
	creators := map[string]bool{}
	create := r.final[relay.StateKey("m.room.create", "")]
	if r.room != nil && id.RoomVersion(r.room.Version).PrivilegedRoomCreators() {
		creators[create.Sender] = true
		content, _ := decodeContent(create.Content)
		additional, _ := content["additional_creators"].([]any)
		for _, user := range additional {
			if userID, ok := user.(string); ok {
				creators[userID] = true
			}
		}
	}
	var owner string
	var ownerLevel int64 = math.MinInt64
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
		if creators[userID] {
			level = math.MaxInt64
		} else if !hasPowerLevels && userID == create.Sender {
			level = 100
		}
		if owner == "" || level > ownerLevel || level == ownerLevel && userID < owner {
			owner, ownerLevel = userID, level
		}
	}
	return owner, members
}

// paginateBack makes Continuwuity backfill until found or the room's start.
// It returns the number of events seen.
func paginateBack(ctx context.Context, c *mautrix.Client, roomID string, found func(*event.Event) bool, retryEmpty bool) (int, bool, error) {
	var total, empty int
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
		if len(page.Chunk) == 0 {
			if empty++; !retryEmpty || empty > maxEmptyBackfillPages {
				break
			}
			slog.Info("backfill returned no older events; asking again", "room", roomID, "attempt", empty)
			continue
		}
		empty = 0
		if page.End == "" || page.End == from {
			break
		}
		from = page.End
	}
	return total, false, nil
}

// backfillRoom requires both the create event and every exported timeline event.
func backfillRoom(ctx context.Context, c *mautrix.Client, roomID string, events []json.RawMessage) (int, error) {
	return backfillRoomEvents(ctx, []*mautrix.Client{c}, roomID, roomEventSequence(events))
}

// readRoom pages back as each reader until done. The first reader triggers
// backfill; the others see events that history visibility hides from it.
// It returns the number of events the first reader saw.
func readRoom(ctx context.Context, readers []*mautrix.Client, roomID string, found func(*event.Event) bool, done func() bool) (int, error) {
	var seen int
	for i, c := range readers {
		count, _, err := paginateBack(ctx, c, roomID, found, i == 0)
		if i == 0 {
			seen = count
		}
		if errors.Is(err, mautrix.MForbidden) && i > 0 {
			continue
		}
		if err != nil {
			return seen, err
		}
		if done() {
			break
		}
	}
	return seen, nil
}

func missingEventsError(prefix string, missing map[string]bool) error {
	ids := slices.Sorted(maps.Keys(missing))
	if len(ids) > 5 {
		ids = ids[:5]
	}
	return fmt.Errorf("%s, %d exported events missing (first: %s)", prefix, len(missing), strings.Join(ids, ", "))
}

func backfillRoomEvents(ctx context.Context, readers []*mautrix.Client, roomID string, events iter.Seq2[json.RawMessage, error]) (int, error) {
	missing := map[string]bool{}
	for raw, err := range events {
		if err != nil {
			return 0, err
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			return 0, err
		}
		if ev.EventID == "" || missing[ev.EventID] {
			return 0, errors.New("missing or duplicate exported event ID")
		}
		missing[ev.EventID] = true
	}
	if len(missing) == 0 {
		return 0, errors.New("room has no exported events")
	}
	reachedCreate := false
	done := func() bool { return reachedCreate && len(missing) == 0 }
	count, err := readRoom(ctx, readers, roomID, func(ev *event.Event) bool {
		delete(missing, string(ev.ID))
		reachedCreate = reachedCreate || ev.Type == event.StateCreate
		return done()
	}, done)
	if err != nil {
		return count, err
	}
	if !reachedCreate || len(missing) > 0 {
		return count, missingEventsError(fmt.Sprintf("incomplete backfill: reached create event: %t", reachedCreate), missing)
	}
	return count, nil
}

func roomEventSequence(events []json.RawMessage) iter.Seq2[json.RawMessage, error] {
	return func(yield func(json.RawMessage, error) bool) {
		for _, raw := range events {
			if !yield(raw, nil) {
				return
			}
		}
	}
}
