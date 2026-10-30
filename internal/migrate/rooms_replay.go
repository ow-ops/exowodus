package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/progress"
	"exowodus/internal/relay"
)

type RoomReport struct {
	ArchiveOnly bool      `json:"archive_only,omitempty"`
	RoomID      string    `json:"room_id"`
	NewRoomID   string    `json:"new_room_id"`
	KeptRoomID  bool      `json:"kept_room_id"`
	Replayed    int       `json:"replayed"`
	Skipped     int       `json:"skipped"`
	Encrypted   int       `json:"encrypted_skipped"`
	Failures    []Failure `json:"failures,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
}

func (r *RoomReport) fail(step, target string, err error) {
	slog.Warn("step failed", "room", r.RoomID, "step", step, "target", target, "err", err)
	r.Failures = append(r.Failures, Failure{Step: step, Target: target, Error: err.Error()})
}

// replay resends a room's history as the original senders and timestamps.
type replay struct {
	im     *Importer
	room   *archive.ArchivedRoom
	st     *archive.RoomImportState
	rep    *RoomReport
	events []json.RawMessage
	final  map[string]roomEvent
	ghosts map[string]bool
	// puppets send through their bridge's token.
	puppets   map[string]bool
	owner     string
	botNeeded bool
	// skip holds timeline indexes createRoom already recreates.
	skip   map[int]bool
	joined map[string]bool
}

func (im *Importer) newReplay(ctx context.Context, room *archive.ArchivedRoom, rep *RoomReport) (*replay, error) {
	r, err := im.loadReplay(ctx, room, rep, true)
	if err != nil {
		return nil, err
	}
	if r.st.NewRoomID != "" {
		if err := r.loadJoined(ctx); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (im *Importer) loadReplay(ctx context.Context, room *archive.ArchivedRoom, rep *RoomReport, keepEvents bool) (*replay, error) {
	im.recordOmittedEvents(room)
	if im.Appservice == nil {
		return nil, errors.New("recreating local-only rooms requires --to-admin-token")
	}
	st, err := im.Archive.ReadRoomState(room.RoomID)
	if err != nil {
		return nil, err
	}
	var events []json.RawMessage
	eventStream := im.Archive.RoomEventsIter(room.RoomID)
	if keepEvents {
		events, err = im.Archive.RoomEvents(room.RoomID)
		if err != nil {
			return nil, err
		}
		eventStream = roomEventSequence(events)
	}
	r := &replay{
		im: im, room: room, st: st, rep: rep, events: events,
		final: map[string]roomEvent{}, ghosts: map[string]bool{}, puppets: map[string]bool{}, skip: map[int]bool{},
		joined: map[string]bool{},
	}
	for _, g := range room.Ghosts {
		r.ghosts[g] = true
	}
	state := im.Archive.RoomStateIter(ctx, room.RoomID)
	if room.State != nil {
		state = roomEventSequence(room.State)
	}
	for raw, err := range state {
		if err != nil {
			return nil, err
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			return nil, err
		}
		if ev.StateKey != nil {
			r.final[relay.StateKey(ev.Type, *ev.StateKey)] = ev
		}
	}
	sameServer := im.Archive.Manifest.ServerName == mx.ServerName(im.Appservice.Bot)
	for raw, err := range eventStream {
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			return nil, err
		}
		for _, userID := range []string{ev.Sender, memberTarget(ev)} {
			if sameServer && userID != "" && mx.ServerName(userID) == im.Archive.Manifest.ServerName && im.bridgeFor(userID) != nil {
				r.puppets[userID] = true
			}
		}
	}
	creator := r.final[relay.StateKey("m.room.create", "")].Sender
	r.owner = r.actor(creator)
	r.botNeeded = r.owner == im.Appservice.Bot

	var sawCreate, sawJoin, sawPL bool
	for i, raw := range events {
		ev, err := decodeEvent(raw)
		if err != nil {
			return nil, err
		}
		switch {
		case !sawCreate && ev.Type == "m.room.create":
			sawCreate, r.skip[i] = true, true
		case !sawJoin && memberTarget(ev) == creator && membership(ev) == "join":
			sawJoin, r.skip[i] = true, true
		case !sawPL && ev.Type == "m.room.power_levels":
			sawPL, r.skip[i] = true, true
		case ev.StateKey == nil && ev.Type == "m.room.message" && !r.local(ev.Sender):
			r.botNeeded = true
		}
	}

	rep.NewRoomID, rep.KeptRoomID = st.NewRoomID, r.keptRoomID()
	return r, nil
}

func membership(ev roomEvent) string {
	var c struct {
		Membership string `json:"membership"`
	}
	_ = json.Unmarshal(ev.Content, &c)
	return c.Membership
}

func (r *replay) save() error { return r.im.Archive.WriteRoomState(r.room.RoomID, r.st) }

func (r *replay) local(userID string) bool {
	return mx.ServerName(userID) == r.im.Archive.Manifest.ServerName && (r.im.Migrated[userID] || r.ghosts[userID] || r.puppets[userID])
}

func (r *replay) mapUser(userID string) string {
	if r.local(userID) {
		return mx.WithServer(userID, mx.ServerName(r.im.Appservice.Bot))
	}
	return userID
}

func (r *replay) actor(userID string) string {
	if r.local(userID) {
		return r.mapUser(userID)
	}
	return r.im.Appservice.Bot
}

func (r *replay) as(userID string) *mautrix.Client {
	if r.puppets[userID] {
		return mx.As(r.im.bridgeFor(userID).client, userID)
	}
	return r.im.Appservice.As(userID)
}

func (r *replay) keptRoomID() bool { return r.st.NewRoomID == r.room.RoomID }

func (r *replay) creatorsArePrivileged() bool {
	v, err := strconv.Atoi(r.room.Version)
	return err == nil && v >= 12
}

func (r *replay) creators() []string {
	create, _ := decodeContent(r.final[relay.StateKey("m.room.create", "")].Content)
	creators := []string{r.owner}
	for _, c := range asSlice(create["additional_creators"]) {
		creators = append(creators, r.mapUser(c))
	}
	return creators
}

// mapPowerLevels keeps the bot at full power during the replay, to post
// remote users' messages.
func (r *replay) mapPowerLevels(content map[string]any, final bool) map[string]any {
	users := map[string]any{}
	if orig, ok := content["users"].(map[string]any); ok {
		for userID, level := range orig {
			users[r.mapUser(userID)] = level
		}
	}
	if !final && r.botNeeded {
		users[r.im.Appservice.Bot] = 100
	}
	if r.creatorsArePrivileged() {
		for _, c := range r.creators() {
			delete(users, c)
		}
	}
	content["users"] = users
	return content
}

func (r *replay) mapState(typ, key string, content map[string]any, final bool) (string, map[string]any) {
	rewriteMXC(content, r.im.media)
	switch typ {
	case "m.room.power_levels":
		content = r.mapPowerLevels(content, final)
	case "m.room.member":
		key = r.mapUser(key)
		delete(content, "join_authorised_via_users_server")
	case "m.space.child", "m.space.parent":
		key = r.im.mapRoom(key)
	case "m.room.join_rules":
		if allow, ok := content["allow"].([]any); ok {
			for _, a := range allow {
				if m, ok := a.(map[string]any); ok && m["room_id"] != nil {
					m["room_id"] = r.im.mapRoom(fmt.Sprint(m["room_id"]))
				}
			}
		}
	case "m.room.pinned_events":
		var pinned []string
		for _, eventID := range asSlice(content["pinned"]) {
			if n, ok := r.st.Events[eventID]; ok {
				pinned = append(pinned, n)
			}
		}
		content["pinned"] = pinned
	}
	return key, content
}

func (r *replay) loadJoined(ctx context.Context) error {
	resp, err := r.as(r.owner).JoinedMembers(ctx, id.RoomID(r.st.NewRoomID))
	if err != nil {
		return err
	}
	for userID := range resp.Joined {
		r.joined[string(userID)] = true
	}
	return nil
}

func (r *replay) putState(ctx context.Context, sender, typ, key string, content any, ts int64) (string, error) {
	evType := event.Type{Type: typ, Class: event.StateEventType}
	resp, err := r.as(sender).SendStateEvent(ctx, id.RoomID(r.st.NewRoomID), evType, key, content, mautrix.ReqSendEvent{Timestamp: ts})
	if err != nil {
		return "", err
	}
	return string(resp.EventID), nil
}

// ensureJoined joins senders whose original join could not be replayed.
func (r *replay) ensureJoined(ctx context.Context, userID string) error {
	if r.joined[userID] {
		return nil
	}
	if userID != r.owner {
		if _, err := r.putState(ctx, r.owner, "m.room.member", userID, map[string]string{"membership": "invite"}, 0); err != nil {
			return fmt.Errorf("invite %s: %w", userID, err)
		}
	}
	if _, err := r.putState(ctx, userID, "m.room.member", userID, map[string]string{"membership": "join"}, 0); err != nil {
		return fmt.Errorf("join %s: %w", userID, err)
	}
	r.joined[userID] = true
	return nil
}

// registerGhosts recreates deactivated users and puppets from the history.
func (r *replay) registerGhosts(ctx context.Context) error {
	for _, g := range r.room.Ghosts {
		if r.puppets[g] {
			continue
		}
		if err := r.im.Appservice.Register(ctx, g); err != nil {
			return err
		}
	}
	for _, p := range slices.Sorted(maps.Keys(r.puppets)) {
		if err := registerAppserviceUser(ctx, r.im.bridgeFor(p).client, p); err != nil {
			return err
		}
	}
	return nil
}

func (r *replay) Create(ctx context.Context) error {
	if err := r.registerGhosts(ctx); err != nil {
		return err
	}
	for _, m := range r.room.Media {
		if _, ok := r.st.Media[m.MXC]; ok {
			continue
		}
		mxc, err := mx.Upload(ctx, r.as(r.im.Appservice.Bot), filepath.Join(r.im.Archive.RoomDir(r.room.RoomID), m.File), m.ContentType, m.Filename)
		if err != nil {
			return fmt.Errorf("upload media %s: %w", m.MXC, err)
		}
		r.st.Media[m.MXC] = mxc
	}
	r.im.addMedia(r.st.Media)

	if r.st.NewRoomID == "" {
		if err := r.createRoom(ctx); err != nil {
			return err
		}
		if err := r.save(); err != nil {
			return err
		}
	}
	r.rep.NewRoomID, r.rep.KeptRoomID = r.st.NewRoomID, r.keptRoomID()
	r.im.rooms[r.room.RoomID] = r.st.NewRoomID

	for i := r.st.Replayed; i < len(r.events); i++ {
		if !r.skip[i] {
			if err := r.replayEvent(ctx, r.events[i]); err != nil {
				return errors.Join(err, r.save())
			}
		}
		r.st.Replayed = i + 1
		if i%25 == 0 {
			if err := r.save(); err != nil {
				return err
			}
		}
	}
	r.rep.Replayed = len(r.st.Events)
	return r.save()
}

func (r *replay) createRoom(ctx context.Context) error {
	createEv := r.final[relay.StateKey("m.room.create", "")]
	create, err := decodeContent(createEv.Content)
	if err != nil {
		return err
	}
	delete(create, "creator")
	delete(create, "room_version")
	if pred, ok := create["predecessor"].(map[string]any); ok {
		if old := fmt.Sprint(pred["room_id"]); r.im.mapRoom(old) != old {
			create["predecessor"] = map[string]any{"room_id": r.im.mapRoom(old)}
		}
	}
	if _, ok := create["additional_creators"]; ok {
		create["additional_creators"] = r.creators()[1:]
	}
	pl := map[string]any{}
	for i := range r.skip {
		if ev, _ := decodeEvent(r.events[i]); ev.Type == "m.room.power_levels" {
			pl, _ = decodeContent(ev.Content)
		}
	}
	// From room version 12 the ID is the create event's hash, reproduced by
	// the same creator, content and timestamp.
	body := map[string]any{
		"preset":                       "private_chat",
		"room_version":                 r.room.Version,
		"creation_content":             create,
		"power_level_content_override": r.mapPowerLevels(pl, false),
		"room_id":                      r.room.RoomID,
		"origin_server_ts":             createEv.OriginServerTS,
	}

	c := r.as(r.owner)
	var resp struct {
		RoomID string `json:"room_id"`
	}
	// room_id and origin_server_ts are Continuwuity extensions.
	send := func() error {
		_, err := c.MakeRequest(ctx, http.MethodPost, c.BuildClientURL("v3", "createRoom"), body, &resp)
		return err
	}
	err = send()
	if mx.IsCode(err, "M_UNSUPPORTED_ROOM_VERSION") {
		slog.Warn("room version unsupported, using the server default", "room", r.room.RoomID, "version", r.room.Version)
		delete(body, "room_version")
		delete(body, "room_id")
		r.room.Version = ""
		err = send()
	}
	if mx.IsCode(err, "M_ROOM_IN_USE") {
		// Created by an interrupted run before its ID was saved.
		resp.RoomID, err = r.room.RoomID, nil
	}
	if err != nil && body["room_id"] != nil {
		slog.Warn("could not recreate the room under its original ID", "room", r.room.RoomID, "err", err)
		delete(body, "room_id")
		err = send()
	}
	if err != nil {
		return fmt.Errorf("create room: %w", err)
	}
	r.st.NewRoomID = resp.RoomID
	if r.keptRoomID() && r.room.RemoteParticipants {
		r.rep.Warnings = append(r.rep.Warnings, "users of other servers were once in this room; if one of those servers joins again, it may reject the recreated room")
	}
	return r.loadJoined(ctx)
}

func (r *replay) record(oldID, newID string) {
	if newID != "" {
		r.st.Events[oldID] = newID
	}
}

func (r *replay) replayEvent(ctx context.Context, raw json.RawMessage) error {
	ev, err := decodeEvent(raw)
	if err != nil {
		return err
	}
	if _, done := r.st.Events[ev.EventID]; done {
		return nil
	}
	before := len(r.rep.Failures)
	if ev.StateKey != nil {
		r.replayState(ctx, ev)
	} else {
		r.replayTimeline(ctx, ev)
	}
	if err := failuresError(r.rep.Failures[before:]); err != nil {
		delete(r.st.Events, ev.EventID)
		return err
	}
	return nil
}

func (r *replay) replayState(ctx context.Context, ev roomEvent) {
	if ev.Type == "m.room.create" {
		return
	}
	content, err := decodeContent(ev.Content)
	if err != nil {
		r.rep.fail("replay", ev.EventID, err)
		return
	}
	if ev.Type == "m.room.member" {
		r.replayMember(ctx, ev, content)
		return
	}
	if !r.local(ev.Sender) {
		// Remote users cannot be impersonated; Finalize restores the state.
		r.rep.Skipped++
		return
	}
	sender := r.actor(ev.Sender)
	if err := r.ensureJoined(ctx, sender); err != nil {
		r.rep.fail("join", sender, err)
		return
	}
	key, content := r.mapState(ev.Type, *ev.StateKey, content, false)
	if ev.Type == "m.room.canonical_alias" {
		r.createAliases(ctx, sender, content)
	}
	newID, err := r.putState(ctx, sender, ev.Type, key, content, ev.OriginServerTS)
	if err != nil {
		r.rep.fail("replay", ev.EventID, err)
		return
	}
	r.record(ev.EventID, newID)
}

func (r *replay) replayMember(ctx context.Context, ev roomEvent, content map[string]any) {
	target := *ev.StateKey
	m := fmt.Sprint(content["membership"])
	if !r.local(target) {
		// Only remote users' bans are replayed: invites would reach them.
		if m != "ban" {
			r.rep.Skipped++
			return
		}
	}
	sender := r.actor(ev.Sender)
	if !r.local(ev.Sender) {
		sender = r.owner
	}
	key, content := r.mapState("m.room.member", target, content, false)
	newID, err := r.putState(ctx, sender, "m.room.member", key, content, ev.OriginServerTS)
	if err != nil && m == "join" && sender == key && !r.joined[key] {
		// The original invite came from a remote user; invite locally.
		if _, ierr := r.putState(ctx, r.owner, "m.room.member", key, map[string]string{"membership": "invite"}, ev.OriginServerTS); ierr == nil {
			newID, err = r.putState(ctx, sender, "m.room.member", key, content, ev.OriginServerTS)
		}
	}
	if err != nil {
		r.rep.fail("replay", ev.EventID, err)
		return
	}
	r.joined[key] = m == "join"
	r.record(ev.EventID, newID)
}

func (r *replay) createAliases(ctx context.Context, sender string, content map[string]any) {
	aliases := asSlice(content["alt_aliases"])
	if a, ok := content["alias"].(string); ok {
		aliases = append([]string{a}, aliases...)
	}
	for _, alias := range aliases {
		if mx.ServerName(alias) != r.im.Archive.Manifest.ServerName {
			continue
		}
		if dest := mx.ServerName(r.im.Appservice.Bot); dest != r.im.Archive.Manifest.ServerName {
			alias = mx.WithServer(alias, dest)
		}
		_, err := r.as(sender).CreateAlias(ctx, id.RoomAlias(alias), id.RoomID(r.st.NewRoomID))
		if err != nil && !mx.IsStatus(err, http.StatusConflict) {
			r.rep.fail("alias", alias, err)
		}
	}
}

func (r *replay) replayTimeline(ctx context.Context, ev roomEvent) {
	content, err := decodeContent(ev.Content)
	if err != nil {
		r.rep.fail("replay", ev.EventID, err)
		return
	}
	sender := r.actor(ev.Sender)
	switch {
	case ev.Type == "m.room.redaction":
		r.replayRedaction(ctx, ev, content, sender)
		return
	case ev.Type == "m.room.encrypted" && (!r.keptRoomID() || sender == r.im.Appservice.Bot):
		// Megolm payloads are bound to the room ID and sender device.
		r.rep.Encrypted++
		return
	case sender == r.im.Appservice.Bot:
		if ev.Type != "m.room.message" || len(ev.Unsigned.RedactedBecause) > 0 {
			r.rep.Skipped++
			return
		}
		content = map[string]any{"msgtype": "m.notice", "body": ev.Sender + ": " + fmt.Sprint(content["body"])}
	}
	rewriteMXC(content, r.im.media)
	if !remapRelations(content, r.st.Events) {
		r.rep.Skipped++
		return
	}
	if err := r.ensureJoined(ctx, sender); err != nil {
		r.rep.fail("join", sender, err)
		r.rep.Skipped++
		return
	}
	evType := event.Type{Type: ev.Type, Class: event.MessageEventType}
	resp, err := r.as(sender).SendMessageEvent(ctx, id.RoomID(r.st.NewRoomID), evType, content,
		mautrix.ReqSendEvent{Timestamp: ev.OriginServerTS, TransactionID: txnID(ev.EventID)})
	if err != nil {
		r.rep.fail("replay", ev.EventID, err)
		return
	}
	r.record(ev.EventID, string(resp.EventID))
}

func (r *replay) replayRedaction(ctx context.Context, ev roomEvent, content map[string]any, sender string) {
	target := ev.Redacts
	if target == "" {
		target = fmt.Sprint(content["redacts"])
	}
	newTarget, ok := r.st.Events[target]
	if !ok || sender == r.im.Appservice.Bot {
		r.rep.Skipped++
		return
	}
	reason, _ := content["reason"].(string)
	c, room := r.as(sender), id.RoomID(r.st.NewRoomID)
	var resp *mautrix.RespSendEvent
	var err error
	if v, _ := strconv.Atoi(r.room.Version); v >= 11 {
		// From room version 11, redactions keep their timestamp.
		body := map[string]any{"redacts": newTarget}
		if reason != "" {
			body["reason"] = reason
		}
		resp, err = c.SendMessageEvent(ctx, room, event.EventRedaction, body,
			mautrix.ReqSendEvent{Timestamp: ev.OriginServerTS, TransactionID: txnID(ev.EventID)})
	}
	if resp == nil {
		resp, err = c.RedactEvent(ctx, room, id.EventID(newTarget), mautrix.ReqRedact{Reason: reason, TxnID: txnID(ev.EventID)})
	}
	if err != nil {
		r.rep.fail("replay", ev.EventID, err)
		return
	}
	r.record(ev.EventID, string(resp.EventID))
}

func txnID(eventID string) string {
	sum := sha256.Sum256([]byte(eventID))
	// Preserve transaction IDs so retries after an upgrade do not duplicate events.
	return "exodus." + hex.EncodeToString(sum[:12])
}

// Finalize runs after every room is replayed, so references between rooms
// resolve.
func (r *replay) Finalize(ctx context.Context) error {
	if r.st.Done {
		return nil
	}
	before := len(r.rep.Failures)
	var events []roomEvent
	c := r.as(r.owner)
	if _, err := c.MakeRequest(ctx, http.MethodGet, c.BuildClientURL("v3", "rooms", r.st.NewRoomID, "state"), nil, &events); err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	current := map[string]map[string]any{}
	for _, ev := range events {
		if ev.StateKey != nil {
			current[relay.StateKey(ev.Type, *ev.StateKey)], _ = decodeContent(ev.Content)
		}
	}

	var finalPL map[string]any
	for _, k := range slices.Sorted(maps.Keys(r.final)) {
		ev := r.final[k]
		content, err := decodeContent(ev.Content)
		if err != nil {
			return fmt.Errorf("decode final state %s: %w", ev.Type, err)
		}
		switch ev.Type {
		case "m.room.create":
			continue
		case "m.room.power_levels":
			_, finalPL = r.mapState(ev.Type, "", content, true)
			continue
		case "m.room.member":
			r.finalizeMember(ctx, *ev.StateKey, content, current)
			continue
		}
		key, content := r.mapState(ev.Type, *ev.StateKey, content, true)
		if jsonEqual(current[relay.StateKey(ev.Type, key)], content) {
			continue
		}
		if ev.Type == "m.room.canonical_alias" {
			r.createAliases(ctx, r.owner, content)
		}
		if _, err := r.putState(ctx, r.owner, ev.Type, key, content, 0); err != nil {
			r.rep.fail("state", ev.Type+" "+key, err)
		}
	}

	if r.room.Public {
		if err := publishRoom(ctx, c, r.st.NewRoomID); err != nil {
			r.rep.fail("directory", r.st.NewRoomID, err)
		}
	}
	if err := failuresError(r.rep.Failures[before:]); err != nil {
		return err
	}
	if finalPL != nil && !jsonEqual(current[relay.StateKey("m.room.power_levels", "")], finalPL) {
		if _, err := r.putState(ctx, r.owner, "m.room.power_levels", "", finalPL, 0); err != nil {
			r.rep.fail("state", "m.room.power_levels", err)
		}
	}
	if err := failuresError(r.rep.Failures[before:]); err != nil {
		return err
	}
	bot := r.im.Appservice.Bot
	if r.joined[bot] && r.owner != bot {
		if _, err := r.putState(ctx, bot, "m.room.member", bot, map[string]string{"membership": "leave"}, 0); err != nil {
			r.rep.fail("membership", bot, err)
		}
	}
	if err := failuresError(r.rep.Failures[before:]); err != nil {
		return err
	}
	r.st.Done = true
	return r.save()
}

func (r *replay) finalizeMember(ctx context.Context, target string, content map[string]any, current map[string]map[string]any) {
	want := fmt.Sprint(content["membership"])
	if !r.local(target) && want != "ban" {
		return
	}
	key, content := r.mapState("m.room.member", target, content, true)
	cur := current[relay.StateKey("m.room.member", key)]
	if cur != nil && fmt.Sprint(cur["membership"]) == want {
		return
	}
	var err error
	switch want {
	case "join":
		err = r.ensureJoined(ctx, key)
	case "leave":
		if r.joined[key] {
			_, err = r.putState(ctx, key, "m.room.member", key, map[string]string{"membership": "leave"}, 0)
			if err == nil {
				r.joined[key] = false
			}
		}
	default:
		_, err = r.putState(ctx, r.owner, "m.room.member", key, content, 0)
	}
	if err != nil {
		r.rep.fail("membership", key, err)
	}
}

func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// ReplayRooms also deactivates the recreated accounts of deactivated users.
func (im *Importer) ReplayRooms(ctx context.Context, rooms []*archive.ArchivedRoom) []*RoomReport {
	if im.rooms == nil {
		im.rooms = map[string]string{}
	}
	if im.roomFailures == nil {
		im.roomFailures = map[string]bool{}
	}
	var reports []*RoomReport
	type pendingReplay struct {
		room   *archive.ArchivedRoom
		report *RoomReport
	}
	var pending []pendingReplay
	for i, room := range rooms {
		progress.Count(ctx, "Rooms replayed", i, len(rooms))
		if ctx.Err() != nil {
			break
		}
		if im.Archive.IsRoomSkipped(room.RoomID) {
			continue
		}
		if room.ArchiveOnly {
			reports = append(reports, &RoomReport{RoomID: room.RoomID, ArchiveOnly: true})
			continue
		}
		rep := &RoomReport{RoomID: room.RoomID}
		reports = append(reports, rep)
		r, err := im.newReplay(ctx, room, rep)
		if err == nil {
			slog.Info("replaying room", "room", room.RoomID)
			err = r.Create(ctx)
		}
		if err != nil {
			rep.fail("replay", room.RoomID, err)
			im.roomFailures[room.RoomID] = true
			continue
		}
		pending = append(pending, pendingReplay{room, rep})
	}
	if ctx.Err() == nil {
		progress.Count(ctx, "Rooms replayed", len(rooms), len(rooms))
	}

	if im.ghosts == nil {
		im.ghosts = map[string]bool{}
	}
	if im.eventMaps == nil {
		im.eventMaps = map[string]map[string]string{}
	}
	for i, job := range pending {
		if ctx.Err() != nil {
			break
		}
		progress.Count(ctx, "Finalize rooms", i, len(pending))
		slog.Info("finalizing room", "room", job.room.RoomID)
		r, err := im.loadReplay(ctx, job.room, job.report, false)
		if err == nil {
			err = r.loadJoined(ctx)
		}
		if err != nil {
			job.report.fail("finalize", job.room.RoomID, err)
			im.roomFailures[job.room.RoomID] = true
			continue
		}
		if err := r.Finalize(ctx); err != nil {
			r.rep.fail("finalize", r.room.RoomID, err)
			im.roomFailures[r.room.RoomID] = true
		} else {
			delete(im.roomFailures, r.room.RoomID)
		}
		im.eventMaps[r.room.RoomID] = r.st.Events
		for _, g := range r.room.Ghosts {
			if !im.Migrated[g] && !r.puppets[g] {
				im.ghosts[r.mapUser(g)] = true
			}
		}
	}
	if ctx.Err() == nil {
		progress.Count(ctx, "Finalize rooms", len(pending), len(pending))
	}
	return reports
}
