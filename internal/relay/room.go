package relay

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

// RoomData contains source events and resolved state.
type RoomData struct {
	// Accepted event IDs, excluding auth-only outliers.
	Timeline []string `json:"timeline,omitempty"`
	// Backfilled events for which the source has no state snapshot.
	StateUnavailable []string `json:"state_unavailable,omitempty"`
	// Discovery links across omitted PDUs; these are never served as events.
	OmittedParents map[string][]string `json:"omitted_parents,omitempty"`
	// Timeline events and auth dependencies.
	Events []EventJSON `json:"events"`
	// EventGroups and Groups hold Synapse's resolved state after each event.
	EventGroups map[string]int64 `json:"event_groups"`
	// Tuwunel stores state before each event.
	BeforeEventGroups map[string]int64 `json:"before_event_groups,omitempty"`
	Groups            map[int64]Group  `json:"groups"`
	Extremities       []string         `json:"extremities"`
	// CurrentState maps StateKey(type, state key) to event IDs.
	CurrentState map[string]string `json:"current_state"`
}

// Group stores changes from its previous state group.
type Group struct {
	Prev    int64             `json:"prev,omitempty"`
	State   map[string]string `json:"state"`
	Removed []StateRemoval    `json:"removed,omitempty"`
}

// StateRemoval deletes a key only if it still points to EventID.
type StateRemoval struct {
	Key     string `json:"key"`
	EventID string `json:"event_id"`
}

type EventJSON struct {
	EventID string          `json:"event_id"`
	PDU     json.RawMessage `json:"pdu"`
}

func StateKey(typ, key string) string { return typ + "\x00" + key }

// SupportsVersion reports whether event IDs are reference hashes (version 3+).
func SupportsVersion(version string) bool {
	n, err := strconv.Atoi(version)
	return err == nil && n >= 3
}

func ParsePDU(raw []byte) (*pdu.PDU, error) {
	var p pdu.PDU
	if err := jsonv2.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

type event struct {
	meta eventMetadata
	raw  json.RawMessage
	// Archived events loaded from a file keep only their position in it.
	offset, size int64
}

// Payloads remain in raw or on disk; only fields needed to traverse the room are cached.
type eventMetadata struct {
	Type       string
	StateKey   *string
	AuthEvents []id.EventID
	PrevEvents []id.EventID
	Depth      int64
}

func cacheEvent(p *pdu.PDU, raw json.RawMessage) event {
	return event{meta: eventMetadata{
		Type: p.Type, StateKey: p.StateKey,
		AuthEvents: p.AuthEvents, PrevEvents: p.PrevEvents, Depth: p.Depth,
	}, raw: raw}
}

type room struct {
	id      id.RoomID
	version id.RoomVersion

	mu               sync.Mutex
	source           *os.File
	events           map[string]event
	groupOf          map[string]int64
	beforeGroupOf    map[string]int64
	stateUnavailable map[string]bool
	groups           map[int64]Group
	extra            map[string]map[string]string // state after events without a group
	current          map[string]string
	extremities      []string
	// archiveHeads are the archived forward extremities; extremities also
	// follow events the relay authors or receives.
	archiveHeads   []string
	omittedParents map[string][]string
	// archiveOrder and archiveIndex are built on the first backfill.
	archiveOrder []string
	archiveIndex map[string]int
}

func newRoom(roomID, version string, data RoomData) (*room, error) {
	events := map[string]event{}
	for _, e := range data.Events {
		wire, p, err := parseArchivedEvent(e, version)
		if err != nil {
			return nil, err
		}
		events[e.EventID] = cacheEvent(p, wire)
	}
	return buildRoom(roomID, version, data, events)
}

// readRoomFile reads a room archived as RoomData JSON. Event bodies stay in
// the file; each event records where its element starts and ends.
func readRoomFile(roomID, version string, f *os.File) (*room, error) {
	dec := jsontext.NewDecoder(bufio.NewReader(f))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, errors.New("room PDUs must be a JSON object")
	}
	fields := map[string]jsontext.Value{}
	events := map[string]event{}
	for dec.PeekKind() != '}' {
		token, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		name := token.String()
		if name != "events" {
			value, err := dec.ReadValue()
			if err != nil {
				return nil, err
			}
			fields[name] = bytes.Clone(value)
			continue
		}
		if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '[' {
			return nil, errors.New("room PDUs events must be an array")
		}
		for dec.PeekKind() != ']' {
			value, err := dec.ReadValue()
			if err != nil {
				return nil, err
			}
			var e EventJSON
			if err := json.Unmarshal(value, &e); err != nil {
				return nil, err
			}
			_, p, err := parseArchivedEvent(e, version)
			if err != nil {
				return nil, err
			}
			ev := cacheEvent(p, nil)
			ev.size = int64(len(value))
			ev.offset = dec.InputOffset() - ev.size
			events[e.EventID] = ev
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	var data RoomData
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, err
	}
	r, err := buildRoom(roomID, version, data, events)
	if err != nil {
		return nil, err
	}
	r.source = f
	return r, nil
}

func parseArchivedEvent(e EventJSON, version string) (json.RawMessage, *pdu.PDU, error) {
	wire, err := federationPDU(e.PDU, version)
	if err != nil {
		return nil, nil, fmt.Errorf("event %s: %w", e.EventID, err)
	}
	p, err := ParsePDU(wire)
	if err != nil {
		return nil, nil, fmt.Errorf("event %s: %w", e.EventID, err)
	}
	return wire, p, nil
}

func buildRoom(roomID, version string, data RoomData, events map[string]event) (*room, error) {
	if !SupportsVersion(version) {
		return nil, fmt.Errorf("room version %q is not supported", version)
	}
	r := &room{id: id.RoomID(roomID), version: id.RoomVersion(version), events: events,
		groupOf: data.EventGroups, groups: data.Groups,
		beforeGroupOf:    data.BeforeEventGroups,
		stateUnavailable: map[string]bool{},
		extra:            map[string]map[string]string{}, current: maps.Clone(data.CurrentState),
		extremities: slices.Clone(data.Extremities), archiveHeads: slices.Clone(data.Extremities),
		omittedParents: data.OmittedParents}
	for _, eventID := range data.StateUnavailable {
		if _, ok := r.events[eventID]; !ok {
			return nil, fmt.Errorf("event %s with unavailable state is missing", eventID)
		}
		if _, ok := r.beforeGroupOf[eventID]; ok {
			return nil, fmt.Errorf("event %s has both known and unavailable state", eventID)
		}
		if _, ok := r.groupOf[eventID]; ok {
			return nil, fmt.Errorf("event %s has both known and unavailable state", eventID)
		}
		if slices.Contains(r.extremities, eventID) {
			return nil, fmt.Errorf("forward extremity %s has unavailable state", eventID)
		}
		r.stateUnavailable[eventID] = true
	}
	if r.current == nil {
		r.current = map[string]string{}
	}
	return r, nil
}

// Remove fields Tuwunel adds after signing before serving PDUs over federation.
func federationPDU(raw json.RawMessage, version string) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	delete(object, "event_id") // relay supports only room versions 3+.
	if n, _ := strconv.Atoi(version); n >= 12 && string(object["type"]) == `"m.room.create"` {
		delete(object, "room_id")
	}
	if unsigned, ok := object["unsigned"]; ok {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(unsigned, &fields); err != nil {
			return nil, err
		}
		delete(fields, "transaction_id")
		encoded, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		object["unsigned"] = encoded
	}
	return json.Marshal(object)
}

// ResolveState applies a group's ancestry without retaining expanded snapshots.
func ResolveState(groups map[int64]Group, gid int64) (map[string]string, error) {
	return ResolveStateContext(context.Background(), groups, gid)
}

// ResolveStateContext resolves a state group while allowing cancellation.
func ResolveStateContext(ctx context.Context, groups map[int64]Group, gid int64) (map[string]string, error) {
	var chain []int64
	seen := map[int64]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[gid] {
			return nil, fmt.Errorf("cycle in state group %d", gid)
		}
		seen[gid] = true
		group, ok := groups[gid]
		if !ok {
			return nil, fmt.Errorf("missing state group %d", gid)
		}
		chain = append(chain, gid)
		if group.Prev == 0 {
			break
		}
		gid = group.Prev
	}
	state := map[string]string{}
	for _, id := range slices.Backward(chain) {
		group := groups[id]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries := 0
		for key, value := range group.State {
			if entries%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			state[key] = value
			entries++
		}
		for i, removed := range group.Removed {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if state[removed.Key] == removed.EventID {
				delete(state, removed.Key)
			}
		}
	}
	return state, nil
}

func (r *room) stateAfter(eventID string) (map[string]string, error) {
	if r.stateUnavailable[eventID] {
		return nil, fmt.Errorf("historical state unavailable for backfilled event %s", eventID)
	}
	if state, ok := r.extra[eventID]; ok {
		return state, nil
	}
	if gid, ok := r.beforeGroupOf[eventID]; ok {
		state, err := ResolveState(r.groups, gid)
		if err != nil {
			return nil, err
		}
		if ev, ok := r.events[eventID]; ok && ev.meta.StateKey != nil {
			state[StateKey(ev.meta.Type, *ev.meta.StateKey)] = eventID
		}
		return state, nil
	}
	if gid, ok := r.groupOf[eventID]; ok {
		return ResolveState(r.groups, gid)
	}
	if r.beforeGroupOf != nil {
		return nil, fmt.Errorf("historical state unavailable for event %s", eventID)
	}
	return map[string]string{}, nil
}

func (r *room) stateBefore(eventID string) (map[string]string, error) {
	if r.stateUnavailable[eventID] {
		return nil, fmt.Errorf("historical state unavailable for backfilled event %s", eventID)
	}
	if gid, ok := r.beforeGroupOf[eventID]; ok {
		return ResolveState(r.groups, gid)
	}
	ev, ok := r.events[eventID]
	after, err := r.stateAfter(eventID)
	if err != nil {
		return nil, err
	}
	if !ok || ev.meta.StateKey == nil {
		return after, nil
	}
	before := maps.Clone(after)
	k := StateKey(ev.meta.Type, *ev.meta.StateKey)
	delete(before, k)
	if len(ev.meta.PrevEvents) > 0 {
		previous, err := r.stateAfter(string(ev.meta.PrevEvents[0]))
		if err != nil {
			return nil, err
		}
		if id, ok := previous[k]; ok {
			before[k] = id
		}
	}
	return before, nil
}

// add appends a new event on top of the room's forward extremities.
func (r *room) add(eventID string, p *pdu.PDU, raw json.RawMessage) {
	if _, ok := r.events[eventID]; ok {
		return
	}
	r.events[eventID] = cacheEvent(p, raw)
	if p.StateKey != nil {
		r.current = maps.Clone(r.current)
		r.current[StateKey(p.Type, *p.StateKey)] = eventID
	}
	r.extra[eventID] = r.current
	r.extremities = []string{eventID}
}

func (r *room) maxDepth() int64 {
	var d int64
	for _, ev := range r.events {
		d = max(d, ev.meta.Depth)
	}
	return d
}

func (r *room) versionNumber() int {
	n, _ := strconv.Atoi(string(r.version))
	return n
}

func (r *room) authEvents(sender, typ, stateKey string, join bool) []id.EventID {
	keys := []string{StateKey("m.room.power_levels", ""), StateKey("m.room.member", sender)}
	if r.versionNumber() < 12 {
		// From version 12 the create event is implied by the room ID.
		keys = append(keys, StateKey("m.room.create", ""))
	}
	if typ == "m.room.member" {
		if join {
			keys = append(keys, StateKey("m.room.join_rules", ""))
		}
		if stateKey != sender {
			keys = append(keys, StateKey("m.room.member", stateKey))
		}
	}
	var ids []id.EventID
	for _, k := range keys {
		if e, ok := r.current[k]; ok && !slices.Contains(ids, id.EventID(e)) {
			ids = append(ids, id.EventID(e))
		}
	}
	return ids
}

// template builds an unsigned state event on top of the room.
func (r *room) template(sender, typ, stateKey string, content any, origin string) (*pdu.PDU, error) {
	raw, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	var membership struct {
		Membership string `json:"membership"`
	}
	_ = json.Unmarshal(raw, &membership)
	p := &pdu.PDU{
		Type:           typ,
		StateKey:       &stateKey,
		Sender:         id.UserID(sender),
		RoomID:         r.id,
		Content:        raw,
		OriginServerTS: time.Now().UnixMilli(),
		Depth:          r.maxDepth() + 1,
		PrevEvents:     toEventIDs(r.extremities),
		AuthEvents:     r.authEvents(sender, typ, stateKey, membership.Membership == "join"),
	}
	if r.versionNumber() < 11 {
		// Before version 11, events carry the deprecated origin field.
		p.DeprecatedOrigin, _ = json.Marshal(origin)
	}
	return p, nil
}

// sign also adds the event to the room.
func (r *room) sign(p *pdu.PDU, server string, key *federation.SigningKey) error {
	if err := p.FillContentHash(); err != nil {
		return err
	}
	if err := p.Sign(r.version, server, key.ID, key.Priv); err != nil {
		return err
	}
	eventID, err := p.GetEventID(r.version)
	if err != nil {
		return err
	}
	raw, err := jsonv2.Marshal(p)
	if err != nil {
		return err
	}
	r.add(string(eventID), p, raw)
	return nil
}

func (r *room) authChain(ids []string) []string {
	seen := map[string]bool{}
	var chain []string
	queue := slices.Clone(ids)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		ev, ok := r.events[cur]
		if !ok {
			continue
		}
		for _, a := range ev.meta.AuthEvents {
			if !seen[string(a)] {
				seen[string(a)] = true
				chain = append(chain, string(a))
				queue = append(queue, string(a))
			}
		}
	}
	return chain
}

// archived lists the events reachable from the archive heads, newest first.
// Backfill resumes from a position in this order: walking back from the last
// event served would skip branches that a page ended in the middle of.
func (r *room) archived() ([]string, map[string]int) {
	if r.archiveIndex != nil {
		return r.archiveOrder, r.archiveIndex
	}
	seen := map[string]bool{}
	queue := slices.Clone(r.archiveHeads)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		ev, ok := r.events[cur]
		if !ok {
			queue = append(queue, r.omittedParents[cur]...)
			continue
		}
		r.archiveOrder = append(r.archiveOrder, cur)
		for _, p := range ev.meta.PrevEvents {
			queue = append(queue, string(p))
		}
	}
	// Parents always have a lower depth than their children.
	slices.SortFunc(r.archiveOrder, func(a, b string) int {
		if d := cmp.Compare(r.events[b].meta.Depth, r.events[a].meta.Depth); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	r.archiveIndex = make(map[string]int, len(r.archiveOrder))
	for i, eventID := range r.archiveOrder {
		r.archiveIndex[eventID] = i
	}
	return r.archiveOrder, r.archiveIndex
}

// backfill serves events preceding and including from. Destination events
// lead back to the archive heads, after which the archive order continues.
func (r *room) backfill(from []string, limit int) []string {
	order, index := r.archived()
	start := -1
	for _, eventID := range from {
		if i, ok := index[eventID]; ok && (start < 0 || i < start) {
			start = i
		}
	}
	if start >= 0 {
		return order[start:min(len(order), start+limit)]
	}
	ids := r.before(from, limit, func(eventID string) bool {
		_, archived := index[eventID]
		return archived
	})
	return append(ids, order[:min(len(order), limit-len(ids))]...)
}

// before walks prev events backwards from the given events, including them.
func (r *room) before(from []string, limit int, stop func(string) bool) []string {
	seen := map[string]bool{}
	var out []string
	queue := slices.Clone(from)
	for len(queue) > 0 && len(out) < limit {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] || stop != nil && stop(cur) {
			continue
		}
		seen[cur] = true
		ev, ok := r.events[cur]
		if !ok {
			queue = append(queue, r.omittedParents[cur]...)
			continue
		}
		out = append(out, cur)
		for _, p := range ev.meta.PrevEvents {
			queue = append(queue, string(p))
		}
	}
	return out
}

// eventJSON returns an event's federation JSON, reading archived events from disk.
func (r *room) eventJSON(ev event) (json.RawMessage, error) {
	if ev.raw != nil || r.source == nil {
		return ev.raw, nil
	}
	buf := make([]byte, ev.size)
	if _, err := r.source.ReadAt(buf, ev.offset); err != nil {
		return nil, err
	}
	var e EventJSON
	if err := json.Unmarshal(buf, &e); err != nil {
		return nil, err
	}
	wire, _, err := parseArchivedEvent(e, string(r.version))
	return wire, err
}

func (r *room) pdus(ids []string) ([]federation.PDU, error) {
	out := make([]federation.PDU, 0, len(ids))
	for _, eid := range ids {
		if ev, ok := r.events[eid]; ok {
			raw, err := r.eventJSON(ev)
			if err != nil {
				return nil, err
			}
			out = append(out, federation.PDU(raw))
		}
	}
	return out, nil
}

func stateIDs(state map[string]string) []string {
	return slices.Sorted(maps.Values(state))
}
