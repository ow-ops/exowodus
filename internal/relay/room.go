package relay

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

// RoomData is a room as exported from the Synapse database.
type RoomData struct {
	// Events are oldest first.
	Events []EventJSON `json:"events"`
	// EventGroups and Groups hold Synapse's resolved state after each event.
	EventGroups map[string]int64 `json:"event_groups"`
	Groups      map[int64]Group  `json:"groups"`
	Extremities []string         `json:"extremities"`
	// CurrentState maps StateKey(type, state key) to event IDs.
	CurrentState map[string]string `json:"current_state"`
}

// Group is a Synapse state group: a delta over its previous group.
type Group struct {
	Prev  int64             `json:"prev,omitempty"`
	State map[string]string `json:"state"`
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
	pdu *pdu.PDU
	raw json.RawMessage
}

type room struct {
	id      id.RoomID
	version id.RoomVersion

	mu          sync.Mutex
	events      map[string]event
	groupOf     map[string]int64
	groups      map[int64]Group
	resolved    map[int64]map[string]string
	extra       map[string]map[string]string // state after events without a group
	current     map[string]string
	extremities []string
}

func newRoom(roomID, version string, data RoomData) (*room, error) {
	if !SupportsVersion(version) {
		return nil, fmt.Errorf("room version %q is not supported", version)
	}
	r := &room{id: id.RoomID(roomID), version: id.RoomVersion(version), events: map[string]event{},
		groupOf: data.EventGroups, groups: data.Groups, resolved: map[int64]map[string]string{},
		extra: map[string]map[string]string{}, current: maps.Clone(data.CurrentState),
		extremities: slices.Clone(data.Extremities)}
	for _, e := range data.Events {
		p, err := ParsePDU(e.PDU)
		if err != nil {
			return nil, fmt.Errorf("event %s: %w", e.EventID, err)
		}
		r.events[e.EventID] = event{pdu: p, raw: e.PDU}
	}
	if r.current == nil {
		r.current = map[string]string{}
	}
	return r, nil
}

func (r *room) groupState(gid int64) map[string]string {
	if s, ok := r.resolved[gid]; ok {
		return s
	}
	g, ok := r.groups[gid]
	if !ok {
		return nil
	}
	state := map[string]string{}
	if g.Prev != 0 {
		maps.Copy(state, r.groupState(g.Prev))
	}
	maps.Copy(state, g.State)
	r.resolved[gid] = state
	return state
}

func (r *room) stateAfter(eventID string) map[string]string {
	if s, ok := r.extra[eventID]; ok {
		return s
	}
	if g, ok := r.groupOf[eventID]; ok {
		if s := r.groupState(g); s != nil {
			return s
		}
	}
	return map[string]string{}
}

func (r *room) stateBefore(eventID string) map[string]string {
	ev, ok := r.events[eventID]
	after := r.stateAfter(eventID)
	if !ok || ev.pdu.StateKey == nil {
		return after
	}
	before := maps.Clone(after)
	k := StateKey(ev.pdu.Type, *ev.pdu.StateKey)
	delete(before, k)
	if len(ev.pdu.PrevEvents) > 0 {
		if prev, ok := r.stateAfter(string(ev.pdu.PrevEvents[0]))[k]; ok {
			before[k] = prev
		}
	}
	return before
}

// add appends a new event on top of the room's forward extremities.
func (r *room) add(eventID string, p *pdu.PDU, raw json.RawMessage) {
	if _, ok := r.events[eventID]; ok {
		return
	}
	r.events[eventID] = event{pdu: p, raw: raw}
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
		d = max(d, ev.pdu.Depth)
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
		for _, a := range ev.pdu.AuthEvents {
			if !seen[string(a)] {
				seen[string(a)] = true
				chain = append(chain, string(a))
				queue = append(queue, string(a))
			}
		}
	}
	return chain
}

// before walks prev events backwards from the given events, including them.
func (r *room) before(from []string, limit int, stop map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	queue := slices.Clone(from)
	for len(queue) > 0 && len(out) < limit {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] || stop[cur] {
			continue
		}
		seen[cur] = true
		ev, ok := r.events[cur]
		if !ok {
			continue
		}
		out = append(out, cur)
		for _, p := range ev.pdu.PrevEvents {
			queue = append(queue, string(p))
		}
	}
	return out
}

func (r *room) pdus(ids []string) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(ids))
	for _, eid := range ids {
		if ev, ok := r.events[eid]; ok {
			out = append(out, ev.raw)
		}
	}
	return out
}

func stateIDs(state map[string]string) []string {
	return slices.Sorted(maps.Values(state))
}
