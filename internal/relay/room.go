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

// RoomData contains source events and resolved state.
type RoomData struct {
	// Accepted event IDs, excluding auth-only outliers.
	Timeline []string `json:"timeline,omitempty"`
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

	mu            sync.Mutex
	events        map[string]event
	groupOf       map[string]int64
	beforeGroupOf map[string]int64
	groups        map[int64]Group
	extra         map[string]map[string]string // state after events without a group
	current       map[string]string
	extremities   []string
}

func newRoom(roomID, version string, data RoomData) (*room, error) {
	if !SupportsVersion(version) {
		return nil, fmt.Errorf("room version %q is not supported", version)
	}
	r := &room{id: id.RoomID(roomID), version: id.RoomVersion(version), events: map[string]event{},
		groupOf: data.EventGroups, groups: data.Groups,
		beforeGroupOf: data.BeforeEventGroups,
		extra:         map[string]map[string]string{}, current: maps.Clone(data.CurrentState),
		extremities: slices.Clone(data.Extremities)}
	for _, e := range data.Events {
		wire, err := federationPDU(e.PDU, version)
		if err != nil {
			return nil, fmt.Errorf("event %s: %w", e.EventID, err)
		}
		p, err := ParsePDU(wire)
		if err != nil {
			return nil, fmt.Errorf("event %s: %w", e.EventID, err)
		}
		r.events[e.EventID] = event{pdu: p, raw: wire}
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
	var chain []int64
	seen := map[int64]bool{}
	for {
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
		maps.Copy(state, group.State)
	}
	return state, nil
}

func (r *room) stateAfter(eventID string) (map[string]string, error) {
	if state, ok := r.extra[eventID]; ok {
		return state, nil
	}
	if gid, ok := r.beforeGroupOf[eventID]; ok {
		state, err := ResolveState(r.groups, gid)
		if err != nil {
			return nil, err
		}
		if ev, ok := r.events[eventID]; ok && ev.pdu.StateKey != nil {
			state[StateKey(ev.pdu.Type, *ev.pdu.StateKey)] = eventID
		}
		return state, nil
	}
	if gid, ok := r.groupOf[eventID]; ok {
		return ResolveState(r.groups, gid)
	}
	return map[string]string{}, nil
}

func (r *room) stateBefore(eventID string) (map[string]string, error) {
	if gid, ok := r.beforeGroupOf[eventID]; ok {
		return ResolveState(r.groups, gid)
	}
	ev, ok := r.events[eventID]
	after, err := r.stateAfter(eventID)
	if err != nil {
		return nil, err
	}
	if !ok || ev.pdu.StateKey == nil {
		return after, nil
	}
	before := maps.Clone(after)
	k := StateKey(ev.pdu.Type, *ev.pdu.StateKey)
	delete(before, k)
	if len(ev.pdu.PrevEvents) > 0 {
		previous, err := r.stateAfter(string(ev.pdu.PrevEvents[0]))
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
