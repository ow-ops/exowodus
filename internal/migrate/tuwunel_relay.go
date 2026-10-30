package migrate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"exowodus/internal/relay"
)

var tuwunelRelayMaps = []string{"global", "server_signingkeys", "pduid_pdu", "eventid_outlierpdu", "shorteventid_eventid", "shortstatekey_statekey", "shorteventid_shortstatehash", "roomid_shortstatehash", "shortstatehash_statediff", "roomid_pduleaves"}

func (d *TuwunelDump) HasRelayData() bool { return d.maps["pduid_pdu"] != nil }

func (d *TuwunelDump) CheckRelayMaps() error {
	for _, name := range tuwunelRelayMaps {
		if d.maps[name] == nil {
			return fmt.Errorf("original-event transfer requires %s.txt", name)
		}
	}
	return nil
}

// SigningKey decodes Ruma's PKCS#8 key and checks its optional public key.
func (d *TuwunelDump) SigningKey() (string, error) {
	version, der, ok := bytes.Cut(d.maps["global"]["keypair"], []byte{0xff})
	if !ok || len(version) == 0 || bytes.ContainsAny(version, " \t\r\n") {
		return "", errors.New("invalid Tuwunel signing key version")
	}
	var key struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		PublicKey  asn1.RawValue `asn1:"optional,tag:1"`
	}
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil || len(rest) != 0 || key.Version < 0 || key.Version > 1 || !key.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) {
		return "", errors.New("invalid Tuwunel Ed25519 private key")
	}
	var seed []byte
	rest, err = asn1.Unmarshal(key.PrivateKey, &seed)
	if err != nil || len(rest) != 0 || len(seed) != ed25519.SeedSize {
		return "", errors.New("invalid Tuwunel Ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if len(key.PublicKey.FullBytes) != 0 {
		var public asn1.BitString
		if key.PublicKey.IsCompound {
			rest, err = asn1.Unmarshal(key.PublicKey.Bytes, &public)
			if err != nil || len(rest) != 0 {
				return "", errors.New("invalid Tuwunel signing public key")
			}
		} else {
			if len(key.PublicKey.Bytes) != 33 || key.PublicKey.Bytes[0] != 0 {
				return "", errors.New("invalid Tuwunel signing public key")
			}
			public = asn1.BitString{Bytes: key.PublicKey.Bytes[1:], BitLength: 256}
		}
		if public.BitLength != 256 || !bytes.Equal(public.Bytes, priv.Public().(ed25519.PublicKey)) {
			return "", errors.New("Tuwunel signing key public key mismatch")
		}
	}
	return "ed25519 " + string(version) + " " + base64.RawStdEncoding.EncodeToString(seed), nil
}

func (d *TuwunelDump) RelayKeys() (map[string][]json.RawMessage, error) {
	keys := map[string][]json.RawMessage{}
	for server, raw := range d.maps["server_signingkeys"] {
		var doc struct {
			Server string `json:"server_name"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil || doc.Server != server {
			return nil, errors.New("invalid Tuwunel cached signing keys")
		}
		keys[server] = []json.RawMessage{json.RawMessage(raw)}
	}
	return keys, nil
}

type tuwunelEventRef struct {
	table string
	value tuwunelValueRef
}

type tuwunelRoomIndex struct {
	diskEvents  map[string]tuwunelEventRef
	events      map[string]json.RawMessage
	recovered   map[string]string
	timeline    map[string]bool // true for forward events, false for backfill
	extremities []string
}

func (d *TuwunelDump) indexRelayData(ctx context.Context) error {
	d.relayOnce.Do(func() { d.relayErr = d.buildRelayIndex(ctx) })
	return d.relayErr
}

func (d *TuwunelDump) buildRelayIndex(ctx context.Context) error {
	d.shortEvents = make(map[string]string, len(d.maps["shorteventid_eventid"]))
	for short, id := range d.maps["shorteventid_eventid"] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(short) != 8 {
			return errors.New("invalid Tuwunel short event ID")
		}
		d.shortEvents[string(id)] = short
	}
	d.relayRooms = map[string]*tuwunelRoomIndex{}
	roomIndex := func(roomID string) *tuwunelRoomIndex {
		r := d.relayRooms[roomID]
		if r == nil {
			r = &tuwunelRoomIndex{diskEvents: map[string]tuwunelEventRef{}, events: map[string]json.RawMessage{}, timeline: map[string]bool{}}
			d.relayRooms[roomID] = r
		}
		return r
	}
	for _, name := range []string{"pduid_pdu", "eventid_outlierpdu"} {
		if err := d.eachValue(ctx, name, func(key string, raw []byte) error {
			var p struct {
				ID   string `json:"event_id"`
				Room string `json:"room_id"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				return err
			}
			if p.Room == "" {
				if name == "pduid_pdu" {
					return errors.New("Tuwunel timeline PDU has no room ID")
				}
				return nil
			}
			if p.ID == "" && name == "eventid_outlierpdu" {
				p.ID = key
			}
			if p.ID == "" {
				return errors.New("Tuwunel PDU has no event ID")
			}
			r := roomIndex(p.Room)
			if name == "pduid_pdu" {
				backfilled := len(key) == 24 && binary.BigEndian.Uint64([]byte(key)[8:16]) == 0 && int64(binary.BigEndian.Uint64([]byte(key)[16:])) <= 0
				r.timeline[p.ID] = r.timeline[p.ID] || !backfilled
			}
			if _, exists := r.events[p.ID]; !exists {
				if _, exists := r.diskEvents[p.ID]; !exists {
					if d.disk[name] != nil {
						r.diskEvents[p.ID] = tuwunelEventRef{name, d.disk[name].values[key]}
					} else {
						r.events[p.ID] = json.RawMessage(raw)
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if table := d.disk[name]; table != nil {
			table.values = nil
		}
	}
	for key := range d.maps["roomid_pduleaves"] {
		room, id, ok := strings.Cut(key, "\xff")
		if ok {
			roomIndex(room).extremities = append(roomIndex(room).extremities, id)
		}
	}
	return nil
}

func (d *TuwunelDump) RoomIDs(ctx context.Context) ([]string, error) {
	if err := d.indexRelayData(ctx); err != nil {
		return nil, err
	}
	var ids []string
	for id, room := range d.relayRooms {
		if len(room.timeline) != 0 {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

type tuwunelRoomMetadata struct {
	*relay.RoomData
	required map[string]eventUse
	dummies  []string
}

type eventUse uint8

const (
	timelineEvent eventUse = 1 << iota
	stateEvent
	authEvent
	roomHead
)

func (d *TuwunelDump) roomRelayMetadata(ctx context.Context, roomID string) (*tuwunelRoomMetadata, error) {
	return d.roomRelayMetadataWithRecovery(ctx, roomID, nil)
}

type authEventResolver func(context.Context, *tuwunelRoomMetadata, string, json.RawMessage) error

func (d *TuwunelDump) roomRelayMetadataWithRecovery(ctx context.Context, roomID string, resolve authEventResolver) (*tuwunelRoomMetadata, error) {
	if err := d.CheckRelayMaps(); err != nil {
		return nil, err
	}
	if err := d.indexRelayData(ctx); err != nil {
		return nil, err
	}
	room := d.relayRooms[roomID]
	if room == nil {
		return nil, fmt.Errorf("Tuwunel room %s missing from dump", roomID)
	}
	data := &tuwunelRoomMetadata{
		RoomData: &relay.RoomData{BeforeEventGroups: map[string]int64{}, Groups: map[int64]relay.Group{}},
		required: map[string]eventUse{},
	}

	var stateFile *os.File
	if table := d.disk["shortstatehash_statediff"]; table != nil {
		var err error
		stateFile, err = os.Open(table.path)
		if err != nil {
			return nil, err
		}
		defer stateFile.Close()
	}

	current := d.maps["roomid_shortstatehash"][roomID]
	if len(current) != 8 {
		return nil, errors.New("Tuwunel room has no current state")
	}
	var err error
	currentGroup := binary.BigEndian.Uint64(current)
	slog.Info("reading current room state", "room", roomID, "group", currentGroup)
	if err := d.loadStateGroups(ctx, data.Groups, currentGroup, stateFile); err != nil {
		return nil, err
	}
	slog.Info("resolving current room state", "room", roomID, "groups", len(data.Groups))
	data.CurrentState, err = relay.ResolveStateContext(ctx, data.Groups, int64(currentGroup))
	if err != nil {
		return nil, err
	}
	slog.Info("reading historical room state", "room", roomID, "events", len(room.events)+len(room.diskEvents))
	processed := 0
	progress := time.Now()
	for entry, err := range d.roomEventsByID(ctx, roomID, slices.Collect(maps.Keys(room.timeline))) {
		if err != nil {
			return nil, err
		}
		id, raw := entry.EventID, entry.PDU
		forward := room.timeline[id]
		data.Timeline = append(data.Timeline, id)
		var p struct {
			Type       string   `json:"type"`
			StateKey   *string  `json:"state_key"`
			AuthEvents []string `json:"auth_events"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if p.Type == "org.matrix.dummy_event" && p.StateKey == nil {
			data.dummies = append(data.dummies, id)
		}
		group := d.maps["shorteventid_shortstatehash"][d.shortEvents[id]]
		if len(group) == 8 {
			gid := binary.BigEndian.Uint64(group)
			if gid > uint64(^uint64(0)>>1) {
				return nil, errors.New("Tuwunel state group overflows archive format")
			}
			if err := d.loadStateGroups(ctx, data.Groups, gid, stateFile); err != nil {
				return nil, err
			}
			data.BeforeEventGroups[id] = int64(gid)
		} else if p.Type == "m.room.create" {
			data.BeforeEventGroups[id] = 0
			data.Groups[0] = relay.Group{State: map[string]string{}}
		} else if forward {
			return nil, fmt.Errorf("Tuwunel accepted event %s has no historical state", id)
		} else {
			data.StateUnavailable = append(data.StateUnavailable, id)
		}
		for _, dependency := range p.AuthEvents {
			if !room.hasEvent(dependency) {
				if resolve == nil {
					return nil, fmt.Errorf("auth event %s required by timeline event %s is missing from dump", dependency, id)
				}
				if err := resolve(ctx, data, dependency, raw); err != nil {
					return nil, fmt.Errorf("auth event %s required by timeline event %s: %w", dependency, id, err)
				}
			}
			data.required[dependency] |= authEvent
		}
		processed++
		if time.Since(progress) >= 5*time.Second {
			slog.Info("reading historical room state", "room", roomID, "processed", processed,
				"events", len(room.events)+len(room.diskEvents), "groups", len(data.Groups))
			progress = time.Now()
		}
	}
	for _, id := range data.CurrentState {
		if !room.hasEvent(id) {
			return nil, fmt.Errorf("current-state event %s missing from Tuwunel dump", id)
		}
	}
	for _, id := range room.extremities {
		if slices.Contains(data.StateUnavailable, id) {
			return nil, fmt.Errorf("Tuwunel forward extremity %s has no historical state", id)
		}
		if !room.hasEvent(id) {
			return nil, errors.New("Tuwunel forward extremity PDU missing")
		}
		data.Extremities = append(data.Extremities, id)
	}
	if len(data.Extremities) == 0 {
		return nil, errors.New("Tuwunel room has no forward extremities")
	}
	slices.Sort(data.Extremities)
	slices.Sort(data.Timeline)
	slices.Sort(data.StateUnavailable)
	if err := d.addRoomAuth(ctx, roomID, data, stateFile, resolve); err != nil {
		return nil, err
	}
	return data, nil
}

func (d *TuwunelDump) addRoomAuth(ctx context.Context, roomID string, data *tuwunelRoomMetadata, stateFile *os.File, resolve authEventResolver) error {
	room := d.relayRooms[roomID]
	required := data.required
	var pending []string
	for id := range required {
		if _, accepted := room.timeline[id]; !accepted {
			pending = append(pending, id)
		}
	}
	add := func(id string, use eventUse) {
		if required[id] == 0 {
			if _, accepted := room.timeline[id]; !accepted {
				pending = append(pending, id)
			}
		}
		required[id] |= use
	}
	for _, id := range data.Timeline {
		add(id, timelineEvent)
	}
	for _, id := range data.Extremities {
		add(id, roomHead)
	}
	for _, id := range data.CurrentState {
		add(id, stateEvent)
	}
	stateGroups := map[int64]bool{}
	stateTargets := map[int64]bool{}
	addState := func(gid int64) {
		if !stateGroups[gid] {
			stateGroups[gid] = true
			stateTargets[gid] = true
		}
	}
	addStates := func() error {
		for id, err := range stateEventIDs(ctx, data.Groups, stateTargets) {
			if err != nil {
				return err
			}
			add(id, stateEvent)
		}
		clear(stateTargets)
		return nil
	}
	for _, gid := range data.BeforeEventGroups {
		addState(gid)
	}
	if err := addStates(); err != nil {
		return err
	}
	reader := tuwunelRoomReader{dump: d, room: room, files: map[string]*os.File{}}
	defer reader.Close()
	processed := 0
	progress := time.Now()
	slog.Info("checking room auth dependencies", "room", roomID, "events", len(required))
	for len(pending) > 0 {
		batch := pending
		pending = nil
		room.sortEventIDs(batch)
		for _, id := range batch {
			raw, err := reader.read(ctx, id)
			if err != nil {
				return err
			}
			var event struct {
				Type       string   `json:"type"`
				AuthEvents []string `json:"auth_events"`
			}
			if err := json.Unmarshal(raw, &event); err != nil {
				return err
			}
			if _, known := data.BeforeEventGroups[id]; !known && required[id]&roomHead != 0 {
				group := d.maps["shorteventid_shortstatehash"][d.shortEvents[id]]
				if len(group) == 8 {
					gid := binary.BigEndian.Uint64(group)
					if err := d.loadStateGroups(ctx, data.Groups, gid, stateFile); err != nil {
						return err
					}
					data.BeforeEventGroups[id] = int64(gid)
					addState(int64(gid))
				} else if event.Type == "m.room.create" {
					data.BeforeEventGroups[id] = 0
					data.Groups[0] = relay.Group{State: map[string]string{}}
				}
			}
			for _, dependency := range event.AuthEvents {
				if !room.hasEvent(dependency) {
					if resolve == nil {
						return fmt.Errorf("auth event %s required by outlier %s is missing from dump", dependency, id)
					}
					if err := resolve(ctx, data, dependency, raw); err != nil {
						return fmt.Errorf("auth event %s required by outlier %s: %w", dependency, id, err)
					}
				}
				add(dependency, authEvent)
			}
			processed++
			if time.Since(progress) >= 5*time.Second {
				slog.Info("checking room auth dependencies", "room", roomID, "processed", processed, "events", len(required))
				progress = time.Now()
			}
		}
		if err := addStates(); err != nil {
			return err
		}
	}
	return nil
}
