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
	"os"
	"slices"
	"strings"

	"exodus/internal/relay"
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
	accepted    map[string]bool
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
			r = &tuwunelRoomIndex{diskEvents: map[string]tuwunelEventRef{}, events: map[string]json.RawMessage{}, accepted: map[string]bool{}}
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
				r.accepted[p.ID] = true
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
		if len(room.accepted) != 0 {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

func (d *TuwunelDump) roomRelayMetadata(ctx context.Context, roomID string) (*relay.RoomData, error) {
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
	data := &relay.RoomData{BeforeEventGroups: map[string]int64{}, Groups: map[int64]relay.Group{}}

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
	if err := d.loadStateGroups(ctx, data.Groups, currentGroup, stateFile); err != nil {
		return nil, err
	}
	data.CurrentState, err = relay.ResolveState(data.Groups, int64(currentGroup))
	if err != nil {
		return nil, err
	}
	for entry, err := range d.roomEvents(ctx, roomID) {
		if err != nil {
			return nil, err
		}
		id, raw := entry.EventID, entry.PDU
		if room.accepted[id] {
			data.Timeline = append(data.Timeline, id)
		}
		var p struct {
			Type       string   `json:"type"`
			AuthEvents []string `json:"auth_events"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
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
		} else if room.accepted[id] {
			return nil, fmt.Errorf("Tuwunel accepted event %s has no historical state", id)
		}
		for _, dependency := range p.AuthEvents {
			if !room.hasEvent(dependency) {
				return nil, fmt.Errorf("auth event %s required by %s missing from dump", dependency, id)
			}
		}
	}
	for _, id := range data.CurrentState {
		if !room.hasEvent(id) {
			return nil, fmt.Errorf("current-state event %s missing from Tuwunel dump", id)
		}
	}
	for _, id := range room.extremities {
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
	return data, nil
}
