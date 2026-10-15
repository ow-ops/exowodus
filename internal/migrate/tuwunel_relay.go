package migrate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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

type tuwunelRoomIndex struct {
	events      map[string]json.RawMessage
	accepted    map[string]bool
	extremities []string
}

func (d *TuwunelDump) indexRelayData() error {
	d.relayOnce.Do(func() { d.relayErr = d.buildRelayIndex() })
	return d.relayErr
}

func (d *TuwunelDump) buildRelayIndex() error {
	d.shortEvents = make(map[string]string, len(d.maps["shorteventid_eventid"]))
	for short, id := range d.maps["shorteventid_eventid"] {
		if len(short) != 8 {
			return errors.New("invalid Tuwunel short event ID")
		}
		d.shortEvents[string(id)] = short
	}
	d.relayRooms = map[string]*tuwunelRoomIndex{}
	roomIndex := func(roomID string) *tuwunelRoomIndex {
		r := d.relayRooms[roomID]
		if r == nil {
			r = &tuwunelRoomIndex{events: map[string]json.RawMessage{}, accepted: map[string]bool{}}
			d.relayRooms[roomID] = r
		}
		return r
	}
	for _, name := range []string{"pduid_pdu", "eventid_outlierpdu"} {
		for key, raw := range d.maps[name] {
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
				continue
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
				r.events[p.ID] = json.RawMessage(raw)
			}
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

func (d *TuwunelDump) RoomIDs() ([]string, error) {
	if err := d.indexRelayData(); err != nil {
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

func (d *TuwunelDump) RoomRelayData(roomID string) (*relay.RoomData, error) {
	if err := d.CheckRelayMaps(); err != nil {
		return nil, err
	}
	if err := d.indexRelayData(); err != nil {
		return nil, err
	}
	room := d.relayRooms[roomID]
	if room == nil {
		return nil, fmt.Errorf("Tuwunel room %s missing from dump", roomID)
	}
	data := &relay.RoomData{BeforeEventGroups: map[string]int64{}, Groups: map[int64]relay.Group{}}
	events, accepted := room.events, room.accepted
	stateCache := map[uint64]map[string]string{}
	visiting := map[uint64]bool{}
	var resolve func(uint64) (map[string]string, error)
	resolve = func(gid uint64) (map[string]string, error) {
		if state, ok := stateCache[gid]; ok {
			return state, nil
		}
		if visiting[gid] {
			return nil, errors.New("cycle in Tuwunel compressed state")
		}
		visiting[gid] = true
		defer delete(visiting, gid)
		key := string(binary.BigEndian.AppendUint64(nil, gid))
		raw := d.maps["shortstatehash_statediff"][key]
		if len(raw) < 8 || len(raw)%8 != 0 {
			return nil, fmt.Errorf("invalid Tuwunel state group %d", gid)
		}
		state := map[string]string{}
		if parent := binary.BigEndian.Uint64(raw[:8]); parent != 0 {
			previous, err := resolve(parent)
			if err != nil {
				return nil, err
			}
			maps.Copy(state, previous)
		}
		remove := false
		for pos := 8; pos < len(raw); {
			if !remove && binary.BigEndian.Uint64(raw[pos:pos+8]) == 0 {
				remove = true
				pos += 8
				continue
			}
			if pos+16 > len(raw) {
				return nil, errors.New("truncated Tuwunel state delta")
			}
			stateKey := d.maps["shortstatekey_statekey"][string(raw[pos:pos+8])]
			typ, sk, ok := bytes.Cut(stateKey, []byte{0xff})
			id := d.maps["shorteventid_eventid"][string(raw[pos+8:pos+16])]
			if !ok || len(typ) == 0 || len(id) == 0 {
				return nil, errors.New("unresolved Tuwunel state identifier")
			}
			k := relay.StateKey(string(typ), string(sk))
			if remove {
				if state[k] == string(id) {
					delete(state, k)
				}
			} else {
				state[k] = string(id)
			}
			pos += 16
		}
		stateCache[gid] = state
		return state, nil
	}
	current := d.maps["roomid_shortstatehash"][roomID]
	if len(current) != 8 {
		return nil, errors.New("Tuwunel room has no current state")
	}
	var err error
	data.CurrentState, err = resolve(binary.BigEndian.Uint64(current))
	if err != nil {
		return nil, err
	}
	for id, raw := range events {
		if accepted[id] {
			data.Timeline = append(data.Timeline, id)
		}
		p, err := relay.ParsePDU(raw)
		if err != nil {
			return nil, err
		}
		group := d.maps["shorteventid_shortstatehash"][d.shortEvents[id]]
		if len(group) == 8 {
			gid := binary.BigEndian.Uint64(group)
			if gid > uint64(^uint64(0)>>1) {
				return nil, errors.New("Tuwunel state group overflows archive format")
			}
			state, err := resolve(gid)
			if err != nil {
				return nil, err
			}
			data.BeforeEventGroups[id] = int64(gid)
			data.Groups[int64(gid)] = relay.Group{State: state}
		} else if p.Type == "m.room.create" {
			data.BeforeEventGroups[id] = 0
			data.Groups[0] = relay.Group{State: map[string]string{}}
		} else if accepted[id] {
			return nil, fmt.Errorf("Tuwunel accepted event %s has no historical state", id)
		}
		data.Events = append(data.Events, relay.EventJSON{EventID: id, PDU: raw})
	}
	for id, raw := range events {
		p, err := relay.ParsePDU(raw)
		if err != nil {
			return nil, err
		}
		for _, dependency := range p.AuthEvents {
			if events[string(dependency)] == nil {
				return nil, fmt.Errorf("auth event %s required by %s missing from dump", dependency, id)
			}
		}
	}
	for _, id := range data.CurrentState {
		if events[id] == nil {
			return nil, fmt.Errorf("current-state event %s missing from Tuwunel dump", id)
		}
	}
	for _, id := range room.extremities {
		if events[id] == nil {
			return nil, errors.New("Tuwunel forward extremity PDU missing")
		}
		data.Extremities = append(data.Extremities, id)
	}
	if len(data.Extremities) == 0 {
		return nil, errors.New("Tuwunel room has no forward extremities")
	}
	slices.Sort(data.Extremities)
	slices.Sort(data.Timeline)
	slices.SortFunc(data.Events, func(a, b relay.EventJSON) int { return strings.Compare(a.EventID, b.EventID) })
	return data, nil
}
