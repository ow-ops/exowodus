package migrate

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"

	"exodus/internal/relay"
)

type tuwunelStateRemoval struct{ key, eventID string }

func (d *TuwunelDump) loadStateGroups(ctx context.Context, groups map[int64]relay.Group, gid uint64, stateFile *os.File) error {
	seen := map[uint64]bool{}
	var chain []int64
	removals := map[int64][]tuwunelStateRemoval{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if gid > uint64(^uint64(0)>>1) {
			return errors.New("Tuwunel state group overflows archive format")
		}
		if seen[gid] {
			return errors.New("cycle in Tuwunel compressed state")
		}
		if _, ok := groups[int64(gid)]; ok {
			break
		}
		seen[gid] = true
		key := string(binary.BigEndian.AppendUint64(nil, gid))
		raw := d.maps["shortstatehash_statediff"][key]
		if stateFile != nil {
			var err error
			raw, err = d.disk["shortstatehash_statediff"].read(stateFile, key)
			if err != nil {
				return err
			}
		}
		if len(raw) < 8 || len(raw)%8 != 0 {
			return fmt.Errorf("invalid Tuwunel state group %d", gid)
		}
		parent := binary.BigEndian.Uint64(raw[:8])
		if parent > uint64(^uint64(0)>>1) {
			return errors.New("Tuwunel state group overflows archive format")
		}
		group := relay.Group{Prev: int64(parent), State: map[string]string{}}
		remove := false
		for pos := 8; pos < len(raw); {
			if !remove && binary.BigEndian.Uint64(raw[pos:pos+8]) == 0 {
				remove = true
				pos += 8
				continue
			}
			if pos+16 > len(raw) {
				return errors.New("truncated Tuwunel state delta")
			}
			stateKey := d.maps["shortstatekey_statekey"][string(raw[pos:pos+8])]
			typ, sk, ok := bytes.Cut(stateKey, []byte{0xff})
			id := d.maps["shorteventid_eventid"][string(raw[pos+8:pos+16])]
			if !ok || len(typ) == 0 || len(id) == 0 {
				return errors.New("unresolved Tuwunel state identifier")
			}
			k := relay.StateKey(string(typ), string(sk))
			if remove {
				removals[int64(gid)] = append(removals[int64(gid)], tuwunelStateRemoval{key: k, eventID: string(id)})
			} else {
				group.State[k] = string(id)
			}
			pos += 16
		}
		groups[int64(gid)] = group
		chain = append(chain, int64(gid))
		if parent == 0 {
			break
		}
		gid = parent
	}
	// Store groups with removals as full snapshots; the archive only supports
	// additions over a parent.
	for _, id := range slices.Backward(chain) {
		if len(removals[id]) == 0 {
			continue
		}
		state, err := relay.ResolveState(groups, id)
		if err != nil {
			return err
		}
		for _, removed := range removals[id] {
			if state[removed.key] == removed.eventID {
				delete(state, removed.key)
			}
		}
		groups[id] = relay.Group{State: state}
	}
	return nil
}
