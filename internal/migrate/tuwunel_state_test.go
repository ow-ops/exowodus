package migrate

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"exodus/internal/relay"
)

func TestTuwunelReplacementStateStaysCompact(t *testing.T) {
	members, updates := 512, 128
	if os.Getenv("EXODUS_MEMORY_STRESS") != "" {
		members, updates = 4096, 4096
	}
	u64 := func(n int) string { return string(binary.BigEndian.AppendUint64(nil, uint64(n))) }
	pair := func(k, e int) []byte { return []byte(u64(k) + u64(e)) }
	d := &TuwunelDump{maps: map[string]map[string][]byte{
		"shortstatehash_statediff": {}, "shortstatekey_statekey": {}, "shorteventid_eventid": {},
	}}
	base := []byte(u64(0))
	for i := 1; i <= members; i++ {
		d.maps["shortstatekey_statekey"][u64(i)] = []byte(fmt.Sprintf("m.room.member\xff@member%d:example.org", i))
		d.maps["shorteventid_eventid"][u64(i)] = []byte(fmt.Sprintf("$initial%d", i))
		base = append(base, pair(i, i)...)
	}
	d.maps["shortstatehash_statediff"][u64(1)] = base
	for group := 2; group <= updates; group++ {
		event := members + group
		previous := event - 1
		if group == 2 {
			previous = 1
		}
		d.maps["shorteventid_eventid"][u64(event)] = []byte(fmt.Sprintf("$update%d", group))
		delta := append([]byte(u64(group-1)), pair(1, event)...)
		delta = append(delta, []byte(u64(0))...)
		delta = append(delta, pair(1, previous)...)
		d.maps["shortstatehash_statediff"][u64(group)] = delta
	}
	groups := map[int64]relay.Group{}
	if err := d.loadStateGroups(t.Context(), groups, uint64(updates), nil); err != nil {
		t.Fatal(err)
	}
	entries := 0
	for _, group := range groups {
		entries += len(group.State)
	}
	if entries != members+updates-1 {
		t.Fatalf("retained %d state entries, want %d", entries, members+updates-1)
	}
	state, err := relay.ResolveState(groups, int64(updates))
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != members || state[relay.StateKey("m.room.member", "@member1:example.org")] != fmt.Sprintf("$update%d", updates) {
		t.Fatal("replacement state changed")
	}
}
