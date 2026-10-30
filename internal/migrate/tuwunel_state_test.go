package migrate

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/relay"
)

func TestTuwunelReplacementStateStaysCompact(t *testing.T) {
	members, updates := 512, 128
	if os.Getenv("EXOWODUS_MEMORY_STRESS") != "" {
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

func deletionStateFixture(members, updates int) *TuwunelDump {
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
	last := 1
	for group := 2; group <= updates; group++ {
		delta := []byte(u64(group - 1))
		if group%2 == 0 {
			delta = append(delta, []byte(u64(0))...)
			delta = append(delta, pair(1, last)...)
		} else {
			last = members + group
			d.maps["shorteventid_eventid"][u64(last)] = []byte(fmt.Sprintf("$update%d", group))
			delta = append(delta, pair(1, last)...)
		}
		d.maps["shortstatehash_statediff"][u64(group)] = delta
	}
	return d
}

func BenchmarkTuwunelDeletionState(b *testing.B) {
	d := deletionStateFixture(512, 256)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		groups := map[int64]relay.Group{}
		if err := d.loadStateGroups(b.Context(), groups, 256, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTuwunelDeletionStateStaysCompact(t *testing.T) {
	members, updates := 512, 128
	if os.Getenv("EXOWODUS_MEMORY_STRESS") != "" {
		members, updates = 4096, 4096
	}
	d := deletionStateFixture(members, updates)
	groups := map[int64]relay.Group{}
	if err := d.loadStateGroups(t.Context(), groups, uint64(updates), nil); err != nil {
		t.Fatal(err)
	}
	entries := 0
	for _, group := range groups {
		entries += len(group.State) + len(group.Removed)
	}
	if entries != members+updates-1 {
		t.Fatalf("retained %d state entries, want %d", entries, members+updates-1)
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoomPDUs("!room:example.org", &relay.RoomData{Groups: groups}); err != nil {
		t.Fatal(err)
	}
	var stored relay.RoomData
	if ok, err := a.ReadRoomPDUs("!room:example.org", &stored); err != nil || !ok {
		t.Fatalf("read state groups: %v", err)
	}
	for _, groupID := range []int64{1, 2, 3, int64(updates)} {
		state, err := relay.ResolveState(stored.Groups, groupID)
		if err != nil {
			t.Fatal(err)
		}
		key := relay.StateKey("m.room.member", "@member1:example.org")
		expected := members
		if groupID%2 == 0 {
			expected--
			if _, present := state[key]; present {
				t.Fatalf("deleted member present in group %d", groupID)
			}
		} else {
			want := "$initial1"
			if groupID > 1 {
				want = fmt.Sprintf("$update%d", groupID)
			}
			if state[key] != want {
				t.Fatalf("group %d: member=%s, want %s", groupID, state[key], want)
			}
		}
		if len(state) != expected {
			t.Fatalf("group %d: members=%d, want %d", groupID, len(state), expected)
		}
	}
}
