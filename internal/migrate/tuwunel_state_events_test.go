package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"exodus/internal/relay"
)

func TestStateEventIDs(t *testing.T) {
	groups := map[int64]relay.Group{
		0: {},
		1: {State: map[string]string{"member": "$old", "keep": "$keep", "alias": "$keep"}},
		2: {Prev: 1, State: map[string]string{"member": "$new"}, Removed: []relay.StateRemoval{{Key: "keep", EventID: "$keep"}}},
		3: {Prev: 2, Removed: []relay.StateRemoval{{Key: "member", EventID: "$new"}, {Key: "alias", EventID: "$keep"}}},
		4: {Prev: 1, State: map[string]string{"member": "$branch"}, Removed: []relay.StateRemoval{{Key: "keep", EventID: "$different"}}},
		5: {State: map[string]string{"other": "$root"}},
		6: {Prev: 4, State: map[string]string{"topic": "$topic"}, Removed: []relay.StateRemoval{{Key: "member", EventID: "$branch"}}},
	}
	before, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]int64{{}, {0}, {1}, {2}, {3}, {3, 4, 5}, {2, 6}, {0, 1, 2, 3, 4, 5, 6}} {
		t.Run(fmt.Sprint(ids), func(t *testing.T) {
			targets := map[int64]bool{}
			want := map[string]bool{}
			for _, gid := range ids {
				targets[gid] = true
				state, err := relay.ResolveState(groups, gid)
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range state {
					want[id] = true
				}
			}
			got := map[string]bool{}
			for id, err := range stateEventIDs(t.Context(), groups, targets) {
				if err != nil {
					t.Fatal(err)
				}
				if got[id] {
					t.Fatalf("duplicate event ID %s", id)
				}
				got[id] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("state IDs=%v, want %v", got, want)
			}
		})
	}
	after, err := json.Marshal(groups)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("state traversal changed the source groups")
	}
}

func TestStateEventIDsRejectsInvalidGroups(t *testing.T) {
	for _, tc := range []struct {
		groups map[int64]relay.Group
		want   string
	}{
		{map[int64]relay.Group{1: {Prev: 2}, 2: {Prev: 1}}, "cycle"},
		{map[int64]relay.Group{1: {Prev: 2}}, "missing state group"},
	} {
		var failure error
		for _, err := range stateEventIDs(t.Context(), tc.groups, map[int64]bool{1: true}) {
			failure = err
		}
		if failure == nil || !strings.Contains(failure.Error(), tc.want) {
			t.Fatalf("error=%v, want %s", failure, tc.want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, err := range stateEventIDs(ctx, map[int64]relay.Group{1: {}}, map[int64]bool{1: true}) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation=%v", err)
		}
	}
}

func TestStateEventIDsLongDeletionChain(t *testing.T) {
	members, updates := 512, 128
	if os.Getenv("EXODUS_MEMORY_STRESS") != "" {
		members, updates = 4096, 4096
	}
	d := deletionStateFixture(members, updates)
	groups := map[int64]relay.Group{}
	if err := d.loadStateGroups(t.Context(), groups, uint64(updates), nil); err != nil {
		t.Fatal(err)
	}
	targets := map[int64]bool{}
	for gid := range groups {
		targets[gid] = true
	}
	count := 0
	for _, err := range stateEventIDs(t.Context(), groups, targets) {
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if want := members + (updates-1)/2; count != want {
		t.Fatalf("emitted %d IDs, want %d", count, want)
	}
}

func BenchmarkStateEventIDs(b *testing.B) {
	d := deletionStateFixture(4096, 4096)
	groups := map[int64]relay.Group{}
	if err := d.loadStateGroups(b.Context(), groups, 4096, nil); err != nil {
		b.Fatal(err)
	}
	targets := map[int64]bool{}
	for gid := range groups {
		targets[gid] = true
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, err := range stateEventIDs(b.Context(), groups, targets) {
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
