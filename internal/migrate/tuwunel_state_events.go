package migrate

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"

	"exodus/internal/relay"
)

type stateUndo struct {
	key, value string
	present    bool
}

type stateVisit struct {
	group   int64
	undo    []stateUndo
	restore bool
}

// stateEventIDs visits requested snapshots with one state map and an undo stack.
// Values removed or replaced before every requested snapshot are not emitted.
func stateEventIDs(ctx context.Context, groups map[int64]relay.Group, targets map[int64]bool) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		needed := map[int64]bool{}
		for target := range targets {
			for gid := target; !needed[gid]; {
				if err := ctx.Err(); err != nil {
					yield("", err)
					return
				}
				group, ok := groups[gid]
				if !ok {
					yield("", fmt.Errorf("missing state group %d", gid))
					return
				}
				needed[gid] = true
				if group.Prev == 0 {
					break
				}
				gid = group.Prev
			}
		}
		children := map[int64][]int64{}
		var stack []stateVisit
		for gid := range needed {
			if parent := groups[gid].Prev; parent != 0 {
				children[parent] = append(children[parent], gid)
			} else {
				stack = append(stack, stateVisit{group: gid})
			}
		}
		state := map[string]string{}
		emitted := map[string]bool{}
		unemitted := map[string]int{}
		set := func(key, value string, present bool) {
			if old, ok := state[key]; ok && !emitted[old] {
				if unemitted[old] <= 1 {
					delete(unemitted, old)
				} else {
					unemitted[old]--
				}
			}
			if present {
				state[key] = value
				if !emitted[value] {
					unemitted[value]++
				}
			} else {
				delete(state, key)
			}
		}
		remaining := maps.Clone(targets)
		for len(stack) > 0 {
			if err := ctx.Err(); err != nil {
				yield("", err)
				return
			}
			visit := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if visit.restore {
				for _, old := range slices.Backward(visit.undo) {
					set(old.key, old.value, old.present)
				}
				continue
			}
			group := groups[visit.group]
			undo := make([]stateUndo, 0, len(group.State)+len(group.Removed))
			for key, value := range group.State {
				if len(undo)%1024 == 0 {
					if err := ctx.Err(); err != nil {
						yield("", err)
						return
					}
				}
				old, present := state[key]
				undo = append(undo, stateUndo{key: key, value: old, present: present})
				set(key, value, true)
			}
			for i, removed := range group.Removed {
				if i%1024 == 0 {
					if err := ctx.Err(); err != nil {
						yield("", err)
						return
					}
				}
				if old, present := state[removed.Key]; present && old == removed.EventID {
					undo = append(undo, stateUndo{key: removed.Key, value: old, present: true})
					set(removed.Key, "", false)
				}
			}
			if _, target := targets[visit.group]; target {
				for id := range unemitted {
					if err := ctx.Err(); err != nil {
						yield("", err)
						return
					}
					emitted[id] = true
					if !yield(id, nil) {
						return
					}
				}
				clear(unemitted)
				delete(remaining, visit.group)
			}
			stack = append(stack, stateVisit{undo: undo, restore: true})
			for _, child := range children[visit.group] {
				stack = append(stack, stateVisit{group: child})
			}
		}
		for gid := range remaining {
			yield("", fmt.Errorf("cycle in state group %d", gid))
			return
		}
	}
}
