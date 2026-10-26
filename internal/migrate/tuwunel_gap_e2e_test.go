//go:build e2e

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

// Uses an empty test homeserver with server_name example.org and cadmin/cadmin-password.
func TestTuwunelDummyGapLive(t *testing.T) {
	target := os.Getenv("EXODUS_DUMMY_GAP_TARGET")
	if target == "" {
		t.Skip("set EXODUS_DUMMY_GAP_TARGET to an isolated Continuwuity instance")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	c := mx.MustNew(target, "")
	login, err := c.Login(ctx, &mautrix.ReqLogin{Type: mautrix.AuthTypePassword, Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: "cadmin"}, Password: "cadmin-password"})
	if err != nil {
		t.Fatal(err)
	}
	c.AccessToken, c.UserID = login.AccessToken, login.UserID
	admin, err := NewContinuwuityAdmin(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	as, err := RegisterAppservice(ctx, admin, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Unregister(context.Background(), admin) })
	if err := as.Register(ctx, "@alice:example.org"); err != nil {
		t.Fatal(err)
	}
	var destinationKeys json.RawMessage
	if _, err := c.MakeRequest(ctx, http.MethodGet, target+"/_matrix/key/v2/server", nil, &destinationKeys); err != nil {
		t.Fatal(err)
	}
	key := federation.GenerateSigningKey()
	key.ID = id.NewKeyID(id.KeyAlgorithmEd25519, rand.Text())
	for _, tc := range []struct {
		name, version string
		prejoined     bool
		relayLeft     bool
		gap           bool
	}{
		{name: "fresh v11", version: "11"},
		{name: "fresh v12", version: "12"},
		{name: "already joined v11", version: "11", prejoined: true},
		{name: "already joined v12", version: "12", prejoined: true},
		{name: "relay left v11", version: "11", prejoined: true, relayLeft: true},
		{name: "relay left v12", version: "12", prejoined: true, relayLeft: true},
		// An earlier attempt backfilled down to the create event but skipped a branch.
		{name: "gap below earliest v11", version: "11", prejoined: true, gap: true},
		{name: "gap below earliest v12", version: "12", prejoined: true, gap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version := tc.version
			roomID := fmt.Sprintf("!gap%s%d:example.org", version, time.Now().UnixNano())
			data := &tuwunelRoomMetadata{RoomData: &relay.RoomData{Groups: map[int64]relay.Group{}, BeforeEventGroups: map[string]int64{}}, required: map[string]eventUse{}}
			index := &tuwunelRoomIndex{events: map[string]json.RawMessage{}, timeline: map[string]bool{}}
			state := map[string]string{}
			var auth []id.EventID
			var previous id.EventID
			var merge []id.EventID
			var skipped string
			depth := int64(0)
			add := func(typ string, stateKey *string, content any) string {
				t.Helper()
				depth++
				raw, _ := json.Marshal(content)
				p := &pdu.PDU{RoomID: id.RoomID(roomID), Sender: "@alice:example.org", Type: typ, StateKey: stateKey, Content: raw, AuthEvents: slices.Clone(auth), PrevEvents: []id.EventID{}, Depth: depth, OriginServerTS: time.Now().UnixMilli()}
				if merge != nil {
					p.PrevEvents, merge = merge, nil
				} else if previous != "" {
					p.PrevEvents = []id.EventID{previous}
				}
				if typ == "m.room.create" && version == "12" {
					p.RoomID = ""
				}
				if err := p.FillContentHash(); err != nil {
					t.Fatal(err)
				}
				eventID, err := p.GetEventID(id.RoomVersion(version))
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Sign(id.RoomVersion(version), "example.org", key.ID, key.Priv); err != nil {
					t.Fatal(err)
				}
				if typ == "m.room.create" && version == "12" {
					roomID = "!" + string(eventID)[1:]
					p.RoomID = id.RoomID(roomID)
				}
				encoded, err := jsonv2.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				var object map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &object); err != nil {
					t.Fatal(err)
				}
				object["event_id"], _ = json.Marshal(eventID)
				encoded, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				eid := string(eventID)
				data.BeforeEventGroups[eid] = depth
				data.Groups[depth] = relay.Group{State: maps.Clone(state)}
				data.Timeline = append(data.Timeline, eid)
				data.required[eid] |= timelineEvent
				index.timeline[eid], index.events[eid] = true, encoded
				for _, dependency := range auth {
					data.required[string(dependency)] |= authEvent
				}
				if stateKey != nil {
					state[relay.StateKey(typ, *stateKey)] = eid
					data.required[eid] |= stateEvent
				}
				previous = eventID
				return eid
			}
			empty, alice := "", "@alice:example.org"
			create := add("m.room.create", &empty, map[string]any{"room_version": version})
			if version != "12" {
				auth = append(auth, id.EventID(create))
			}
			member := add("m.room.member", &alice, map[string]any{"membership": "join"})
			auth = append(auth, id.EventID(member))
			levels := map[string]int{}
			if version != "12" {
				levels[alice] = 100
			}
			oldPower := add("m.room.power_levels", &empty, map[string]any{"users": levels})
			auth = append(auth, id.EventID(oldPower))
			power := add("m.room.power_levels", &empty, map[string]any{"users": levels})
			auth[len(auth)-1] = id.EventID(power)
			// An auth outlier has a PDU and auth chain but no exported state snapshot.
			delete(index.timeline, oldPower)
			delete(data.BeforeEventGroups, oldPower)
			data.Timeline = slices.DeleteFunc(data.Timeline, func(eid string) bool { return eid == oldPower })
			data.required[oldPower] &^= timelineEvent
			// More than one Continuwuity backfill page (100 events), with
			// branches that a later event merges, as dummy events do.
			for i := range 250 {
				if i%5 == 4 {
					fork := previous
					left := add("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": fmt.Sprintf("left %d", i)})
					previous = fork
					right := add("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": fmt.Sprintf("right %d", i)})
					if skipped == "" {
						skipped = right
					}
					merge = []id.EventID{id.EventID(left), id.EventID(right)}
				}
				add("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": fmt.Sprintf("history %d", i)})
			}
			add("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": "before gap"})
			dummy := add("org.matrix.dummy_event", nil, map[string]any{})
			// Change a hashed field while retaining the stored event ID.
			var bad map[string]json.RawMessage
			_ = json.Unmarshal(index.events[dummy], &bad)
			bad["depth"] = json.RawMessage(`999`)
			index.events[dummy], _ = json.Marshal(bad)
			last := add("m.room.message", nil, map[string]any{"msgtype": "m.text", "body": "after gap"})
			data.required[last] |= roomHead
			data.Extremities, data.CurrentState = []string{last}, state
			data.dummies = []string{dummy}
			dump := &TuwunelDump{relayRooms: map[string]*tuwunelRoomIndex{roomID: index}}
			omitted, err := dump.omitInvalidDummies(ctx, roomID, version, data)
			if err != nil || len(omitted) != 1 {
				t.Fatalf("omission=%v error=%v", omitted, err)
			}
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			oldPowerPDU := index.events[oldPower]
			delete(index.events, oldPower)
			keyCache := federation.NewInMemoryCache()
			var originKeys federation.ServerKeyResponse
			if err := json.Unmarshal(keyJSON(t, key, "example.org"), &originKeys); err != nil {
				t.Fatal(err)
			}
			keyCache.StoreKeys(&originKeys)
			remoteAuth := federation.NewServerAuth(nil, keyCache, func(federation.XMatrixAuth) string { return "remote.example" })
			var fetches atomic.Int32
			remote := recoveryClient(t, remoteAuth.AuthenticateMiddleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				fetches.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{"pdus": []json.RawMessage{oldPowerPDU}})
			})).ServeHTTP)
			remote.Key = key
			exp := &Exporter{Archive: a, TuwunelDump: dump, authRecovery: &authRecovery{
				client: remote, keys: map[string][]*federation.ServerKeyResponse{},
				baseKeys: map[string][]json.RawMessage{"example.org": {keyJSON(t, key, "example.org")}},
			}}
			if err := exp.recoverAuth(ctx, roomID, data, oldPower, json.RawMessage(`{"sender":"@bob:remote.example"}`)); err != nil {
				t.Fatal(err)
			}
			if fetches.Load() != 1 {
				t.Fatalf("auth recovery requests = %d", fetches.Load())
			}
			room := &archive.ArchivedRoom{RoomID: roomID, Version: version, OmittedEvents: omitted}
			for _, eid := range []string{create, member, power} {
				room.State = append(room.State, index.events[eid])
			}
			for entry, err := range dump.roomEventsByID(ctx, roomID, slices.Collect(maps.Keys(data.required))) {
				if err != nil {
					t.Fatal(err)
				}
				data.Events = append(data.Events, entry)
			}
			if err := a.WriteRoom(room); err != nil {
				t.Fatal(err)
			}
			if err := a.WriteRoomEventsFrom(roomID, dump.checkpointTimeline(ctx, roomID, omitted)); err != nil {
				t.Fatal(err)
			}
			if err := a.WriteRoomPDUs(roomID, data.RoomData); err != nil {
				t.Fatal(err)
			}
			rl := relay.New("host.docker.internal:38321", "example.org", key, map[string][]json.RawMessage{"example.org": {destinationKeys}})
			if err := rl.Trust(ctx, "example.org", target+"/_matrix/key/v2/server"); err != nil {
				t.Fatal(err)
			}
			if err := rl.Start(":38321", "", ""); err != nil {
				t.Fatal(err)
			}
			defer rl.Stop(context.Background())
			if tc.prejoined {
				served := *data.RoomData
				if tc.gap {
					served.Events = slices.DeleteFunc(slices.Clone(served.Events), func(e relay.EventJSON) bool { return e.EventID == skipped })
				}
				if err := rl.AddRoom(roomID, version, served); err != nil {
					t.Fatal(err)
				}
				if err := rl.Enter(roomID, alice); err != nil {
					t.Fatal(err)
				}
				if _, err := as.As(alice).JoinRoom(ctx, roomID, &mautrix.ReqJoinRoom{Via: []string{rl.Name}}); err != nil {
					t.Fatal(err)
				}
				if tc.relayLeft {
					if _, err := as.As(alice).SendStateEvent(ctx, id.RoomID(roomID), event.StateMember, rl.UserID(), map[string]string{"membership": "leave"}); err != nil {
						t.Fatal(err)
					}
				}
				if tc.gap {
					_, err := backfillRoomEvents(ctx, []*mautrix.Client{as.As(alice)}, roomID, a.RoomEventsIter(roomID))
					var incomplete *incompleteBackfillError
					if !errors.As(err, &incomplete) || !incomplete.reachedCreate || len(incomplete.missing) != 1 || !incomplete.missing[skipped] {
						t.Fatalf("earlier attempt did not leave the expected gap: %v", err)
					}
				}
			}
			im := &Importer{RequireLossless: true, Archive: a, Dest: c, Admin: admin, Appservice: as, Migrated: map[string]bool{alice: true}}
			reports, rest := im.RelayRooms(ctx, []*archive.ArchivedRoom{room}, rl)
			if len(rest) != 0 || len(reports) != 1 {
				t.Fatalf("reports=%v rest=%v", reports, rest)
			}
			if len(reports[0].Failures) != 0 {
				t.Fatal(reports[0].Failures)
			}
			if _, err := as.As(alice).GetEvent(ctx, id.RoomID(roomID), id.EventID(dummy)); err == nil {
				t.Fatal("omitted dummy was imported")
			}
			t.Logf("verified original messages before and after omitted dummy in room v%s", version)
		})
	}
}
