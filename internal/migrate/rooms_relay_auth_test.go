package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"

	"maunium.net/go/mautrix/federation"
)

func relayAuthFixture(t *testing.T, version, creator string, additional, members []string, powerLevels map[string]any) (*replay, *relay.Relay) {
	t.Helper()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	roomID, createID := "!room:example.org", "$create"
	if version == "12" {
		roomID = "!" + strings.Repeat("A", 43)
		createID = "$" + roomID[1:]
	}
	r := &replay{
		im:   &Importer{Archive: a, RequireLossless: true, Migrated: map[string]bool{}, Appservice: &Appservice{Bot: "@exodus:example.org"}},
		room: &archive.ArchivedRoom{RoomID: roomID, Version: version}, final: map[string]roomEvent{},
	}
	data := relay.RoomData{CurrentState: map[string]string{}}
	add := func(eventID, sender, typ, stateKey string, content any) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"event_id": eventID, "room_id": roomID, "sender": sender, "type": typ, "state_key": stateKey, "content": content})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		r.final[relay.StateKey(typ, stateKey)] = ev
		r.room.State = append(r.room.State, raw)
		data.Events = append(data.Events, relay.EventJSON{EventID: eventID, PDU: raw})
		data.CurrentState[relay.StateKey(typ, stateKey)] = eventID
	}
	add(createID, creator, "m.room.create", "", map[string]any{"room_version": version, "additional_creators": additional})
	for i, member := range members {
		r.im.Migrated[member] = true
		add(fmt.Sprintf("$member%d", i), member, "m.room.member", member, map[string]string{"membership": "join"})
	}
	if powerLevels != nil {
		add("$power", creator, "m.room.power_levels", "", powerLevels)
	}
	if err := a.WriteRoom(r.room); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoomEvents(roomID, r.room.State); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoomPDUs(roomID, data); err != nil {
		t.Fatal(err)
	}
	rl := relay.New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	if err := rl.AddRoom(roomID, version, data); err != nil {
		t.Fatal(err)
	}
	return r, rl
}

func TestRelayHandoverRequiresAuthorizedLocalMember(t *testing.T) {
	const member = "@alice:example.org"
	pl := map[string]any{"users": map[string]any{"@owner:remote.test": 100}, "events": map[string]any{"m.room.power_levels": 100}}
	r, rl := relayAuthFixture(t, "11", "@owner:remote.test", nil, []string{member}, pl)
	owner, members := r.relayMembers()
	before := rl.Content(r.room.RoomID, "m.room.power_levels", "")
	if err := rl.CheckEnter(r.room.RoomID, owner); err != nil {
		t.Fatalf("ordinary member should be able to invite: %v", err)
	}
	if err := r.relayHandOver(rl, owner, members); err == nil || !strings.Contains(err.Error(), "no migrated member can authorize") {
		t.Fatalf("unauthorized power-level handover accepted: %v", err)
	}
	if !reflect.DeepEqual(before, rl.Content(r.room.RoomID, "m.room.power_levels", "")) || rl.Content(r.room.RoomID, "m.room.member", rl.UserID()) != nil {
		t.Fatal("failed authorization changed relay state")
	}
	requests := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer api.Close()
	r.room.Ghosts = []string{"@ghost:example.org"}
	r.im.Appservice.client = mx.MustNew(api.URL, "as-token")
	reports, rest := r.im.RelayRooms(t.Context(), []*archive.ArchivedRoom{r.room}, rl)
	if requests != 0 || len(rest) != 0 || len(reports) != 1 || len(reports[0].Failures) != 1 {
		t.Fatal("unsupported relay handover reached the destination or fell back to replay")
	}
	state, err := r.im.Archive.ReadRoomState(r.room.RoomID)
	if err != nil || state.Done || state.NewRoomID != "" {
		t.Fatal("unsupported relay handover advanced the checkpoint")
	}
}

func TestRelaySelectsAuthorizedCreatorAndHandover(t *testing.T) {
	const creator = "@zoe:example.org"
	const admin = "@alice:example.org"
	for _, tc := range []struct {
		name, version, creator string
		additional             []string
		powerLevels            map[string]any
	}{
		{"numeric admin", "11", "@owner:remote.test", nil, map[string]any{"users": map[string]any{creator: 100}}},
		{"creator without power event", "11", creator, nil, nil},
		{"v12 creator", "12", creator, nil, map[string]any{"users": map[string]any{admin: 100}}},
		{"v12 additional creator", "12", "@owner:remote.test", []string{creator}, map[string]any{"users": map[string]any{admin: 100}}},
		{"v12 creator without power event", "12", creator, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rl := relayAuthFixture(t, tc.version, tc.creator, tc.additional, []string{creator, admin}, tc.powerLevels)
			owner, members := r.relayMembers()
			if owner != creator {
				t.Fatalf("selected %s instead of authorized creator/admin %s", owner, creator)
			}
			if err := rl.CheckEnter(r.room.RoomID, owner); err != nil {
				t.Fatal(err)
			}
			if _, err := r.relayHandOverContent(rl, owner, members); err != nil {
				t.Fatal(err)
			}
			if err := rl.Enter(r.room.RoomID, owner); err != nil {
				t.Fatal(err)
			}
			if err := r.relayHandOver(rl, owner, members); err != nil {
				t.Fatal(err)
			}
			users := rl.Content(r.room.RoomID, "m.room.power_levels", "")["users"].(map[string]any)
			if powerValue(users[rl.UserID()]) != 1 {
				t.Fatal("authorized handover did not grant relay backfill power")
			}
			if tc.version == "12" {
				if _, ok := users[creator]; ok {
					t.Fatal("implicit creator power was inserted into the users map")
				}
			}
		})
	}
}

func TestRelayInvitationChecksPowerBeforeMutation(t *testing.T) {
	const member = "@alice:example.org"
	r, rl := relayAuthFixture(t, "11", "@owner:remote.test", nil, []string{member}, map[string]any{"invite": 50})
	if err := rl.CheckEnter(r.room.RoomID, member); err == nil {
		t.Fatal("insufficient invite power accepted")
	}
	if err := rl.Enter(r.room.RoomID, member); err == nil {
		t.Fatal("unauthorized relay invitation authored")
	}
	if rl.Content(r.room.RoomID, "m.room.member", rl.UserID()) != nil {
		t.Fatal("failed invitation changed relay membership")
	}
}
