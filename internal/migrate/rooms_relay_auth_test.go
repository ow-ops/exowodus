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

func relayAuthFixture(t *testing.T, version, creator string, additional, members []string, powerLevels map[string]any, joinRules ...string) (*replay, *relay.Relay) {
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
		raw, err := json.Marshal(map[string]any{"event_id": eventID, "room_id": roomID, "sender": sender, "type": typ, "state_key": stateKey, "content": content, "origin_server_ts": 1})
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
	if len(joinRules) > 0 {
		add("$joinrules", creator, "m.room.join_rules", "", map[string]string{"join_rule": joinRules[0]})
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
	if requests == 0 || len(rest) != 0 || len(reports) != 1 || len(reports[0].Failures) != 1 {
		t.Fatal("same-name migration did not attempt trusted relay backfill or fell back to replay")
	}
	state, err := r.im.Archive.ReadRoomState(r.room.RoomID)
	if err != nil || state.Done || state.NewRoomID != "" {
		t.Fatal("unsupported relay handover advanced the checkpoint")
	}
}

func TestPublicRelayJoinDoesNotRequireInvitePower(t *testing.T) {
	const member = "@alice:example.org"
	for _, rule := range []string{"public", "invite", "knock", "restricted"} {
		t.Run(rule, func(t *testing.T) {
			r, rl := relayAuthFixture(t, "11", "@owner:remote.test", nil, []string{member}, map[string]any{"invite": 50}, rule)
			err := rl.CheckEnter(r.room.RoomID, member)
			if rule != "public" {
				if err == nil || rl.Enter(r.room.RoomID, member) == nil {
					t.Fatal("relay bypassed room admission rules")
				}
				if rl.Content(r.room.RoomID, "m.room.member", rl.UserID()) != nil {
					t.Fatal("rejected admission changed relay membership")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := rl.Enter(r.room.RoomID, member); err != nil {
				t.Fatal(err)
			}
			if rl.Content(r.room.RoomID, "m.room.member", rl.UserID())["membership"] != "join" {
				t.Fatal("relay did not join the public room")
			}
		})
	}
}

func TestOrdinaryMemberRestoresRoomThroughTrustedRelay(t *testing.T) {
	const member = "@alice:example.org"
	for _, tc := range []struct {
		name, rule  string
		invite      int
		public      bool
		ignoreLeave bool
		resume      bool
	}{
		{name: "ordinary invitation", rule: "invite"},
		{name: "public join without invite power", rule: "public", invite: 50, public: true},
		{name: "departure must be confirmed", rule: "invite", ignoreLeave: true},
		{name: "resume remote-created room", rule: "invite", resume: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rl := relayAuthFixture(t, "11", "@owner:remote.test", nil, []string{member}, map[string]any{"users": map[string]any{"@owner:remote.test": 100}, "invite": tc.invite}, tc.rule)
			r.room.Public = tc.public
			if tc.resume {
				state, err := r.im.Archive.ReadRoomState(r.room.RoomID)
				if err != nil {
					t.Fatal(err)
				}
				state.NewRoomID = r.room.RoomID
				if err := r.im.Archive.WriteRoomState(r.room.RoomID, state); err != nil {
					t.Fatal(err)
				}
			}
			var original relay.RoomData
			if _, err := r.im.Archive.ReadRoomPDUs(r.room.RoomID, &original); err != nil {
				t.Fatal(err)
			}
			peerKey := federation.GenerateSigningKey()
			left, reads, published, joins := false, 0, 0, 0
			joined := tc.resume
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case req.URL.Path == "/_matrix/key/v2/server":
					_ = json.NewEncoder(w).Encode(peerKey.GenerateKeyResponse("example.org", nil))
				case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/join/"):
					if req.URL.Query().Get("user_id") != member {
						t.Error("destination join used the wrong local member")
					}
					joins++
					joined = true
					fmt.Fprintf(w, `{"room_id":%q}`, r.room.RoomID)
				case strings.HasSuffix(req.URL.Path, "/messages"):
					reads++
					_ = json.NewEncoder(w).Encode(map[string]any{"chunk": r.room.State, "end": ""})
				case strings.HasSuffix(req.URL.Path, "/joined_members"):
					if req.URL.Query().Get("user_id") != member {
						t.Error("membership lookup used a non-member instead of the joining user")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"joined": map[string]any{member: map[string]any{}, rl.UserID(): map[string]any{}}})
				case strings.Contains(req.URL.Path, "/_matrix/federation/v1/make_leave/"):
					_ = json.NewEncoder(w).Encode(map[string]any{"room_version": "11", "event": map[string]any{
						"room_id": r.room.RoomID, "sender": rl.UserID(), "state_key": rl.UserID(), "type": "m.room.member",
						"content": map[string]string{"membership": "leave"}, "depth": 9, "origin_server_ts": 1,
						"prev_events": []string{"$destinationHead"}, "auth_events": []string{"$destinationMember"},
					}})
				case strings.Contains(req.URL.Path, "/_matrix/federation/v2/send_leave/"):
					auth := federation.ParseXMatrixAuth(req.Header.Get("Authorization"))
					if auth.Origin != rl.Name || auth.Destination != "example.org" || auth.Signature == "" {
						t.Error("departure did not use the relay's federation identity")
					}
					left = !tc.ignoreLeave
					_, _ = w.Write([]byte(`{}`))
				case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/state/m.room.member/"+member):
					if !joined {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"You don't have permission to view this room."}`))
						return
					}
					_, _ = w.Write([]byte(`{"membership":"join"}`))
				case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/state/m.room.member/"):
					membership := "join"
					if left {
						membership = "leave"
					}
					fmt.Fprintf(w, `{"membership":%q}`, membership)
				case strings.Contains(req.URL.Path, "/directory/list/room/"):
					if req.Header.Get("Authorization") != "Bearer admin-token" {
						t.Error("room publication did not use the server administrator")
					}
					published++
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected mutation or request: %s %s", req.Method, req.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			r.im.Appservice.client = mx.MustNew(api.URL, "as-token")
			r.im.Admin = &ContinuwuityAdmin{client: mx.MustNew(api.URL, "admin-token"), bot: "@conduit:example.org", room: "!admins:example.org"}
			if err := rl.Trust(t.Context(), "example.org", api.URL+"/_matrix/key/v2/server"); err != nil {
				t.Fatal(err)
			}
			reports, rest := r.im.RelayRooms(t.Context(), []*archive.ArchivedRoom{r.room}, rl)
			if tc.ignoreLeave {
				state, err := r.im.Archive.ReadRoomState(r.room.RoomID)
				if err != nil || state.Done || len(reports) != 1 || len(reports[0].Failures) != 1 || !strings.Contains(reports[0].Failures[0].Error, "departure did not update") {
					t.Fatalf("unconfirmed departure state=%+v reports=%+v error=%v", state, reports, err)
				}
				return
			}
			if len(rest) != 0 || len(reports) != 1 || len(reports[0].Failures) != 0 || !left || reads != 2 || (published == 1) != tc.public {
				t.Fatalf("reports=%+v rest=%d left=%t reads=%d published=%d", reports, len(rest), left, reads, published)
			}
			// A resumed room must not be joined again through events the destination never received.
			if wantJoins := map[bool]int{false: 1, true: 0}[tc.resume]; joins != wantJoins {
				t.Fatalf("joins through the relay = %d, want %d", joins, wantJoins)
			}
			state, err := r.im.Archive.ReadRoomState(r.room.RoomID)
			if err != nil || !state.Done || state.NewRoomID != r.room.RoomID {
				t.Fatalf("room state=%+v error=%v", state, err)
			}
			var after relay.RoomData
			if _, err := r.im.Archive.ReadRoomPDUs(r.room.RoomID, &after); err != nil || !reflect.DeepEqual(original, after) {
				t.Fatal("relay import changed the archived original events")
			}
		})
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

func TestRemoveRelayPowerEditsDestinationLevels(t *testing.T) {
	const relayUser = "@exodus:relay.test"
	for _, tc := range []struct {
		name    string
		current string
		want    string
	}{
		// Levels changed on the destination after the archive must survive.
		{name: "granted", current: `{"users":{"@alice:example.org":100,"@new:example.org":9007199254740991,"` + relayUser + `":1},"ban":50}`,
			want: `{"ban":50,"users":{"@alice:example.org":100,"@new:example.org":9007199254740991}}`},
		{name: "already removed", current: `{"users":{"@alice:example.org":100}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var put string
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch req.Method {
				case http.MethodGet:
					_, _ = w.Write([]byte(tc.current))
				case http.MethodPut:
					var body json.RawMessage
					_ = json.NewDecoder(req.Body).Decode(&body)
					put = string(body)
					_, _ = w.Write([]byte(`{"event_id":"$levels"}`))
				}
			}))
			defer api.Close()
			r := &replay{room: &archive.ArchivedRoom{RoomID: "!room:example.org"}, st: &archive.RoomImportState{NewRoomID: "!room:example.org"}, im: &Importer{Appservice: &Appservice{client: mx.MustNew(api.URL, "as-token")}}}
			if err := removeRelayPower(t.Context(), r, r.as("@alice:example.org"), "@alice:example.org", relayUser); err != nil {
				t.Fatal(err)
			}
			if put != tc.want {
				t.Fatalf("power levels sent = %s, want %s", put, tc.want)
			}
		})
	}
}

func TestEnsureRelayJoinedInvitesWhenJoinIsForbidden(t *testing.T) {
	const roomID, member = "!room:example.org", "@alice:example.org"
	rl := relay.New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	if err := rl.AddRoom(roomID, "11", relay.RoomData{}); err != nil {
		t.Fatal(err)
	}
	peerKey := federation.GenerateSigningKey()
	invited, joined, makeJoins := false, false, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.URL.Path == "/_matrix/key/v2/server":
			_ = json.NewEncoder(w).Encode(peerKey.GenerateKeyResponse("example.org", nil))
		case strings.Contains(req.URL.Path, "/state/m.room.member/"):
			if !joined {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"no membership"}`))
				return
			}
			_, _ = w.Write([]byte(`{"membership":"join"}`))
		case strings.Contains(req.URL.Path, "/make_join/"):
			makeJoins++
			if !invited {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"not invited"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"room_version": "11", "event": map[string]any{
				"room_id": roomID, "sender": rl.UserID(), "state_key": rl.UserID(), "type": "m.room.member",
				"content": map[string]string{"membership": "join"}, "depth": 9, "origin_server_ts": 1,
				"prev_events": []string{"$invite"}, "auth_events": []string{"$invite"},
			}})
		case strings.HasSuffix(req.URL.Path, "/invite"):
			if req.URL.Query().Get("user_id") != member {
				t.Error("relay invitation used the wrong member")
			}
			invited = true
			_, _ = w.Write([]byte(`{}`))
		case strings.Contains(req.URL.Path, "/send_join/"):
			joined = true
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer api.Close()
	if err := rl.Trust(t.Context(), "example.org", api.URL+"/_matrix/key/v2/server"); err != nil {
		t.Fatal(err)
	}
	c := mx.As(mx.MustNew(api.URL, "as-token"), member)
	if err := ensureRelayJoined(t.Context(), c, roomID, rl); err != nil {
		t.Fatal(err)
	}
	if !invited || !joined || makeJoins != 2 {
		t.Fatalf("invited=%t joined=%t make_join=%d", invited, joined, makeJoins)
	}
}
