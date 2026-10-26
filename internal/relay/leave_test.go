package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

// destinationFixture serves make_join/make_leave templates referencing
// destination-only events, and records the signed membership events.
func destinationFixture(t *testing.T, version string, edit func(map[string]any)) (*Relay, string, *[]*pdu.PDU) {
	t.Helper()
	const member, peer = "@alice:example.org", "destination.test"
	roomID, createID := "!room:example.org", "$create"
	if version == "12" {
		roomID = "!" + strings.Repeat("A", 43)
		createID = "$" + roomID[1:]
	}
	rl := New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	data := RoomData{CurrentState: map[string]string{}}
	add := func(eventID, sender, typ, key string, content any) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"event_id": eventID, "room_id": roomID, "sender": sender, "type": typ, "state_key": key, "content": content})
		if err != nil {
			t.Fatal(err)
		}
		data.Events = append(data.Events, EventJSON{EventID: eventID, PDU: raw})
		data.CurrentState[StateKey(typ, key)] = eventID
	}
	add(createID, "@owner:remote.test", "m.room.create", "", map[string]string{"room_version": version})
	add("$member", member, "m.room.member", member, map[string]string{"membership": "join"})
	add("$power", "@owner:remote.test", "m.room.power_levels", "", map[string]any{"users": map[string]any{"@admin:remote.test": 100}})
	if err := rl.AddRoom(roomID, version, data); err != nil {
		t.Fatal(err)
	}
	cache := federation.NewInMemoryCache()
	response, err := rl.keyResponse(rl.Name)
	if err != nil {
		t.Fatal(err)
	}
	rawKeys, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var keys federation.ServerKeyResponse
	if err := json.Unmarshal(rawKeys, &keys); err != nil {
		t.Fatal(err)
	}
	cache.StoreKeys(&keys)
	auth := federation.NewServerAuth(nil, cache, func(federation.XMatrixAuth) string { return peer })
	peerKey := federation.GenerateSigningKey()
	var sent []*pdu.PDU
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/_matrix/key/v2/server" {
			_ = json.NewEncoder(w).Encode(peerKey.GenerateKeyResponse(peer, nil))
			return
		}
		verified, authErr := auth.Authenticate(req)
		if authErr != nil {
			t.Errorf("membership request authentication: %v", authErr)
			w.WriteHeader(401)
			return
		}
		for _, membership := range []string{"join", "leave"} {
			if req.Method == http.MethodGet && req.URL.Path == fmt.Sprintf("/_matrix/federation/v1/make_%s/%s/%s", membership, roomID, rl.UserID()) {
				template := map[string]any{
					"room_id": roomID, "sender": rl.UserID(), "state_key": rl.UserID(), "type": "m.room.member",
					"content": map[string]string{"membership": membership}, "depth": 40, "origin_server_ts": 1,
					"prev_events": []string{"$destinationHead"}, "auth_events": []string{"$destinationPower", "$destinationMember"},
				}
				if edit != nil {
					edit(template)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"room_version": version, "event": template})
				return
			}
		}
		var raw json.RawMessage
		if err := json.NewDecoder(verified.Body).Decode(&raw); err != nil {
			t.Error(err)
		}
		p, err := ParsePDU(raw)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		eventID, err := p.GetEventID(id.RoomVersion(version))
		var membership struct {
			Membership string `json:"membership"`
		}
		_ = json.Unmarshal(p.Content, &membership)
		if err != nil || req.Method != http.MethodPut || req.URL.Path != fmt.Sprintf("/_matrix/federation/v2/send_%s/%s/%s", membership.Membership, roomID, eventID) {
			t.Errorf("membership route or event ID mismatch: %s error=%v", req.URL.Path, err)
		}
		if membership.Membership == "join" && req.URL.Query().Get("omit_members") != "true" {
			t.Error("relay join requested the full member list")
		}
		if !p.VerifyContentHash() {
			t.Error("membership content hash is invalid")
		}
		if err := p.VerifySignature(id.RoomVersion(version), rl.Name, func(string, id.KeyID, time.Time) (id.SigningKey, time.Time, error) {
			return rl.key.Pub, time.Now().Add(time.Hour), nil
		}); err != nil {
			t.Errorf("membership PDU signature: %v", err)
		}
		sent = append(sent, p)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(api.Close)
	if err := rl.Trust(t.Context(), peer, api.URL+"/_matrix/key/v2/server"); err != nil {
		t.Fatal(err)
	}
	return rl, roomID, &sent
}

func TestRelayMembershipUsesDestinationTemplates(t *testing.T) {
	for _, version := range []string{"11", "12"} {
		t.Run(version, func(t *testing.T) {
			rl, roomID, sent := destinationFixture(t, version, nil)
			if err := rl.Join(t.Context(), roomID); err != nil {
				t.Fatal(err)
			}
			if rl.Content(roomID, "m.room.member", rl.UserID())["membership"] != "join" {
				t.Fatal("accepted join missing from the relay's room")
			}
			if err := rl.Leave(t.Context(), roomID); err != nil {
				t.Fatal(err)
			}
			if len(*sent) != 2 {
				t.Fatalf("membership events sent = %d", len(*sent))
			}
			for _, p := range *sent {
				if !slices.Equal(p.PrevEvents, []id.EventID{"$destinationHead"}) || !slices.Equal(p.AuthEvents, []id.EventID{"$destinationPower", "$destinationMember"}) {
					t.Fatalf("membership references prev=%v auth=%v", p.PrevEvents, p.AuthEvents)
				}
			}
			if rl.Content(roomID, "m.room.member", rl.UserID())["membership"] != "leave" {
				t.Fatal("accepted leave missing from the relay's room")
			}
		})
	}
}

func TestRelayMembershipRejectsInvalidTemplates(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"other sender":     func(m map[string]any) { m["sender"] = "@alice:example.org" },
		"other state key":  func(m map[string]any) { m["state_key"] = "@alice:example.org" },
		"other room":       func(m map[string]any) { m["room_id"] = "!other:example.org" },
		"other membership": func(m map[string]any) { m["content"] = map[string]string{"membership": "ban"} },
		"other type":       func(m map[string]any) { m["type"] = "m.room.message" },
	} {
		t.Run(name, func(t *testing.T) {
			rl, roomID, sent := destinationFixture(t, "11", edit)
			if rl.Join(t.Context(), roomID) == nil || rl.Leave(t.Context(), roomID) == nil || len(*sent) != 0 {
				t.Fatalf("invalid template signed and sent: %d", len(*sent))
			}
		})
	}
}

func TestPeerTransportRejectsOtherDestinations(t *testing.T) {
	transport := peerTransport{peer: "destination.test", scheme: "https", host: "destination.test"}
	for _, target := range []string{"matrix-federation://other.test/path", "https://destination.test/path"} {
		req := httptest.NewRequest(http.MethodPut, target, nil)
		if _, err := transport.RoundTrip(req); err == nil {
			t.Fatalf("forwarded unexpected relay destination %s", target)
		}
	}
}
