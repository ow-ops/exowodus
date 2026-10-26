package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

func TestRelaySignedSelfLeave(t *testing.T) {
	for _, version := range []string{"11", "12"} {
		t.Run(version, func(t *testing.T) {
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
			if err := rl.Enter(roomID, member); err != nil {
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
			leaves := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if req.URL.Path == "/_matrix/key/v2/server" {
					_ = json.NewEncoder(w).Encode(peerKey.GenerateKeyResponse(peer, nil))
					return
				}
				verified, authErr := auth.Authenticate(req)
				if authErr != nil {
					t.Errorf("leave request authentication: %v", authErr)
					w.WriteHeader(401)
					return
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
				if !p.VerifyContentHash() {
					t.Error("leave content hash is invalid")
				}
				if err := p.VerifySignature(id.RoomVersion(version), rl.Name, func(server string, keyID id.KeyID, minValidUntil time.Time) (id.SigningKey, time.Time, error) {
					return rl.key.Pub, time.Now().Add(time.Hour), nil
				}); err != nil {
					t.Errorf("leave PDU signature: %v", err)
				}
				eventID, err := p.GetEventID(id.RoomVersion(version))
				if err != nil || req.Method != http.MethodPut || req.URL.Path != fmt.Sprintf("/_matrix/federation/v2/send_leave/%s/%s", roomID, eventID) {
					t.Errorf("leave route or event ID mismatch: %s error=%v", req.URL.Path, err)
				}
				if p.Sender != id.UserID(rl.UserID()) || p.StateKey == nil || *p.StateKey != rl.UserID() || string(p.Content) != `{"membership":"leave"}` {
					t.Error("leave was not authored by the relay for itself")
				}
				if rl.Content(roomID, "m.room.member", rl.UserID())["membership"] != "leave" {
					t.Error("leave state unavailable while destination handles the event")
				}
				leaves++
				_, _ = w.Write([]byte(`{}`))
			}))
			defer api.Close()
			if err := rl.Trust(t.Context(), peer, api.URL+"/_matrix/key/v2/server"); err != nil {
				t.Fatal(err)
			}
			if err := rl.Leave(t.Context(), roomID); err != nil || leaves != 1 {
				t.Fatalf("leave error=%v requests=%d", err, leaves)
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
