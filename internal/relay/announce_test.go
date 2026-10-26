package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"maunium.net/go/mautrix/federation"
)

func TestAnnounceSendsAuthoredEventsToOtherServers(t *testing.T) {
	const roomID, owner = "!room:example.org", "@owner:example.org"
	rl := New("relay.test", "example.org", federation.GenerateSigningKey(), nil)
	data := RoomData{CurrentState: map[string]string{}}
	add := func(eventID, sender, typ, key string, content any) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"event_id": eventID, "room_id": roomID, "sender": sender, "type": typ, "state_key": key, "content": content, "depth": len(data.Events) + 1})
		if err != nil {
			t.Fatal(err)
		}
		data.Events = append(data.Events, EventJSON{EventID: eventID, PDU: raw})
		data.CurrentState[StateKey(typ, key)] = eventID
	}
	add("$create", owner, "m.room.create", "", map[string]string{"creator": owner, "room_version": "11"})
	add("$owner", owner, "m.room.member", owner, map[string]string{"membership": "join"})
	add("$power", owner, "m.room.power_levels", "", map[string]any{"users": map[string]int{owner: 100}})
	add("$rules", owner, "m.room.join_rules", "", map[string]string{"join_rule": "invite"})
	add("$bob", "@bob:remote.test", "m.room.member", "@bob:remote.test", map[string]string{"membership": "join"})
	add("$carol", "@carol:remote.test", "m.room.member", "@carol:remote.test", map[string]string{"membership": "join"})
	add("$dave", "@dave:gone.test", "m.room.member", "@dave:gone.test", map[string]string{"membership": "leave"})
	if err := rl.AddRoom(roomID, "11", data); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	received := map[string][]string{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var txn federation.ReqSendTransaction
		if err := json.NewDecoder(r.Body).Decode(&txn); err != nil || !strings.HasPrefix(r.URL.Path, "/_matrix/federation/v1/send/") || txn.Origin != rl.Name {
			t.Errorf("invalid transaction to %s: %v", r.URL.Path, err)
		}
		mu.Lock()
		for _, raw := range txn.PDUs {
			p, err := ParsePDU(raw)
			if err != nil {
				t.Error(err)
				continue
			}
			received[r.Host] = append(received[r.Host], string(p.Type)+" "+*p.StateKey+" "+string(p.Sender))
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"pdus":{}}`))
	}))
	defer api.Close()
	rl.remote.HTTP.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		forward := req.Clone(req.Context())
		forward.URL.Scheme, forward.URL.Host = "http", strings.TrimPrefix(api.URL, "http://")
		forward.Host = req.URL.Host
		return http.DefaultTransport.RoundTrip(forward)
	})

	if err := rl.Enter(roomID, owner); err != nil {
		t.Fatal(err)
	}
	if err := rl.Announce(t.Context(), roomID); err != nil {
		t.Fatal(err)
	}
	want := []string{"m.room.member @exodus:relay.test " + owner, "m.room.member @exodus:relay.test @exodus:relay.test"}
	if len(received) != 1 || !slices.Equal(received["remote.test"], want) {
		t.Fatalf("servers received %v, want only remote.test with %v", received, want)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
