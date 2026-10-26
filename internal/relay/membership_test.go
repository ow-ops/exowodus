package relay

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

func TestRelayInvitations(t *testing.T) {
	const peer, roomID = "example.org", "!room:example.org"
	key := federation.GenerateSigningKey()
	rl := New("relay.test", peer, key, nil)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(key.GenerateKeyResponse(peer, nil))
	}))
	defer keys.Close()
	if err := rl.Trust(t.Context(), peer, keys.URL); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(rl.handler())
	defer api.Close()
	client := federation.NewClient(peer, key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
	client.HTTP.Transport = peerTransport{peer: rl.Name, scheme: "http", host: strings.TrimPrefix(api.URL, "http://")}
	for _, tc := range []struct {
		name string
		edit func(*pdu.PDU, *federation.ReqSendInvite, *id.EventID)
	}{
		{name: "valid"},
		{name: "wrong recipient", edit: func(p *pdu.PDU, _ *federation.ReqSendInvite, _ *id.EventID) { *p.StateKey = "@other:relay.test" }},
		{name: "wrong sender", edit: func(p *pdu.PDU, _ *federation.ReqSendInvite, _ *id.EventID) { p.Sender = "@alice:other.test" }},
		{name: "wrong room", edit: func(p *pdu.PDU, _ *federation.ReqSendInvite, _ *id.EventID) { p.RoomID = "!other:example.org" }},
		{name: "wrong version", edit: func(_ *pdu.PDU, req *federation.ReqSendInvite, _ *id.EventID) { req.RoomVersion = "12" }},
		{name: "wrong event ID", edit: func(_ *pdu.PDU, _ *federation.ReqSendInvite, eventID *id.EventID) { *eventID = "$wrong" }},
		{name: "unsigned", edit: func(p *pdu.PDU, _ *federation.ReqSendInvite, _ *id.EventID) { p.Signatures = nil }},
		{name: "changed content", edit: func(p *pdu.PDU, _ *federation.ReqSendInvite, _ *id.EventID) {
			p.Content = json.RawMessage(`{"membership":"invite","displayname":"changed"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := rl.AddRoom(roomID, "11", RoomData{}); err != nil {
				t.Fatal(err)
			}
			target := rl.UserID()
			p := &pdu.PDU{RoomID: roomID, Sender: "@alice:example.org", Type: "m.room.member", StateKey: &target, Content: json.RawMessage(`{"membership":"invite"}`), OriginServerTS: time.Now().UnixMilli()}
			if err := p.Sign("11", peer, key.ID, key.Priv); err != nil {
				t.Fatal(err)
			}
			eventID, err := p.GetEventID("11")
			if err != nil {
				t.Fatal(err)
			}
			req := federation.ReqSendInvite{RoomVersion: "11"}
			if tc.edit != nil {
				tc.edit(p, &req, &eventID)
			}
			req.Event, err = jsonv2.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var resp federation.RespSendInvite
			_, _, err = client.MakeFullRequest(t.Context(), federation.RequestParams{
				ServerName: rl.Name, Method: http.MethodPut,
				Path:         federation.URLPath{"v2", "invite", roomID, eventID},
				Authenticate: true, RequestJSON: &req, ResponseJSON: &resp,
			})
			if tc.edit != nil {
				if err == nil || len(rl.room(roomID).events) != 0 {
					t.Fatalf("invalid invite accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			signed, err := ParsePDU(resp.Event)
			if err != nil {
				t.Fatal(err)
			}
			returnedID, err := signed.GetEventID("11")
			if err != nil || returnedID != eventID || !signed.VerifyContentHash() {
				t.Fatalf("invite changed: ID=%s error=%v", returnedID, err)
			}
			if err := signed.VerifySignature("11", rl.Name, func(string, id.KeyID, time.Time) (id.SigningKey, time.Time, error) {
				return rl.key.Pub, time.Now().Add(time.Hour), nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
