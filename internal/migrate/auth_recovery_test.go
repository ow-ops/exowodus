package migrate

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"exodus/internal/archive"
	"exodus/internal/relay"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

type recoveryTransport func(*http.Request) (*http.Response, error)

func (f recoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func signedAuth(t *testing.T, key *federation.SigningKey, room, server, version string, auth []string) relay.EventJSON {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"room_id": room, "sender": "@bob:" + server, "type": "m.room.member", "state_key": "@bob:" + server, "content": map[string]string{"membership": "join"}, "auth_events": auth, "prev_events": []string{}, "origin_server_ts": time.Now().UnixMilli(), "depth": 1})
	if err != nil {
		t.Fatal(err)
	}
	p, err := relay.ParsePDU(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Sign(id.RoomVersion(version), server, key.ID, key.Priv); err != nil {
		t.Fatal(err)
	}
	eventID, err := p.GetEventID(id.RoomVersion(version))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = jsonv2.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return relay.EventJSON{EventID: string(eventID), PDU: raw}
}

func recoveryClient(t *testing.T, handler http.HandlerFunc) *federation.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := federation.NewClient("example.org", federation.GenerateSigningKey(), federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
	c.ResponseSizeLimit = 1 << 20
	c.HTTP = &http.Client{Transport: recoveryTransport(func(req *http.Request) (*http.Response, error) {
		cloned := req.Clone(req.Context())
		cloned.URL.Scheme = "http"
		cloned.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		return http.DefaultTransport.RoundTrip(cloned)
	})}
	return c
}

func keyJSON(t *testing.T, key *federation.SigningKey, server string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(key.GenerateKeyResponse(server, nil))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthRecoveryAndOfflineResume(t *testing.T) {
	const roomID, peer = "!room:example.org", "remote.example"
	dump, timeline := checkpointFixture(t)
	key := federation.GenerateSigningKey()
	first := signedAuth(t, key, roomID, peer, "11", nil)
	second := signedAuth(t, key, roomID, peer, "11", []string{first.EventID})
	var requests atomic.Int32
	c := recoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/_matrix/key/v2/server" {
			_, _ = w.Write(keyJSON(t, key, peer))
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), `origin="example.org"`) {
			t.Error("request did not use the source federation identity")
		}
		event := first
		if strings.HasSuffix(r.URL.Path, second.EventID) {
			event = second
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pdus": []json.RawMessage{event.PDU}})
	})
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	makeExporter := func() *Exporter {
		return &Exporter{Archive: a, TuwunelDump: dump, authRecovery: &authRecovery{client: c, keys: map[string][]*federation.ServerKeyResponse{}}}
	}
	if err := dump.indexRelayData(t.Context()); err != nil {
		t.Fatal(err)
	}
	var message map[string]any
	if err := json.Unmarshal(timeline[2], &message); err != nil {
		t.Fatal(err)
	}
	messageID := message["event_id"].(string)
	message["sender"], message["auth_events"] = "@bob:"+peer, []string{second.EventID}
	modified, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	dump.relayRooms[roomID].events[messageID] = modified
	data, err := makeExporter().tuwunelRoomMetadata(t.Context(), roomID)
	if err != nil {
		t.Fatal(err)
	}
	if data.required[first.EventID] == 0 || data.required[second.EventID] == 0 {
		t.Fatal("recovered auth chain was incomplete")
	}
	if len(dump.relayRooms[roomID].timeline) != 3 {
		t.Fatal("recovered outliers were added to the accepted timeline")
	}
	reader := tuwunelRoomReader{dump: dump, room: dump.relayRooms[roomID], files: map[string]*os.File{}}
	defer reader.Close()
	for _, event := range []relay.EventJSON{first, second} {
		raw, err := reader.read(t.Context(), event.EventID)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := originalEventFields(event.PDU)
		got, _ := originalEventFields(raw)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("recovery changed event %s", event.EventID)
		}
	}
	keys, err := a.ServerKeys()
	if err != nil || len(keys[peer]) == 0 {
		t.Fatalf("recovered signing keys missing: %v", err)
	}
	before := requests.Load()
	clear(dump.relayRooms[roomID].recovered)
	c.HTTP.Transport = recoveryTransport(func(*http.Request) (*http.Response, error) {
		t.Error("resume used the network")
		return nil, errors.New("offline")
	})
	if _, err := makeExporter().tuwunelRoomMetadata(t.Context(), roomID); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != before {
		t.Fatal("resume downloaded recovered events again")
	}
}

func TestRecoveredAuthValidation(t *testing.T) {
	const room, peer = "!room:example.org", "remote.example"
	for _, version := range []string{"11", "12"} {
		key := federation.GenerateSigningKey()
		event := signedAuth(t, key, room, peer, version, nil)
		for _, kind := range []string{"valid", "wrong room", "wrong ID", "bad signature", "bad content", "bad key response"} {
			t.Run(version+"/"+kind, func(t *testing.T) {
				r := &authRecovery{keys: map[string][]*federation.ServerKeyResponse{}, baseKeys: map[string][]json.RawMessage{peer: {keyJSON(t, key, peer)}}}
				raw, wanted := event.PDU, event.EventID
				var object map[string]any
				if err := json.Unmarshal(raw, &object); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "wrong room":
					object["room_id"] = "!other:example.org"
				case "wrong ID":
					wanted = "$different"
				case "bad signature":
					object["signatures"] = map[string]any{peer: map[string]string{string(key.ID): "invalid"}}
				case "bad content":
					object["content"] = map[string]string{"membership": "join", "displayname": "unverified"}
				case "bad key response":
					r.baseKeys[peer] = []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"server_name":%q,"verify_keys":{}}`, peer))}
				}
				raw, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				verified, _, err := r.verify(t.Context(), room, wanted, version, raw)
				if kind == "valid" || kind == "bad content" {
					if err != nil {
						t.Fatal(err)
					}
					if kind == "bad content" && strings.Contains(string(verified), "unverified") {
						t.Fatal("retained content with an invalid hash")
					}
				} else if err == nil {
					t.Fatal("accepted invalid recovered event")
				}
			})
		}
	}
}

func TestRecoveryPeerSelection(t *testing.T) {
	got := recoveryPeers("!room:creator.example", json.RawMessage(`{"sender":"@bob:sender.example"}`), map[string]string{
		relay.StateKey("m.room.member", "@alice:example.org"): "$local",
		relay.StateKey("m.room.member", "@a:sender.example"):  "$duplicate",
		relay.StateKey("m.room.member", "@b:other.example"):   "$other",
	}, "example.org")
	if !reflect.DeepEqual(got, []string{"sender.example", "creator.example", "other.example"}) {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	e := &Exporter{}
	if err := e.recoverAuth(ctx, "", nil, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestAuthRecoveryPeerFailureAndFallback(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			dump, _ := checkpointFixture(t)
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			const room = "!room:example.org"
			data, err := dump.roomRelayMetadata(t.Context(), room)
			if err != nil {
				t.Fatal(err)
			}
			data.CurrentState[relay.StateKey("m.room.member", "@bob:remote.example")] = "$remote"
			key := federation.GenerateSigningKey()
			event := signedAuth(t, key, room, "remote.example", "11", nil)
			var failed atomic.Int32
			c := recoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_matrix/key/v2/server" {
					_, _ = w.Write(keyJSON(t, key, "remote.example"))
					return
				}
				if unavailable || strings.Contains(r.Header.Get("Authorization"), `destination="bad.example"`) {
					failed.Add(1)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"pdus": []json.RawMessage{event.PDU}})
			})
			e := &Exporter{Archive: a, TuwunelDump: dump, authRecovery: &authRecovery{client: c, keys: map[string][]*federation.ServerKeyResponse{}}}
			err = e.recoverAuth(t.Context(), room, data, event.EventID, json.RawMessage(`{"sender":"@someone:bad.example"}`))
			if unavailable {
				if err == nil || len(a.Manifest.SkippedRooms) != 0 {
					t.Fatal("failed recovery silently skipped the room")
				}
				if _, err := os.Stat(a.RecoveredAuthPath(room, event.EventID)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed response was cached")
				}
			} else if err != nil || failed.Load() != 1 {
				t.Fatalf("fallback failed: %v, failures=%d", err, failed.Load())
			}
		})
	}
}

func TestAuthRecoveryRejectsOversizedResponse(t *testing.T) {
	c := recoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"pdus":[],"padding":"` + strings.Repeat("x", 2<<20) + `"}`))
	})
	if _, err := c.GetEvent(t.Context(), "remote.example", "$missing"); err == nil {
		t.Fatal("oversized recovery response accepted")
	}
}
