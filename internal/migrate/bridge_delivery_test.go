package migrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

func TestCanceledDeviceDeliveryStopsWithoutFailureFlood(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	state := &archive.ServerImportState{ToDevice: map[string]bool{}}
	var failures []Failure
	im.deliverToDevice(ctx, make([]archive.ToDevice, 20000), state, &failures)
	if len(failures) != 1 || len(state.ToDevice) != 0 || !strings.Contains(failures[0].Error, "retained for retry") {
		t.Fatalf("cancellation checkpoint or failure count is wrong: %d", len(failures))
	}
}

func TestBridgeQueuedDeviceMessages(t *testing.T) {
	for _, sender := range []string{"@puppet_123:example.org", "@puppet_bot:example.org"} {
		t.Run(sender, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.WriteImportState("@alice:example.org", &archive.ImportState{DestUserID: "@alice:example.org", Devices: map[string]bool{"PHONE": true}}); err != nil {
				t.Fatal(err)
			}
			var registrations, deliveries int
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer bridge-test-token" {
					t.Error("queued bridge message used another appservice")
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/register"):
					registrations++
					var body struct {
						Username     string `json:"username"`
						InhibitLogin bool   `json:"inhibit_login"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Username != mx.Localpart(sender) || !body.InhibitLogin {
						t.Errorf("registration=%+v", body)
					}
					_, _ = w.Write([]byte(`{"user_id":"` + sender + `"}`))
				case strings.Contains(r.URL.Path, "/sendToDevice/"):
					deliveries++
					if r.URL.Query().Get("user_id") != sender {
						t.Error("queued message sender changed")
					}
					var body struct {
						Messages map[string]map[string]json.RawMessage `json:"messages"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if string(body.Messages["@alice:example.org"]["PHONE"]) != `{"ciphertext":"secret"}` {
						t.Error("queued payload changed")
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer api.Close()
			b, err := parseBridge([]byte(testBridgeRegistration), mx.MustNew(api.URL, ""))
			if err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Bridges: []*Bridge{b}, Migrated: map[string]bool{"@alice:example.org": true}}
			message := archive.ToDevice{Key: "queued-bridge-key", Sender: sender, Recipient: "@alice:example.org", DeviceID: "PHONE", Type: "m.room.encrypted", Content: json.RawMessage(`{"ciphertext":"secret"}`)}
			state := &archive.ServerImportState{ToDevice: map[string]bool{}}
			var failures []Failure
			im.deliverToDevice(t.Context(), []archive.ToDevice{message}, state, &failures)
			im.deliverToDevice(t.Context(), []archive.ToDevice{message}, state, &failures)
			if registrations != 1 || deliveries != 1 || len(failures) != 0 || !state.ToDevice[message.Key] {
				t.Fatalf("registrations=%d deliveries=%d failures=%+v state=%+v", registrations, deliveries, failures, state)
			}
		})
	}
}

func TestQueuedDeviceMessagesRejectUnrestoredAccounts(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteImportState("@alice:example.org", &archive.ImportState{DestUserID: "@alice:example.org", Devices: map[string]bool{"PHONE": true}}); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Migrated: map[string]bool{"@alice:example.org": true}}
	for _, message := range []archive.ToDevice{
		{Key: "sender", Sender: "@missing:example.org", Recipient: "@alice:example.org", DeviceID: "PHONE"},
		{Key: "recipient", Sender: "@alice:example.org", Recipient: "@missing:example.org"},
		{Key: "device", Sender: "@alice:example.org", Recipient: "@alice:example.org", DeviceID: "NOT_RESTORED"},
	} {
		state := &archive.ServerImportState{ToDevice: map[string]bool{}}
		var failures []Failure
		im.deliverToDevice(t.Context(), []archive.ToDevice{message}, state, &failures)
		if len(failures) != 1 || state.ToDevice[message.Key] {
			t.Fatalf("failures=%+v state=%+v", failures, state)
		}
	}
}

func TestBridgeRecipientDevices(t *testing.T) {
	const recipient = "@bridgebot:example.org"
	for _, tc := range []struct {
		name, response string
		status         int
		deliver        bool
	}{
		{"original device", `{"devices":[{"device_id":"OLD"}]}`, 200, true},
		{"different device", `{"devices":[{"device_id":"NEW"}]}`, 200, false},
		{"no device", `{"devices":[]}`, 200, false},
		{"rejected token", `{"errcode":"M_FORBIDDEN"}`, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			var queries, deliveries int
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/devices"):
					queries++
					if r.Header.Get("Authorization") != "Bearer bridge-test-token" || r.URL.Query().Get("user_id") != recipient {
						t.Error("recipient lookup did not use its bridge identity")
					}
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.response))
				case strings.Contains(r.URL.Path, "/sendToDevice/"):
					deliveries++
					if r.Header.Get("Authorization") != "Bearer migration-token" || r.URL.Query().Get("user_id") != "@alice:example.org" {
						t.Error("recipient bridge changed the message sender")
					}
					var body struct {
						Messages map[string]map[string]json.RawMessage `json:"messages"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || string(body.Messages[recipient]["OLD"]) != `{"ciphertext":"unchanged"}` {
						t.Errorf("queued ciphertext or device changed: body=%+v error=%v", body, err)
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			dest := mx.MustNew(api.URL, "migration-token")
			b, err := parseBridge([]byte(strings.ReplaceAll(testBridgeRegistration, "sender_localpart: puppet_bot", "sender_localpart: bridgebot")), dest)
			if err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Appservice: &Appservice{client: dest}, Bridges: []*Bridge{b}, Migrated: map[string]bool{"@alice:example.org": true}}
			messages := []archive.ToDevice{
				{Key: "one", Sender: "@alice:example.org", Recipient: recipient, DeviceID: "OLD", Type: "m.room.encrypted", Content: json.RawMessage(`{"ciphertext":"unchanged"}`)},
				{Key: "two", Sender: "@alice:example.org", Recipient: recipient, DeviceID: "OLD", Type: "m.room.encrypted", Content: json.RawMessage(`{"ciphertext":"unchanged"}`)},
			}
			state := &archive.ServerImportState{ToDevice: map[string]bool{}}
			var failures []Failure
			im.deliverToDevice(t.Context(), messages, state, &failures)
			if queries != 1 || (deliveries == 2) != tc.deliver || state.ToDevice["one"] != tc.deliver || state.ToDevice["two"] != tc.deliver || (len(failures) == 0) != tc.deliver {
				t.Fatalf("queries=%d deliveries=%d state=%+v failures=%+v", queries, deliveries, state, failures)
			}
			if tc.deliver {
				im.deliverToDevice(t.Context(), messages, state, &failures)
				if queries != 1 || deliveries != 2 {
					t.Fatal("resumed import redelivered completed messages")
				}
			}
		})
	}
}

func TestBridgePendingInvites(t *testing.T) {
	for _, tc := range []struct {
		name, inviter string
		configured    bool
		status        int
		wantInvite    bool
	}{
		{"sender", "@puppet_bot:example.org", true, 200, true},
		{"puppet", "@puppet_123:example.org", true, 200, true},
		{"registration missing", "@puppet_bot:example.org", false, 200, false},
		{"unrelated account", "@other:example.org", true, 200, false},
		{"subscription only", "@shared_123:example.org", true, 200, false},
		{"remote account", "@puppet_bot:other.org", true, 200, false},
		{"membership missing", "@puppet_bot:example.org", true, 403, true},
		{"room missing", "@puppet_bot:example.org", true, 404, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invites int
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer bridge-test-token" {
					t.Error("bridge action used another identity")
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/register"):
					_, _ = w.Write([]byte(`{}`))
				case strings.HasSuffix(r.URL.Path, "/invite"):
					invites++
					var request struct {
						UserID string `json:"user_id"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.UserID != "@alice:example.org" || r.URL.Query().Get("user_id") != tc.inviter {
						t.Errorf("invite identity changed: request=%+v error=%v", request, err)
					}
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			b, err := parseBridge([]byte(testBridgeRegistration), mx.MustNew(api.URL, ""))
			if err != nil {
				t.Fatal(err)
			}
			u := &archive.User{UserID: "@alice:example.org", Invites: []archive.Invite{{RoomID: "!invite:example.org", Inviter: tc.inviter}}}
			im := &Importer{Archive: &archive.Archive{Manifest: archive.Manifest{ServerName: "example.org"}}, sessions: map[string]destAccount{u.UserID: {id: u.UserID}}}
			if tc.configured {
				im.Bridges = []*Bridge{b}
			}
			failures := im.RestoreInvites(t.Context(), []*archive.User{u})
			if (invites == 1) != tc.wantInvite || (len(failures) == 0) != (tc.wantInvite && tc.status == 200) {
				t.Fatalf("invites=%d failures=%+v", invites, failures)
			}
		})
	}
}

func TestBridgeSubscriptionCannotClaimRecipient(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("subscription tried to access recipient: %s", r.URL.Path)
		w.WriteHeader(403)
	}))
	defer api.Close()
	b, err := parseBridge([]byte(testBridgeRegistration), mx.MustNew(api.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: &archive.Archive{Manifest: archive.Manifest{ServerName: "example.org"}}, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Bridges: []*Bridge{b}}
	message := archive.ToDevice{Key: "subscription", Sender: "@alice:example.org", Recipient: "@shared_123:example.org", DeviceID: "OLD"}
	state := &archive.ServerImportState{ToDevice: map[string]bool{}}
	var failures []Failure
	im.deliverToDevice(t.Context(), []archive.ToDevice{message}, state, &failures)
	if len(failures) != 1 || state.ToDevice[message.Key] || !strings.Contains(failures[0].Error, "recipient account was not restored") {
		t.Fatalf("subscription claimed account ownership: state=%+v failures=%+v", state, failures)
	}
}

func TestBridgeOwnership(t *testing.T) {
	b, err := parseBridge([]byte(testBridgeRegistration), nil)
	if err != nil {
		t.Fatal(err)
	}
	broad, err := parseBridge([]byte(strings.ReplaceAll(strings.ReplaceAll(testBridgeRegistration, "example-bridge", "subscriber"), "exclusive: true", "exclusive: false")), nil)
	if err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: &archive.Archive{Manifest: archive.Manifest{ServerName: "example.org"}}, Bridges: []*Bridge{broad, b}}
	if im.bridgeFor("@puppet_123:example.org") != b {
		t.Fatal("exclusive owner lost to a subscription")
	}
	if im.bridgeFor("@puppet_bot:elsewhere.org") != nil {
		t.Fatal("remote bridge sender was claimed")
	}
}

func TestRestoreBridgeRejectsChangedRegistration(t *testing.T) {
	b, err := parseBridge([]byte(strings.ReplaceAll(testBridgeRegistration, "bridge-test-token", "changed-token")), nil)
	if err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: &archive.Archive{Manifest: archive.Manifest{ServerName: "example.org"}}, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Bridges: []*Bridge{b}}
	err = im.RestoreBridges(t.Context(), &archive.Server{AppserviceRegistrations: []string{testBridgeRegistration}})
	if err == nil || !strings.Contains(err.Error(), "differs from the archived registration") {
		t.Fatalf("changed credentials accepted: %v", err)
	}
}
