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
