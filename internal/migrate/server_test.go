package migrate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"exodus/internal/archive"
)

func TestRemoteToDeviceMessagesRetainedForProxy(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	message := archive.ToDevice{
		Key: "inbox/1", Sender: "@remote:other.org", Recipient: "@alice:example.org", DeviceID: "PHONE", Type: "m.room.encrypted",
		Content: json.RawMessage(`{"ciphertext":"unchanged"}`),
	}
	srv := &archive.Server{ToDevice: []archive.ToDevice{message}}
	if err := a.WriteServer(srv); err != nil {
		t.Fatal(err)
	}
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
	if err := im.CheckLosslessImport(nil, nil, srv, false); err != nil {
		t.Fatal(err)
	}
	state := &archive.ServerImportState{ToDevice: map[string]bool{}}
	var failures []Failure
	notes := im.deliverToDevice(t.Context(), srv.ToDevice, state, &failures)
	if len(failures) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "retained for delivery by exodus proxy") || state.ToDevice[message.Key] {
		t.Fatalf("remote message not retained: %v %v %+v", failures, notes, state)
	}
	stored, err := a.ReadServer()
	if err != nil || len(stored.ToDevice) != 1 {
		t.Fatal("archived message missing")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, stored.ToDevice[0].Content); err != nil || compact.String() != string(message.Content) {
		t.Fatal("archived ciphertext changed")
	}
}

func TestTokenLimit(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	ptr := func(v int) *int { return &v }
	ts := func(v int64) *int64 { return &v }
	tests := []struct {
		name    string
		token   archive.RegistrationToken
		want    string
		wantErr bool
	}{
		{name: "unlimited", want: "--immortal"},
		{name: "remaining uses", token: archive.RegistrationToken{UsesAllowed: ptr(5), Completed: 2}, want: "--max-uses 3"},
		{name: "used up", token: archive.RegistrationToken{UsesAllowed: ptr(2), Completed: 2}, wantErr: true},
		{name: "remaining lifetime", token: archive.RegistrationToken{ExpiryTime: ts(1_060_000)}, want: "--max-age 60s"},
		{name: "expired", token: archive.RegistrationToken{ExpiryTime: ts(999_000)}, wantErr: true},
		{name: "uses win over expiry", token: archive.RegistrationToken{UsesAllowed: ptr(1), ExpiryTime: ts(1_060_000)}, want: "--max-uses 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenLimit(tt.token, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
