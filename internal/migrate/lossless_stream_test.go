package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/relay"
)

func TestLosslessStreamChecksOriginalEventIDs(t *testing.T) {
	const roomID = "!room:example.org"
	raw := json.RawMessage(`{"auth_events":[],"content":{"body":"hello","msgtype":"m.text"},"depth":1,"hashes":{"sha256":"4U1qKjD+hkK7t3fcQnSrixaNtCrhdJTDvQoNoIGgVBY"},"origin_server_ts":123456789,"prev_events":[],"room_id":"!room:example.org","sender":"@alice:example.org","type":"m.room.message"}`)
	event := relay.EventJSON{EventID: "$3eajWN6Kz4CKpnf6gp3a4MsuUpMShqh_5QcwW7HZsAg", PDU: raw}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(encoded), "123456789", "123456790", 1)
	for _, tc := range []struct {
		name, input string
		fails       bool
	}{
		{"original", `{"events":[` + string(encoded) + `],"groups":{}}`, false},
		{"changed", `{"events":[` + changed + `]}`, true},
		{"duplicate", `{"events":[` + string(encoded) + `,` + string(encoded) + `]}`, true},
		{"missing array", `{}`, true},
		{"empty", `{"events":[]}`, true},
		{"malformed", `{"events":[{"event_id":"$event","pdu":null}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(a.RoomDir(roomID), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(a.RoomDir(roomID), "pdus.json"), []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a}
			err = im.checkArchivedEventIDs(t.Context(), &archive.ArchivedRoom{RoomID: roomID, Version: "12"})
			if (err != nil) != tc.fails {
				t.Fatalf("verification error=%v", err)
			}
		})
	}
}

func TestLosslessStreamHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	im := &Importer{}
	if err := im.CheckLosslessImportContext(ctx, nil, nil, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
