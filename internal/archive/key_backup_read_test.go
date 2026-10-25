package archive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyBackupReaderPreservesSessions(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	const user = "@alice:example.org"
	if err := os.MkdirAll(a.UserDir(user), 0700); err != nil {
		t.Fatal(err)
	}
	// Metadata after rooms must work too, without buffering the rooms object.
	raw := `{"rooms":{"!first:example.org":{"sessions":{"one":{"session_data":{"ciphertext":"first"}},"two":{"session_data":{"ciphertext":"second"}}}},"!second:example.org":{"sessions":{"three":{"session_data":{"ciphertext":"third"}}}}},"auth_data":{"public_key":"original"},"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2"}`
	if err := os.WriteFile(filepath.Join(a.UserDir(user), "key_backup.json"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := a.OpenKeyBackup(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Algorithm != "m.megolm_backup.v1.curve25519-aes-sha2" || string(r.AuthData) != `{"public_key":"original"}` {
		t.Fatal("backup authentication metadata changed")
	}
	var sessions []BackupSession
	for session, err := range r.Sessions(t.Context()) {
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	if len(sessions) != 3 || sessions[0].RoomID != "!first:example.org" || sessions[2].RoomID != "!second:example.org" || sessions[0].SessionID != "one" || string(sessions[0].Data) != `{"session_data":{"ciphertext":"first"}}` {
		t.Fatal("backup records were lost or their buffers were reused")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	count := 0
	for _, err := range r.Sessions(ctx) {
		if count == 0 {
			count++
			cancel()
			continue
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled key iterator: %v", err)
		}
		count++
	}
	if count != 2 {
		t.Fatal("iterator continued after cancellation")
	}
}
