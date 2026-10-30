//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

type tuwunelCryptoFixture struct {
	Room       string `json:"room"`
	Recovery   string `json:"recovery"`
	PublicKey  string `json:"public_key"`
	SessionID  string `json:"session_id"`
	Ciphertext string `json:"ciphertext"`
}

// Seeds a disposable source server before the database snapshot.
func TestTuwunelSeedCryptoLive(t *testing.T) {
	source, path := os.Getenv("EXOWODUS_TUWUNEL_LIVE_SOURCE"), os.Getenv("EXOWODUS_TUWUNEL_CRYPTO_FIXTURE")
	if source == "" || path == "" {
		t.Skip("set EXOWODUS_TUWUNEL_LIVE_SOURCE and EXOWODUS_TUWUNEL_CRYPTO_FIXTURE")
	}
	c := login(t, t.Context(), mx.MustNew(source, ""), "admin")
	room := createRoom(t, t.Context(), c, map[string]any{"preset": "private_chat", "room_version": "10", "name": "Encrypted migration fixture"})
	fixture := createKeyBackup(t, t.Context(), c, room)
	raw, err := json.Marshal(tuwunelCryptoFixture{room, fixture.recovery, fixture.publicKey, fixture.sessionID, fixture.ciphertext})
	must(t, err)
	must(t, os.WriteFile(path, raw, 0600))
}

func TestTuwunelDecryptAfterRelayLive(t *testing.T) {
	path, target, dir := os.Getenv("EXOWODUS_TUWUNEL_CRYPTO_FIXTURE"), os.Getenv("EXOWODUS_TUWUNEL_LIVE_TARGET"), os.Getenv("EXOWODUS_TUWUNEL_LIVE_ARCHIVE")
	if path == "" || target == "" || dir == "" {
		t.Skip("set live Tuwunel fixture, target and archive variables")
	}
	raw, err := os.ReadFile(path)
	must(t, err)
	var fixture tuwunelCryptoFixture
	must(t, json.Unmarshal(raw, &fixture))
	a, err := archive.Open(dir)
	must(t, err)
	sessions, err := a.Sessions()
	must(t, err)
	var token string
	for _, session := range sessions {
		if !session.Refresh {
			token = session.Token
			break
		}
	}
	if token == "" {
		t.Fatal("no migrated device token available")
	}
	c := mx.MustNew(target, token)
	who, err := c.Whoami(t.Context())
	must(t, err)
	c.UserID, c.DeviceID = who.UserID, who.DeviceID
	assertKeyBackup(t, t.Context(), c, fixture.Room, backupFixture{fixture.Recovery, fixture.PublicKey, fixture.SessionID, fixture.Ciphertext})
}
