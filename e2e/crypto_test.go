//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type backupFixture struct {
	recovery, publicKey, sessionID, ciphertext string
}

func createKeyBackup(t *testing.T, ctx context.Context, c *mautrix.Client, roomID string) backupFixture {
	t.Helper()
	out, err := session.NewMegolmOutboundSession()
	must(t, err)
	in, err := session.NewMegolmInboundSession([]byte(out.Key()))
	must(t, err)
	exported, err := in.Export(0)
	must(t, err)
	plaintext, err := json.Marshal(map[string]any{"room_id": roomID, "type": "m.room.message", "content": map[string]string{"msgtype": "m.text", "body": "decrypt after migration"}})
	must(t, err)
	ciphertext, err := out.Encrypt(plaintext)
	must(t, err)
	send(t, ctx, c, roomID, "m.room.encrypted", map[string]any{
		"algorithm": "m.megolm.v1.aes-sha2", "session_id": out.ID(), "ciphertext": string(ciphertext), "device_id": c.DeviceID, "sender_key": "sender-key",
	})
	key, err := backup.NewMegolmBackupKey()
	must(t, err)
	encrypted, err := backup.EncryptSessionData(key, backup.MegolmSessionData{Algorithm: id.AlgorithmMegolmV1, SessionKey: string(exported), SenderKey: "sender-key"})
	must(t, err)
	secrets := ssss.NewSSSSMachine(c)
	recovery, err := secrets.GenerateAndUploadKey(ctx, "")
	must(t, err)
	must(t, secrets.SetDefaultKeyID(ctx, recovery.ID))
	must(t, secrets.SetEncryptedAccountData(ctx, event.AccountDataMegolmBackupKey, []byte(base64.RawStdEncoding.EncodeToString(key.Bytes())), recovery))
	public := base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes())
	var ver struct {
		Version string `json:"version"`
	}
	must(t, do(ctx, c, http.MethodPost, "/_matrix/client/v3/room_keys/version", nil, map[string]any{"algorithm": "m.megolm_backup.v1.curve25519-aes-sha2", "auth_data": map[string]string{"public_key": public}}, &ver))
	body := map[string]any{"rooms": map[string]any{roomID: map[string]any{"sessions": map[string]any{string(out.ID()): map[string]any{"first_message_index": 0, "forwarded_count": 0, "is_verified": false, "session_data": encrypted}}}}}
	must(t, do(ctx, c, http.MethodPut, "/_matrix/client/v3/room_keys/keys", url.Values{"version": {ver.Version}}, body, nil))
	return backupFixture{recovery: recovery.RecoveryKey(), publicKey: public, sessionID: string(out.ID()), ciphertext: string(ciphertext)}
}

func assertKeyBackup(t *testing.T, ctx context.Context, c *mautrix.Client, roomID string, fixture backupFixture) {
	t.Helper()
	secrets := ssss.NewSSSSMachine(c)
	keyID, meta, err := secrets.GetDefaultKeyData(ctx)
	must(t, err)
	recovery, err := meta.VerifyRecoveryKey(keyID, fixture.recovery)
	must(t, err)
	encoded, err := secrets.GetDecryptedAccountData(ctx, event.AccountDataMegolmBackupKey, recovery)
	must(t, err)
	raw, err := base64.RawStdEncoding.DecodeString(string(encoded))
	must(t, err)
	key, err := backup.MegolmBackupKeyFromBytes(raw)
	must(t, err)
	var ver struct {
		Version  string `json:"version"`
		AuthData struct {
			PublicKey string `json:"public_key"`
		} `json:"auth_data"`
	}
	must(t, do(ctx, c, http.MethodGet, "/_matrix/client/v3/room_keys/version", nil, nil, &ver))
	if ver.AuthData.PublicKey != fixture.publicKey {
		t.Fatal("backup identity changed")
	}
	var keys struct {
		Rooms map[string]struct {
			Sessions map[string]struct {
				Data backup.EncryptedSessionData[backup.MegolmSessionData] `json:"session_data"`
			} `json:"sessions"`
		} `json:"rooms"`
	}
	must(t, do(ctx, c, http.MethodGet, "/_matrix/client/v3/room_keys/keys", url.Values{"version": {ver.Version}}, nil, &keys))
	encrypted, ok := keys.Rooms[roomID].Sessions[fixture.sessionID]
	if !ok {
		t.Fatal("session missing from migrated backup")
	}
	restored, err := encrypted.Data.Decrypt(key)
	must(t, err)
	in, err := session.NewMegolmInboundSessionFromExport([]byte(restored.SessionKey))
	must(t, err)
	for _, ev := range roomEvents(t, ctx, c, roomID) {
		var content struct {
			SessionID  string `json:"session_id"`
			Ciphertext string `json:"ciphertext"`
		}
		must(t, json.Unmarshal(ev.Content, &content))
		if content.SessionID != fixture.sessionID {
			continue
		}
		plaintext, _, err := in.Decrypt([]byte(content.Ciphertext))
		must(t, err)
		var message struct {
			RoomID  string `json:"room_id"`
			Content struct {
				Body string `json:"body"`
			} `json:"content"`
		}
		must(t, json.Unmarshal(plaintext, &message))
		if message.RoomID != roomID || message.Content.Body != "decrypt after migration" {
			t.Fatalf("decrypted payload mismatch: %s", plaintext)
		}
		return
	}
	t.Fatal("encrypted message missing from migrated room")
}
