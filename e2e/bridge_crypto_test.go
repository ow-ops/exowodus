//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/id"
)

// Retain the private account outside the homeserver, like a bridge crypto store.
type bridgeCrypto struct {
	user, device, pickle string
	ed                   id.Ed25519
	curve                id.Curve25519
	sender               *account.Account
}

func newBridgeCrypto(t *testing.T, ctx context.Context, bot *mautrix.Client, user, device string) *bridgeCrypto {
	t.Helper()
	receiver, err := account.NewAccount()
	must(t, err)
	ed, curve, err := receiver.IdentityKeys()
	must(t, err)
	sign := func(value map[string]any) map[string]any {
		raw, err := json.Marshal(value)
		must(t, err)
		sig, err := receiver.Sign(raw)
		must(t, err)
		value["signatures"] = map[string]map[string]string{user: {"ed25519:" + device: string(sig)}}
		return value
	}
	keys := sign(map[string]any{"user_id": user, "device_id": device, "algorithms": []string{"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"}, "keys": map[string]string{"ed25519:" + device: string(ed), "curve25519:" + device: string(curve)}})
	must(t, receiver.GenOneTimeKeys(2))
	public, err := receiver.OneTimeKeys()
	must(t, err)
	oneTime := map[string]any{}
	for key, value := range public {
		oneTime["signed_curve25519:"+key] = sign(map[string]any{"key": value})
	}
	must(t, do(ctx, bot, http.MethodPost, "/_matrix/client/v3/keys/upload", nil, map[string]any{"device_keys": keys, "one_time_keys": oneTime}, nil))
	pickled, err := receiver.Pickle([]byte("bridge-test-pickle-key"))
	must(t, err)
	path := filepath.Join(t.TempDir(), "bridge-account.pickle")
	must(t, os.WriteFile(path, pickled, 0600))
	sender, err := account.NewAccount()
	must(t, err)
	return &bridgeCrypto{user: user, device: device, pickle: path, ed: ed, curve: curve, sender: sender}
}

func (f *bridgeCrypto) encrypt(t *testing.T, ctx context.Context, c *mautrix.Client, text string) json.RawMessage {
	t.Helper()
	var claim struct {
		Keys map[string]map[string]map[string]struct {
			Key id.Curve25519 `json:"key"`
		} `json:"one_time_keys"`
	}
	must(t, do(ctx, c, http.MethodPost, "/_matrix/client/v3/keys/claim", nil, map[string]any{"one_time_keys": map[string]map[string]string{f.user: {f.device: "signed_curve25519"}}}, &claim))
	var key id.Curve25519
	for _, value := range claim.Keys[f.user][f.device] {
		key = value.Key
	}
	if key == "" {
		t.Fatal("original device's one-time key was not available")
	}
	session, err := f.sender.NewOutboundSession(f.curve, key)
	must(t, err)
	kind, ciphertext, err := session.Encrypt([]byte(text))
	must(t, err)
	_, senderKey, err := f.sender.IdentityKeys()
	must(t, err)
	raw, err := json.Marshal(map[string]any{"algorithm": "m.olm.v1.curve25519-aes-sha2", "sender_key": senderKey, "ciphertext": map[string]any{string(f.curve): map[string]any{"type": kind, "body": string(ciphertext)}}})
	must(t, err)
	return raw
}

func (f *bridgeCrypto) decrypt(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	pickled, err := os.ReadFile(f.pickle)
	must(t, err)
	receiver, err := account.AccountFromPickled(pickled, []byte("bridge-test-pickle-key"))
	must(t, err)
	var content struct {
		SenderKey  id.Curve25519 `json:"sender_key"`
		Ciphertext map[string]struct {
			Type id.OlmMsgType `json:"type"`
			Body string        `json:"body"`
		} `json:"ciphertext"`
	}
	must(t, json.Unmarshal(raw, &content))
	ciphertext := content.Ciphertext[string(f.curve)]
	session, err := receiver.NewInboundSessionFrom(&content.SenderKey, ciphertext.Body)
	must(t, err)
	plaintext, err := session.Decrypt(ciphertext.Body, ciphertext.Type)
	must(t, err)
	return string(plaintext)
}
