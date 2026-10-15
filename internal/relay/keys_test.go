package relay

import (
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/signutil"
)

func TestKeyResponseIncludesSignedEmptyOldKeys(t *testing.T) {
	origin := federation.GenerateSigningKey()
	rl := New("relay.test", "source.test", origin, nil)
	for _, server := range []string{rl.Name, rl.origin} {
		keys, err := rl.keyResponse(server)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(keys)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		if string(object["old_verify_keys"]) != "{}" {
			t.Fatal("required empty map omitted")
		}
		key := origin
		if server == rl.Name {
			key = rl.key
		}
		if err := signutil.VerifyJSON(server, key.ID, key.Pub, json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
		if err := signutil.VerifyJSON(rl.Name, rl.key.ID, rl.key.Pub, json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
	}
}
