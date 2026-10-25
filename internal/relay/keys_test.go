package relay

import (
	"encoding/json"
	"testing"
	"time"

	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"
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

func TestSourceKeyResponsesPreserveArchivedSigningKeys(t *testing.T) {
	current := federation.GenerateSigningKey()
	old := federation.GenerateSigningKey()
	retired := federation.GenerateSigningKey()
	expired := jsontime.UM(time.Unix(1000, 0))
	valid := jsontime.UM(time.Unix(2000, 0))
	first := old.GenerateKeyResponse("source.test", map[id.KeyID]federation.OldVerifyKey{
		retired.ID: {Key: retired.Pub, ExpiredTS: expired},
	})
	first.ValidUntilTS = valid
	second := current.GenerateKeyResponse("source.test", nil)
	second.VerifyKeys[retired.ID] = federation.ServerVerifyKey{Key: retired.Pub}
	second.VerifyKeys[old.ID] = federation.ServerVerifyKey{Key: old.Pub}
	second.ValidUntilTS = jsontime.UM(valid.Add(time.Hour))
	var cached []json.RawMessage
	for _, response := range []*federation.ServerKeyResponse{first, second} {
		raw, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		cached = append(cached, raw)
	}
	rl := New("relay.test", "source.test", current, map[string][]json.RawMessage{"source.test": cached})
	for _, path := range []string{"notary", "http"} {
		t.Run(path, func(t *testing.T) {
			var raw []byte
			var err error
			if path == "notary" {
				keys, loadErr := (notaryKeys{rl}).LoadKeys("source.test")
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				raw, err = json.Marshal(keys)
			} else {
				keys, loadErr := rl.keyResponse("source.test")
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				raw, err = json.Marshal(keys)
			}
			if err != nil {
				t.Fatal(err)
			}
			var keys federation.ServerKeyResponse
			if err := json.Unmarshal(raw, &keys); err != nil {
				t.Fatal(err)
			}
			if len(keys.VerifyKeys) != 1 || keys.VerifyKeys[current.ID].Key != current.Pub || len(keys.OldVerifyKeys) != 2 {
				t.Fatalf("lost or misclassified source keys: %+v", keys)
			}
			if key := keys.OldVerifyKeys[retired.ID]; key.Key != retired.Pub || !key.ExpiredTS.Equal(expired.Time) {
				t.Fatal("explicit retirement time was changed")
			}
			if key := keys.OldVerifyKeys[old.ID]; key.Key != old.Pub || !key.ExpiredTS.Equal(second.ValidUntilTS.Time) {
				t.Fatal("previously active source key was lost or expired too early")
			}
			if err := signutil.VerifyJSON("source.test", current.ID, current.Pub, json.RawMessage(raw)); err != nil {
				t.Fatal(err)
			}
			if path == "http" {
				if err := signutil.VerifyJSON(rl.Name, rl.key.ID, rl.key.Pub, json.RawMessage(raw)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSourceKeyResponseRejectsConflictingArchivedKey(t *testing.T) {
	current := federation.GenerateSigningKey()
	other := federation.GenerateSigningKey()
	keys := other.GenerateKeyResponse("source.test", nil)
	keys.VerifyKeys[current.ID] = federation.ServerVerifyKey{Key: other.Pub}
	raw, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	rl := New("relay.test", "source.test", current, map[string][]json.RawMessage{"source.test": {raw}})
	if _, err := rl.keyResponse("source.test"); err == nil {
		t.Fatal("conflicting source key was published")
	}
}
