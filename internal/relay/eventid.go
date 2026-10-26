package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

// EventID calculates a reference hash as Ruma does. Ruma keeps non-object
// content unchanged when redacting, while mautrix replaces it with {}; some
// servers have sent dummy events with string or null content.
func EventID(p *pdu.PDU, version id.RoomVersion) (id.EventID, error) {
	content := p.Content
	if len(content) == 0 || content.Kind() == '{' {
		return p.GetEventID(version)
	}
	clone := p.Clone()
	if clone.Hashes == nil || clone.Hashes.SHA256 == nil {
		if err := clone.FillContentHash(); err != nil {
			return "", err
		}
	}
	raw, err := jsonv2.Marshal(clone.RedactForSignature(version))
	if err != nil {
		return "", err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", err
	}
	object["content"] = json.RawMessage(content)
	if raw, err = json.Marshal(object); err != nil {
		return "", err
	}
	canonical, err := canonicaljson.CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	encoding := base64.RawURLEncoding
	if version.EventIDFormat() == id.EventIDFormatBase64 {
		encoding = base64.RawStdEncoding
	}
	return id.EventID("$" + encoding.EncodeToString(hash[:])), nil
}
