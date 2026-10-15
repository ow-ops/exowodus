package relay

import (
	"encoding/json"
	"net/http"

	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

// Ruma includes empty old_verify_keys when verifying signatures.
type keyResponse struct {
	ServerName    string                                  `json:"server_name"`
	VerifyKeys    map[id.KeyID]federation.ServerVerifyKey `json:"verify_keys"`
	OldVerifyKeys map[id.KeyID]federation.OldVerifyKey    `json:"old_verify_keys"`
	ValidUntilTS  jsontime.UnixMilli                      `json:"valid_until_ts"`
	Signatures    map[string]map[id.KeyID]string          `json:"signatures"`
}

func (rl *Relay) keyResponse(server string) (*keyResponse, error) {
	var source *federation.ServerKeyResponse
	var signer *federation.SigningKey
	switch server {
	case rl.Name:
		source, signer = rl.key.GenerateKeyResponse(server, nil), rl.key
	case rl.origin:
		source, signer = rl.originKey.GenerateKeyResponse(server, nil), rl.originKey
	default:
		var err error
		source, err = (notaryKeys{rl}).LoadKeys(server)
		if err != nil {
			return nil, err
		}
	}
	response := &keyResponse{ServerName: source.ServerName, VerifyKeys: source.VerifyKeys, OldVerifyKeys: source.OldVerifyKeys, ValidUntilTS: source.ValidUntilTS, Signatures: source.Signatures}
	if response.OldVerifyKeys == nil {
		response.OldVerifyKeys = map[id.KeyID]federation.OldVerifyKey{}
	}
	if response.Signatures == nil {
		response.Signatures = map[string]map[id.KeyID]string{}
	}
	if signer != nil {
		sig, err := signer.SignJSON(response)
		if err != nil {
			return nil, err
		}
		response.Signatures[server] = map[id.KeyID]string{signer.ID: sig}
	}
	if server != rl.Name {
		sig, err := rl.key.SignJSON(response)
		if err != nil {
			return nil, err
		}
		response.Signatures[rl.Name] = map[id.KeyID]string{rl.key.ID: sig}
	}
	return response, nil
}

func (rl *Relay) serverKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := rl.keyResponse(rl.Name)
	if err != nil {
		mautrix.MUnknown.WithMessage("%v", err).Write(w)
		return
	}
	writeJSON(w, keys)
}

func (rl *Relay) queryKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := rl.keyResponse(r.PathValue("serverName"))
	if err != nil {
		mautrix.MNotFound.WithMessage("%v", err).Write(w)
		return
	}
	writeJSON(w, map[string]any{"server_keys": []*keyResponse{keys}})
}

func (rl *Relay) postKeyResponses(w http.ResponseWriter, r *http.Request) {
	var request federation.ReqQueryKeys
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	keys := []*keyResponse{}
	for server := range request.ServerKeys {
		response, err := rl.keyResponse(server)
		if err != nil {
			continue
		}
		keys = append(keys, response)
	}
	writeJSON(w, map[string]any{"server_keys": keys})
}
