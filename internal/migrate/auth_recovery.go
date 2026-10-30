package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/relay"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

const authRecoveryTimeout = 15 * time.Second

type authRecovery struct {
	client   *federation.Client
	baseKeys map[string][]json.RawMessage
	keys     map[string][]*federation.ServerKeyResponse
}

func (e *Exporter) tuwunelRoomMetadata(ctx context.Context, roomID string) (*tuwunelRoomMetadata, error) {
	resolve := func(ctx context.Context, data *tuwunelRoomMetadata, missing string, parent json.RawMessage) error {
		e.authMu.Lock()
		defer e.authMu.Unlock()
		if e.authRecovery == nil {
			keyText, err := e.TuwunelDump.SigningKey()
			if err != nil {
				return err
			}
			key, err := federation.ParseSynapseKey(keyText)
			if err != nil {
				return err
			}
			keys, err := e.TuwunelDump.RelayKeys()
			if err != nil {
				return err
			}
			own, err := json.Marshal(key.GenerateKeyResponse(e.Archive.Manifest.ServerName, nil))
			if err != nil {
				return err
			}
			keys[e.Archive.Manifest.ServerName] = append(keys[e.Archive.Manifest.ServerName], own)
			client := federation.NewClient(e.Archive.Manifest.ServerName, key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
			client.ResponseSizeLimit = 1 << 20
			e.authRecovery = &authRecovery{client: client, baseKeys: keys, keys: map[string][]*federation.ServerKeyResponse{}}
		}
		return e.recoverAuth(ctx, roomID, data, missing, parent)
	}
	return e.TuwunelDump.roomRelayMetadataWithRecovery(ctx, roomID, resolve)
}

func (e *Exporter) recoverAuth(ctx context.Context, roomID string, data *tuwunelRoomMetadata, missing string, parent json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	room := e.TuwunelDump.relayRooms[roomID]
	reader := tuwunelRoomReader{dump: e.TuwunelDump, room: room, files: map[string]*os.File{}}
	defer reader.Close()
	create, err := reader.read(ctx, data.CurrentState[relay.StateKey("m.room.create", "")])
	if err != nil {
		return err
	}
	var creation struct {
		Content struct {
			Version string `json:"room_version"`
		} `json:"content"`
	}
	if err := json.Unmarshal(create, &creation); err != nil {
		return err
	}
	version := creation.Content.Version
	if version == "" {
		version = "1"
	}
	if !relay.SupportsVersion(version) {
		return fmt.Errorf("auth recovery does not support room version %s", version)
	}
	path := e.Archive.RecoveredAuthPath(roomID, missing)
	cached, err := archive.ReadRecoveredAuth(path)
	if err != nil {
		slog.Warn("could not read recovered auth cache; fetching again", "room", roomID, "event", missing, "err", err)
	}
	if cached != nil {
		if cached.RoomID != roomID || cached.EventID != missing {
			err = errors.New("recovered auth cache contains another event or room")
		}
		for server, docs := range cached.Keys {
			for _, raw := range docs {
				if keyErr := e.authRecovery.addKeys(server, raw); keyErr != nil {
					err = keyErr
				}
			}
		}
		if err == nil {
			var verified json.RawMessage
			var keys map[string][]json.RawMessage
			verified, keys, err = e.authRecovery.verify(ctx, roomID, missing, version, cached.PDU)
			if err == nil && !bytes.Equal(verified, cached.PDU) {
				cached.PDU, cached.Keys = verified, keys
				if err := e.Archive.WriteRecoveredAuth(cached); err != nil {
					return err
				}
			}
		}
		if err != nil {
			slog.Warn("recovered auth cache failed verification; fetching again", "room", roomID, "event", missing, "err", err)
			cached = nil
		} else {
			slog.Info("reusing recovered auth event", "room", roomID, "event", missing)
		}
	}
	if cached == nil {
		var failures []error
		for _, server := range recoveryPeers(roomID, parent, data.CurrentState, e.Archive.Manifest.ServerName) {
			slog.Info("recovering auth event", "room", roomID, "event", missing, "server", server)
			attempt, cancel := context.WithTimeout(ctx, authRecoveryTimeout)
			response, fetchErr := e.authRecovery.client.GetEvent(attempt, server, id.EventID(missing))
			var raw json.RawMessage
			var keys map[string][]json.RawMessage
			if fetchErr == nil {
				if response == nil || len(response.PDUs) != 1 {
					fetchErr = errors.New("expected one event from federation")
				} else {
					raw, keys, fetchErr = e.authRecovery.verify(attempt, roomID, missing, version, response.PDUs[0])
				}
			}
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if fetchErr != nil {
				slog.Warn("auth event recovery failed", "room", roomID, "event", missing, "server", server, "err", fetchErr)
				failures = append(failures, fmt.Errorf("%s: %w", server, fetchErr))
				continue
			}
			cached = &archive.RecoveredAuth{RoomID: roomID, EventID: missing, PDU: raw, Keys: keys}
			if err := e.Archive.WriteRecoveredAuth(cached); err != nil {
				return err
			}
			break
		}
		if cached == nil {
			if len(failures) == 0 {
				return errors.New("no other room server available for auth recovery")
			}
			return fmt.Errorf("auth event unavailable after federation recovery: %w", errors.Join(failures...))
		}
	}
	if room.recovered == nil {
		room.recovered = map[string]string{}
	}
	room.recovered[missing] = path
	return nil
}

func recoveryPeers(roomID string, parent json.RawMessage, current map[string]string, source string) []string {
	var peers []string
	add := func(server string) {
		if server != "" && server != source && !slices.Contains(peers, server) && len(peers) < 8 {
			peers = append(peers, server)
		}
	}
	var event struct {
		Sender string `json:"sender"`
	}
	_ = json.Unmarshal(parent, &event)
	add(mx.ServerName(event.Sender))
	add(mx.ServerName(roomID))
	for _, key := range slices.Sorted(maps.Keys(current)) {
		if user, ok := strings.CutPrefix(key, "m.room.member\x00"); ok {
			add(mx.ServerName(user))
		}
		if len(peers) == 8 {
			break
		}
	}
	return peers
}

func (r *authRecovery) addKeys(server string, raw json.RawMessage) error {
	var doc federation.ServerKeyResponse
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if doc.ServerName != server || len(doc.VerifyKeys) == 0 {
		return errors.New("signing key response does not match its server")
	}
	if err := doc.VerifySelfSignature(); err != nil {
		return err
	}
	for _, known := range r.keys[server] {
		if bytes.Equal(known.Raw, raw) {
			return nil
		}
	}
	r.keys[server] = append(r.keys[server], &doc)
	return nil
}

func (r *authRecovery) verify(ctx context.Context, roomID, eventID, version string, raw json.RawMessage) (json.RawMessage, map[string][]json.RawMessage, error) {
	p, err := relay.ParsePDU(raw)
	if err != nil {
		return nil, nil, err
	}
	var stored struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, nil, err
	}
	if stored.EventID != "" && stored.EventID != eventID {
		return nil, nil, errors.New("response contains a different event ID")
	}
	v := id.RoomVersion(version)
	if p.Type == "m.room.create" && v.RoomIDIsCreateEventID() {
		if roomID != "!"+strings.TrimPrefix(eventID, "$") || (p.RoomID != "" && string(p.RoomID) != roomID) {
			return nil, nil, errors.New("create event belongs to another room")
		}
		p.RoomID = ""
	} else if string(p.RoomID) != roomID {
		return nil, nil, errors.New("auth event belongs to another room")
	}
	if p.StateKey == nil {
		return nil, nil, errors.New("auth dependency is not a state event")
	}
	if p.Hashes == nil || len(p.Hashes.SHA256) != 32 {
		return nil, nil, errors.New("auth event has no valid SHA-256 content hash")
	}
	if p.Type == "m.room.create" {
		var content struct {
			Version string `json:"room_version"`
		}
		if err := json.Unmarshal(p.Content, &content); err != nil {
			return nil, nil, err
		}
		if content.Version != version {
			return nil, nil, errors.New("create event room version does not match")
		}
	}
	if err := checkEventID(relay.EventJSON{EventID: eventID, PDU: raw}, version); err != nil {
		return nil, nil, err
	}
	used := map[string][]json.RawMessage{}
	getKey := func(server string, keyID id.KeyID, at time.Time) (id.SigningKey, time.Time, error) {
		for _, raw := range r.baseKeys[server] {
			if err := r.addKeys(server, raw); err != nil {
				return "", time.Time{}, err
			}
		}
		delete(r.baseKeys, server)
		find := func() (id.SigningKey, time.Time) {
			for _, doc := range r.keys[server] {
				key, until := id.SigningKey(""), time.Time{}
				if active, ok := doc.VerifyKeys[keyID]; ok {
					key, until = active.Key, doc.ValidUntilTS.Time
				}
				if old, ok := doc.OldVerifyKeys[keyID]; ok && key == "" {
					key, until = old.Key, old.ExpiredTS.Time
				}
				if key != "" && (!v.EnforceSigningKeyValidity() || !until.Before(at)) {
					used[server] = append(used[server], doc.Raw)
					return key, until
				}
			}
			return "", time.Time{}
		}
		if key, until := find(); key != "" {
			return key, until, nil
		}
		doc, err := r.client.ServerKeys(ctx, server)
		if err != nil {
			return "", time.Time{}, err
		}
		if doc == nil {
			return "", time.Time{}, errors.New("empty signing key response")
		}
		if err := r.addKeys(server, doc.Raw); err != nil {
			return "", time.Time{}, err
		}
		if key, until := find(); key != "" {
			return key, until, nil
		}
		return "", time.Time{}, fmt.Errorf("signing key %s unavailable for %s", keyID, server)
	}
	_, sender, err := p.Sender.Parse()
	if err != nil {
		return nil, nil, err
	}
	if err := p.VerifySignature(v, sender, getKey); err != nil {
		return nil, nil, err
	}
	if p.Type == "m.room.member" {
		var content struct {
			Membership string `json:"membership"`
			Authorizer string `json:"join_authorised_via_users_server"`
		}
		if err := json.Unmarshal(p.Content, &content); err != nil {
			return nil, nil, err
		}
		if content.Membership == "join" && content.Authorizer != "" {
			if err := p.VerifySignature(v, mx.ServerName(content.Authorizer), getKey); err != nil {
				return nil, nil, err
			}
		}
	}
	if !p.VerifyContentHash() {
		raw, err = jsonv2.Marshal(p.Redact(v))
		if err != nil {
			return nil, nil, err
		}
		if err := checkEventID(relay.EventJSON{EventID: eventID, PDU: raw}, version); err != nil {
			return nil, nil, err
		}
	}
	return raw, used, nil
}
