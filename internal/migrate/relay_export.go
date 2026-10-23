package migrate

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"iter"
	"os"
	"strings"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"exodus/internal/relay"
)

// checkEventIDs returns how many recomputed event IDs differ from Synapse's.
func checkEventIDs(pdus []relay.EventJSON, roomVersion string) int {
	if !relay.SupportsVersion(roomVersion) {
		return len(pdus)
	}
	var mismatched int
	for _, p := range pdus {
		ev, err := relay.ParsePDU(p.PDU)
		if err != nil {
			mismatched++
			continue
		}
		if eventID, err := ev.GetEventID(id.RoomVersion(roomVersion)); err != nil || string(eventID) != p.EventID {
			mismatched++
		}
	}
	return mismatched
}

// redactPDUs applies redactions Synapse has not purged yet. Signatures cover
// the redacted form, so they stay valid.
func redactPDUs(pdus []relay.EventJSON, events iter.Seq2[json.RawMessage, error], roomVersion string) error {
	if !relay.SupportsVersion(roomVersion) {
		return nil
	}
	redacted := map[string]bool{}
	for raw, readErr := range events {
		if readErr != nil {
			return readErr
		}
		ev, err := decodeEvent(raw)
		if err == nil && len(ev.Unsigned.RedactedBecause) > 0 {
			redacted[ev.EventID] = true
		}
	}
	for i, p := range pdus {
		if !redacted[p.EventID] {
			continue
		}
		ev, err := relay.ParsePDU(p.PDU)
		if err != nil {
			return err
		}
		if pdus[i].PDU, err = jsonv2.Marshal(ev.Redact(id.RoomVersion(roomVersion))); err != nil {
			return err
		}
	}
	return nil
}

// ExportRelayKeys saves the signing key and cached server keys, so the relay
// can vouch for the original events.
func (e *Exporter) ExportRelayKeys(ctx context.Context, signingKeyPath string) error {
	raw, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return err
	}
	if _, err := federation.ParseSynapseKey(strings.TrimSpace(string(raw))); err != nil {
		return fmt.Errorf("%s: %w", signingKeyPath, err)
	}
	if err := e.Archive.WriteSigningKey(string(raw)); err != nil {
		return err
	}
	if e.DB == nil {
		return nil
	}
	keys, err := e.DB.ServerKeys(ctx)
	if err != nil {
		return err
	}
	return e.Archive.WriteServerKeys(keys)
}

func (e *Exporter) ExportTuwunelRelayKeys() error {
	if err := e.TuwunelDump.CheckRelayMaps(); err != nil {
		return err
	}
	key, err := e.TuwunelDump.SigningKey()
	if err != nil {
		return err
	}
	if err := e.Archive.WriteSigningKey(key); err != nil {
		return err
	}
	keys, err := e.TuwunelDump.RelayKeys()
	if err != nil {
		return err
	}
	return e.Archive.WriteServerKeys(keys)
}
