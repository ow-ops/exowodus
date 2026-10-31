package migrate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"exowodus/internal/archive"
	"maunium.net/go/mautrix/federation"
)

// CheckBridgePreservation runs before registering services or preparing users.
// Original IDs keep each service's external message mappings valid.
func (im *Importer) CheckBridgePreservation(ctx context.Context, rooms []*archive.ArchivedRoom, server *archive.Server, hasRelay bool) error {
	if len(im.Bridges) == 0 && (server == nil || len(server.AppserviceRegistrations) == 0) {
		return nil
	}
	im.bridgePreservation = true
	if im.Admin == nil || im.Admin.ServerName() != im.Archive.Manifest.ServerName {
		return errors.New("appservice migration requires --to-admin-token and the original server name")
	}
	if server == nil || !server.BridgeQueuesDrained {
		return errors.New("source appservice queues were not verified; re-export with source bridge registrations and the matching database after their queues drain")
	}
	for _, b := range im.Bridges {
		found := false
		for _, raw := range server.AppserviceRegistrations {
			found = found || b.MatchesRegistration(raw)
		}
		if !found {
			return fmt.Errorf("appservice %s does not match an exported registration; export it with the source delivery queue checks", b.ID)
		}
	}
	for _, room := range rooms {
		if im.Archive.IsRoomSkipped(room.RoomID) || room.ArchiveOnly {
			continue
		}
		state, err := im.Archive.ReadRoomState(room.RoomID)
		if err != nil {
			return err
		}
		if state.NewRoomID != "" && state.NewRoomID != room.RoomID {
			return fmt.Errorf("%s: room ID changed during an earlier import; existing bridge mappings cannot be preserved", room.RoomID)
		}
		for old, newID := range state.Events {
			if old != newID {
				return fmt.Errorf("%s: history was already replayed with changed event IDs; preserving bridge mappings requires an original-event import into a fresh destination", room.RoomID)
			}
		}
		if !hasRelay {
			return errors.New("appservice migration requires original event IDs; use --relay-name with exported PDUs and the source signing key; history replay is disabled")
		}
		key, err := im.Archive.SigningKey()
		if err != nil {
			return fmt.Errorf("appservice migration needs the exported source signing key: %w", err)
		}
		if _, err := federation.ParseSynapseKey(strings.TrimSpace(key)); err != nil {
			return fmt.Errorf("source signing key: %w", err)
		}
		if err := im.checkArchivedEventIDs(ctx, room); err != nil {
			return fmt.Errorf("%s: original event preservation required for appservices: %w", room.RoomID, err)
		}
	}
	return nil
}

// CheckAppserviceQueues prevents discarding undelivered source messages as
// already handled history. The bridge stays online until these queues drain.
func (d *SynapseDB) CheckAppserviceQueues(ctx context.Context, bridges []*Bridge) error {
	var position, latest int64
	if err := d.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(stream_ordering),0) FROM appservice_stream_position`).Scan(&position); err != nil {
		return fmt.Errorf("source appservice stream: %w", err)
	}
	if err := d.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(stream_ordering),0) FROM events WHERE stream_ordering > 0`).Scan(&latest); err != nil {
		return fmt.Errorf("source event stream: %w", err)
	}
	if position < latest {
		return fmt.Errorf("source appservice dispatcher has not caught up (%d/%d); pause client and federation writes, let dispatch finish, then take a matching database snapshot", position, latest)
	}
	for _, b := range bridges {
		var count int
		if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM application_services_txns WHERE as_id=$1`, b.ID).Scan(&count); err != nil {
			return fmt.Errorf("source appservice queue: %w", err)
		}
		if count != 0 {
			return fmt.Errorf("appservice %s still has %d undelivered transactions; keep the original bridge running until they drain, then stop it and take the final database snapshot", b.ID, count)
		}
	}
	return nil
}
