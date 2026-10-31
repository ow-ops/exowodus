package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
)

// LockImport excludes imports while a bridge queue is being repaired.
func (a *Archive) LockImport() (io.Closer, error) {
	return a.lockProxyFile("import.lock")
}

// BridgeHistory returns exact event IDs that must not be delivered as new
// messages. Hold LockImport while using this snapshot.
func (a *Archive) BridgeHistory(ctx context.Context) (map[string]bool, error) {
	if err := a.CheckExport(); err != nil {
		return nil, err
	}
	var report struct {
		Complete bool `json:"complete"`
	}
	if err := readJSON(filepath.Join(a.Dir, "import-report.json"), &report); err != nil {
		return nil, fmt.Errorf("completed import report required: %w", err)
	}
	if !report.Complete {
		return nil, fmt.Errorf("finish importing accounts, devices and rooms before releasing bridge delivery")
	}
	// Include excluded rooms too: an earlier import may have replayed them.
	all := *a
	all.Manifest.SkippedRooms = nil
	rooms, err := all.RoomHeaders()
	if err != nil {
		return nil, err
	}
	history := make(map[string]bool)
	for _, room := range rooms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		state, err := a.ReadRoomState(room.RoomID)
		if err != nil {
			return nil, err
		}
		if !state.Done && (state.NewRoomID != "" || !room.ArchiveOnly && !a.IsRoomSkipped(room.RoomID)) {
			return nil, fmt.Errorf("room %s import is incomplete; finish importing before repairing bridge delivery", room.RoomID)
		}
		if !state.Done {
			continue
		}
		if !state.OriginalEvents || state.NewRoomID != room.RoomID {
			return nil, fmt.Errorf("%s: original event and room IDs were not verified; bridge delivery cannot be released safely", room.RoomID)
		}
		for oldID, newID := range state.Events {
			if oldID != newID {
				return nil, fmt.Errorf("%s: replay changed event IDs; bridge mappings are not preserved", room.RoomID)
			}
			if oldID != "" {
				history[oldID] = true
			}
		}
		// Relay imports retain original IDs instead of an old-to-new mapping.
		for raw, err := range a.RoomEventsIter(room.RoomID) {
			if err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var ev struct {
				EventID string `json:"event_id"`
			}
			if err := json.Unmarshal(raw, &ev); err != nil {
				return nil, fmt.Errorf("room %s event: %w", room.RoomID, err)
			}
			if ev.EventID != "" {
				history[ev.EventID] = true
			}
		}
		// Federation can also deliver archived auth/state events that were not
		// in the client timeline. They are history too.
		for raw, err := range a.RoomPDUEvents(ctx, room.RoomID) {
			if err != nil {
				return nil, err
			}
			var ev struct {
				EventID string `json:"event_id"`
			}
			if err := json.Unmarshal(raw, &ev); err != nil {
				return nil, err
			}
			if ev.EventID == "" {
				return nil, fmt.Errorf("room %s has an archived PDU without an event ID", room.RoomID)
			}
			history[ev.EventID] = true
		}
	}
	return history, nil
}

// FinishBridgeDelivery updates the report while LockImport is held.
func (a *Archive) FinishBridgeDelivery(bridgeID string) error {
	var report map[string]json.RawMessage
	if err := readJSON(filepath.Join(a.Dir, "import-report.json"), &report); err != nil {
		return err
	}
	var held []string
	if raw, ok := report["bridge_deliveries_held"]; ok {
		if err := json.Unmarshal(raw, &held); err != nil {
			return err
		}
	}
	held = slices.DeleteFunc(held, func(id string) bool { return id == bridgeID })
	var err error
	report["bridge_deliveries_held"], err = json.Marshal(held)
	if err != nil {
		return err
	}
	return a.WriteImportReport(report)
}
