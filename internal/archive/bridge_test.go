package archive

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestBridgeHistoryRequiresFinishedReplay(t *testing.T) {
	a, err := Create(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteImportReport(map[string]bool{"complete": true}); err != nil {
		t.Fatal(err)
	}
	room := &ArchivedRoom{RoomID: "!room:test"}
	if err := a.WriteRoom(room); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoomEvents(room.RoomID, []json.RawMessage{json.RawMessage(`{"event_id":"$relay-original"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoomPDUs(room.RoomID, map[string]any{"events": []json.RawMessage{json.RawMessage(`{"event_id":"$auth","pdu":{}}`)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BridgeHistory(t.Context()); err == nil {
		t.Fatal("unfinished import accepted")
	}
	state := &RoomImportState{NewRoomID: room.RoomID, Done: true, OriginalEvents: true, Events: map[string]string{"$source": "$source"}}
	if err := a.WriteRoomState(room.RoomID, state); err != nil {
		t.Fatal(err)
	}
	if err := a.SetSkippedRooms([]string{room.RoomID}); err != nil {
		t.Fatal(err)
	}
	history, err := a.BridgeHistory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"$source", "$relay-original", "$auth"} {
		if !history[id] {
			t.Fatalf("lost imported event %s after excluding room", id)
		}
	}
	if len(history) != 3 {
		t.Fatalf("history=%v", history)
	}
	for _, mode := range []string{"unverified", "new room", "new event", "failed accounts"} {
		unsafe := *state
		switch mode {
		case "unverified":
			unsafe.OriginalEvents = false
		case "new room":
			unsafe.NewRoomID = "!replacement:test"
		case "new event":
			unsafe.Events = map[string]string{"$source": "$replacement"}
		case "failed accounts":
			if err := a.WriteImportReport(map[string]bool{"complete": false}); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.WriteRoomState(room.RoomID, &unsafe); err != nil {
			t.Fatal(err)
		}
		if _, err := a.BridgeHistory(t.Context()); err == nil {
			t.Fatalf("%s accepted", mode)
		}
	}
	if err := a.WriteImportReport(map[string]bool{"complete": true}); err != nil {
		t.Fatal(err)
	}
	state.Done = false
	if err := a.WriteRoomState(room.RoomID, state); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BridgeHistory(t.Context()); err == nil {
		t.Fatal("partially imported excluded room accepted")
	}
}

func TestFinishBridgeDeliveryKeepsOtherReportFields(t *testing.T) {
	a, err := Create(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteImportReport(map[string]any{"complete": true, "bridge_deliveries_held": []string{"one", "two"}, "other": json.RawMessage(`{"number":9007199254740993}`)}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishBridgeDelivery("one"); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Complete bool     `json:"complete"`
		Held     []string `json:"bridge_deliveries_held"`
		Other    struct {
			Number int64 `json:"number"`
		} `json:"other"`
	}
	if err := readJSON(filepath.Join(a.Dir, "import-report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Complete || len(report.Held) != 1 || report.Held[0] != "two" || report.Other.Number != 9007199254740993 {
		t.Fatalf("report changed: %+v", report)
	}
}

func TestBridgeRepairExcludesConcurrentImport(t *testing.T) {
	a, err := Create(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := a.LockImport()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := a.LockImport(); err == nil {
		second.Close()
		t.Fatal("concurrent import accepted")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = a.LockImport()
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
}
