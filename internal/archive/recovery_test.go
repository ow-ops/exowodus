package archive

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestSkippedRoomPolicyAndReport(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetSkippedRooms([]string{"!room:example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	b, err := Open(a.Dir)
	if err != nil || !b.IsRoomSkipped("!room:example.org") {
		t.Fatalf("exclusion did not persist: %v", err)
	}
	var report ExportReport
	if err := readJSON(filepath.Join(a.Dir, "export-report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Complete || len(report.SkippedRooms) != 1 {
		t.Fatal(report)
	}
	if err := b.CheckExport(); err != nil {
		t.Fatal(err)
	}
	if err := b.SetSkippedRooms(nil); err != nil {
		t.Fatal(err)
	}
	if b.IsRoomSkipped("!room:example.org") {
		t.Fatal("old exclusion remained enabled")
	}
	if err := b.SetSkippedRooms([]string{"not a room"}); err == nil {
		t.Fatal("invalid room exclusion accepted")
	}
}

func TestRecoveredKeyPersistence(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	key := json.RawMessage(`{"server_name":"remote.example","verify_keys":{}}`)
	event := &RecoveredAuth{RoomID: "!room:example.org", EventID: "$auth", PDU: json.RawMessage(`{"type":"m.room.member"}`), Keys: map[string][]json.RawMessage{"remote.example": {key}}}
	if err := a.WriteRecoveredAuth(event); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteServerKeys(map[string][]json.RawMessage{}); err != nil {
		t.Fatal(err)
	}
	keys, err := a.ServerKeys()
	if err != nil || len(keys["remote.example"]) != 1 {
		t.Fatalf("re-export lost recovered keys: %v", err)
	}
	stored, err := ReadRecoveredAuth(a.RecoveredAuthPath(event.RoomID, event.EventID))
	if err != nil || stored == nil || stored.EventID != event.EventID {
		t.Fatalf("recovery cache missing: %v", err)
	}
}
