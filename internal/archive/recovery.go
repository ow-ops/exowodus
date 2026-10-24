package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type RecoveredAuth struct {
	RoomID  string                       `json:"room_id"`
	EventID string                       `json:"event_id"`
	PDU     json.RawMessage              `json:"pdu"`
	Keys    map[string][]json.RawMessage `json:"keys"`
}

func (a *Archive) RecoveredAuthPath(roomID, eventID string) string {
	hash := sha256.Sum256([]byte(eventID))
	return filepath.Join(a.RoomDir(roomID), "recovered-auth", hex.EncodeToString(hash[:])+".json")
}

func ReadRecoveredAuth(path string) (*RecoveredAuth, error) {
	var event RecoveredAuth
	if err := readJSON(path, &event); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &event, nil
}

func (a *Archive) WriteRecoveredAuth(event *RecoveredAuth) error {
	for _, docs := range event.Keys {
		for _, raw := range docs {
			hash := sha256.Sum256(raw)
			path := filepath.Join(a.Dir, "recovered-keys", hex.EncodeToString(hash[:])+".json")
			if err := writeJSON(path, raw); err != nil {
				return err
			}
		}
	}
	return writeJSON(a.RecoveredAuthPath(event.RoomID, event.EventID), event)
}

func (a *Archive) addRecoveryKeys(keys map[string][]json.RawMessage) error {
	dir := filepath.Join(a.Dir, "recovered-keys")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var raw json.RawMessage
		if err := readJSON(filepath.Join(dir, entry.Name()), &raw); err != nil {
			return err
		}
		var doc struct {
			ServerName string `json:"server_name"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil || doc.ServerName == "" {
			return fmt.Errorf("invalid recovered server keys: %s", entry.Name())
		}
		keys[doc.ServerName] = append(keys[doc.ServerName], raw)
	}
	return nil
}

func (a *Archive) SetSkippedRooms(ids []string) error {
	rooms := map[string]string{}
	for _, roomID := range ids {
		if !strings.HasPrefix(roomID, "!") || len(roomID) < 2 || strings.ContainsAny(roomID, " \t\r\n") {
			return fmt.Errorf("invalid skipped room ID %q", roomID)
		}
		rooms[roomID] = "excluded with --skip-room"
	}
	a.Manifest.SkippedRooms = rooms
	if len(rooms) > 0 {
		a.Manifest.Version = version
	}
	return writeJSON(filepath.Join(a.Dir, "manifest.json"), a.Manifest)
}

func (a *Archive) IsRoomSkipped(roomID string) bool {
	if a == nil {
		return false
	}
	_, skipped := a.Manifest.SkippedRooms[roomID]
	return skipped
}
