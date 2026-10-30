package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"

	"exowodus/internal/archive"
)

const threadedReceiptLimitation = "threaded read receipts are not supported by the destination"

// Older exports flattened threaded receipts into room-wide read markers.
func (im *Importer) LoadThreadedReceipts(ctx context.Context, users []*archive.User, server *archive.Server) error {
	if !im.SkipThreadedReceipts || server == nil || !slices.Contains(server.Limitations, threadedReceiptLimitation) {
		return nil
	}
	rooms := map[string]*archive.Room{}
	for _, user := range users {
		for i := range user.Rooms {
			room := &user.Rooms[i]
			rooms[room.RoomID+"\x00"+user.UserID] = room
			room.Receipt = ""
		}
	}
	timestamps := map[string]int64{}
	path := filepath.Join(im.Archive.Dir, "source", "tuwunel", "readreceiptid_readreceipt.txt")
	return walkTuwunelScan(ctx, path, func(_ string, raw []byte, _ tuwunelValueRef) error {
		var receipt struct {
			RoomID  string `json:"room_id"`
			Content map[string]map[string]map[string]struct {
				ThreadID string `json:"thread_id"`
				TS       int64  `json:"ts"`
			} `json:"content"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil || receipt.RoomID == "" {
			return errors.New("invalid archived Tuwunel receipt")
		}
		for eventID, types := range receipt.Content {
			for userID, r := range types["m.read"] {
				key := receipt.RoomID + "\x00" + userID
				room := rooms[key]
				if room == nil || (r.ThreadID != "" && r.ThreadID != "main") {
					continue
				}
				if r.TS > timestamps[key] || r.TS == timestamps[key] && eventID > room.Receipt {
					room.Receipt, timestamps[key] = eventID, r.TS
				}
			}
		}
		return nil
	})
}
