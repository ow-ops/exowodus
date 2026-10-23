package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"maunium.net/go/mautrix"
)

func (e *Exporter) ResumeUser(ctx context.Context, id string) (*archive.User, error) {
	if e.Resume == nil {
		return nil, nil
	}
	slog.Info("checking account export checkpoint", "user", id)
	checkpoint, err := e.Resume.Load(ctx, "users", id)
	if err != nil || checkpoint == nil {
		return nil, err
	}
	user, err := e.Archive.ReadUser(id)
	if err != nil {
		return nil, err
	}
	if user.UserID != id {
		return nil, errors.New("export checkpoint contains the wrong user")
	}
	if e.quarantined == nil {
		e.quarantined = map[string]bool{}
	}
	for _, mxc := range checkpoint.Quarantined {
		e.quarantined[mxc] = true
	}
	slog.Info("reusing exported account", "user", id)
	return user, nil
}

func (e *Exporter) saveUserExport(ctx context.Context, user *archive.User) error {
	if e.Resume == nil {
		return nil
	}
	dir := e.Archive.UserDir(user.UserID)
	paths := []string{filepath.Join(dir, "user.json"), filepath.Join(dir, "secrets.json")}
	backup := filepath.Join(dir, "key_backup.json")
	if _, err := os.Stat(backup); err == nil {
		paths = append(paths, backup)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, media := range user.Media {
		paths = append(paths, filepath.Join(dir, media.File))
	}
	return e.Resume.Save(ctx, "users", user.UserID, paths, archive.ExportCheckpoint{Quarantined: slices.Sorted(maps.Keys(e.quarantined))})
}

func (e *Exporter) resumeRoom(ctx context.Context, id string, client *mautrix.Client) (bool, error) {
	if e.Resume == nil {
		return false, nil
	}
	if e.completedRooms[id] {
		return true, nil
	}
	slog.Info("checking room export checkpoint", "room", id)
	checkpoint, err := e.Resume.Load(ctx, "rooms", id)
	if err != nil || checkpoint == nil {
		return false, err
	}
	if err := e.verifyRoomTip(ctx, client, id, checkpoint.Tip); err != nil {
		return false, err
	}
	if e.completedRooms == nil {
		e.completedRooms = map[string]bool{}
	}
	e.completedRooms[id] = true
	slog.Info("reusing exported room", "room", id)
	return true, nil
}

func (e *Exporter) saveRoomExport(ctx context.Context, room *archive.ArchivedRoom, tip string) error {
	if e.Resume == nil {
		return nil
	}
	dir := e.Archive.RoomDir(room.RoomID)
	paths := []string{filepath.Join(dir, "room.json"), filepath.Join(dir, "events.jsonl")}
	if e.TuwunelDump.HasRelayData() {
		paths = append(paths, filepath.Join(dir, "pdus.json"))
	}
	for _, media := range room.Media {
		paths = append(paths, filepath.Join(dir, media.File))
	}
	if err := e.Resume.Save(ctx, "rooms", room.RoomID, paths, archive.ExportCheckpoint{Tip: tip}); err != nil {
		return err
	}
	if e.completedRooms == nil {
		e.completedRooms = map[string]bool{}
	}
	e.completedRooms[room.RoomID] = true
	return nil
}

func (e *Exporter) resumeHistory(ctx context.Context, id string) (bool, error) {
	if e.Resume == nil {
		return false, nil
	}
	checkpoint, err := e.Resume.Load(ctx, "history", id)
	if err != nil {
		return false, err
	}
	if checkpoint != nil {
		return true, nil
	}
	if !e.Resume.CanReuseLegacyHistory() {
		return false, nil
	}
	path := filepath.Join(e.Archive.RoomDir(id), "events.jsonl")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := e.TuwunelDump.compareTimeline(ctx, id, e.Archive.RoomEventsIter(id)); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		slog.Info("existing room history failed snapshot verification; exporting it again", "room", id)
		return false, nil
	}
	return true, nil
}

func (e *Exporter) saveHistoryExport(ctx context.Context, id, tip string) error {
	if e.Resume == nil {
		return nil
	}
	if e.TuwunelDump != nil && e.TuwunelDump.HasRelayData() {
		if err := e.TuwunelDump.compareTimeline(ctx, id, e.Archive.RoomEventsIter(id)); err != nil {
			return fmt.Errorf("room %s: source snapshot/API mismatch: %w", id, err)
		}
	}
	return e.Resume.Save(ctx, "history", id, []string{filepath.Join(e.Archive.RoomDir(id), "events.jsonl")}, archive.ExportCheckpoint{Tip: tip})
}

func (e *Exporter) downloadExportMedia(ctx context.Context, client *mautrix.Client, mxc, path string) (string, string, error) {
	key, err := filepath.Rel(e.Archive.Dir, path)
	if err != nil {
		return "", "", err
	}
	if e.Resume != nil {
		checkpoint, err := e.Resume.Load(ctx, "media", key)
		if err != nil {
			return "", "", err
		}
		if checkpoint != nil {
			if checkpoint.Media == nil || checkpoint.Media.MXC != mxc {
				return "", "", fmt.Errorf("media checkpoint does not match %s", mxc)
			}
			return checkpoint.Media.ContentType, checkpoint.Media.Filename, nil
		}
	}
	contentType, filename, err := mx.Download(ctx, client, mxc, path)
	if err != nil {
		return "", "", err
	}
	if e.Resume != nil {
		media := &archive.Media{MXC: mxc, ContentType: contentType, Filename: filename}
		if err := e.Resume.Save(ctx, "media", key, []string{path}, archive.ExportCheckpoint{Media: media}); err != nil {
			return "", "", err
		}
	}
	return contentType, filename, nil
}

func (e *Exporter) verifyRoomTip(ctx context.Context, client *mautrix.Client, roomID, tip string) error {
	var page struct {
		Chunk []struct {
			EventID string `json:"event_id"`
		} `json:"chunk"`
	}
	query := url.Values{"dir": {"b"}, "limit": {"1"}}
	if _, err := client.MakeRequest(ctx, http.MethodGet, e.roomURL(client, roomID, query, "messages"), nil, &page); err != nil {
		return fmt.Errorf("check resumed room %s: %w", roomID, err)
	}
	latest := ""
	if len(page.Chunk) > 0 {
		latest = page.Chunk[0].EventID
	}
	if latest != tip {
		return fmt.Errorf("source room %s changed since export; use a new dump and --archive directory", roomID)
	}
	return nil
}
