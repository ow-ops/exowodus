package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"maunium.net/go/mautrix"

	"exodus/internal/archive"
	"exodus/internal/mx"
	"exodus/internal/relay"
)

const messagesPageSize = "100"

// LocalOnlyRooms returns rooms no other server is in: they cannot be rejoined
// once the source is gone.
func LocalOnlyRooms(users []*archive.User) []string {
	var ids []string
	for _, u := range users {
		for _, r := range u.Rooms {
			if len(r.Via) == 0 && !slices.Contains(ids, r.RoomID) {
				ids = append(ids, r.RoomID)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// ExportRoom uses the Synapse admin API when available, else the client API
// as member, limited by history visibility. known lists media already exported.
func (e *Exporter) ExportRoom(ctx context.Context, roomID string, known map[string]bool, member *mautrix.Client) error {
	c := e.Admin
	if c == nil {
		c = member
	}
	if reused, err := e.resumeRoom(ctx, roomID, c); err != nil || reused {
		return err
	}
	roomURL := func(query url.Values, path ...any) string { return e.roomURL(c, roomID, query, path...) }
	log := slog.With("room", roomID)
	room := &archive.ArchivedRoom{RoomID: roomID}
	var checkpoint *relay.RoomData
	var stateEvents iter.Seq2[json.RawMessage, error]
	if e.HistoryAtCheckpoint {
		if e.TuwunelDump == nil || !e.TuwunelDump.HasRelayData() || !e.AllUsers || e.Admin == nil {
			return errors.New("checkpoint history requires a whole-server Tuwunel dump and admin API access")
		}
		var err error
		checkpoint, err = e.TuwunelDump.roomRelayMetadata(ctx, roomID)
		if err != nil {
			return err
		}
		stateEvents = e.TuwunelDump.roomStateEvents(ctx, roomID, checkpoint.CurrentState)
		log.Info("exporting room from database checkpoint")
	}

	if e.Admin != nil {
		if !e.HistoryAtCheckpoint {
			var state struct {
				State []json.RawMessage `json:"state"`
			}
			if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(nil, "state"), nil, &state); err != nil {
				return fmt.Errorf("room state: %w", err)
			}
			room.State = state.State
		}
		var details struct {
			Public bool `json:"public"`
		}
		if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(nil), nil, &details); err != nil {
			if checkpoint == nil || !mx.IsStatus(err, http.StatusNotFound) {
				return fmt.Errorf("room details: %w", err)
			}
			log.Info("room details unavailable; leaving directory listing private")
		}
		room.Public = details.Public
	} else {
		if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(nil, "state"), nil, &room.State); err != nil {
			return fmt.Errorf("room state: %w", err)
		}
		var err error
		if room.Public, err = roomIsPublic(ctx, c, roomID); err != nil {
			return fmt.Errorf("room listing: %w", err)
		}
	}
	room.ArchiveOnly = e.Admin != nil
	room.Version = "1"
	if stateEvents == nil {
		stateEvents = func(yield func(json.RawMessage, error) bool) {
			for _, raw := range room.State {
				if !yield(raw, nil) {
					return
				}
			}
		}
	}
	var mediaRefs []string
	seenMedia := map[string]bool{}
	collectMedia := func(raw json.RawMessage) {
		for _, mxc := range collectMXC([]json.RawMessage{raw}) {
			if !seenMedia[mxc] {
				seenMedia[mxc] = true
				mediaRefs = append(mediaRefs, mxc)
			}
		}
	}
	for raw, err := range stateEvents {
		if err != nil {
			return err
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			return err
		}
		if ev.Type == "m.room.member" && membership(ev) == "join" && mx.ServerName(memberTarget(ev)) == e.Archive.Manifest.ServerName {
			room.ArchiveOnly = false
		}
		if ev.Type == "m.room.create" {
			var create struct {
				RoomVersion string `json:"room_version"`
			}
			if err := json.Unmarshal(ev.Content, &create); err == nil && create.RoomVersion != "" {
				room.Version = create.RoomVersion
			}
		}
		collectMedia(raw)
	}

	server := e.Archive.Manifest.ServerName
	local := map[string]bool{}
	count := 0
	tip := ""
	inspect := func(raw json.RawMessage) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		ev, err := decodeEvent(raw)
		if err != nil {
			return err
		}
		tip = ev.EventID
		for _, userID := range []string{ev.Sender, memberTarget(ev)} {
			switch {
			case userID == "":
			case mx.ServerName(userID) != server:
				room.RemoteParticipants = true
			default:
				local[userID] = true
			}
		}
		collectMedia(raw)
		count++
		return nil
	}
	historyReady, err := e.resumeHistory(ctx, roomID)
	if err != nil {
		return err
	}
	if historyReady {
		log.Info("reusing exported room history")
		for raw, err := range e.Archive.RoomEventsIter(roomID) {
			if err != nil {
				return err
			}
			if err := inspect(raw); err != nil {
				return err
			}
		}
		if err := e.verifyRoomTip(ctx, c, roomID, tip); err != nil {
			return err
		}
	} else if e.HistoryAtCheckpoint {
		events := func(yield func(json.RawMessage, error) bool) {
			for raw, err := range e.TuwunelDump.checkpointTimeline(ctx, roomID) {
				if err == nil {
					err = inspect(raw)
				}
				if !yield(raw, err) || err != nil {
					return
				}
			}
		}
		if err := e.Archive.WriteRoomEventsFrom(roomID, events); err != nil {
			return err
		}
	} else {
		events := func(yield func(json.RawMessage, error) bool) {
			q := url.Values{"dir": {"f"}, "limit": {messagesPageSize}}
			for {
				var page struct {
					Chunk []json.RawMessage `json:"chunk"`
					End   string            `json:"end"`
				}
				if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(q, "messages"), nil, &page); err != nil {
					yield(nil, fmt.Errorf("room messages: %w", err))
					return
				}
				for _, raw := range page.Chunk {
					if err := inspect(raw); err != nil {
						yield(nil, err)
						return
					}
					if !yield(raw, nil) {
						return
					}
				}
				if page.End == "" || page.End == q.Get("from") {
					return
				}
				q.Set("from", page.End)
			}
		}
		if err := e.Archive.WriteRoomEventsFrom(roomID, events); err != nil {
			return err
		}
	}
	if err := e.saveHistoryExport(ctx, roomID, tip); err != nil {
		return err
	}
	log.Info("exported room history", "events", count)

	if e.DB != nil {
		data, err := e.DB.RoomRelayData(ctx, roomID)
		if err != nil {
			return err
		}
		if err := redactPDUs(data.Events, e.Archive.RoomEventsIter(roomID), room.Version); err != nil {
			return err
		}
		if mismatched := checkEventIDs(data.Events, room.Version); mismatched > 0 {
			log.Warn("some event IDs could not be recomputed; the relay will not be used for this room", "count", mismatched)
		} else if err := e.Archive.WriteRoomPDUs(roomID, data); err != nil {
			return err
		}
	}
	if checkpoint != nil {
		if err := e.TuwunelDump.writeRoomPDUs(ctx, e.Archive, roomID, room.Version, checkpoint); err != nil {
			return err
		}
	} else if e.TuwunelDump != nil && e.TuwunelDump.HasRelayData() {
		if err := e.TuwunelDump.exportRoomPDUs(ctx, e.Archive, roomID, room.Version); err != nil {
			return err
		}
	}

	// Deactivated users can only be told apart with admin access.
	if e.Admin != nil {
		for _, userID := range slices.Sorted(maps.Keys(local)) {
			d, err := synapseUser(ctx, e.Admin, userID)
			if err != nil {
				log.Warn("could not look up user", "user", userID, "err", err)
				continue
			}
			if d.Deactivated || d.IsGuest {
				room.Ghosts = append(room.Ghosts, userID)
			}
		}
	}

	dir := e.Archive.RoomDir(roomID)
	for _, mxc := range mediaRefs {
		srv, mediaID, err := mx.ParseMXC(mxc)
		if err != nil || srv != server || known[mxc] || e.quarantined[mxc] {
			continue
		}
		m := archive.Media{MXC: mxc, File: mediaFile(srv, mediaID)}
		path := filepath.Join(dir, m.File)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if m.ContentType, m.Filename, err = e.downloadExportMedia(ctx, c, mxc, path); err != nil {
			if e.skipMissingMedia(mxc, path, err) {
				continue
			}
			return fmt.Errorf("download media %s: %w", mxc, err)
		}
		room.Media = append(room.Media, m)
	}
	if checkpoint != nil {
		err = e.Archive.WriteRoomWithState(room, stateEvents)
	} else {
		err = e.Archive.WriteRoom(room)
	}
	if err != nil {
		return err
	}
	return e.saveRoomExport(ctx, room, tip)
}

func (e *Exporter) roomURL(client *mautrix.Client, roomID string, query url.Values, path ...any) string {
	full := append([]any{"v3", "rooms", roomID}, path...)
	var prefix mautrix.PrefixableURLPath = mautrix.ClientURLPath(full)
	if e.Admin != nil {
		full[0] = "v1"
		prefix = mautrix.SynapseAdminURLPath(full)
	}
	return client.BuildURLWithFullQuery(prefix, func(q url.Values) { maps.Copy(q, query) })
}

type roomEvent struct {
	Type           string          `json:"type"`
	Sender         string          `json:"sender"`
	EventID        string          `json:"event_id"`
	StateKey       *string         `json:"state_key"`
	OriginServerTS int64           `json:"origin_server_ts"`
	Content        json.RawMessage `json:"content"`
	Redacts        string          `json:"redacts"`
	Unsigned       struct {
		RedactedBecause json.RawMessage `json:"redacted_because"`
	} `json:"unsigned"`
}

func decodeEvent(raw json.RawMessage) (roomEvent, error) {
	var ev roomEvent
	err := json.Unmarshal(raw, &ev)
	return ev, err
}

func memberTarget(ev roomEvent) string {
	if ev.Type == "m.room.member" && ev.StateKey != nil {
		return *ev.StateKey
	}
	return ""
}

func decodeContent(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if len(raw) > 0 {
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func collectMXC(events []json.RawMessage) []string {
	var found []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if strings.HasPrefix(x, "mxc://") && !slices.Contains(found, x) {
				found = append(found, x)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	for _, raw := range events {
		var ev struct {
			Content any `json:"content"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			walk(ev.Content)
		}
	}
	return found
}

func rewriteMXC(v any, media map[string]string) any {
	switch x := v.(type) {
	case string:
		if n, ok := media[x]; ok {
			return n
		}
	case map[string]any:
		for k, e := range x {
			x[k] = rewriteMXC(e, media)
		}
	case []any:
		for i, e := range x {
			x[i] = rewriteMXC(e, media)
		}
	}
	return v
}

// remapRelations returns false when the event is meaningless without its
// missing target.
func remapRelations(content map[string]any, events map[string]string) bool {
	rel, ok := content["m.relates_to"].(map[string]any)
	if !ok {
		return true
	}
	if irt, ok := rel["m.in_reply_to"].(map[string]any); ok {
		if n, ok := events[fmt.Sprint(irt["event_id"])]; ok {
			irt["event_id"] = n
		} else {
			delete(rel, "m.in_reply_to")
		}
	}
	if id, ok := rel["event_id"].(string); ok {
		if n, ok := events[id]; ok {
			rel["event_id"] = n
		} else {
			switch rel["rel_type"] {
			case "m.annotation", "m.replace":
				return false
			}
			delete(rel, "event_id")
			delete(rel, "rel_type")
			delete(rel, "is_falling_back")
		}
	}
	if len(rel) == 0 {
		delete(content, "m.relates_to")
	}
	return true
}

func asSlice(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// ExportDepartedRooms archives rooms with no joined local users.
func (e *Exporter) ExportDepartedRooms(ctx context.Context, known map[string]bool) error {
	if !e.AllUsers || e.Admin == nil || e.HistoryAtCheckpoint {
		return nil
	}
	q := map[string]string{"limit": "100", "order_by": "name"}
	for {
		var page struct {
			Rooms []struct {
				RoomID             string `json:"room_id"`
				JoinedLocalMembers int    `json:"joined_local_members"`
			} `json:"rooms"`
			NextToken any `json:"next_token"`
		}
		if _, err := e.Admin.MakeRequest(ctx, http.MethodGet, adminURL(e.Admin, q, "v1", "rooms"), nil, &page); err != nil {
			return fmt.Errorf("list departed rooms: %w", err)
		}
		for _, room := range page.Rooms {
			if room.JoinedLocalMembers != 0 {
				continue
			}
			if err := e.ExportRoom(ctx, room.RoomID, known, nil); err != nil {
				return fmt.Errorf("archive departed room %s: %w", room.RoomID, err)
			}
		}
		if page.NextToken == nil {
			return nil
		}
		next := fmt.Sprint(page.NextToken)
		if next == q["from"] {
			return fmt.Errorf("room inventory pagination did not advance from %s", next)
		}
		q["from"] = next
	}
}
