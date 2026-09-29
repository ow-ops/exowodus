package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
)

const messagesPageSize = "1000"

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
	// Room endpoints of the Synapse admin API mirror the client API's.
	roomURL := func(query url.Values, path ...any) string {
		full := append([]any{"v3", "rooms", roomID}, path...)
		var p mautrix.PrefixableURLPath = mautrix.ClientURLPath(full)
		if e.Admin != nil {
			full[0] = "v1"
			p = mautrix.SynapseAdminURLPath(full)
		}
		return c.BuildURLWithFullQuery(p, func(q url.Values) { maps.Copy(q, query) })
	}
	log := slog.With("room", roomID)
	room := &archive.ArchivedRoom{RoomID: roomID}

	if e.Admin != nil {
		var state struct {
			State []json.RawMessage `json:"state"`
		}
		if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(nil, "state"), nil, &state); err != nil {
			return fmt.Errorf("room state: %w", err)
		}
		room.State = state.State
		var details struct {
			Public bool `json:"public"`
		}
		if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(nil), nil, &details); err != nil {
			return fmt.Errorf("room details: %w", err)
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
	for _, raw := range room.State {
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
	}

	var events []json.RawMessage
	q := url.Values{"dir": {"f"}, "limit": {messagesPageSize}}
	for {
		var page struct {
			Chunk []json.RawMessage `json:"chunk"`
			End   string            `json:"end"`
		}
		if _, err := c.MakeRequest(ctx, http.MethodGet, roomURL(q, "messages"), nil, &page); err != nil {
			return fmt.Errorf("room messages: %w", err)
		}
		events = append(events, page.Chunk...)
		if page.End == "" || page.End == q.Get("from") {
			break
		}
		q.Set("from", page.End)
	}
	log.Info("exported room history", "events", len(events))
	if err := e.Archive.WriteRoomEvents(roomID, events); err != nil {
		return err
	}
	if e.DB != nil {
		data, err := e.DB.RoomRelayData(ctx, roomID)
		if err != nil {
			return err
		}
		if err := redactPDUs(data.Events, events, room.Version); err != nil {
			return err
		}
		if mismatched := checkEventIDs(data.Events, room.Version); mismatched > 0 {
			log.Warn("some event IDs could not be recomputed; the relay will not be used for this room", "count", mismatched)
		} else if err := e.Archive.WriteRoomPDUs(roomID, data); err != nil {
			return err
		}
	}

	server := e.Archive.Manifest.ServerName
	local := map[string]bool{}
	for _, raw := range events {
		ev, err := decodeEvent(raw)
		if err != nil {
			return err
		}
		for _, userID := range []string{ev.Sender, memberTarget(ev)} {
			switch {
			case userID == "":
			case mx.ServerName(userID) != server:
				room.RemoteParticipants = true
			default:
				local[userID] = true
			}
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
	for _, mxc := range collectMXC(append(slices.Clone(room.State), events...)) {
		srv, mediaID, err := mx.ParseMXC(mxc)
		if err != nil || srv != server || known[mxc] || e.quarantined[mxc] {
			continue
		}
		m := archive.Media{MXC: mxc, File: mediaFile(srv, mediaID)}
		path := filepath.Join(dir, m.File)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if m.ContentType, m.Filename, err = mx.Download(ctx, c, mxc, path); err != nil {
			if e.skipMissingMedia(mxc, path, err) {
				continue
			}
			return fmt.Errorf("download media %s: %w", mxc, err)
		}
		room.Media = append(room.Media, m)
	}
	return e.Archive.WriteRoom(room)
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
	if !e.AllUsers || e.Admin == nil {
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
