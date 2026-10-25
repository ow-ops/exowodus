package migrate

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

const maxVia = 5

// Keeps timeline events: rooms with an empty sync response are omitted.
const syncFilter = `{
	"presence": {"not_types": ["*"]},
	"room": {
		"timeline": {"limit": 1},
		"state": {"not_types": ["*"]},
		"ephemeral": {"types": ["m.receipt"]}
	}
}`

type Exporter struct {
	authRecovery        *authRecovery
	Resume              *archive.ExportResume
	completedRooms      map[string]bool
	quarantined         map[string]bool
	AllUsers            bool
	HistoryAtCheckpoint bool
	// SkipMissingMedia keeps importing when the source no longer serves an MXC.
	SkipMissingMedia bool
	Archive          *archive.Archive
	// Optional. Without it, the avatar is the only media exported.
	Admin       *mautrix.Client
	DB          *SynapseDB
	MAS         *MAS
	MASDB       *MASDB
	TuwunelDump *TuwunelDump
}

func (e *Exporter) skipMissingMedia(mxc, path string, err error) bool {
	if !e.SkipMissingMedia || !mx.IsStatus(err, http.StatusNotFound) {
		return false
	}
	_ = os.Remove(path)
	slog.Warn("skipping missing media", "mxc", mxc, "err", err)
	return true
}

func (e *Exporter) ExportUser(ctx context.Context, s *Session) (*archive.User, error) {
	log := slog.With("user", s.UserID)
	u := &archive.User{UserID: s.UserID, Admin: s.Admin, Locked: s.Locked, Suspended: s.Suspended, ShadowBanned: s.ShadowBanned, Guest: s.Guest, ExternalIDs: s.ExternalIDs, AccountData: map[string]json.RawMessage{}}

	profile, err := s.Client.GetProfile(ctx, id.UserID(s.UserID))
	if err != nil && !mx.IsStatus(err, http.StatusNotFound) {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if profile != nil {
		u.DisplayName, u.AvatarURL = profile.DisplayName, profile.AvatarURL.String()
		for k, v := range profile.Extra {
			raw, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("profile field %s: %w", k, err)
			}
			if u.ProfileFields == nil {
				u.ProfileFields = map[string]json.RawMessage{}
			}
			u.ProfileFields[k] = raw
		}
	}

	var threepids struct {
		Threepids []struct {
			Medium  string `json:"medium"`
			Address string `json:"address"`
		} `json:"threepids"`
	}
	if _, err := s.Client.MakeRequest(ctx, http.MethodGet, s.Client.BuildClientURL("v3", "account", "3pid"), nil, &threepids); s.optional(err) != nil {
		return nil, fmt.Errorf("3pids: %w", err)
	}
	for _, t := range threepids.Threepids {
		if t.Medium == "email" {
			u.Emails = append(u.Emails, t.Address)
		}
	}
	if e.MAS != nil && s.masUserID != "" {
		if u.Emails, err = e.MAS.Emails(ctx, s.masUserID); err != nil {
			return nil, fmt.Errorf("emails: %w", err)
		}
	}

	log.Info("syncing account")
	sync, err := s.Client.FullSyncRequest(ctx, mautrix.ReqSync{FilterID: syncFilter, SetPresence: event.PresenceOffline})
	if err != nil {
		return nil, fmt.Errorf("sync: %w", err)
	}
	for _, ev := range sync.AccountData.Events {
		u.AccountData[ev.Type.Type] = ev.Content.VeryRaw
	}
	for _, roomID := range slices.Sorted(maps.Keys(sync.Rooms.Invite)) {
		if e.HistoryAtCheckpoint && e.TuwunelDump.relayRooms[string(roomID)] == nil {
			continue
		}
		for _, ev := range sync.Rooms.Invite[roomID].State.Events {
			if ev.Type == event.StateMember && ev.GetStateKey() == s.UserID {
				u.Invites = append(u.Invites, archive.Invite{RoomID: string(roomID), Inviter: string(ev.Sender)})
			}
		}
	}

	for _, roomID := range slices.Sorted(maps.Keys(sync.Rooms.Knock)) {
		if e.HistoryAtCheckpoint && e.TuwunelDump.relayRooms[string(roomID)] == nil {
			continue
		}
		k := archive.Knock{RoomID: string(roomID)}
		for _, ev := range sync.Rooms.Knock[roomID].State.Events {
			if server := ev.Sender.Homeserver(); server != mx.ServerName(s.UserID) && !slices.Contains(k.Via, server) {
				k.Via = append(k.Via, server)
			}
			if ev.Type == event.StateMember && ev.GetStateKey() == s.UserID {
				var member struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(ev.Content.VeryRaw, &member)
				k.Reason = member.Reason
			}
		}
		u.Knocks = append(u.Knocks, k)
	}

	rules, err := s.Client.GetPushRules(ctx)
	if s.optional(err) != nil {
		return nil, fmt.Errorf("push rules: %w", err)
	}
	if rules != nil {
		if u.PushRules, err = json.Marshal(map[string]any{"global": rules}); err != nil {
			return nil, err
		}
	}

	joined, err := s.Client.JoinedRooms(ctx)
	if s.optional(err) != nil {
		return nil, fmt.Errorf("joined rooms: %w", err)
	}
	server := mx.ServerName(s.UserID)
	members := map[string]bool{}
	var roomIDs []string
	if joined != nil {
		for _, r := range joined.JoinedRooms {
			roomIDs = append(roomIDs, string(r))
		}
	}
	slices.Sort(roomIDs)
	log.Info("collecting rooms", "count", len(roomIDs))
	for _, roomID := range roomIDs {
		room := archive.Room{RoomID: roomID}
		if e.Archive.IsRoomSkipped(roomID) {
			u.Rooms = append(u.Rooms, room)
			continue
		}
		if e.HistoryAtCheckpoint {
			include, err := e.TuwunelDump.checkpointUserRoom(ctx, s.UserID, &room)
			if err != nil {
				return nil, fmt.Errorf("checkpoint room %s: %w", roomID, err)
			}
			if !include {
				log.Info("room membership absent from checkpoint; skipping", "room", roomID)
				continue
			}
		}
		if joinedRoom := sync.Rooms.Join[id.RoomID(roomID)]; joinedRoom != nil {
			if evs := joinedRoom.AccountData.Events; len(evs) > 0 {
				room.AccountData = map[string]json.RawMessage{}
				for _, ev := range evs {
					room.AccountData[ev.Type.Type] = ev.Content.VeryRaw
				}
			}
			room.Receipt = ownReceipt(joinedRoom.Ephemeral.Events, s.UserID, "m.read")
			room.PrivateReceipt = ownReceipt(joinedRoom.Ephemeral.Events, s.UserID, "m.read.private")
		}
		var roomMembers []string
		if room.Via, roomMembers, err = viaServers(ctx, s.Client, roomID, server); err != nil {
			return nil, fmt.Errorf("room %s members: %w", roomID, err)
		}
		for _, m := range roomMembers {
			members[m] = true
		}
		if e.HistoryAtCheckpoint {
			e.TuwunelDump.trimCheckpointReceipts(&room)
		} else if err := s.optional(exportRoomListing(ctx, s, &room, server)); err != nil {
			return nil, fmt.Errorf("room %s details: %w", roomID, err)
		}
		u.Rooms = append(u.Rooms, room)
	}

	if u.Media, err = e.exportMedia(ctx, s, u.AvatarURL); err != nil {
		return nil, err
	}

	if u.CrossSigning, u.Devices, err = exportKeys(ctx, s.Client, s.UserID, s.close != nil); s.optional(err) != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	if u.Dehydrated, err = exportDehydrated(ctx, s.Client, s.UserID); s.optional(err) != nil {
		return nil, fmt.Errorf("dehydrated device: %w", err)
	}
	if u.Dehydrated != nil {
		u.Devices = slices.DeleteFunc(u.Devices, func(d archive.Device) bool { return d.ID == u.Dehydrated.DeviceID })
	}
	if presence, err := s.Client.GetPresence(ctx, id.UserID(s.UserID)); err == nil {
		u.StatusMsg = presence.StatusMsg
	}
	delete(members, s.UserID)
	if u.Verified, err = exportVerifications(ctx, s.Client, s.UserID, u.CrossSigning, slices.Sorted(maps.Keys(members))); s.optional(err) != nil {
		return nil, fmt.Errorf("verifications: %w", err)
	}
	if e.DB != nil || e.MASDB != nil || e.TuwunelDump != nil {
		secrets := &archive.Secrets{}
		if e.TuwunelDump != nil {
			if secrets, err = e.TuwunelDump.Secrets(s.UserID); err != nil {
				return nil, err
			}
		}
		if e.DB != nil {
			if secrets, err = e.DB.Secrets(ctx, s.UserID); err != nil {
				return nil, err
			}
		}
		if e.MASDB != nil {
			if err := e.MASDB.addSecrets(ctx, s.UserID, secrets); err != nil {
				return nil, err
			}
		}
		if err := e.Archive.WriteSecrets(s.UserID, secrets); err != nil {
			return nil, err
		}
	}
	kb, err := exportKeyBackup(ctx, s.Client)
	if s.optional(err) != nil {
		return nil, fmt.Errorf("key backup: %w", err)
	}
	if kb != nil {
		if err := e.Archive.WriteKeyBackup(s.UserID, kb); err != nil {
			return nil, err
		}
	}
	if err := e.Archive.WriteUser(u); err != nil {
		return nil, err
	}
	return u, e.saveUserExport(ctx, u)
}

func exportRoomListing(ctx context.Context, s *Session, room *archive.Room, server string) error {
	roomID := id.RoomID(room.RoomID)
	if err := s.Client.StateEvent(ctx, roomID, event.StateMember, s.UserID, &room.Member); err != nil {
		return err
	}
	aliases, err := s.Client.GetAliases(ctx, roomID)
	if err != nil {
		return err
	}
	for _, a := range aliases.Aliases {
		if mx.ServerName(string(a)) == server {
			room.Aliases = append(room.Aliases, string(a))
		}
	}
	room.Public, err = roomIsPublic(ctx, s.Client, string(roomID))
	return err
}

func roomIsPublic(ctx context.Context, c *mautrix.Client, roomID string) (bool, error) {
	var listing struct {
		Visibility string `json:"visibility"`
	}
	_, err := c.MakeRequest(ctx, http.MethodGet, c.BuildClientURL("v3", "directory", "list", "room", roomID), nil, &listing)
	return listing.Visibility == "public", err
}

// mediaFile is relative to the user or room directory.
func mediaFile(server, mediaID string) string {
	return filepath.Join("media", url.PathEscape(server), url.PathEscape(mediaID))
}

// ExportDeactivated keeps the user ID reserved on the destination.
func (e *Exporter) ExportDeactivated(userID string) (*archive.User, error) {
	previous, err := e.Archive.ReadUser(userID)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if previous.UserID != userID {
			return nil, errors.New("archived account contains the wrong user")
		}
		if previous.Passwordless && !previous.Deactivated {
			return previous, nil
		}
	}
	u := &archive.User{UserID: userID, Deactivated: true, AccountData: map[string]json.RawMessage{}}
	return u, e.Archive.WriteUser(u)
}

func ownReceipt(events []*event.Event, userID, typ string) string {
	var latest string
	var latestTS int64
	for _, ev := range events {
		if ev.Type != event.EphemeralEventReceipt {
			continue
		}
		var content map[string]map[string]map[string]struct {
			TS       int64  `json:"ts"`
			ThreadID string `json:"thread_id"`
		}
		if json.Unmarshal(ev.Content.VeryRaw, &content) != nil {
			continue
		}
		for eventID, receipts := range content {
			if r, ok := receipts[typ][userID]; ok && (r.ThreadID == "" || r.ThreadID == "main") && r.TS >= latestTS {
				latest, latestTS = eventID, r.TS
			}
		}
	}
	return latest
}

// viaServers returns the servers with the most joined members, excluding
// own, then the joined members.
func viaServers(ctx context.Context, c *mautrix.Client, roomID, own string) ([]string, []string, error) {
	resp, err := c.JoinedMembers(ctx, id.RoomID(roomID))
	if err != nil {
		return nil, nil, err
	}
	counts := map[string]int{}
	var members []string
	for user := range resp.Joined {
		members = append(members, string(user))
		if s := user.Homeserver(); s != own {
			counts[s]++
		}
	}
	servers := make([]string, 0, len(counts))
	for s := range counts {
		servers = append(servers, s)
	}
	slices.SortFunc(servers, func(a, b string) int {
		return cmp.Or(cmp.Compare(counts[b], counts[a]), cmp.Compare(a, b))
	})
	return servers[:min(len(servers), maxVia)], members, nil
}

func (e *Exporter) exportMedia(ctx context.Context, s *Session, avatar string) ([]archive.Media, error) {
	var wanted []archive.Media
	if e.Admin != nil {
		list, err := listSynapseMedia(ctx, e.Admin, s.UserID)
		if err != nil {
			return nil, fmt.Errorf("list media: %w", err)
		}
		server := mx.ServerName(s.UserID)
		for _, m := range list {
			if m.QuarantinedBy != nil {
				if e.quarantined == nil {
					e.quarantined = map[string]bool{}
				}
				e.quarantined["mxc://"+server+"/"+m.MediaID] = true
				continue
			}
			am := archive.Media{MXC: "mxc://" + server + "/" + m.MediaID, ContentType: m.MediaType}
			if m.UploadName != nil {
				am.Filename = *m.UploadName
			}
			wanted = append(wanted, am)
		}
	}
	if avatar != "" && !e.quarantined[avatar] && !slices.ContainsFunc(wanted, func(m archive.Media) bool { return m.MXC == avatar }) {
		wanted = append(wanted, archive.Media{MXC: avatar})
	}

	dir := e.Archive.UserDir(s.UserID)
	log := slog.With("user", s.UserID)
	log.Info("exporting media", "count", len(wanted))
	var out []archive.Media
	for _, m := range wanted {
		server, mediaID, err := mx.ParseMXC(m.MXC)
		if err != nil {
			return nil, fmt.Errorf("media %s: %w", m.MXC, err)
		}
		if server != e.Archive.Manifest.ServerName {
			continue
		}
		m.File = mediaFile(server, mediaID)
		path := filepath.Join(dir, m.File)
		if _, err := os.Stat(path); err == nil && m.ContentType != "" && e.Resume == nil {
			out = append(out, m)
			continue
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		ct, name, err := e.downloadExportMedia(ctx, s.Client, m.MXC, path)
		if err != nil {
			if e.skipMissingMedia(m.MXC, path, err) {
				continue
			}
			return nil, fmt.Errorf("download media %s: %w", m.MXC, err)
		}
		m.ContentType = cmp.Or(m.ContentType, ct)
		m.Filename = cmp.Or(m.Filename, name)
		out = append(out, m)
	}
	return out, nil
}
