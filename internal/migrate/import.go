package migrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

type Importer struct {
	Archive *archive.Archive
	Dest    *mautrix.Client
	// Without DestToken or DestPassword, accounts get generated passwords.
	DestToken         string
	DestPassword      string
	RegistrationToken string
	// Migrated source user IDs; references between them are rewritten.
	Migrated map[string]bool

	// Admin and Appservice are optional.
	Admin      *ContinuwuityAdmin
	Appservice *Appservice
	Bridges    []*Bridge

	sessions     map[string]destAccount
	media        map[string]string
	rooms        map[string]string
	roomFailures map[string]bool
	// oldSessions and pending are loaded lazily.
	oldSessions map[string]archive.Session
	pending     map[string]archive.PendingPassword
	// eventMaps maps old event IDs to new ones, per room.
	eventMaps map[string]map[string]string
	// ghosts are deactivated once rooms are replayed.
	ghosts    map[string]bool
	aliases   map[string]bool
	published map[string]bool
	// members invite later users locally, avoiding federated invites.
	members map[string][]destAccount
}

type destAccount struct {
	id       string
	client   *mautrix.Client
	password string
	// generated passwords may be replaced by the proxy with the old one.
	generated bool
	ephemeral bool
}

type Report struct {
	SourceUserID string    `json:"source_user_id"`
	DestUserID   string    `json:"dest_user_id"`
	RoomsJoined  int       `json:"rooms_joined"`
	AdminGranted bool      `json:"admin_granted,omitempty"`
	Failures     []Failure `json:"failures,omitempty"`
}

type Failure struct {
	Step   string `json:"step"`
	Target string `json:"target,omitempty"`
	Error  string `json:"error"`
}

func (r *Report) fail(step, target string, err error) {
	slog.Warn("step failed", "user", r.SourceUserID, "step", step, "target", target, "err", err)
	r.Failures = append(r.Failures, Failure{Step: step, Target: target, Error: err.Error()})
}

// ImportUser runs every phase. Call PrepareUser and FinishUser directly to
// replay rooms in between.
func (im *Importer) ImportUser(ctx context.Context, u *archive.User, src *Session) (*Report, error) {
	job, err := im.PrepareUser(ctx, u)
	if err != nil {
		return nil, err
	}
	return im.FinishUser(ctx, job, src)
}

type UserJob struct {
	User   *archive.User
	Report *Report
	acct   destAccount
	state  *archive.ImportState
}

func (j *UserJob) save(a *archive.Archive) error { return a.WriteImportState(j.User.UserID, j.state) }

func (j *UserJob) sameServer() bool {
	return mx.ServerName(j.User.UserID) == mx.ServerName(j.acct.id)
}

// PrepareUser imports what does not depend on rooms.
func (im *Importer) PrepareUser(ctx context.Context, u *archive.User) (*UserJob, error) {
	acct, err := im.destSession(ctx, u)
	if err != nil {
		return nil, err
	}
	state, err := im.Archive.ReadImportState(u.UserID)
	if err != nil {
		return nil, err
	}
	state.DestUserID = acct.id
	job := &UserJob{User: u, Report: &Report{SourceUserID: u.UserID, DestUserID: acct.id}, acct: acct, state: state}
	rep := job.Report
	save := func() error { return job.save(im.Archive) }
	slog.Info("importing user", "user", u.UserID, "dest", acct.id)
	if u.Deactivated {
		// Only the account is recreated; ApplyStatus deactivates it.
		return job, save()
	}

	dir := im.Archive.UserDir(u.UserID)
	for _, m := range u.Media {
		if _, ok := state.Media[m.MXC]; ok {
			continue
		}
		mxc, err := mx.Upload(ctx, acct.client, filepath.Join(dir, m.File), m.ContentType, m.Filename)
		if err != nil {
			rep.fail("media", m.MXC, err)
			continue
		}
		state.Media[m.MXC] = mxc
		if err := save(); err != nil {
			return nil, err
		}
	}
	im.addMedia(state.Media)

	importProfile(ctx, acct.client, u, state, rep)

	if u.Admin && im.Admin != nil && !state.Admin {
		if _, err := im.Admin.Run(ctx, AdminHint(acct.id)); err != nil {
			rep.fail("admin", acct.id, err)
		} else {
			state.Admin = true
		}
	}
	rep.AdminGranted = state.Admin

	if len(u.Emails) > 0 && !state.Email {
		if im.Admin == nil {
			rep.fail("email", "", errors.New("restoring email addresses requires --to-admin-token"))
		} else if _, err := im.Admin.Run(ctx, "!admin users change-email "+acct.id+" "+u.Emails[0]); err != nil {
			rep.fail("email", u.Emails[0], err)
		} else {
			state.Email = true
			for _, e := range u.Emails[1:] {
				rep.fail("email", e, errors.New("only one email address per account is supported by Continuwuity"))
			}
		}
	}

	kb, err := im.Archive.ReadKeyBackup(u.UserID)
	if err != nil {
		return nil, err
	}
	if kb != nil && !state.KeysDone {
		if err := importKeyBackup(ctx, acct.client, kb, state, save); err != nil {
			rep.fail("key_backup", "", err)
		}
	}
	if job.sameServer() && u.CrossSigning != nil && !state.Signing {
		if err := importCrossSigning(ctx, acct, im.Appservice, u.CrossSigning); err != nil {
			rep.fail("cross_signing", "", err)
		} else {
			state.Signing = true
		}
	}

	secrets, err := im.Archive.ReadSecrets(u.UserID)
	if err != nil {
		return nil, err
	}
	if job.sameServer() && (len(u.Devices) > 0 || secrets != nil && (len(secrets.Tokens) > 0 || len(secrets.Devices) > 0)) {
		if im.Appservice == nil {
			rep.fail("devices", "", errors.New("restoring devices requires --to-admin-token"))
		} else {
			if err := im.importDevices(ctx, job, secrets); err != nil {
				return nil, err
			}
			if secrets != nil && len(secrets.Pushers) > 0 && !state.Pushers {
				before := len(rep.Failures)
				im.importPushers(ctx, job, secrets.Pushers)
				state.Pushers = len(rep.Failures) == before
			}
		}
	}
	if job.sameServer() && u.Dehydrated != nil && !state.Dehydrated {
		if err := importDehydrated(ctx, acct.client, u.Dehydrated, secrets); err != nil {
			rep.fail("dehydrated_device", u.Dehydrated.DeviceID, err)
		} else {
			state.Dehydrated = true
		}
	}
	if secrets != nil && secrets.PasswordHash != "" && acct.generated {
		if err := im.addPendingPassword(acct.id, archive.PendingPassword{SourceUserID: u.UserID, Hash: secrets.PasswordHash, Scheme: secrets.PasswordScheme, Version: secrets.PasswordVersion}); err != nil {
			return nil, err
		}
	}
	return job, save()
}

// importDevices keeps device IDs and maps old tokens, so the proxy keeps
// clients logged in.
func (im *Importer) importDevices(ctx context.Context, job *UserJob, secrets *archive.Secrets) error {
	if im.oldSessions == nil {
		var err error
		if im.oldSessions, err = im.Archive.Sessions(); err != nil {
			return err
		}
	}
	devices := slices.Clone(job.User.Devices)
	if secrets != nil {
		// Devices hidden from the device list (guests') are known from their tokens.
		ids := slices.Clone(secrets.Devices)
		for _, t := range secrets.Tokens {
			ids = append(ids, t.DeviceID)
		}
		for _, deviceID := range ids {
			if dh := job.User.Dehydrated; dh != nil && dh.DeviceID == deviceID {
				continue
			}
			if !slices.ContainsFunc(devices, func(d archive.Device) bool { return d.ID == deviceID }) {
				devices = append(devices, archive.Device{ID: deviceID})
			}
		}
	}
	for _, d := range devices {
		if job.state.Devices[d.ID] {
			continue
		}
		token := job.state.DeviceTokens[d.ID]
		if token == "" {
			var err error
			token, err = im.Appservice.Login(ctx, job.acct.id, d.ID, d.DisplayName)
			if err != nil {
				job.Report.fail("device", d.ID, err)
				continue
			}
			job.state.DeviceTokens[d.ID] = token
			if err := job.save(im.Archive); err != nil {
				return err
			}
		}
		body := map[string]any{}
		if len(d.Keys) > 0 {
			body["device_keys"] = d.Keys
		}
		if secrets != nil {
			// Unclaimed one-time keys let others start sessions right away.
			if otks := secrets.OneTimeKeys[d.ID]; len(otks) > 0 {
				body["one_time_keys"] = otks
			}
			if fallback := secrets.FallbackKeys[d.ID]; len(fallback) > 0 {
				body["fallback_keys"] = fallback
			}
		}
		if len(body) > 0 {
			c := mx.WithToken(im.Dest, token)
			if _, err := c.MakeRequest(ctx, http.MethodPost, c.BuildClientURL("v3", "keys", "upload"), body, nil); err != nil {
				job.Report.fail("device_keys", d.ID, err)
				continue
			}
		}
		if secrets != nil {
			for _, t := range secrets.Tokens {
				if t.DeviceID == d.ID {
					im.oldSessions[t.Token] = archive.Session{UserID: job.acct.id, DeviceID: d.ID, Token: token, Refresh: t.Refresh, OAuth: t.OAuth}
				}
			}
		}
		if job.User.Guest {
			im.oldSessions[archive.GuestSessionKey(job.User.UserID)] = archive.Session{UserID: job.acct.id, DeviceID: d.ID, Token: token}
		}
		if err := im.Archive.WriteSessions(im.oldSessions); err != nil {
			return err
		}
		job.state.Devices[d.ID] = true
		if err := job.save(im.Archive); err != nil {
			return err
		}
	}
	return nil
}

func (im *Importer) addPendingPassword(destID string, p archive.PendingPassword) error {
	if im.pending == nil {
		var err error
		if im.pending, err = im.Archive.PendingPasswords(); err != nil {
			return err
		}
	}
	im.pending[destID] = p
	return im.Archive.WritePendingPasswords(im.pending)
}

func (im *Importer) Close(ctx context.Context) {
	for _, a := range im.sessions {
		if !a.ephemeral {
			continue
		}
		if _, err := a.client.Logout(ctx); err != nil {
			slog.Warn("could not log out", "user", a.id, "err", err)
		}
	}
	im.sessions = nil
}

func (im *Importer) FinishUser(ctx context.Context, job *UserJob, src *Session) (*Report, error) {
	u, acct, state, rep := job.User, job.acct, job.state, job.Report
	save := func() error { return job.save(im.Archive) }
	if u.Deactivated {
		return rep, writeReport(im.Archive.UserDir(u.UserID), rep)
	}

	sameServer := job.sameServer()
	srcServer, destServer := mx.ServerName(u.UserID), mx.ServerName(acct.id)
	if src != nil && !sameServer {
		checkRooms := false
		for roomID, complete := range state.Rooms {
			if _, recreated := im.rooms[roomID]; complete && !recreated {
				checkRooms = true
				break
			}
		}
		if checkRooms {
			joined, err := acct.client.JoinedRooms(ctx)
			if err != nil {
				return nil, fmt.Errorf("list destination rooms: %w", err)
			}
			joinedSet := map[id.RoomID]bool{}
			for _, roomID := range joined.JoinedRooms {
				joinedSet[roomID] = true
			}
			changed := false
			for roomID, complete := range state.Rooms {
				if _, recreated := im.rooms[roomID]; complete && !recreated && !joinedSet[id.RoomID(roomID)] {
					delete(state.Rooms, roomID)
					changed = true
				}
			}
			if changed {
				if err := save(); err != nil {
					return nil, err
				}
			}
		}
	}
	mapID := func(userID string) string {
		switch {
		case userID == u.UserID:
			return acct.id
		case !sameServer && im.Migrated[userID] && mx.ServerName(userID) == srcServer:
			return mx.WithServer(userID, destServer)
		}
		return userID
	}

	importAccountData(ctx, acct.client, u, mapID, im.mapRoom, sameServer, rep)
	importPushRules(ctx, acct.client, u, mapID, im.mapRoom, rep)
	if sameServer && len(u.Verified) > 0 && !state.Verified {
		if err := importVerifications(ctx, acct.client, u.Verified); err != nil {
			rep.fail("verifications", "", err)
		} else {
			state.Verified = true
		}
	}

	if im.members == nil {
		im.members = map[string][]destAccount{}
	}
	for _, r := range u.Rooms {
		if im.roomFailures[r.RoomID] {
			rep.fail("room", r.RoomID, errors.New("room history or state restoration is incomplete"))
			continue
		}
		before := len(rep.Failures)
		if newID, ok := im.rooms[r.RoomID]; ok {
			// Replayed room: membership was restored by FinalizeRoom.
			if !state.Rooms[r.RoomID] {
				for typ, content := range r.AccountData {
					if err := setRoomAccountData(ctx, acct.client, newID, typ, content); err != nil {
						rep.fail("room_account_data", newID+" "+typ, err)
					}
				}
				im.restoreReadMarker(ctx, acct, r, newID, rep)
				state.Rooms[r.RoomID] = len(rep.Failures) == before
				if err := save(); err != nil {
					return nil, err
				}
			}
			rep.RoomsJoined++
			continue
		}
		if !state.Rooms[r.RoomID] {
			if src != nil && !sameServer {
				state.PowerPending[r.RoomID] = true
				if err := save(); err != nil {
					return nil, err
				}
			}
			if err := im.importRoom(ctx, acct, u.UserID, r, src, sameServer, rep); err != nil {
				rep.fail("join", r.RoomID, err)
				continue
			}
			if state.PowerPending[r.RoomID] {
				if src == nil {
					rep.fail("power_levels", r.RoomID, errors.New("rerun migrate with the source online to finish power transfer"))
				} else if err := transferPower(ctx, src.Client, r.RoomID, u.UserID, acct.id); err != nil {
					rep.fail("power_levels", r.RoomID, err)
				} else {
					delete(state.PowerPending, r.RoomID)
				}
			}
			im.restoreRoomDetails(ctx, acct, u, r, sameServer, rep)
			state.Rooms[r.RoomID] = len(rep.Failures) == before
			if err := save(); err != nil {
				return nil, err
			}
		} else if src != nil && !sameServer {
			if err := transferPower(ctx, src.Client, r.RoomID, u.UserID, acct.id); err != nil {
				rep.fail("power_levels", r.RoomID, err)
			}
		}
		rep.RoomsJoined++
		im.members[r.RoomID] = append(im.members[r.RoomID], acct)
	}

	if err := save(); err != nil {
		return nil, err
	}
	return rep, writeReport(im.Archive.UserDir(u.UserID), rep)
}

// Without a receipt, a private one at the marker clears the unread count.
// Continuwuity rejects private receipts on backfilled events, so they may be lost.
func (im *Importer) restoreReadMarker(ctx context.Context, acct destAccount, r archive.Room, roomID string, rep *Report) {
	mapEvent := func(eventID string) string {
		if events, ok := im.eventMaps[r.RoomID]; ok {
			return events[eventID]
		}
		return eventID
	}
	var marker struct {
		EventID string `json:"event_id"`
	}
	if raw, ok := r.AccountData["m.fully_read"]; ok {
		_ = json.Unmarshal(raw, &marker)
	}
	body := map[string]string{}
	private := mapEvent(r.PrivateReceipt)
	if eventID := mapEvent(marker.EventID); eventID != "" {
		body["m.fully_read"] = eventID
		if r.Receipt == "" && private == "" {
			private = eventID
		}
	}
	if eventID := mapEvent(r.Receipt); eventID != "" {
		body["m.read"] = eventID
	}
	requests := []map[string]string{body}
	if private != "" {
		requests = append(requests, map[string]string{"m.read.private": private})
	}
	for _, b := range requests {
		if len(b) == 0 {
			continue
		}
		err := acct.client.SetReadMarkers(ctx, id.RoomID(roomID), b)
		// Not backfilled yet, or backfilled, which private receipts do not allow.
		if mx.IsStatus(err, http.StatusNotFound) || mx.IsStatus(err, http.StatusBadRequest) {
			slog.Debug("read marker not restored", "room", roomID, "err", err)
		} else if err != nil {
			rep.fail("read_marker", roomID, err)
		}
	}
}

func (im *Importer) restoreRoomDetails(ctx context.Context, acct destAccount, u *archive.User, r archive.Room, sameServer bool, rep *Report) {
	im.restoreReadMarker(ctx, acct, r, r.RoomID, rep)

	var member struct {
		DisplayName string `json:"displayname"`
		AvatarURL   string `json:"avatar_url"`
	}
	if len(r.Member) > 0 && json.Unmarshal(r.Member, &member) == nil &&
		(member.DisplayName != u.DisplayName || member.AvatarURL != u.AvatarURL) {
		avatar := member.AvatarURL
		if n, ok := im.media[avatar]; ok {
			avatar = n
		}
		body := map[string]any{"membership": "join", "displayname": member.DisplayName}
		if avatar != "" {
			body["avatar_url"] = avatar
		}
		if _, err := acct.client.SendStateEvent(ctx, id.RoomID(r.RoomID), event.StateMember, acct.id, body); err != nil {
			rep.fail("room_profile", r.RoomID, err)
		}
	}

	if im.aliases == nil {
		im.aliases, im.published = map[string]bool{}, map[string]bool{}
	}
	for _, alias := range r.Aliases {
		if !sameServer {
			alias = mx.WithServer(alias, mx.ServerName(acct.id))
		}
		if im.aliases[alias] {
			continue
		}
		_, err := acct.client.CreateAlias(ctx, id.RoomAlias(alias), id.RoomID(r.RoomID))
		if err != nil && !mx.IsStatus(err, http.StatusConflict) {
			rep.fail("alias", alias, err)
			continue
		}
		im.aliases[alias] = true
	}

	if r.Public && !im.published[r.RoomID] {
		err := publishRoom(ctx, acct.client, r.RoomID)
		if err != nil && im.Admin != nil {
			err = publishRoom(ctx, im.Admin.client, r.RoomID)
		}
		if err != nil {
			rep.fail("directory", r.RoomID, err)
		} else {
			im.published[r.RoomID] = true
		}
	}
}

func (im *Importer) importPushers(ctx context.Context, job *UserJob, pushers []archive.Pusher) {
	tokens := maps.Clone(job.state.DeviceTokens)
	if tokens == nil {
		tokens = map[string]string{}
	}
	for _, s := range im.oldSessions {
		if s.UserID == job.acct.id {
			tokens[s.DeviceID] = s.Token
		}
	}
	for _, p := range pushers {
		token, ok := tokens[p.DeviceID]
		if !ok {
			job.Report.fail("pusher", p.DeviceID, errors.New("its device was not migrated"))
			continue
		}
		var pusher mautrix.Pusher
		if err := json.Unmarshal(p.Body, &pusher); err != nil {
			job.Report.fail("pusher", p.DeviceID, err)
			continue
		}
		pusher.Append = true
		if err := mx.WithToken(im.Dest, token).SetPusher(ctx, &pusher); err != nil {
			job.Report.fail("pusher", p.DeviceID, err)
		}
	}
}

// LinkSSO needs OIDC, which disables the logins the import relies on, so it
// runs as a separate step.
func LinkSSO(ctx context.Context, a *archive.Archive, admin *ContinuwuityAdmin) (int, []Failure) {
	users, err := a.Users()
	if err != nil {
		return 0, []Failure{{Step: "sso", Error: err.Error()}}
	}
	var linked int
	var failures []Failure
	for _, u := range users {
		if len(u.ExternalIDs) == 0 {
			continue
		}
		state, err := a.ReadImportState(u.UserID)
		if err != nil {
			failures = append(failures, Failure{Step: "sso", Target: u.UserID, Error: err.Error()})
			continue
		}
		if state.DestUserID == "" {
			failures = append(failures, Failure{Step: "sso", Target: u.UserID, Error: "user was not imported"})
			continue
		}
		if state.SSO {
			continue
		}
		ok := true
		for _, ext := range u.ExternalIDs {
			if _, err := admin.Run(ctx, "!admin oidc link "+state.DestUserID+" "+ext.ExternalID); err != nil {
				failures = append(failures, Failure{Step: "sso", Target: ext.AuthProvider + " " + ext.ExternalID, Error: err.Error()})
				ok = false
			}
		}
		if ok {
			state.SSO = true
			linked++
			if err := a.WriteImportState(u.UserID, state); err != nil {
				failures = append(failures, Failure{Step: "sso", Target: u.UserID, Error: err.Error()})
			}
		}
	}
	return linked, failures
}

// RestoreInvites only resends invites from migrated inviters in the room;
// others are reported.
func (im *Importer) RestoreInvites(ctx context.Context, users []*archive.User) []Failure {
	var failures []Failure
	for _, u := range users {
		acct, ok := im.sessions[u.UserID]
		if !ok {
			continue
		}
		for _, inv := range u.Invites {
			if _, replayed := im.rooms[inv.RoomID]; replayed {
				continue
			}
			inviter, ok := im.sessions[inv.Inviter]
			if !ok {
				failures = append(failures, Failure{Step: "invite", Target: inv.RoomID,
					Error: fmt.Sprintf("pending invite from %s to %s not restored: the inviter was not migrated", inv.Inviter, acct.id)})
				continue
			}
			_, err := inviter.client.InviteUser(ctx, id.RoomID(inv.RoomID), &mautrix.ReqInviteUser{UserID: id.UserID(acct.id)})
			if err != nil {
				failures = append(failures, Failure{Step: "invite", Target: inv.RoomID,
					Error: fmt.Sprintf("pending invite from %s to %s not restored: %v", inv.Inviter, acct.id, err)})
			}
		}
	}
	return failures
}

func (im *Importer) RestoreKnocks(ctx context.Context, users []*archive.User) []Failure {
	var failures []Failure
	for _, u := range users {
		acct, ok := im.sessions[u.UserID]
		if !ok || len(u.Knocks) == 0 {
			continue
		}
		state, err := im.Archive.ReadImportState(u.UserID)
		if err != nil {
			failures = append(failures, Failure{Step: "knock", Error: err.Error()})
			continue
		}
		if state.Knocks == nil {
			state.Knocks = map[string]bool{}
		}
		for _, k := range u.Knocks {
			if _, replayed := im.rooms[k.RoomID]; replayed || state.Knocks[k.RoomID] {
				continue
			}
			via := k.Via
			if server := mx.ServerName(u.UserID); server != mx.ServerName(acct.id) {
				via = append([]string{server}, via...)
			}
			if _, err := acct.client.KnockRoom(ctx, k.RoomID, &mautrix.ReqKnockRoom{Via: via, Reason: k.Reason}); err != nil {
				failures = append(failures, Failure{Step: "knock", Target: k.RoomID,
					Error: fmt.Sprintf("pending knock of %s not restored: %v", acct.id, err)})
				continue
			}
			state.Knocks[k.RoomID] = true
			if err := im.Archive.WriteImportState(u.UserID, state); err != nil {
				failures = append(failures, Failure{Step: "knock", Target: k.RoomID, Error: err.Error()})
			}
		}
	}
	return failures
}

// ApplyStatus runs last: deactivated, locked or suspended accounts can no
// longer act.
func (im *Importer) ApplyStatus(ctx context.Context, users []*archive.User) []Failure {
	var failures []Failure
	fail := func(step, target string, err error) {
		slog.Warn("step failed", "step", step, "target", target, "err", err)
		failures = append(failures, Failure{Step: step, Target: target, Error: err.Error()})
	}
	for _, u := range users {
		state, err := im.Archive.ReadImportState(u.UserID)
		if err != nil {
			fail("status", u.UserID, err)
			continue
		}
		if state.Status || state.DestUserID == "" {
			continue
		}
		userID := state.DestUserID
		var cmds []string
		if u.Deactivated {
			if im.Admin == nil {
				acct, ok := im.sessions[u.UserID]
				if !ok || acct.password == "" {
					fail("deactivate", userID, errors.New("requires --to-admin-token"))
					continue
				}
				if err := mx.DoWithPassword(ctx, acct.client, http.MethodPost, acct.client.BuildClientURL("v3", "account", "deactivate"), map[string]any{"erase": false}, userID, acct.password); err != nil {
					fail("deactivate", userID, err)
					continue
				}
			} else {
				cmds = append(cmds, "!admin users deactivate --no-leave-rooms "+userID)
			}
			delete(im.sessions, u.UserID)
		} else {
			if u.Locked {
				cmds = append(cmds, "!admin users lock "+userID)
			}
			if u.Suspended {
				cmds = append(cmds, "!admin users suspend "+userID)
			}
		}
		if len(cmds) > 0 && im.Admin == nil {
			fail("status", userID, errors.New("requires --to-admin-token"))
			continue
		}
		ok := true
		for _, c := range cmds {
			if _, err := im.Admin.Run(ctx, c); err != nil {
				fail("status", userID, err)
				ok = false
			}
		}
		if ok {
			state.Status = true
			if err := im.Archive.WriteImportState(u.UserID, state); err != nil {
				fail("status", userID, err)
			}
		}
	}
	if im.Admin != nil {
		for _, g := range slices.Sorted(maps.Keys(im.ghosts)) {
			if _, err := im.Admin.Run(ctx, "!admin users deactivate --no-leave-rooms "+g); err != nil && !strings.Contains(err.Error(), "already deactivated") {
				fail("deactivate", g, err)
			}
		}
	}
	return failures
}

func (im *Importer) addMedia(m map[string]string) {
	if im.media == nil {
		im.media = map[string]string{}
	}
	maps.Copy(im.media, m)
}

func (im *Importer) destSession(ctx context.Context, u *archive.User) (destAccount, error) {
	if a, ok := im.sessions[u.UserID]; ok {
		return a, nil
	}
	c, password, err := im.login(ctx, u)
	if err != nil {
		return destAccount{}, err
	}
	if im.sessions == nil {
		im.sessions = map[string]destAccount{}
	}
	a := destAccount{
		id: string(c.UserID), client: c, password: password,
		generated: im.DestPassword == "" && im.DestToken == "" && !u.Guest,
		ephemeral: im.DestToken == "",
	}
	im.sessions[u.UserID] = a
	return a, nil
}

// login also returns the account's password, when known.
func (im *Importer) login(ctx context.Context, u *archive.User) (*mautrix.Client, string, error) {
	if u.Guest {
		return im.guestLogin(ctx, u)
	}
	if im.DestToken != "" {
		c := mx.WithToken(im.Dest, im.DestToken)
		who, err := c.Whoami(ctx)
		if err != nil {
			return nil, "", err
		}
		c.UserID, c.DeviceID = who.UserID, who.DeviceID
		return c, "", nil
	}

	localpart := mx.Localpart(u.UserID)
	password := im.DestPassword
	if password == "" {
		creds, err := im.Archive.Credentials()
		if err != nil {
			return nil, "", err
		}
		password = creds[u.UserID].Password
	}
	if password != "" {
		c, err := mx.Login(ctx, im.Dest, localpart, password)
		if err == nil {
			return c, password, nil
		}
		if status := mx.Status(err); status == 0 || status >= 500 {
			return nil, "", err
		}
	}

	generated := password == ""
	if generated {
		password = rand.Text()
	}
	c, err := mx.Register(ctx, im.Dest, localpart, password, im.RegistrationToken)
	if mx.IsCode(err, "M_USER_IN_USE") {
		return nil, "", fmt.Errorf("%s already exists on the destination; pass its password or access token", localpart)
	}
	if err != nil {
		return nil, "", err
	}
	if generated {
		cred := archive.Credential{SourceUserID: u.UserID, DestUserID: string(c.UserID), Password: password}
		if err := im.Archive.AddCredential(cred); err != nil {
			return nil, "", err
		}
	}
	return c, password, nil
}

// guestLogin uses an appservice account, which like a guest has no password.
func (im *Importer) guestLogin(ctx context.Context, u *archive.User) (*mautrix.Client, string, error) {
	if im.Appservice == nil {
		return nil, "", errors.New("guest accounts require --to-admin-token")
	}
	userID := mx.WithServer(u.UserID, mx.ServerName(im.Appservice.Bot))
	if err := im.Appservice.Register(ctx, userID); err != nil {
		return nil, "", fmt.Errorf("recreate guest %s: %w", u.UserID, err)
	}
	token, err := im.Appservice.Login(ctx, userID, "EXODUS", "exodus")
	if err != nil {
		return nil, "", err
	}
	c := mx.WithToken(im.Dest, token)
	c.UserID, c.DeviceID = id.UserID(userID), "EXODUS"
	return c, "", nil
}

func importProfile(ctx context.Context, dest *mautrix.Client, u *archive.User, state *archive.ImportState, rep *Report) {
	if u.DisplayName != "" {
		if err := dest.SetDisplayName(ctx, u.DisplayName); err != nil {
			rep.fail("displayname", "", err)
		}
	}
	for key, value := range u.ProfileFields {
		dec := json.NewDecoder(bytes.NewReader(value))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			rep.fail("profile", key, err)
			continue
		}
		if err := dest.SetProfileField(ctx, key, rewriteMXC(v, state.Media)); err != nil {
			rep.fail("profile", key, err)
		}
	}
	if u.StatusMsg != "" {
		if err := dest.SetPresence(ctx, mautrix.ReqPresence{Presence: event.PresenceOffline, StatusMsg: u.StatusMsg}); err != nil {
			rep.fail("status_msg", "", err)
		}
	}
	if u.AvatarURL == "" {
		return
	}
	mxc, ok := state.Media[u.AvatarURL]
	if !ok {
		rep.fail("avatar", u.AvatarURL, errors.New("avatar media was not uploaded"))
		return
	}
	uri, err := id.ParseContentURI(mxc)
	if err == nil {
		err = dest.SetAvatarURL(ctx, uri)
	}
	if err != nil {
		rep.fail("avatar", u.AvatarURL, err)
	}
}

func importAccountData(ctx context.Context, dest *mautrix.Client, u *archive.User, mapID, mapRoom func(string) string, keepIdentity bool, rep *Report) {
	for typ, content := range u.AccountData {
		out, ok, err := transformAccountData(typ, content, mapID, mapRoom, keepIdentity)
		if err != nil {
			rep.fail("account_data", typ, err)
			continue
		}
		if !ok {
			continue
		}
		if err := dest.SetAccountData(ctx, typ, out); err != nil {
			rep.fail("account_data", typ, err)
		}
	}
}

func importPushRules(ctx context.Context, dest *mautrix.Client, u *archive.User, mapID, mapRoom func(string) string, rep *Report) {
	ops, err := pushRuleOps(u.PushRules, mapID, mapRoom)
	if err != nil {
		rep.fail("push_rules", "", err)
		return
	}
	for _, op := range ops {
		u := op.url(dest)
		_, err := dest.MakeRequest(ctx, http.MethodPut, u, op.Body, nil)
		if err != nil && (!op.Optional || !mx.IsStatus(err, http.StatusNotFound)) {
			rep.fail("push_rules", u, err)
		}
	}
}

// importRoom is invited by the old account, else by a migrated member already
// in the room.
func (im *Importer) importRoom(ctx context.Context, acct destAccount, srcID string, r archive.Room, src *Session, sameServer bool, rep *Report) error {
	dest, destID := acct.client, acct.id
	via := r.Via
	if !sameServer {
		via = append([]string{mx.ServerName(srcID)}, via...)
	}
	if len(via) == 0 {
		return errors.New("no other server participates in this room; export with --from-admin-token and import with --to-admin-token to recreate it")
	}

	live := src != nil && !sameServer
	invite := func(c *mautrix.Client) error {
		_, err := c.InviteUser(ctx, id.RoomID(r.RoomID), &mautrix.ReqInviteUser{UserID: id.UserID(destID)})
		return err
	}
	var inviteErrs []error
	invited := false
	if live {
		err := invite(src.Client)
		invited = err == nil
		inviteErrs = append(inviteErrs, err)
	}
	for _, m := range im.members[r.RoomID] {
		if invited {
			break
		}
		err := invite(m.client)
		invited = err == nil
		inviteErrs = append(inviteErrs, err)
	}

	join := func() error {
		_, err := dest.JoinRoom(ctx, r.RoomID, &mautrix.ReqJoinRoom{Via: via})
		return err
	}
	err := join()
	if err != nil && live && !invited {
		slog.Warn("invite rejected, opening room temporarily", "room", r.RoomID)
		err = withPublicJoinRule(ctx, src.Client, r.RoomID, join)
	}
	if err != nil {
		if ie := errors.Join(inviteErrs...); ie != nil && !invited {
			return fmt.Errorf("%w (invite: %v)", err, ie)
		}
		return err
	}

	for typ, content := range r.AccountData {
		if err := setRoomAccountData(ctx, dest, r.RoomID, typ, content); err != nil {
			rep.fail("room_account_data", r.RoomID+" "+typ, err)
		}
	}
	return nil
}

func setRoomAccountData(ctx context.Context, dest *mautrix.Client, roomID, typ string, content json.RawMessage) error {
	switch typ {
	case "m.fully_read":
		return nil
	case "m.tag":
		var tags struct {
			Tags map[event.RoomTag]json.RawMessage `json:"tags"`
		}
		if err := json.Unmarshal(content, &tags); err != nil {
			return err
		}
		for tag, v := range tags.Tags {
			if err := dest.AddTagWithCustomData(ctx, id.RoomID(roomID), tag, v); err != nil {
				return err
			}
		}
		return nil
	}
	return dest.SetRoomAccountData(ctx, id.RoomID(roomID), typ, content)
}

func publishRoom(ctx context.Context, c *mautrix.Client, roomID string) error {
	body := map[string]string{"visibility": "public"}
	_, err := c.MakeRequest(ctx, http.MethodPut, c.BuildClientURL("v3", "directory", "list", "room", roomID), body, nil)
	return err
}

// withPublicJoinRule opens the room while fn runs: Continuwuity rejects
// Synapse's federated invites, which carry stripped invite_room_state.
func withPublicJoinRule(ctx context.Context, src *mautrix.Client, roomID string, fn func() error) error {
	room := id.RoomID(roomID)
	var original json.RawMessage
	if err := src.StateEvent(ctx, room, event.StateJoinRules, "", &original); err != nil {
		return fmt.Errorf("read join rules: %w", err)
	}
	var rule struct {
		JoinRule string `json:"join_rule"`
	}
	if err := json.Unmarshal(original, &rule); err != nil {
		return err
	}
	if rule.JoinRule == "public" {
		return fn()
	}
	if _, err := src.SendStateEvent(ctx, room, event.StateJoinRules, "", map[string]string{"join_rule": "public"}); err != nil {
		return fmt.Errorf("open room: %w", err)
	}
	fnErr := fn()
	if _, err := src.SendStateEvent(context.WithoutCancel(ctx), room, event.StateJoinRules, "", original); err != nil {
		return errors.Join(fnErr, fmt.Errorf("restore join rules to %s: %w", rule.JoinRule, err))
	}
	return fnErr
}

func transferPower(ctx context.Context, src *mautrix.Client, roomID, oldID, newID string) error {
	room := id.RoomID(roomID)
	var raw json.RawMessage
	if err := src.StateEvent(ctx, room, event.StatePowerLevels, "", &raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var content map[string]any
	if err := dec.Decode(&content); err != nil {
		return err
	}
	if !raisePower(content, oldID, newID) {
		state, err := src.StateAsArray(ctx, room)
		if err != nil {
			return fmt.Errorf("read room state: %w", err)
		}
		if !isV12Creator(state, oldID) || !grantPower(content, newID, 100) {
			return nil
		}
	}
	_, err := src.SendStateEvent(ctx, room, event.StatePowerLevels, "", content)
	return err
}

func writeReport(dir string, rep *Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "import-report.json"), data, 0o600)
}

func AdminHint(destID string) string {
	return "!admin users make-user-admin " + destID
}

func failuresError(failures []Failure) error {
	errs := make([]error, 0, len(failures))
	for _, f := range failures {
		errs = append(errs, fmt.Errorf("%s %s: %s", f.Step, f.Target, f.Error))
	}
	return errors.Join(errs...)
}
