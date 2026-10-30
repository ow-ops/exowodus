package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/mx"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ExportServer needs database access for blocked rooms.
func (e *Exporter) ExportServer(ctx context.Context) error {
	if e.Admin == nil {
		return nil
	}
	if e.Resume != nil {
		slog.Info("checking server export checkpoint")
		checkpoint, err := e.Resume.Load(ctx, "server", "server")
		if err != nil {
			return err
		}
		if checkpoint != nil && maps.Equal(checkpoint.SkippedRooms, e.Archive.Manifest.SkippedRooms) {
			slog.Info("reusing exported server data")
			return nil
		}
	}
	srv := &archive.Server{SkippedRemoteMedia: true, HistoryAtCheckpoint: e.HistoryAtCheckpoint}
	if e.MAS != nil {
		var err error
		if srv.RegistrationTokens, err = e.MAS.RegistrationTokens(ctx); err != nil {
			return fmt.Errorf("registration tokens: %w", err)
		}
	} else {
		var tokens struct {
			RegistrationTokens []archive.RegistrationToken `json:"registration_tokens"`
		}
		u := adminURL(e.Admin, map[string]string{"valid": "true"}, "v1", "registration_tokens")
		if _, err := e.Admin.MakeRequest(ctx, http.MethodGet, u, nil, &tokens); err != nil {
			return fmt.Errorf("registration tokens: %w", err)
		}
		srv.RegistrationTokens = tokens.RegistrationTokens
	}
	if e.DB != nil {
		var err error
		if srv.BlockedRooms, err = e.DB.BlockedRooms(ctx); err != nil {
			return err
		}
		if srv.Aliases, err = e.DB.Aliases(ctx); err != nil {
			return err
		}
		if srv.Reports, err = e.DB.Reports(ctx); err != nil {
			return err
		}
		if srv.ToDevice, err = e.DB.ToDevice(ctx); err != nil {
			return err
		}
	}
	if e.TuwunelDump != nil {
		if err := e.TuwunelDump.addServer(srv, e.Archive.Manifest.ServerName, e.Archive.IsRoomSkipped); err != nil {
			return err
		}
		if e.AllUsers {
			bridges, err := e.TuwunelDump.appservices()
			if err != nil {
				return err
			}
			for _, b := range bridges {
				srv.AppserviceRegistrations = append(srv.AppserviceRegistrations, b.registration)
			}
		}
		if err := e.exportTuwunelMedia(ctx, srv); err != nil {
			return err
		}
	}
	if err := e.Archive.WriteServer(srv); err != nil {
		return err
	}
	if e.Resume != nil {
		paths := []string{filepath.Join(e.Archive.Dir, "server.json")}
		for _, media := range srv.Media {
			paths = append(paths, filepath.Join(e.Archive.Dir, media.File))
		}
		return e.Resume.Save(ctx, "server", "server", paths, archive.ExportCheckpoint{SkippedRooms: e.Archive.Manifest.SkippedRooms})
	}
	return nil
}

// ImportServer returns the new registration tokens: Continuwuity chooses
// token strings itself.
func (im *Importer) ImportServer(ctx context.Context) ([]string, []Failure) {
	srv, err := im.Archive.ReadServer()
	if err != nil {
		return nil, []Failure{{Step: "server", Error: err.Error()}}
	}
	if srv == nil {
		return nil, nil
	}
	if im.Admin == nil {
		if len(srv.RegistrationTokens)+len(srv.BlockedRooms)+len(srv.Reports)+len(srv.ToDevice) == 0 {
			return nil, nil
		}
		return nil, []Failure{{Step: "server", Error: "registration tokens, blocked rooms, reports and to-device messages require --to-admin-token"}}
	}
	rooms, err := im.Archive.RoomHeaders()
	if err != nil {
		return nil, []Failure{{Step: "server", Error: err.Error()}}
	}
	archiveOnly := map[string]bool{}
	for _, room := range rooms {
		archiveOnly[room.RoomID] = room.ArchiveOnly
	}
	var notes []string
	if im.outboxSummary != nil {
		notes = append(notes, fmt.Sprintf("Pending federation deliveries retained for proxy retry; %d expired typing notifications omitted.", im.outboxSummary.ExpiredTyping))
		if im.outboxSummary.OmittedEvents > 0 {
			notes = append(notes, fmt.Sprintf("%d pending deliveries referenced events already omitted from room history.", im.outboxSummary.OmittedEvents))
		}
	}
	if im.SkipPrivateReceipts {
		notes = append(notes, "Private read receipts were omitted (--skip-private-receipts).")
	}
	if im.SkipThreadedReceipts {
		notes = append(notes, "Threaded read receipts were omitted (--skip-threaded-receipts).")
	}
	for _, room := range rooms {
		if im.archiveOnlyRooms[room.RoomID] {
			notes = append(notes, "Room "+room.RoomID+" retained in the archive only (--archive-departed-rooms).")
		}
	}
	for _, user := range im.bridgeAccounts {
		notes = append(notes, "Appservice account "+user+" retained with its bridge registration.")
	}
	for _, user := range im.deactivatedAppserviceSenders {
		notes = append(notes, "Bridge bot "+user+" remains deactivated (--deactivated-id-only). To restore it as active, run repair-tuwunel-accounts --include-appservice-senders before importing it.")
	}
	if im.DeactivatedIDOnly {
		notes = append(notes, "Deactivated accounts were recreated with their IDs and deactivated status only (--deactivated-id-only).")
	}
	for _, roomID := range slices.Sorted(maps.Keys(im.Archive.Manifest.SkippedRooms)) {
		notes = append(notes, fmt.Sprintf("Skipped room %s: %s", roomID, im.Archive.Manifest.SkippedRooms[roomID]))
	}
	for _, room := range rooms {
		for _, eventID := range slices.Sorted(maps.Keys(room.OmittedEvents)) {
			notes = append(notes, fmt.Sprintf("Room %s omitted event %s: %s", room.RoomID, eventID, room.OmittedEvents[eventID]))
		}
	}
	if srv.HistoryAtCheckpoint {
		notes = append(notes, "Room history and state were exported from the database checkpoint; later changes were omitted.")
	}
	if srv.SkippedRemoteMedia {
		notes = append(notes, "Remote media cache was skipped during export; those files depend on their original servers.")
	}
	for _, mxc := range srv.UnavailableMedia {
		notes = append(notes, "Remote media unavailable on source: "+mxc)
	}
	for _, limitation := range srv.Limitations {
		if im.SkipPrivateReceipts && limitation == "private read receipts on backfilled events cannot currently be restored" {
			continue
		}
		if im.SkipThreadedReceipts && limitation == threadedReceiptLimitation {
			continue
		}
		if table, count, ok := outgoingLimitation(limitation); ok && im.outboxSummary != nil && im.outboxSummary.Rows[table] == count {
			continue
		}
		notes = append(notes, "Source limitation: "+limitation)
	}
	var failures []Failure
	server := im.Admin.ServerName()
	sameServer := server == im.Archive.Manifest.ServerName
	for _, alias := range slices.Sorted(maps.Keys(srv.Aliases)) {
		if ctx.Err() != nil {
			return notes, failures
		}
		if archiveOnly[srv.Aliases[alias]] || im.Archive.IsRoomSkipped(srv.Aliases[alias]) {
			continue
		}
		target := alias
		if !sameServer {
			target = mx.WithServer(alias, server)
		}
		if im.aliases[target] {
			continue
		}
		room := im.mapRoom(srv.Aliases[alias])
		_, err := im.Admin.client.CreateAlias(ctx, id.RoomAlias(target), id.RoomID(room))
		if ctx.Err() != nil {
			return notes, failures
		}
		if im.RequireLossless && err != nil {
			if mx.IsStatus(err, http.StatusConflict) {
				existing, resolveErr := im.Admin.client.ResolveAlias(ctx, id.RoomAlias(target))
				if resolveErr != nil {
					failures = append(failures, Failure{Step: "alias", Target: target, Error: fmt.Sprintf("check existing alias: %v", resolveErr)})
					continue
				}
				if string(existing.RoomID) == room {
					continue
				}
				if target == "#admins:"+server && existing.RoomID == im.Admin.room {
					notes = append(notes, fmt.Sprintf("Kept %s for Continuwuity's admin room %s; source admin room: %s.", target, im.Admin.room, room))
					continue
				}
			}
			failures = append(failures, Failure{Step: "alias", Target: target, Error: err.Error()})
			continue
		}
		if err != nil && !mx.IsStatus(err, http.StatusConflict) {
			notes = append(notes, fmt.Sprintf("alias %s for %s not restored: %v", target, room, err))
		}
	}
	for _, room := range srv.BlockedRooms {
		if ctx.Err() != nil {
			return notes, failures
		}
		if _, err := im.Admin.Run(ctx, "!admin rooms moderation ban-room "+room); err != nil {
			failures = append(failures, Failure{Step: "blocked_room", Target: room, Error: err.Error()})
		}
	}
	state, err := im.Archive.ReadServerState()
	if err != nil {
		return nil, append(failures, Failure{Step: "server", Error: err.Error()})
	}
	for _, t := range srv.RegistrationTokens {
		if ctx.Err() != nil {
			return notes, failures
		}
		if newToken, ok := state.Tokens[t.Token]; ok {
			notes = append(notes, fmt.Sprintf("registration token %s is now %s", t.Token, newToken))
			continue
		}
		limit, err := tokenLimit(t, time.Now())
		if err != nil {
			failures = append(failures, Failure{Step: "registration_token", Target: t.Token, Error: err.Error()})
			continue
		}
		out, err := im.Admin.Run(ctx, "!admin token issue "+limit)
		if err != nil {
			failures = append(failures, Failure{Step: "registration_token", Target: t.Token, Error: err.Error()})
			continue
		}
		_, rest, _ := strings.Cut(out, "`")
		newToken, _, _ := strings.Cut(rest, "`")
		state.Tokens[t.Token] = newToken
		if err := im.Archive.WriteServerState(state); err != nil {
			failures = append(failures, Failure{Step: "registration_token", Target: t.Token, Error: err.Error()})
		}
		notes = append(notes, fmt.Sprintf("registration token %s is now %s", t.Token, newToken))
	}
	for _, r := range srv.Reports {
		if ctx.Err() != nil {
			return notes, failures
		}
		if im.Archive.IsRoomSkipped(r.RoomID) {
			continue
		}
		if state.Reports[r.Key()] {
			continue
		}
		if err := im.fileReport(ctx, r); err != nil {
			failures = append(failures, Failure{Step: "report", Target: r.Key(), Error: err.Error()})
			continue
		}
		state.Reports[r.Key()] = true
		if err := im.Archive.WriteServerState(state); err != nil {
			failures = append(failures, Failure{Step: "report", Target: r.Key(), Error: err.Error()})
		}
	}
	notes = append(notes, im.deliverToDevice(ctx, srv.ToDevice, state, &failures)...)
	return notes, failures
}

// Local senders use the appservice; the proxy delivers remote senders' messages.
func (im *Importer) deliverToDevice(ctx context.Context, msgs []archive.ToDevice, state *archive.ServerImportState, failures *[]Failure) []string {
	if len(msgs) == 0 {
		return nil
	}
	server := im.Archive.Manifest.ServerName
	if mx.ServerName(im.Admin.bot) != server {
		return []string{fmt.Sprintf("%d undelivered to-device messages dropped: devices do not carry over to a new server name", len(msgs))}
	}
	local := func(userID string) bool { return mx.ServerName(userID) == server }
	var remote int
	devices := map[string]map[string]bool{}
	for _, m := range msgs {
		if err := ctx.Err(); err != nil {
			*failures = append(*failures, Failure{Step: "to_device", Error: "delivery canceled; remaining messages retained for retry: " + err.Error()})
			break
		}
		if state.ToDevice[m.Key] {
			continue
		}
		if !local(m.Sender) {
			if err := archive.ValidateProxyInboxMessage(m, server); err != nil {
				*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: err.Error()})
				continue
			}
			remote++
			continue
		}
		if local(m.Recipient) && !im.Migrated[m.Recipient] {
			*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: "recipient account was not restored"})
			continue
		}
		if local(m.Recipient) {
			ready, ok := devices[m.Recipient]
			if !ok {
				var err error
				ready, err = im.restoredRecipientDevices(m.Recipient)
				if err != nil {
					*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: err.Error()})
					continue
				}
				devices[m.Recipient] = ready
			}
			if !ready[m.DeviceID] {
				*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: "recipient device has not been restored; message retained for retry"})
				continue
			}
		}
		c, err := im.toDeviceSender(ctx, m.Sender)
		if err != nil {
			*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: err.Error()})
			continue
		}
		body := map[string]any{"messages": map[string]map[string]json.RawMessage{m.Recipient: {m.DeviceID: m.Content}}}
		if _, err := c.MakeRequest(ctx, http.MethodPut, c.BuildClientURL("v3", "sendToDevice", m.Type, txnID(m.Key)), body, nil); err != nil {
			*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: err.Error()})
			continue
		}
		state.ToDevice[m.Key] = true
		if err := im.Archive.WriteServerState(state); err != nil {
			*failures = append(*failures, Failure{Step: "to_device", Target: m.Key, Error: err.Error()})
		}
	}
	if remote > 0 {
		if err := im.Archive.UpgradeFormat(); err != nil {
			*failures = append(*failures, Failure{Step: "to_device", Error: err.Error()})
			return nil
		}
		return []string{fmt.Sprintf("%d queued to-device messages from remote senders retained for delivery by exowodus proxy", remote)}
	}
	return nil
}

func (im *Importer) restoredRecipientDevices(userID string) (map[string]bool, error) {
	state, err := im.Archive.ReadImportState(userID)
	if err != nil {
		return nil, err
	}
	if state.DestUserID != userID {
		return nil, fmt.Errorf("recipient %s has no matching imported account", userID)
	}
	devices := maps.Clone(state.Devices)
	if state.Dehydrated {
		u, err := im.Archive.ReadUser(userID)
		if err != nil {
			return nil, err
		}
		if u.Dehydrated != nil {
			if devices == nil {
				devices = map[string]bool{}
			}
			devices[u.Dehydrated.DeviceID] = true
		}
	}
	return devices, nil
}

func (im *Importer) toDeviceSender(ctx context.Context, userID string) (*mautrix.Client, error) {
	if b := im.bridgeFor(userID); b != nil {
		if b.client == nil {
			return nil, fmt.Errorf("appservice %s is not connected to the destination", b.ID)
		}
		if !im.Migrated[userID] {
			if err := registerAppserviceUser(ctx, b.client, userID); err != nil {
				return nil, err
			}
		}
		return mx.As(b.client, userID), nil
	}
	if !im.Migrated[userID] {
		return nil, fmt.Errorf("sender %s was not restored and has no registered appservice", userID)
	}
	if im.Appservice == nil {
		return nil, errors.New("the exowodus appservice is not registered")
	}
	return im.Appservice.As(userID), nil
}

// Continuwuity's limit, in bytes.
const maxReportReason = 750

// fileReport refiles as the reporter so it reaches the admin room.
func (im *Importer) fileReport(ctx context.Context, r archive.Report) error {
	reporter := im.mapLocalUser(r.Reporter)
	c := im.sessions[r.Reporter].client
	if c == nil {
		if im.Appservice == nil || mx.ServerName(reporter) != mx.ServerName(im.Appservice.Bot) {
			return fmt.Errorf("reporter %s was not migrated", r.Reporter)
		}
		c = im.Appservice.As(reporter)
	}
	suffix := " (reported on " + time.UnixMilli(r.ReceivedTS).UTC().Format(time.RFC3339) + ")"
	reason := r.Reason
	if len(reason)+len(suffix) > maxReportReason {
		reason = strings.ToValidUTF8(reason[:maxReportReason-len(suffix)], "")
	}
	reason += suffix
	roomID := im.mapRoom(r.RoomID)
	switch r.Kind {
	case "event":
		eventID := r.EventID
		if n, ok := im.eventMaps[r.RoomID][eventID]; ok {
			eventID = n
		}
		err := c.ReportEvent(ctx, id.RoomID(roomID), id.EventID(eventID), reason)
		if mx.IsStatus(err, http.StatusNotFound) {
			isEvent := func(ev *event.Event) bool { return string(ev.ID) == eventID }
			if _, found, _ := paginateBack(ctx, c, roomID, isEvent, true); found {
				err = c.ReportEvent(ctx, id.RoomID(roomID), id.EventID(eventID), reason)
			}
		}
		return err
	case "room":
		return c.ReportRoom(ctx, id.RoomID(roomID), reason)
	case "user":
		body := map[string]string{"reason": reason}
		_, err := c.MakeRequest(ctx, http.MethodPost, c.BuildClientURL("v3", "users", im.mapLocalUser(r.TargetUserID), "report"), body, nil)
		return err
	}
	return fmt.Errorf("unknown report kind %q", r.Kind)
}

func (im *Importer) mapLocalUser(userID string) string {
	if mx.ServerName(userID) != im.Archive.Manifest.ServerName {
		return userID
	}
	return mx.WithServer(userID, im.Admin.ServerName())
}

func (im *Importer) mapRoom(roomID string) string {
	if n, ok := im.rooms[roomID]; ok {
		return n
	}
	return roomID
}

// Continuwuity tokens carry one limit, so the use count wins over lifetime.
func tokenLimit(t archive.RegistrationToken, now time.Time) (string, error) {
	if t.UsesAllowed != nil {
		left := *t.UsesAllowed - t.Completed
		if left <= 0 {
			return "", errors.New("no uses left")
		}
		return fmt.Sprintf("--max-uses %d", left), nil
	}
	if t.ExpiryTime != nil {
		left := time.UnixMilli(*t.ExpiryTime).Sub(now)
		if left <= 0 {
			return "", errors.New("expired")
		}
		return fmt.Sprintf("--max-age %ds", int(left.Seconds())), nil
	}
	return "--immortal", nil
}
