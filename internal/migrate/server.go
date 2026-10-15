package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"exodus/internal/archive"
	"exodus/internal/mx"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ExportServer needs database access for blocked rooms.
func (e *Exporter) ExportServer(ctx context.Context) error {
	if e.Admin == nil {
		return nil
	}
	srv := &archive.Server{}
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
		if err := e.TuwunelDump.AddServer(srv, e.Archive.Manifest.ServerName); err != nil {
			return err
		}
		var err error
		if srv.Media, err = e.exportTuwunelMedia(ctx); err != nil {
			return err
		}
	}
	return e.Archive.WriteServer(srv)
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
	rooms, err := im.Archive.Rooms()
	if err != nil {
		return nil, []Failure{{Step: "server", Error: err.Error()}}
	}
	archiveOnly := map[string]bool{}
	for _, room := range rooms {
		archiveOnly[room.RoomID] = room.ArchiveOnly
	}
	var notes []string
	for _, limitation := range srv.Limitations {
		notes = append(notes, "Source limitation: "+limitation)
	}
	var failures []Failure
	server := im.Admin.ServerName()
	sameServer := server == im.Archive.Manifest.ServerName
	for _, alias := range slices.Sorted(maps.Keys(srv.Aliases)) {
		if archiveOnly[srv.Aliases[alias]] {
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
		if im.RequireLossless && err != nil {
			if mx.IsStatus(err, http.StatusConflict) {
				existing, resolveErr := im.Admin.client.ResolveAlias(ctx, id.RoomAlias(target))
				if resolveErr == nil && string(existing.RoomID) == room {
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
		if _, err := im.Admin.Run(ctx, "!admin rooms moderation ban-room "+room); err != nil {
			failures = append(failures, Failure{Step: "blocked_room", Target: room, Error: err.Error()})
		}
	}
	state, err := im.Archive.ReadServerState()
	if err != nil {
		return nil, append(failures, Failure{Step: "server", Error: err.Error()})
	}
	for _, t := range srv.RegistrationTokens {
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

// deliverToDevice resends as the original senders. Messages are encrypted
// for device keys, which only survive an unchanged server name.
func (im *Importer) deliverToDevice(ctx context.Context, msgs []archive.ToDevice, state *archive.ServerImportState, failures *[]Failure) []string {
	if len(msgs) == 0 {
		return nil
	}
	server := im.Archive.Manifest.ServerName
	if mx.ServerName(im.Admin.bot) != server {
		return []string{fmt.Sprintf("%d undelivered to-device messages dropped: devices do not carry over to a new server name", len(msgs))}
	}
	if im.Appservice == nil {
		*failures = append(*failures, Failure{Step: "to_device", Error: "the exodus appservice is not registered"})
		return nil
	}
	local := func(userID string) bool { return mx.ServerName(userID) == server }
	var remote int
	for _, m := range msgs {
		if state.ToDevice[m.Key] {
			continue
		}
		if !local(m.Sender) {
			remote++
			continue
		}
		if !im.Migrated[m.Sender] || local(m.Recipient) && !im.Migrated[m.Recipient] {
			continue
		}
		c := im.Appservice.As(m.Sender)
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
		return []string{fmt.Sprintf("%d undelivered to-device messages from other servers dropped; clients request the keys again", remote)}
	}
	return nil
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
			if _, found, _ := paginateBack(ctx, c, roomID, isEvent); found {
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
