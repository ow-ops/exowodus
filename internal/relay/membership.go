package relay

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

// Join joins an existing destination room using its current state.
func (rl *Relay) Join(ctx context.Context, roomID string) error {
	return rl.changeMembership(ctx, roomID, "join")
}

// Leave leaves through the destination's template, so the event references
// the destination's room heads rather than the relay's archived view.
func (rl *Relay) Leave(ctx context.Context, roomID string) error {
	return rl.changeMembership(ctx, roomID, "leave")
}

func (rl *Relay) changeMembership(ctx context.Context, roomID, membership string) error {
	if rl.sender == nil || rl.peer == "" {
		return errors.New("relay destination is not configured")
	}
	rm := rl.room(roomID)
	if rm == nil {
		return fmt.Errorf("unknown room %s", roomID)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var resp *federation.RespMakeJoin
	var err error
	if membership == "join" {
		resp, err = rl.sender.MakeJoin(ctx, &federation.ReqMakeJoin{
			RoomID: rm.id, UserID: id.UserID(rl.UserID()), Via: rl.peer,
			SupportedVersions: []id.RoomVersion{rm.version},
		})
	} else {
		resp, err = rl.sender.MakeLeave(ctx, &federation.ReqMakeLeave{RoomID: rm.id, UserID: id.UserID(rl.UserID()), Via: rl.peer})
	}
	if err != nil {
		return err
	}
	if resp.RoomVersion != "" && resp.RoomVersion != rm.version {
		return errors.New("destination room version differs from the archive")
	}
	p, err := ParsePDU(resp.Event)
	if err != nil {
		return err
	}
	var member struct {
		Membership string `json:"membership"`
	}
	if err := json.Unmarshal(p.Content, &member); err != nil {
		return err
	}
	if p.RoomID != rm.id || p.Type != "m.room.member" || p.Sender != id.UserID(rl.UserID()) || p.StateKey == nil || *p.StateKey != rl.UserID() || member.Membership != membership {
		return fmt.Errorf("destination returned an invalid relay %s template", membership)
	}
	p.Hashes, p.Signatures = nil, nil
	if err := p.Sign(rm.version, rl.Name, rl.key.ID, rl.key.Priv); err != nil {
		return err
	}
	eventID, err := p.GetEventID(rm.version)
	if err != nil {
		return err
	}
	raw, err := jsonv2.Marshal(p)
	if err != nil {
		return err
	}
	if membership == "join" {
		// The destination already has the state; only the admission result is needed.
		_, _, err = rl.sender.MakeFullRequest(ctx, federation.RequestParams{
			ServerName: rl.peer, Method: http.MethodPut,
			Path:         federation.URLPath{"v2", "send_join", rm.id, eventID},
			Query:        url.Values{"omit_members": {"true"}},
			Authenticate: true, RequestJSON: federation.PDU(raw),
		})
	} else {
		err = rl.sender.SendLeave(ctx, &federation.ReqSendLeave{RoomID: rm.id, EventID: eventID, Event: raw, Via: rl.peer})
	}
	if err != nil {
		return err
	}
	rm.mu.Lock()
	rm.add(string(eventID), p, raw)
	rm.mu.Unlock()
	return nil
}

func (rl *Relay) invite(w http.ResponseWriter, r *http.Request) {
	var req federation.ReqSendInvite
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	rm := rl.room(r.PathValue("roomID"))
	if rm == nil {
		mautrix.MNotFound.WithMessage("Unknown room").Write(w)
		return
	}
	p, err := ParsePDU(req.Event)
	if err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	var member struct {
		Membership string `json:"membership"`
	}
	if err := json.Unmarshal(p.Content, &member); err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	eventID, err := p.GetEventID(rm.version)
	if err != nil || req.RoomVersion != rm.version || string(eventID) != r.PathValue("eventID") || p.RoomID != rm.id || p.Type != "m.room.member" || p.Sender.Homeserver() != rl.peer || p.StateKey == nil || *p.StateKey != rl.UserID() || member.Membership != "invite" || !p.VerifyContentHash() {
		mautrix.MForbidden.WithMessage("Invalid relay invitation").Write(w)
		return
	}
	if err := p.VerifySignature(rm.version, rl.peer, func(server string, keyID id.KeyID, _ time.Time) (id.SigningKey, time.Time, error) {
		keys, err := rl.auth.GetKeysWithCache(r.Context(), server, keyID)
		if err != nil {
			return "", time.Time{}, err
		}
		if key, ok := keys.VerifyKeys[keyID]; ok {
			return key.Key, keys.ValidUntilTS.Time, nil
		}
		if key, ok := keys.OldVerifyKeys[keyID]; ok {
			return key.Key, key.ExpiredTS.Time, nil
		}
		return "", time.Time{}, errors.New("invitation signing key is unavailable")
	}); err != nil {
		mautrix.MForbidden.WithMessage("Invalid invitation signature: %v", err).Write(w)
		return
	}
	if err := p.Sign(rm.version, rl.Name, rl.key.ID, rl.key.Priv); err != nil {
		mautrix.MUnknown.WithMessage("%v", err).Write(w)
		return
	}
	raw, err := jsonv2.Marshal(p)
	if err != nil {
		mautrix.MUnknown.WithMessage("%v", err).Write(w)
		return
	}
	rm.mu.Lock()
	rm.add(string(eventID), p, raw)
	rm.mu.Unlock()
	writeJSON(w, federation.RespSendInvite{Event: raw})
}
