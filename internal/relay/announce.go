package relay

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

// Announce sends the events the relay signed to the room's other servers.
// Continuwuity receives them as join state and does not serve them onward.
func (rl *Relay) Announce(ctx context.Context, roomID string) error {
	r := rl.room(roomID)
	if r == nil {
		return fmt.Errorf("unknown room %s", roomID)
	}
	r.mu.Lock()
	pdus, servers, err := rl.announcement(r)
	r.mu.Unlock()
	if err != nil || len(pdus) == 0 {
		return err
	}
	var mu sync.Mutex
	var errs []error
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Go(func() {
			if err := rl.sendTransaction(ctx, server, pdus); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", server, err))
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (rl *Relay) announcement(r *room) ([]federation.PDU, []string, error) {
	var pdus []federation.PDU
	for _, eventID := range r.authored {
		raw, err := r.eventJSON(r.events[eventID])
		if err != nil {
			return nil, nil, err
		}
		pdus = append(pdus, federation.PDU(raw))
	}
	seen := map[string]bool{rl.Name: true, rl.origin: true, rl.peer: true}
	var servers []string
	for key, eventID := range r.current {
		userID, ok := strings.CutPrefix(key, StateKey("m.room.member", ""))
		server := id.UserID(userID).Homeserver()
		if !ok || seen[server] {
			continue
		}
		raw, err := r.eventJSON(r.events[eventID])
		if err != nil {
			return nil, nil, err
		}
		var member struct {
			Content struct{ Membership string } `json:"content"`
		}
		if err := json.Unmarshal(raw, &member); err != nil {
			return nil, nil, err
		}
		if member.Content.Membership == "join" {
			seen[server] = true
			servers = append(servers, server)
		}
	}
	return pdus, servers, nil
}

func (rl *Relay) sendTransaction(ctx context.Context, server string, pdus []federation.PDU) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := rl.remote.SendTransaction(ctx, &federation.ReqSendTransaction{
		Destination: server, TxnID: rand.Text(),
		Origin: rl.Name, OriginServerTS: jsontime.UnixMilliNow(), PDUs: pdus,
	})
	if err != nil {
		return err
	}
	var errs []error
	for eventID, result := range resp.PDUs {
		if result.Error != "" {
			errs = append(errs, fmt.Errorf("%s: %s", eventID, result.Error))
		}
	}
	return errors.Join(errs...)
}
