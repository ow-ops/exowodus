package migrate

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/progress"
	"maunium.net/go/mautrix"
)

// RefreshMASSessions maps current MAS tokens to restored devices.
func RefreshMASSessions(ctx context.Context, a *archive.Archive, dest *mautrix.Client, db *MASDB) (int, []Failure, error) {
	return refreshMASSessions(ctx, a, dest, db.sessionTokens)
}

func refreshMASSessions(ctx context.Context, a *archive.Archive, dest *mautrix.Client, tokensFor func(context.Context, string) ([]archive.Token, error)) (int, []Failure, error) {
	lock, err := a.LockAccountRepair()
	if err != nil {
		return 0, nil, err
	}
	defer lock.Close()
	if err := a.CheckExport(); err != nil {
		return 0, nil, err
	}
	users, err := a.Users()
	if err != nil {
		return 0, nil, err
	}
	sessions, err := a.Sessions()
	if err != nil {
		return 0, nil, err
	}
	if sessions == nil {
		sessions = map[string]archive.Session{}
	}
	var failures []Failure
	updated := 0
	for i, user := range users {
		progress.Count(ctx, "Accounts checked", i, len(users))
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		if user.Deactivated || user.Guest {
			continue
		}
		if mx.ServerName(user.UserID) != a.Manifest.ServerName {
			return 0, nil, errors.New("archive contains a user from another server")
		}
		tokens, err := tokensFor(ctx, user.UserID)
		if err != nil {
			return 0, nil, fmt.Errorf("read MAS sessions for %s: %w", user.UserID, err)
		}
		state, err := a.ReadImportState(user.UserID)
		if err != nil {
			return 0, nil, err
		}
		devices := map[string][]archive.Token{}
		for _, token := range tokens {
			if token.Token == "" || token.DeviceID == "" {
				return 0, nil, errors.New("MAS session is missing its token or device")
			}
			devices[token.DeviceID] = append(devices[token.DeviceID], token)
		}
		for device, tokens := range devices {
			target := user.UserID + "/" + device
			destination := state.DeviceTokens[device]
			if state.DestUserID != user.UserID || !state.Devices[device] || destination == "" {
				failures = append(failures, Failure{Step: "session", Target: target, Error: "device was not restored on the same server name"})
				continue
			}
			who, err := mx.WithToken(dest, destination).Whoami(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return 0, nil, ctx.Err()
				}
				failures = append(failures, Failure{Step: "session", Target: target, Error: "saved destination session could not be verified"})
				continue
			}
			if string(who.UserID) != user.UserID || string(who.DeviceID) != device {
				failures = append(failures, Failure{Step: "session", Target: target, Error: "saved destination session belongs to another user or device"})
				continue
			}
			for _, token := range tokens {
				mapped := archive.Session{UserID: user.UserID, DeviceID: device, Token: destination, Refresh: token.Refresh, OAuth: token.OAuth}
				previous, exists := sessions[token.Token]
				if exists && (previous.UserID != mapped.UserID || previous.DeviceID != mapped.DeviceID || previous.Refresh != mapped.Refresh || previous.OAuth != mapped.OAuth) {
					return 0, nil, errors.New("MAS token conflicts with an existing session mapping; archive was not changed")
				}
				if !exists || previous != mapped {
					sessions[token.Token] = mapped
					updated++
				}
			}
			slog.Info("verified MAS session", "user", user.UserID, "device", device)
		}
	}
	progress.Count(ctx, "Accounts checked", len(users), len(users))
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	if updated > 0 {
		if err := a.WriteSessions(sessions); err != nil {
			return 0, nil, err
		}
	}
	slices.SortFunc(failures, func(a, b Failure) int { return cmp.Compare(a.Target, b.Target) })
	return updated, failures, nil
}
