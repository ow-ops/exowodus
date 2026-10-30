package migrate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"exowodus/internal/archive"
	"exowodus/internal/progress"
)

// RestoreSessions writes the source access tokens and Tuwunel password hashes
// into a stopped Continuwuity database. A device is restored only while it
// still uses the token import created for it. Restored entries are removed
// from the archive, so the proxy passes the old tokens through.
func RestoreSessions(ctx context.Context, a *archive.Archive, database, ldb string) (tokens, passwords, kept int, err error) {
	slog.Info("restoring passwords and sessions")
	if _, err := os.Stat(filepath.Join(database, "CURRENT")); err != nil {
		return 0, 0, 0, errors.New("--database must name an existing, stopped Continuwuity RocksDB database")
	}
	sessions, err := a.Sessions()
	if err != nil {
		return 0, 0, 0, err
	}
	pending, err := a.PendingPasswords()
	if err != nil {
		return 0, 0, 0, err
	}
	args := []string{"--db=" + database, "--try_load_options", "--ignore_unknown_options"}
	current, err := ldbScan(ctx, ldb, args, "userdeviceid_token")
	if err != nil {
		return 0, 0, 0, err
	}
	expires, err := ldbScan(ctx, ldb, args, "userdeviceid_tokenexpires")
	if err != nil {
		return 0, 0, 0, err
	}

	// Continuwuity keeps one token per device.
	perDevice := map[string]int{}
	for old, s := range sessions {
		if restorableSession(old, s) {
			perDevice[s.UserID+"\xff"+s.DeviceID]++
		}
	}
	var forward, reverse, passwordRows bytes.Buffer
	var stale, expiring, restored []string
	checked := 0
	for old, s := range sessions {
		progress.Count(ctx, "Sessions checked", checked, len(sessions))
		checked++
		if !restorableSession(old, s) {
			continue
		}
		device := s.UserID + "\xff" + s.DeviceID
		token, ok := current[device]
		if perDevice[device] != 1 || !ok || token != s.Token && token != old {
			kept++
			continue
		}
		fmt.Fprintf(&forward, "0x%x ==> 0x%x\n", old, device)
		fmt.Fprintf(&reverse, "0x%x ==> 0x%x\n", device, old)
		if s.Token != old {
			stale = append(stale, s.Token)
		}
		if _, ok := expires[device]; ok {
			expiring = append(expiring, device)
		}
		restored = append(restored, old)
	}
	progress.Count(ctx, "Sessions checked", len(sessions), len(sessions))
	var restoredPasswords []string
	for user, p := range pending {
		if p.Scheme != archive.SchemeTuwunel || !strings.HasPrefix(p.Hash, "$argon2id$") {
			continue
		}
		fmt.Fprintf(&passwordRows, "0x%x ==> 0x%x\n", user, p.Hash)
		restoredPasswords = append(restoredPasswords, user)
	}

	// Add the old tokens before removing the import's, so a failure leaves
	// every device usable and a rerun completes it.
	for _, load := range []struct {
		family string
		rows   *bytes.Buffer
	}{{"token_userdeviceid", &forward}, {"userdeviceid_token", &reverse}, {"userid_password", &passwordRows}} {
		if load.rows.Len() == 0 {
			continue
		}
		if err := runLDB(ctx, ldb, append(args, "--column_family="+load.family, "load", "--hex"), load.rows); err != nil {
			return 0, 0, 0, fmt.Errorf("write %s: %w", load.family, err)
		}
	}
	for _, del := range []struct {
		family string
		keys   []string
	}{{"token_userdeviceid", stale}, {"userdeviceid_tokenexpires", expiring}} {
		for _, key := range del.keys {
			if err := runLDB(ctx, ldb, append(args, "--column_family="+del.family, "--hex", "delete", fmt.Sprintf("0x%x", key)), nil); err != nil {
				return 0, 0, 0, fmt.Errorf("delete from %s: %w", del.family, err)
			}
		}
	}

	for _, old := range restored {
		delete(sessions, old)
	}
	if len(restored) > 0 {
		if err := a.WriteSessions(sessions); err != nil {
			return 0, 0, 0, err
		}
	}
	for _, user := range restoredPasswords {
		if err := a.MarkPasswordRestored(pending[user].SourceUserID); err != nil {
			return 0, 0, 0, err
		}
		delete(pending, user)
	}
	if len(restoredPasswords) > 0 {
		if err := a.WritePendingPasswords(pending); err != nil {
			return 0, 0, 0, err
		}
	}
	return len(restored), len(restoredPasswords), kept, nil
}

// Guest macaroons, refresh tokens and OAuth tokens are not plain access tokens.
func restorableSession(old string, s archive.Session) bool {
	return !strings.HasPrefix(old, archive.GuestSessionKey("")) && !s.Refresh && !s.OAuth
}

func runLDB(ctx context.Context, ldb string, args []string, stdin *bytes.Buffer) error {
	slog.Info("updating destination database")
	cmd := exec.CommandContext(ctx, ldb, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	output := &ldbOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w; stop Continuwuity and use a compatible ldb version", ldbCommandError(err, output.data))
	}
	return nil
}
