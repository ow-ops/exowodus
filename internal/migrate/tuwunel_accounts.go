package migrate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"exodus/internal/archive"
)

var accountCheckpointTables = []string{
	"userid_password", "token_userdeviceid", "userdeviceid_refresh", "userdeviceid_metadata",
	"onetimekeyid4225_otk", "onetimekeyid_onetimekeys", "userdeviceidalgorithm_fallback",
	"senderkey_pusher", "pushkey_deviceid", "global",
}

var accountRecoveryTables = []string{
	"keyid_key", "userid_masterkeyid", "userid_selfsigningkeyid", "userid_usersigningkeyid",
	"userid_dehydrateddevice", "useridprofilekey_value", "roomuserdataid_accountdata",
	"roomusertype_roomuserdataid", "backupid_algorithm", "backupkeyid_backup",
	"userroomid_joined", "userroomid_invitestate", "userroomid_knockedstate",
	"userid_locked", "userid_suspended",
}

// RepairTuwunelAccounts recovers users misclassified as deactivated by the
// source API's empty-password test. Real deactivation deletes device metadata.
func RepairTuwunelAccounts(ctx context.Context, a *archive.Archive, database, ldb string) ([]string, error) {
	if err := a.CheckExport(); err != nil {
		return nil, err
	}
	lock, err := a.LockAccountRepair()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, err := os.Stat(filepath.Join(database, "CURRENT")); err != nil {
		return nil, errors.New("--database must name the original Tuwunel RocksDB backup")
	}
	users, err := a.Users()
	if err != nil {
		return nil, err
	}
	candidates := map[string]bool{}
	for _, u := range users {
		if u.Deactivated || u.Passwordless {
			candidates[u.UserID] = true
		}
	}
	selected := map[string]bool{}
	source := filepath.Join(a.Dir, "source", "tuwunel")
	err = walkTuwunelScan(ctx, filepath.Join(source, "userdeviceid_metadata.txt"), func(key string, _ []byte, _ tuwunelValueRef) error {
		user, _, _, err := tuwunelDeviceKey(key)
		if err == nil && candidates[user] {
			selected[user] = true
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return nil, nil
	}
	for user := range selected {
		if _, err := os.Stat(filepath.Join(a.UserDir(user), "import.json")); !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: account import has already started or its progress cannot be read; repair before importing accounts", user)
		}
	}
	families, err := accountColumnFamilies(ctx, database, ldb)
	if err != nil {
		return nil, err
	}
	if err := checkAccountRecoveryTables(families); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(a.Dir, ".tuwunel-account-repair-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	pushkeys := map[string]bool{}
	for _, table := range append(slices.Clone(accountCheckpointTables), accountRecoveryTables...) {
		slog.Info("reading account recovery table", "table", table, "users", len(selected))
		checkpoint := slices.Contains(accountCheckpointTables, table)
		expected := sha256.New()
		if checkpoint {
			err := walkTuwunelScan(ctx, filepath.Join(source, table+".txt"), func(key string, value []byte, _ tuwunelValueRef) error {
				hashAccountRow(expected, key, value)
				return nil
			})
			if err != nil && !(optionalAccountTable(table) && errors.Is(err, os.ErrNotExist)) {
				return nil, err
			}
		}
		f, err := os.OpenFile(filepath.Join(stage, table+".txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		out := bufio.NewWriter(f)
		actual := sha256.New()
		if families[table] {
			err = scanAccountTable(ctx, database, ldb, table, func(key string, value []byte, _ tuwunelValueRef) error {
				hashAccountRow(actual, key, value)
				user := accountRowUser(table, key, value)
				keep := selected[user]
				switch table {
				case "pushkey_deviceid":
					keep = pushkeys[key]
				case "senderkey_pusher":
					if keep {
						_, pushkey, _ := strings.Cut(key, "\xff")
						pushkeys[pushkey] = true
					}
				case "keyid_key":
					// Other users' master keys may carry this user's verification.
					keep = true
				}
				if keep {
					_, err := fmt.Fprintf(out, "0x%x ==> 0x%x\n", key, value)
					return err
				}
				return nil
			})
		}
		err = errors.Join(err, out.Flush(), f.Sync(), f.Close())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", table, err)
		}
		if checkpoint && !bytes.Equal(expected.Sum(nil), actual.Sum(nil)) {
			return nil, fmt.Errorf("%s differs from the archived checkpoint; use the original database backup; account files were not changed", table)
		}
	}
	recovered := slices.Sorted(maps.Keys(selected))
	staged, err := archive.Create(filepath.Join(stage, "accounts"), a.Manifest.ServerName)
	if err != nil {
		return nil, err
	}
	for _, user := range recovered {
		slog.Info("recovering passwordless account", "user", user)
		u, secrets, backup, err := recoverTuwunelAccount(ctx, a, stage, user)
		if err != nil {
			return nil, fmt.Errorf("recover %s: %w", user, err)
		}
		if err := staged.WriteRecoveredAccount(u, secrets, backup); err != nil {
			return nil, err
		}
	}
	// Keep recovery inputs and staged accounts for audit and interrupted retries.
	retained := stage + "-saved"
	if err := os.Rename(stage, retained); err != nil {
		return nil, err
	}
	staged.Dir = filepath.Join(retained, "accounts")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.UpgradeFormat(); err != nil {
		return nil, err
	}
	for _, user := range recovered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u, err := staged.ReadUser(user)
		if err != nil {
			return nil, err
		}
		secrets, err := staged.ReadSecrets(user)
		if err != nil {
			return nil, err
		}
		backup, err := staged.ReadKeyBackup(user)
		if err != nil {
			return nil, err
		}
		if err := a.WriteRecoveredAccount(u, secrets, backup); err != nil {
			return nil, err
		}
	}
	return recovered, nil
}

func optionalAccountTable(table string) bool {
	return table == "userdeviceid_refresh" || table == "onetimekeyid4225_otk" || table == "onetimekeyid_onetimekeys"
}

func checkAccountRecoveryTables(families map[string]bool) error {
	var missing []string
	for _, table := range append(slices.Clone(accountCheckpointTables), accountRecoveryTables...) {
		if !families[table] && !optionalAccountTable(table) {
			missing = append(missing, table)
		}
	}
	if !families["onetimekeyid4225_otk"] && !families["onetimekeyid_onetimekeys"] {
		missing = append(missing, "onetimekeyid4225_otk or onetimekeyid_onetimekeys")
	}
	if len(missing) > 0 {
		return fmt.Errorf("account recovery database is missing required tables: %s; no account files were changed", strings.Join(missing, ", "))
	}
	return nil
}

func hashAccountRow(h hash.Hash, key string, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(key)))
	h.Write(size[:])
	h.Write([]byte(key))
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	h.Write(size[:])
	h.Write(value)
}

func accountRowUser(table, key string, value []byte) string {
	if table == "token_userdeviceid" {
		user, _, _ := bytes.Cut(value, []byte{0xff})
		return string(user)
	}
	if table == "roomuserdataid_accountdata" || table == "roomusertype_roomuserdataid" {
		_, rest, _ := strings.Cut(key, "\xff")
		user, _, _ := strings.Cut(rest, "\xff")
		return user
	}
	user, _, _ := strings.Cut(key, "\xff")
	return user
}

func accountColumnFamilies(ctx context.Context, database, ldb string) (map[string]bool, error) {
	cmd := exec.CommandContext(ctx, ldb, "--db="+database, "list_column_families")
	var stdout, stderr ldbOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, ldbCommandError(err, stderr.data)
	}
	_, tail, ok := strings.Cut(string(stdout.data), "{")
	list, _, end := strings.Cut(tail, "}")
	if !ok || !end {
		return nil, errors.New("ldb did not return a column-family list")
	}
	families := map[string]bool{}
	for name := range strings.SplitSeq(list, ",") {
		families[strings.TrimSpace(name)] = true
	}
	return families, nil
}

func scanAccountTable(ctx context.Context, database, ldb, table string, visit func(string, []byte, tuwunelValueRef) error) error {
	cmd := exec.CommandContext(ctx, ldb, "--db="+database, "--column_family="+table, "--try_load_options", "--ignore_unknown_options", "scan", "--hex")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr ldbOutput
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	readErr := walkTuwunelReader(ctx, table, stdout, visit)
	if readErr != nil {
		_ = cmd.Process.Kill()
	}
	if err := cmd.Wait(); err != nil {
		return errors.Join(readErr, ldbCommandError(err, stderr.data))
	}
	return readErr
}
