package migrate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"exodus/internal/archive"
	"maunium.net/go/mautrix/federation"
)

// RestoreSigningKey uses ldb's database lock and passes private key material on stdin.
// The previous key is backed up before the single global record is replaced.
func RestoreSigningKey(ctx context.Context, a *archive.Archive, database, ldb string) (string, error) {
	if _, err := os.Stat(filepath.Join(database, "CURRENT")); err != nil {
		return "", errors.New("--database must name an existing, stopped Continuwuity RocksDB database")
	}
	sourceText, err := a.SigningKey()
	if err != nil {
		return "", err
	}
	source, err := federation.ParseSynapseKey(strings.TrimSpace(sourceText))
	if err != nil {
		return "", fmt.Errorf("read source signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(source.Priv)
	if err != nil {
		return "", err
	}
	_, version, ok := strings.Cut(string(source.ID), ":")
	if !ok {
		return "", errors.New("invalid source signing key ID")
	}
	wanted := append(append([]byte(version), 0xff), der...)
	args := []string{"--db=" + database, "--column_family=global", "--try_load_options", "--ignore_unknown_options"}
	read := func() ([]byte, error) {
		cmd := exec.CommandContext(ctx, ldb, append(args, "get", "--hex", "0x6b657970616972")...)
		raw, err := cmd.Output()
		if err != nil {
			var exit *exec.ExitError
			var diagnostic []byte
			if errors.As(err, &exit) {
				diagnostic = exit.Stderr
			}
			return nil, fmt.Errorf("read destination key: %w; stop Continuwuity and use a compatible ldb version", ldbCommandError(err, diagnostic))
		}
		text := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(text, "0x") {
			return nil, errors.New("ldb returned an invalid signing key record")
		}
		value, err := hex.DecodeString(text[2:])
		if err != nil {
			return nil, errors.New("ldb returned an invalid signing key record")
		}
		return value, nil
	}
	previous, err := read()
	if err != nil {
		return "", err
	}
	decoded := &TuwunelDump{maps: map[string]map[string][]byte{"global": {"keypair": previous}}}
	previousText, err := decoded.SigningKey()
	if err != nil {
		return "", errors.New("destination signing key has an unsupported format; no changes made")
	}
	old, err := federation.ParseSynapseKey(strings.TrimSpace(previousText))
	if err != nil {
		return "", err
	}
	if old.ID == source.ID && old.Pub == source.Pub {
		config := filepath.Join(a.Dir, "continuwuity-old-verify-key.toml")
		if _, err := os.Stat(config); err == nil {
			return config, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", nil
	}
	if old.ID == source.ID {
		return "", errors.New("source and destination use the same key ID for different keys; cannot preserve both identities automatically")
	}
	backup := filepath.Join(a.Dir, "continuwuity-signing-key-backup.txt")
	backupRow := []byte(fmt.Sprintf("0x6b657970616972 ==> 0x%x\n", previous))
	if err := writeKeyBackup(backup, backupRow); err != nil {
		return "", err
	}
	config := filepath.Join(a.Dir, "continuwuity-old-verify-key.toml")
	snippet := []byte(fmt.Sprintf("[global.old_verify_keys.%q]\nexpired_ts = %d\nkey = %q\n", string(old.ID), time.Now().UnixMilli(), string(old.Pub)))
	if _, err := os.Stat(config); errors.Is(err, os.ErrNotExist) {
		if err := writeKeyBackup(config, snippet); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, ldb, append(args, "load", "--hex")...)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("0x6b657970616972 ==> 0x%x\n", wanted))
	output := &ldbOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("restore source signing key: %w; previous key saved in %s", ldbCommandError(err, output.data), backup)
	}
	stored, err := read()
	if err != nil {
		return "", err
	}
	if !bytes.Equal(stored, wanted) {
		return "", fmt.Errorf("destination key did not match after transfer; keep Continuwuity stopped and restore %s", backup)
	}
	return config, nil
}

func writeKeyBackup(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(raw, data) {
			return fmt.Errorf("backup %s already holds a different key; no changes made", path)
		}
		return os.Chmod(path, 0600)
	}
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		return errors.Join(dir.Sync(), dir.Close())
	}
	return nil
}
