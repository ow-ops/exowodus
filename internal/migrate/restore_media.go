package migrate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

type archivedMedia struct {
	archive.Media
	path, owner string
}

// RestoreMedia stores archived local media under its original IDs in a
// stopped Continuwuity database, so old links work without the proxy.
// Media IDs Continuwuity already has are left unchanged.
func RestoreMedia(ctx context.Context, a *archive.Archive, database, ldb string) (restored, kept int, err error) {
	if _, err := os.Stat(filepath.Join(database, "CURRENT")); err != nil {
		return 0, 0, errors.New("--database must name an existing, stopped Continuwuity RocksDB database")
	}
	media, err := localArchivedMedia(a)
	if err != nil {
		return 0, 0, err
	}
	args := []string{"--db=" + database, "--try_load_options", "--ignore_unknown_options"}
	existing, err := existingMedia(ctx, ldb, args)
	if err != nil {
		return 0, 0, err
	}
	dir := filepath.Join(database, "media")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, 0, err
	}
	var files, owners bytes.Buffer
	var written []string
	for _, m := range media {
		if existing[m.MXC] {
			kept++
			continue
		}
		key := continuwuityMediaKey(m.MXC, m.Filename, m.ContentType)
		digest := sha256.Sum256(key)
		path := filepath.Join(dir, base64.RawURLEncoding.EncodeToString(digest[:]))
		if err := copyMediaFile(m.path, path); err != nil {
			removeFiles(written)
			return 0, kept, fmt.Errorf("%s: %w", m.MXC, err)
		}
		written = append(written, path)
		fmt.Fprintf(&files, "0x%x ==> 0x\n", key)
		if m.owner != "" {
			fmt.Fprintf(&owners, "0x%x ==> 0x%x\n", append(append([]byte(m.MXC), 0xff), m.owner...), m.owner)
		}
		restored++
	}
	for _, load := range []struct {
		family string
		rows   *bytes.Buffer
	}{{"mediaid_file", &files}, {"mediaid_user", &owners}} {
		if load.rows.Len() == 0 {
			continue
		}
		if err := runLDB(ctx, ldb, append(args, "--column_family="+load.family, "load", "--hex"), load.rows); err != nil {
			if load.family == "mediaid_file" {
				// Without their rows the copied files are unreachable.
				removeFiles(written)
			}
			return 0, kept, fmt.Errorf("write %s: %w", load.family, err)
		}
	}
	return restored, kept, nil
}

// localArchivedMedia lists media the source server stored, as the proxy serves it.
func localArchivedMedia(a *archive.Archive) ([]archivedMedia, error) {
	seen := map[string]bool{}
	var out []archivedMedia
	add := func(dir, owner string, media []archive.Media) {
		for _, m := range media {
			server, _, err := mx.ParseMXC(m.MXC)
			if err != nil || server != a.Manifest.ServerName || seen[m.MXC] {
				continue
			}
			seen[m.MXC] = true
			out = append(out, archivedMedia{Media: m, path: filepath.Join(dir, m.File), owner: owner})
		}
	}
	users, err := a.Users()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		add(a.UserDir(u.UserID), u.UserID, u.Media)
	}
	rooms, err := a.Rooms()
	if err != nil {
		return nil, err
	}
	for _, r := range rooms {
		add(a.RoomDir(r.RoomID), "", r.Media)
	}
	server, err := a.ReadServer()
	if err != nil {
		return nil, err
	}
	if server != nil {
		add(a.Dir, "", server.Media)
	}
	return out, nil
}

// continuwuityMediaKey matches Continuwuity's mediaid_file key for an original
// upload: the MXC URI, a zero width and height, the content disposition, then
// the content type. Downloads take only the filename from the disposition.
func continuwuityMediaKey(mxc, filename, contentType string) []byte {
	key := append([]byte(mxc), 0xff)
	key = append(key, make([]byte, 8)...)
	key = append(key, 0xff)
	if filename != "" {
		key = append(key, mime.FormatMediaType("inline", map[string]string{"filename": filename})...)
	}
	key = append(key, 0xff)
	return append(key, contentType...)
}

func existingMedia(ctx context.Context, ldb string, args []string) (map[string]bool, error) {
	rows, err := ldbScan(ctx, ldb, args, "mediaid_file")
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for key := range rows {
		mxc, _, _ := strings.Cut(key, "\xff")
		existing[mxc] = true
	}
	return existing, nil
}

// ldbScan reads a column family as raw keys and values.
func ldbScan(ctx context.Context, ldb string, args []string, family string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, ldb, append(args, "--column_family="+family, "scan", "--hex")...)
	stderr := &ldbOutput{}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	rows := map[string]string{}
	scanner := bufio.NewScanner(out)
	scanner.Buffer(nil, 1<<20)
	for scanner.Scan() {
		hexKey, hexValue, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ==> ")
		key, keyErr := hex.DecodeString(strings.TrimPrefix(hexKey, "0x"))
		value, valueErr := hex.DecodeString(strings.TrimPrefix(hexValue, "0x"))
		if !ok || keyErr != nil || valueErr != nil {
			continue
		}
		rows[string(key)] = string(value)
	}
	scanErr := scanner.Err()
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("read %s: %w; stop Continuwuity and use a compatible ldb version", family, ldbCommandError(err, stderr.data))
	}
	return rows, scanErr
}

func removeFiles(paths []string) {
	for _, path := range paths {
		os.Remove(path)
	}
}

func copyMediaFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	if err := errors.Join(copyErr, out.Sync(), out.Close()); err != nil {
		os.Remove(destination + ".tmp")
		return err
	}
	return os.Rename(destination+".tmp", destination)
}
