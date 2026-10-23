package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

var exportHashBuffers = sync.Pool{New: func() any { buffer := make([]byte, 64<<10); return &buffer }}

type ExportSource struct {
	Fingerprint string            `json:"fingerprint"`
	Dump        map[string]string `json:"dump"`
}

type exportResumeHeader struct {
	Version int          `json:"version"`
	Source  ExportSource `json:"source"`
	Legacy  bool         `json:"legacy,omitempty"`
}

type ExportCheckpoint struct {
	ID          string            `json:"id"`
	Tip         string            `json:"tip,omitempty"`
	Files       map[string]string `json:"files"`
	Media       *Media            `json:"media,omitempty"`
	Quarantined []string          `json:"quarantined,omitempty"`
}

type ExportResume struct {
	archive *Archive
	lock    *os.File
	header  exportResumeHeader
}

// OpenExportResume locks the archive until Close or process exit.
func (a *Archive) OpenExportResume(ctx context.Context, source ExportSource, allowLegacy bool) (*ExportResume, error) {
	lock, err := os.OpenFile(filepath.Join(a.Dir, "export-progress.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockExportFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("lock export archive %s: %w", a.Dir, err)
	}
	r := &ExportResume{archive: a, lock: lock}
	if err := r.open(ctx, source, allowLegacy); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *ExportResume) open(ctx context.Context, source ExportSource, allowLegacy bool) error {
	path := filepath.Join(r.archive.Dir, "export-progress", "source.json")
	err := readJSON(path, &r.header)
	if err == nil {
		if r.header.Version != 1 || !reflect.DeepEqual(r.header.Source, source) {
			return errors.New("export source or dump changed; use a new --archive directory")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.header = exportResumeHeader{Version: 1, Source: source}
	if allowLegacy {
		retained, err := HashExportDump(ctx, filepath.Join(r.archive.Dir, "source", "tuwunel"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		r.header.Legacy = reflect.DeepEqual(retained, source.Dump)
		if !r.header.Legacy {
			users, err := os.ReadDir(filepath.Join(r.archive.Dir, "users"))
			if err != nil {
				return err
			}
			if len(users) > 0 {
				return errors.New("existing archive has a different or incomplete retained dump; use a new --archive directory")
			}
			for _, name := range []string{"rooms", "server.json"} {
				if _, err := os.Stat(filepath.Join(r.archive.Dir, name)); err == nil {
					return errors.New("existing archive has a different or incomplete retained dump; use a new --archive directory")
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
	}
	return writeJSON(path, r.header)
}

func (r *ExportResume) Close() error                { return r.lock.Close() }
func (r *ExportResume) CanReuseLegacyHistory() bool { return r.header.Legacy }

func (r *ExportResume) checkpointPath(kind, id string) string {
	hash := sha256.Sum256([]byte(id))
	return filepath.Join(r.archive.Dir, "export-progress", kind, hex.EncodeToString(hash[:])+".json")
}

// Load verifies every artifact before treating a step as complete.
func (r *ExportResume) Load(ctx context.Context, kind, id string) (*ExportCheckpoint, error) {
	var checkpoint ExportCheckpoint
	err := readJSON(r.checkpointPath(kind, id), &checkpoint)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if checkpoint.ID != id || len(checkpoint.Files) == 0 {
		return nil, errors.New("invalid export checkpoint")
	}
	for path := range checkpoint.Files {
		if !filepath.IsLocal(path) {
			return nil, errors.New("export checkpoint path is outside the archive")
		}
		if _, err := os.Stat(filepath.Join(r.archive.Dir, path)); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
	}
	progress := time.Now()
	checked := 0
	for path, want := range checkpoint.Files {
		got, err := HashExportFile(ctx, filepath.Join(r.archive.Dir, path))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, nil
		}
		checked++
		if time.Since(progress) >= 5*time.Second {
			slog.Info("checking export checkpoint", "step", kind, "id", id, "files", checked, "total", len(checkpoint.Files))
			progress = time.Now()
		}
	}
	return &checkpoint, nil
}

func (r *ExportResume) Save(ctx context.Context, kind, id string, paths []string, checkpoint ExportCheckpoint) error {
	checkpoint.ID = id
	checkpoint.Files = make(map[string]string, len(paths))
	progress := time.Now()
	for index, path := range paths {
		relative, err := filepath.Rel(r.archive.Dir, path)
		if err != nil || !filepath.IsLocal(relative) {
			return fmt.Errorf("export artifact is outside the archive: %s", path)
		}
		hash, err := HashExportFile(ctx, path)
		if err != nil {
			return err
		}
		checkpoint.Files[relative] = hash
		if time.Since(progress) >= 5*time.Second {
			slog.Info("saving export checkpoint", "step", kind, "id", id, "files", index+1, "total", len(paths))
			progress = time.Now()
		}
	}
	if len(checkpoint.Files) == 0 {
		return errors.New("export checkpoint has no artifacts")
	}
	return writeJSON(r.checkpointPath(kind, id), checkpoint)
}

func HashExportDump(ctx context.Context, dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	hashes := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		hash, err := HashExportFile(ctx, filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		hashes[entry.Name()] = hash
	}
	return hashes, nil
}

func HashExportFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	buffer := exportHashBuffers.Get().(*[]byte)
	defer exportHashBuffers.Put(buffer)
	progress := time.Now()
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(*buffer)
		if n > 0 {
			_, _ = hash.Write((*buffer)[:n])
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if time.Since(progress) >= 5*time.Second {
			slog.Info("checking export file", "path", path, "bytes", total)
			progress = time.Now()
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *ExportResume) RetainDump(ctx context.Context, dir string) error {
	destination := filepath.Join(r.archive.Dir, "source", "tuwunel")
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(r.header.Source.Dump)) {
		want := r.header.Source.Dump[name]
		source := filepath.Join(dir, name)
		got, err := HashExportFile(ctx, source)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("dump file %s changed during export", name)
		}
		target := filepath.Join(destination, name)
		got, err = HashExportFile(ctx, target)
		if err == nil && got == want {
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		slog.Info("copying Tuwunel dump", "table", name)
		if err := copyExportFile(ctx, source, target); err != nil {
			return err
		}
		got, err = HashExportFile(ctx, target)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("dump file %s changed while copying", name)
		}
	}
	return nil
}

func copyExportFile(ctx context.Context, source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	copyErr := func() error {
		buffer := make([]byte, 64<<10)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, readErr := in.Read(buffer)
			if n > 0 {
				written, err := out.Write(buffer[:n])
				if err != nil {
					return err
				}
				if written != n {
					return io.ErrShortWrite
				}
			}
			if readErr == io.EOF {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	}()
	if err := errors.Join(copyErr, out.Close()); err != nil {
		_ = os.Remove(target + ".tmp")
		return err
	}
	return os.Rename(target+".tmp", target)
}
