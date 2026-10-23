package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func (d *TuwunelDump) MediaIDs() ([]string, error) {
	ids := map[string]bool{}
	for _, table := range []string{"mediaid_file", "mediaid_lazy", "mediaid_lazycontent"} {
		for key := range d.maps[table] {
			mxc, _, _ := strings.Cut(key, "\xff")
			if !utf8.ValidString(mxc) {
				return nil, errors.New("invalid Tuwunel media key")
			}
			if _, _, err := mx.ParseMXC(mxc); err != nil {
				return nil, fmt.Errorf("invalid Tuwunel media MXC: %w", err)
			}
			ids[mxc] = true
		}
	}
	return slices.Sorted(maps.Keys(ids)), nil
}

func (e *Exporter) exportTuwunelMedia(ctx context.Context, srv *archive.Server) error {
	ids, err := e.TuwunelDump.MediaIDs()
	if err != nil {
		return err
	}
	skipped := 0
	srv.SkippedRemoteMedia = true
	slog.Info("exporting database media", "count", len(ids))
	for _, mxc := range ids {
		server, id, err := mx.ParseMXC(mxc)
		if err != nil {
			return err
		}
		if server != e.Archive.Manifest.ServerName {
			skipped++
			continue
		}
		file := filepath.Join("server", mediaFile(server, id))
		path := filepath.Join(e.Archive.Dir, file)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		contentType, name, err := e.downloadExportMedia(ctx, e.Admin, mxc, path)
		if err != nil {
			if e.skipMissingMedia(mxc, path, err) {
				continue
			}
			return fmt.Errorf("database media %s: %w", mxc, err)
		}
		srv.Media = append(srv.Media, archive.Media{MXC: mxc, File: file, ContentType: contentType, Filename: name})
	}
	slog.Info("exported database media", "files", len(srv.Media), "skipped_remote", skipped)
	return nil
}
