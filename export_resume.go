package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
)

func (f *sourceFlags) exportResume(ctx context.Context, s *source, a *archive.Archive) (*archive.ExportResume, error) {
	if s.dump == nil || !f.allUsers || !f.requireLossless {
		if _, err := os.Stat(filepath.Join(a.Dir, "export-progress", "source.json")); err == nil {
			return nil, errors.New("archive belongs to a whole-server Tuwunel export; use a new --archive directory")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, nil
	}
	slog.Info("checking Tuwunel dump for export resume")
	dump, err := archive.HashExportDump(ctx, f.tuwunelDump)
	if err != nil {
		return nil, err
	}
	accounts := slices.Concat(s.users, s.deactivated)
	slices.SortFunc(accounts, func(a, b migrate.SynapseUser) int { return strings.Compare(a.UserID, b.UserID) })
	input := struct {
		Version                              int
		URL, Kind, Admin, ServerUser         string
		Users                                []migrate.SynapseUser
		AllUsers, Lossless, SkipMissingMedia bool
		Dump                                 map[string]string
		HistoryAtCheckpoint                  bool `json:",omitempty"`
	}{
		Version: 1, URL: strings.TrimRight(f.url, "/"), Kind: f.kind, Admin: s.adminID, ServerUser: f.serverUser,
		Users: accounts, AllUsers: f.allUsers, Lossless: f.requireLossless,
		SkipMissingMedia: f.skipMissingMedia, Dump: dump,
		HistoryAtCheckpoint: f.historyAtCheckpoint,
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	return a.OpenExportResume(ctx, archive.ExportSource{Fingerprint: hex.EncodeToString(hash[:]), Dump: dump}, s.dump.HasRelayData())
}
