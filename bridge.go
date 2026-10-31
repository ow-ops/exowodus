package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"exowodus/internal/mx"
	"exowodus/internal/progress"
	"exowodus/internal/proxy"
)

func newRepairBridgeCmd() *cobra.Command {
	var dir, registration, to, token, listen, publicURL, upstream string
	cmd := &cobra.Command{
		Use:   "repair-bridge",
		Short: "Drain imported history from a bridge's delivery queue",
		Long: `Keep the bridge stopped until this command reports that filtering is active.
It temporarily routes appservice deliveries through Exowodus, removes imported
event IDs, and forwards new events to the bridge. Once both homeserver queues
are empty, it restores the registration's original URL and exits.

--public-url must be reachable from Continuwuity. For Docker Desktop with
Exowodus on the host, use http://host.docker.internal:8011. --upstream overrides
the bridge URL if its registration uses a Docker hostname the host cannot reach.

If interrupted, delivery stays routed through this command. Rerun it with the
same archive and registration. It does not restore a deleted bridge database.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			u, err := url.Parse(publicURL)
			if err != nil || u == nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
				return errors.New("--public-url must be an HTTP(S) URL without a path, credentials, query or fragment")
			}
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			lock, err := a.LockImport()
			if err != nil {
				return err
			}
			defer lock.Close()
			history, err := a.BridgeHistory(ctx)
			if err != nil {
				return err
			}
			source, err := a.ReadServer()
			if err != nil {
				return err
			}
			if source == nil || !source.BridgeQueuesDrained {
				return errors.New("source appservice delivery queues were not verified; re-export from a drained source before releasing bridge delivery")
			}
			b, err := migrate.LoadBridge(registration, nil)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(source.AppserviceRegistrations, b.MatchesRegistration) {
				return errors.New("registration differs from the exported appservice; use the original registration with its original delivery URL")
			}
			if b.URL == "" || b.URL == "null" {
				return errors.New("registration has no bridge delivery URL")
			}
			if upstream == "" {
				upstream = b.URL
			}
			if strings.TrimRight(publicURL, "/") == strings.TrimRight(upstream, "/") || strings.TrimRight(publicURL, "/") == strings.TrimRight(b.URL, "/") {
				return errors.New("--public-url must differ from the bridge URL")
			}
			filter, err := proxy.NewBridgeFilter(upstream, b.HSToken, history)
			if err != nil {
				return err
			}
			c, err := mx.New(to, token)
			if err != nil {
				return err
			}
			admin, err := migrate.NewContinuwuityAdmin(ctx, c)
			if err != nil {
				return err
			}
			if admin.ServerName() != a.Manifest.ServerName {
				return errors.New("bridge repair requires the archive's server name")
			}
			// Verify queue inspection before changing the live registration.
			if _, err := b.DeliveriesPending(ctx, admin); err != nil {
				return err
			}
			listener, err := net.Listen("tcp", listen)
			if err != nil {
				return err
			}
			srv := &http.Server{Handler: filter, ReadHeaderTimeout: 15 * time.Second, ReadTimeout: time.Minute, IdleTimeout: time.Minute}
			serveErr := make(chan error, 1)
			go func() { serveErr <- srv.Serve(listener) }()
			defer func() {
				stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := srv.Shutdown(stopCtx); err != nil {
					_ = srv.Close()
				}
			}()
			complete := false
			defer func() {
				if !complete {
					slog.Warn("bridge filtering stopped; delivery may still be routed here; rerun repair-bridge with the same arguments", "bridge", b.ID)
				}
			}()
			if err := b.Route(ctx, admin, u.String()); err != nil {
				return err
			}
			slog.Info("bridge filtering active; the bridge can now be started", "bridge", b.ID, "listen", listener.Addr(), "history_ids", len(history))
			slog.Info("waiting for Continuwuity to deliver queued transactions; new bridge-room traffic triggers retries")
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			// Two empty checks avoid switching during a queue transition.
			empty := 0
			for empty < 2 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case err := <-serveErr:
					return fmt.Errorf("bridge filter stopped: %w", err)
				case <-ticker.C:
					pending, err := b.DeliveriesPending(ctx, admin)
					if err != nil {
						return err
					}
					filtered, forwarded := filter.Counts()
					progress.Panel(ctx, "Bridge delivery", []string{fmt.Sprintf("Imported event deliveries filtered: %d", filtered), fmt.Sprintf("New event deliveries forwarded: %d", forwarded), "Waiting for Continuwuity's bridge queues to empty"})
					if pending {
						empty = 0
					} else {
						empty++
					}
				}
			}
			if err := b.Register(ctx, admin); err != nil {
				return err
			}
			complete = true
			if err := a.FinishBridgeDelivery(b.ID); err != nil {
				return fmt.Errorf("direct delivery restored, but updating the import report failed: %w", err)
			}
			filtered, forwarded := filter.Counts()
			fmt.Fprintf(cmd.OutOrStdout(), "Bridge %s queue drained; direct delivery restored. Filtered %d imported event deliveries; forwarded %d new event deliveries.\n", b.ID, filtered, forwarded)
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "archive", defaultArchiveDir(), "archive used for the completed import")
	fs.StringVar(&registration, "registration", "", "bridge registration YAML, with its original delivery URL")
	fs.StringVar(&to, "to", "", "Continuwuity client API URL")
	fs.StringVar(&token, "to-admin-token", configEnv("TO_ADMIN_TOKEN"), "Continuwuity admin access token [$EXOWODUS_TO_ADMIN_TOKEN]")
	fs.Lookup("to-admin-token").DefValue = ""
	fs.StringVar(&listen, "listen", ":8011", "temporary bridge filter listen address")
	fs.StringVar(&publicURL, "public-url", "", "filter URL reachable from Continuwuity")
	fs.StringVar(&upstream, "upstream", "", "bridge URL reachable from Exowodus (default: registration URL)")
	for _, flag := range []string{"registration", "to", "public-url"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}
