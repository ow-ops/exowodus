package main

import (
	"fmt"

	"exodus/internal/archive"
	"exodus/internal/migrate"
	"github.com/spf13/cobra"
)

func newFinishCmd() *cobra.Command {
	var dir, database, ldb string
	cmd := &cobra.Command{
		Use: "finish", Short: "Restore the signing key, media and sessions to a stopped Continuwuity database",
		Long: `Run after import with Continuwuity and the proxy stopped. It runs
restore-signing-key (when the archive has the source key), restore-media and
restore-sessions in that order. Each step is safe to rerun.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			if err := a.CheckExport(); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if key, err := a.SigningKey(); err != nil {
				return err
			} else if key != "" {
				config, err := migrate.RestoreSigningKey(cmd.Context(), a, database, ldb)
				if err != nil {
					return fmt.Errorf("signing key: %w", err)
				}
				if config == "" {
					fmt.Fprintln(out, "Continuwuity already uses the source signing key.")
				} else {
					fmt.Fprintf(out, "Source signing key restored. Add %s to Continuwuity's configuration before restarting it.\n", config)
				}
			}
			restored, present, err := migrate.RestoreMedia(cmd.Context(), a, database, ldb)
			if err != nil {
				return fmt.Errorf("media: %w", err)
			}
			fmt.Fprintf(out, "Restored %d media files; %d were already present.\n", restored, present)
			tokens, passwords, kept, err := migrate.RestoreSessions(cmd.Context(), a, database, ldb)
			if err != nil {
				return fmt.Errorf("sessions: %w", err)
			}
			fmt.Fprintf(out, "Restored %d access tokens and %d passwords; %d sessions still need the proxy.\n", tokens, passwords, kept)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	cmd.Flags().StringVar(&database, "database", "", "path to the stopped Continuwuity RocksDB database")
	cmd.Flags().StringVar(&ldb, "ldb", "ldb", "path to a compatible RocksDB ldb executable")
	_ = cmd.MarkFlagRequired("database")
	return cmd
}
