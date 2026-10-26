package main

import (
	"fmt"

	"exodus/internal/archive"
	"exodus/internal/migrate"
	"github.com/spf13/cobra"
)

func newRestoreSessionsCmd() *cobra.Command {
	var dir, database, ldb string
	cmd := &cobra.Command{
		Use: "restore-sessions", Short: "Keep source access tokens and passwords valid in a stopped Continuwuity database",
		Long: `Stop Continuwuity and the proxy before running this command. Access tokens
from the source server and Tuwunel password hashes become valid in Continuwuity,
so clients stay logged in without the proxy. Devices that changed their token
since the import, refresh tokens and OAuth sessions are left to the proxy.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			tokens, passwords, kept, err := migrate.RestoreSessions(cmd.Context(), a, database, ldb)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Restored %d access tokens and %d passwords; %d sessions still need the proxy.\n", tokens, passwords, kept)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	cmd.Flags().StringVar(&database, "database", "", "path to the stopped Continuwuity RocksDB database")
	cmd.Flags().StringVar(&ldb, "ldb", "ldb", "path to a compatible RocksDB ldb executable")
	_ = cmd.MarkFlagRequired("database")
	return cmd
}
