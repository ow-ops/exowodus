package main

import (
	"fmt"

	"exodus/internal/archive"
	"exodus/internal/migrate"
	"github.com/spf13/cobra"
)

func newRestoreMediaCmd() *cobra.Command {
	var dir, database, ldb string
	cmd := &cobra.Command{
		Use: "restore-media", Short: "Store archived media under its original IDs in a stopped Continuwuity database",
		Long: `Stop Continuwuity before running this command. Media uploaded to the source
server keeps its original mxc:// IDs, so Continuwuity serves old links without
the proxy. Run it as the database owner; IDs Continuwuity already has are kept.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			restored, kept, err := migrate.RestoreMedia(cmd.Context(), a, database, ldb)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Restored %d media files; %d were already present.\n", restored, kept)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	cmd.Flags().StringVar(&database, "database", "", "path to the stopped Continuwuity RocksDB database")
	cmd.Flags().StringVar(&ldb, "ldb", "ldb", "path to a compatible RocksDB ldb executable")
	_ = cmd.MarkFlagRequired("database")
	return cmd
}
