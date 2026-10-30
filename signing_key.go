package main

import (
	"fmt"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"github.com/spf13/cobra"
)

func newRestoreSigningKeyCmd() *cobra.Command {
	var dir, database, ldb string
	cmd := &cobra.Command{
		Use: "restore-signing-key", Short: "Restore the source signing key to a stopped Continuwuity database",
		Long: `Stop Continuwuity before running this command. It saves the current key in
the archive, then restores the original source key using ldb. Add the generated
old-verify-key TOML to Continuwuity's configuration before restarting it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			if err := a.CheckExport(); err != nil {
				return err
			}
			config, err := migrate.RestoreSigningKey(cmd.Context(), a, database, ldb)
			if err != nil {
				return err
			}
			if config == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "Continuwuity already uses the source signing key.")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Source signing key restored; previous key backed up in %s.\nAdd %s to Continuwuity's configuration before restarting it.\n", a.Dir, config)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", defaultArchiveDir(), "archive directory")
	cmd.Flags().StringVar(&database, "database", "", "path to the stopped Continuwuity RocksDB database")
	cmd.Flags().StringVar(&ldb, "ldb", "ldb", "path to a compatible RocksDB ldb executable")
	_ = cmd.MarkFlagRequired("database")
	return cmd
}
