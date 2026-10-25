package main

import (
	"fmt"

	"exodus/internal/archive"
	"exodus/internal/migrate"
	"github.com/spf13/cobra"
)

func newRepairTuwunelAccountsCmd() *cobra.Command {
	var dir, database, ldb string
	var includeAppserviceSenders bool
	cmd := &cobra.Command{
		Use: "repair-tuwunel-accounts", Short: "Recover passwordless accounts from the original Tuwunel backup",
		Long: `Read missing account data from the database backup used for this archive.
The backup is opened read-only. Room histories are not exported again.
Stop export and import commands before running this repair.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			users, err := migrate.RepairTuwunelAccounts(cmd.Context(), a, database, ldb, includeAppserviceSenders)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Recovered %d passwordless accounts. Rerun import with the same archive.\n", len(users))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	cmd.Flags().StringVar(&database, "database", "", "original Tuwunel database backup used to create the dump")
	cmd.Flags().StringVar(&ldb, "ldb", "ldb", "path to a compatible RocksDB ldb executable")
	cmd.Flags().BoolVar(&includeAppserviceSenders, "include-appservice-senders", false, "restore registered bridge bots with empty passwords and no devices as active; may reactivate intentionally deactivated bots")
	_ = cmd.MarkFlagRequired("database")
	return cmd
}
