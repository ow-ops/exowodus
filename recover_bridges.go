package main

import (
	"fmt"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"exowodus/internal/mx"
	"github.com/spf13/cobra"
)

func newRecoverBridgeAccountsCmd() *cobra.Command {
	var dir, from, token, database string
	var registrations []string
	cmd := &cobra.Command{
		Use:   "recover-bridge-accounts",
		Short: "Add missing Synapse bridge bot accounts and devices to an existing archive",
		Long: `Read missing bridge accounts from the original Synapse API and database.
Have Synapse's public proxy return HTTP 503 and stop the bridge services.
Keep Synapse running and pass its internal address with --from. Its database
must match the data available through its API. MAS impersonation is not used.
Existing archived users and room history are kept. Then rerun import with this
archive. Private encryption keys from a deleted bridge database are not recovered.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			c, err := mx.New(from, token)
			if err != nil {
				return err
			}
			admin, err := whoami(ctx, c)
			if err != nil {
				return err
			}
			db, err := migrate.OpenSynapseDB(ctx, database)
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()
			var bridges []*migrate.Bridge
			for _, path := range registrations {
				b, err := migrate.LoadBridge(path, c)
				if err != nil {
					return err
				}
				bridges = append(bridges, b)
			}
			count, err := migrate.RecoverSynapseBridgeAccounts(ctx, a, admin, db, bridges)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Recovered %d bridge accounts. Rerun import with the same archive to restore their devices and retry pending deliveries.\n", count)
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&dir, "archive", defaultArchiveDir(), "existing archive directory")
	fs.StringVar(&from, "from", "", "original Synapse client API URL")
	fs.StringVar(&token, "from-admin-token", configEnv("FROM_ADMIN_TOKEN"), "source admin access token [$EXOWODUS_FROM_ADMIN_TOKEN]")
	fs.Lookup("from-admin-token").DefValue = ""
	fs.StringVar(&database, "synapse-db", "", "original Synapse SQLite file or PostgreSQL DSN")
	fs.StringSliceVar(&registrations, "registration", nil, "source bridge registration YAML (repeatable)")
	for _, name := range []string{"from", "synapse-db", "registration"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}
