package main

import (
	"errors"
	"fmt"
	"log/slog"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"exowodus/internal/mx"
	"github.com/spf13/cobra"
)

func newRefreshMASSessionsCmd() *cobra.Command {
	var dir, to, database string
	cmd := &cobra.Command{
		Use:   "refresh-mas-sessions",
		Short: "Recover MAS logins that changed after export",
		Long: `Read active MAS tokens and map them to verified, restored devices.
Stop MAS and any running import. Keep PostgreSQL and Continuwuity running.
Use the original MAS database and archive, then restart the proxy.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if database == "" {
				return errors.New("set --mas-db or EXOWODUS_MAS_DB to the original MAS database")
			}
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			c, err := mx.New(to, "")
			if err != nil {
				return err
			}
			slog.Info("reading current MAS sessions")
			db, err := migrate.OpenMASDB(cmd.Context(), database)
			if err != nil {
				return err
			}
			defer db.Close()
			updated, failures, err := migrate.RefreshMASSessions(cmd.Context(), a, c, db)
			if err != nil {
				return err
			}
			for _, failure := range failures {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", failure.Target, failure.Error)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Updated %d session mappings. Restart the proxy with --archive %s.\n", updated, dir)
			if len(failures) > 0 {
				return fmt.Errorf("%d devices could not be recovered", len(failures))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", defaultArchiveDir(), "archive directory used for import")
	cmd.Flags().StringVar(&to, "to", "", "Continuwuity client API URL")
	cmd.Flags().StringVar(&database, "mas-db", configEnv("MAS_DB"), "original MAS PostgreSQL database [$EXOWODUS_MAS_DB]")
	cmd.Flags().Lookup("mas-db").DefValue = ""
	_ = cmd.MarkFlagRequired("to")
	return cmd
}
