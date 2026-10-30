package main

import (
	"fmt"

	"exowodus/internal/archive"
	"github.com/spf13/cobra"
)

func newResetImportCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use: "reset-import", Short: "Clear import progress to import the archive into an empty Continuwuity",
		Long: `Stop the proxy before running this command. Import progress, generated
passwords, sessions and finish backups move to a reset-<time> directory in the
archive; export data stays. Then import into a new, empty Continuwuity database.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			backup, moved, err := a.ResetImport()
			if err != nil {
				return fmt.Errorf("%w; files moved so far are in %s", err, backup)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Moved %d import files to %s.\n", moved, backup)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", defaultArchiveDir(), "archive directory")
	return cmd
}
