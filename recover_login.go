package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"exowodus/internal/mx"
	"exowodus/internal/progress"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newRecoverLoginCmd() *cobra.Command {
	var dir, to, user string
	cmd := &cobra.Command{
		Use: "recover-login", Short: "Verify an existing destination login and save it for import",
		Long: `Verify the current destination password for one archived account, then save
the credentials and a temporary migration session in the archive.
Stop any running import before using this command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			if err := a.CheckExport(); err != nil {
				return err
			}
			if _, err := a.ReadUser(user); err != nil {
				return fmt.Errorf("archived account %s: %w", user, err)
			}
			c, err := mx.New(to, "")
			if err != nil {
				return err
			}
			resume := progress.Pause(cmd.Context())
			password, err := readRecoveryPassword(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr())
			resume()
			if err != nil {
				return err
			}
			defer clear(password)
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			im := &migrate.Importer{Archive: a, Dest: c}
			if err := im.RecoverLogin(ctx, user, string(password)); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Verified destination login for %s. Rerun import with the same archive.\n", user)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", defaultArchiveDir(), "archive directory")
	cmd.Flags().StringVar(&to, "to", "", "Continuwuity client API URL")
	cmd.Flags().StringVar(&user, "user", "", "archived user ID whose destination password is known")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func readRecoveryPassword(ctx context.Context, in io.Reader, out io.Writer) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fd := int(file.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			return nil, err
		}
		defer term.Restore(fd, state)
		type result struct {
			password []byte
			err      error
		}
		ready := make(chan result, 1)
		terminal := term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{in, out}, "")
		go func() {
			password, err := terminal.ReadPassword("Current destination password: ")
			ready <- result{[]byte(password), err}
		}()
		select {
		case got := <-ready:
			if errors.Is(got.err, io.EOF) {
				return nil, errors.New("password entry canceled")
			}
			return got.password, got.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 1024), 1<<20)
	if !scan.Scan() {
		if err := scan.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("provide the destination password on stdin")
	}
	password := scan.Text()
	if password == "" {
		return nil, errors.New("destination password is empty")
	}
	return []byte(password), nil
}
