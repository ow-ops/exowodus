package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/spf13/cobra"

	"exowodus/internal/progress"
)

func TestCommandPresentation(t *testing.T) {
	for _, mode := range []string{"auto", "plain", "tty"} {
		t.Run(mode, func(t *testing.T) {
			oldLogger := slog.Default()
			defer slog.SetDefault(oldLogger)
			var out, errOut bytes.Buffer
			verbose := false
			failure := errors.New("migration failed")
			root := &cobra.Command{Use: "exowodus", SilenceErrors: true, SilenceUsage: true}
			cmd := &cobra.Command{Use: "test", Short: "Test migration", RunE: func(cmd *cobra.Command, _ []string) error {
				slog.Warn("Preserve this warning")
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Migration summary")
				return failure
			}}
			root.SetOut(&out)
			root.SetErr(&errOut)
			root.AddCommand(cmd)
			styleCommands(root, &mode, &verbose)
			root.SetArgs([]string{"test"})
			if err := root.ExecuteContext(t.Context()); !errors.Is(err, failure) {
				t.Fatalf("command error = %v", err)
			}
			if out.String() != "Migration summary\n" {
				t.Fatalf("summary changed: %q", out.String())
			}
			if cmd.Context() != t.Context() || slog.Default() != oldLogger {
				t.Fatal("presentation did not restore command context and logger")
			}
			if mode == "tty" {
				view := ansi.Strip(errOut.String())
				if !strings.Contains(view, "Failed") || !strings.Contains(view, "Preserve this warning") {
					t.Fatalf("failure details lost: %q", view)
				}
			} else if errOut.Len() != 0 {
				t.Fatalf("plain command produced a terminal display: %q", errOut.String())
			}
		})
	}
}

func TestPresentationLeavesPasswordInputAlone(t *testing.T) {
	ctx, display := progress.Start(t.Context(), "recover-login", &bytes.Buffer{})
	resume := progress.Pause(ctx)
	password, err := readRecoveryPassword(ctx, strings.NewReader("destination-password\n"), &bytes.Buffer{})
	resume()
	display.Stop(context.Canceled)
	if err != nil || string(password) != "destination-password" {
		t.Fatalf("password input was consumed by the display: %v", err)
	}
	clear(password)
}

func TestProgressModeValidation(t *testing.T) {
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"reset-import", "--progress", "invalid"})
	if err := root.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "--progress must be") {
		t.Fatalf("progress mode error = %v", err)
	}
}

func TestHelpDoesNotExposeMASClientSecret(t *testing.T) {
	t.Setenv("EXOWODUS_FROM_MAS_CLIENT_SECRET", "private-mas-client-secret")
	root := newRootCmd()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"export", "--help"})
	if err := root.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private-mas-client-secret") {
		t.Fatal("help exposed the client secret from the environment")
	}
	if !strings.Contains(output.String(), "--from-mas-client-secret") {
		t.Fatal("help omitted the MAS client option")
	}
}
