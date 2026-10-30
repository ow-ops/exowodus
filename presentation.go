package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"exodus/internal/progress"
)

func styleCommands(root *cobra.Command, mode *string, verbose *bool) {
	for _, cmd := range root.Commands() {
		run := cmd.RunE
		if run == nil {
			continue
		}
		cmd.RunE = func(cmd *cobra.Command, args []string) (result error) {
			out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
			interactive := *mode == "tty"
			if *mode == "auto" {
				interactive = os.Getenv("TERM") != "dumb" && os.Getenv("CI") == "" && progress.IsTerminal(out) && progress.IsTerminal(errOut)
			}
			if !interactive {
				return run(cmd, args)
			}
			ctx, logger := cmd.Context(), slog.Default()
			liveCtx, display := progress.Start(ctx, cmd.Name(), errOut)
			level := slog.LevelInfo
			if *verbose {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(display.Handler(level)))
			cmd.SetContext(liveCtx)
			slog.Info(cmd.Short)
			var summary bytes.Buffer
			cmd.SetOut(&summary)
			defer func() {
				display.Stop(result)
				slog.SetDefault(logger)
				cmd.SetContext(ctx)
				cmd.SetOut(out)
				_, err := io.Copy(out, &summary)
				result = errors.Join(result, err)
			}()
			return run(cmd, args)
		}
	}
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		_, noColor := os.LookupEnv("NO_COLOR")
		if *mode == "plain" || !progress.IsTerminal(out) || os.Getenv("TERM") == "dumb" || noColor {
			defaultHelp(cmd, args)
			return
		}
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		defaultHelp(cmd, args)
		cmd.SetOut(out)
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#B9A2FF")).Bold(true)
		for _, line := range strings.SplitAfter(buf.String(), "\n") {
			if line != "" && line[0] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
				line = style.Render(strings.TrimSuffix(line, "\n")) + "\n"
			}
			_, _ = io.WriteString(out, line)
		}
	})
}
