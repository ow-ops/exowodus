package progress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	bar "charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"github.com/charmbracelet/x/ansi"
)

func testContext(t *testing.T) (context.Context, *Display) {
	t.Helper()
	now := time.Now()
	d := &Display{state: &activity{title: "export", stage: "Exporting keys", started: now, changed: now}}
	return context.WithValue(t.Context(), contextKey{}, d), d
}

func TestTransferPreservesSeekForRetries(t *testing.T) {
	ctx, d := testContext(t)
	r := Reader(ctx, strings.NewReader("abcdef"), 6, "Upload")
	first := make([]byte, 3)
	if _, err := io.ReadFull(r, first); err != nil {
		t.Fatal(err)
	}
	if d.state.transfer.done != 3 {
		t.Fatalf("transferred = %d", d.state.transfer.done)
	}
	seeker, ok := r.(io.ReadSeeker)
	if !ok {
		t.Fatal("progress removed the seek support used by HTTP retries")
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil || string(data) != "abcdef" || d.state.transfer.done != 6 {
		t.Fatalf("retried transfer = %q, bytes = %d, error = %v", data, d.state.transfer.done, err)
	}
	plain := strings.NewReader("plain")
	if Reader(t.Context(), plain, 5, "Upload") != plain {
		t.Fatal("noninteractive transfers should use their original reader")
	}
}

func TestRequestAttemptsAndPrivacy(t *testing.T) {
	ctx, d := testContext(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://user:secret@matrix.example/keys/query?access_token=hidden", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer private")
	Request(req)
	Request(req)
	if d.state.attempt != 2 {
		t.Fatalf("attempt = %d", d.state.attempt)
	}
	m := model{state: d.state, spinner: spinner.New(), bar: bar.New(), width: 80}
	view := ansi.Strip(m.View().Content)
	for _, secret := range []string{"secret", "hidden", "private", "access_token"} {
		if strings.Contains(view, secret) {
			t.Fatalf("request display contains %q: %s", secret, view)
		}
	}
	if !strings.Contains(view, "attempt 2") || !strings.Contains(view, "matrix.example/keys/query") {
		t.Fatalf("missing request activity: %s", view)
	}
	Response(req)
	if d.state.request != nil {
		t.Fatal("completed request still shown as waiting")
	}
	Request(req.Clone(ctx))
	if d.state.attempt != 1 {
		t.Fatal("a new request should start with attempt one")
	}
	Request(req.Clone(WithRequestAttempt(ctx, 3)))
	if d.state.attempt != 3 {
		t.Fatal("application retries should retain their attempt number")
	}
}

func TestUnknownTransferSizeAndNarrowTerminal(t *testing.T) {
	ctx, d := testContext(t)
	_, _ = io.Copy(io.Discard, Reader(ctx, strings.NewReader("some bytes"), -1, "Download"))
	d.state.stage = "Reading media\x1b[2J\n" + strings.Repeat("長", 80)
	for _, width := range []int{24, 40, 80} {
		m := model{state: d.state, spinner: spinner.New(), bar: bar.New(), width: width}
		view := ansi.Strip(m.View().Content)
		if strings.Contains(view, "%") {
			t.Fatalf("unknown transfer size displayed a percentage: %s", view)
		}
		for _, line := range strings.Split(view, "\n") {
			if ansi.StringWidth(line) > width {
				t.Fatalf("line exceeds terminal width %d: %q", width, line)
			}
		}
	}
}

func TestDisplayFinishesAndRetainsWarnings(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		err          error
	}{
		{"success", "Completed", nil},
		{"failure", "Failed", errors.New("source failed")},
		{"cancel", "Canceled", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			ctx, d := Start(t.Context(), "export", &output)
			logger := slog.New(d.Handler(slog.LevelInfo)).With("user", "@mia:example.org")
			logger.Info("Exporting keys")
			logger.Warn("Retry needed", "reason", "server unavailable")
			Count(ctx, "Accounts", 1, 2)
			d.Stop(tc.err)
			view := ansi.Strip(output.String())
			for _, want := range []string{tc.status, "Retry needed", "server unavailable", "1 / 2"} {
				if !strings.Contains(view, want) {
					t.Fatalf("missing %q in terminal output: %q", want, view)
				}
			}
			logger.Warn("Warning after terminal closed")
			if !strings.Contains(output.String(), "Warning after terminal closed") {
				t.Fatal("closed terminal swallowed a log message")
			}
		})
	}
}
