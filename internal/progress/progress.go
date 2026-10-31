// Package progress renders command activity without taking ownership of stdin.
package progress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

type contextKey struct{}
type requestAttemptKey struct{}

func WithRequestAttempt(ctx context.Context, attempt int) context.Context {
	return context.WithValue(ctx, requestAttemptKey{}, attempt)
}

type counter struct {
	label       string
	done, total int
}

type transfer struct {
	done, total int64
	started     time.Time
	updated     time.Time
	label       string
}

type activity struct {
	sync.Mutex
	title, stage, detail string
	started, changed     time.Time
	counters             []counter
	transfer             *transfer
	request              *http.Request
	requestStarted       time.Time
	attempt              int
	warnings, failures   int
}

type Display struct {
	state   *activity
	program *tea.Program
	done    chan struct{}
	output  io.Writer
}

func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func Start(ctx context.Context, title string, out io.Writer) (context.Context, *Display) {
	now := time.Now()
	d := &Display{state: &activity{title: title, stage: "Starting", started: now, changed: now}, done: make(chan struct{}), output: out}
	ready := make(chan struct{})
	s := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#B9A2FF"))
	m := model{state: d.state, spinner: s, bar: progress.New(progress.WithDefaultBlend(), progress.WithoutPercentage()), width: 80, ready: ready}
	opts := []tea.ProgramOption{tea.WithOutput(out), tea.WithInput(nil), tea.WithoutSignalHandler(), tea.WithFPS(12), tea.WithWindowSize(80, 24)}
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		opts = append(opts, tea.WithColorProfile(colorprofile.Ascii))
	}
	d.program = tea.NewProgram(m, opts...)
	go func() {
		defer close(d.done)
		_, _ = d.program.Run()
	}()
	select {
	case <-ready:
	case <-d.done:
	}
	return context.WithValue(ctx, contextKey{}, d), d
}

func (d *Display) Stop(err error) {
	d.program.Send(finishMsg{err})
	<-d.done
}

// Pause leaves password prompts and their terminal state to the caller.
func Pause(ctx context.Context) func() {
	if d, ok := ctx.Value(contextKey{}).(*Display); ok {
		_ = d.program.ReleaseTerminal()
		return func() { _ = d.program.RestoreTerminal() }
	}
	return func() {}
}

// Count records how many items a batch has processed.
func Count(ctx context.Context, label string, done, total int) {
	if d, ok := ctx.Value(contextKey{}).(*Display); ok {
		d.state.Lock()
		defer d.state.Unlock()
		for i := range d.state.counters {
			if d.state.counters[i].label == label {
				d.state.counters[i] = counter{label, done, total}
				return
			}
		}
		d.state.counters = append(d.state.counters, counter{label, done, total})
	}
}

// Request tracks each actual HTTP attempt, including library retries.
func Request(req *http.Request) {
	if d, ok := req.Context().Value(contextKey{}).(*Display); ok {
		d.state.Lock()
		defer d.state.Unlock()
		if attempt, ok := req.Context().Value(requestAttemptKey{}).(int); ok {
			d.state.attempt = attempt
		} else if d.state.request == req {
			d.state.attempt++
		} else {
			d.state.attempt = 1
		}
		d.state.request, d.state.requestStarted = req, time.Now()
	}
}

func Response(req *http.Request) {
	if d, ok := req.Context().Value(contextKey{}).(*Display); ok {
		d.state.Lock()
		defer d.state.Unlock()
		if d.state.request == req {
			d.state.request = nil
		}
	}
}

// Reader tracks transfer progress and preserves seeking for retries.
func Reader(ctx context.Context, r io.Reader, total int64, label string) io.Reader {
	d, ok := ctx.Value(contextKey{}).(*Display)
	if !ok {
		return r
	}
	now := time.Now()
	t := &transfer{total: total, started: now, updated: now, label: label}
	d.state.Lock()
	d.state.transfer = t
	d.state.Unlock()
	counted := &countingReader{Reader: r, state: d.state, transfer: t}
	if seeker, ok := r.(io.ReadSeeker); ok {
		return &countingReadSeeker{countingReader: counted, seeker: seeker}
	}
	return counted
}

type countingReader struct {
	io.Reader
	state    *activity
	transfer *transfer
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.state.Lock()
	r.transfer.done += int64(n)
	if n > 0 {
		r.transfer.updated = time.Now()
	}
	r.state.Unlock()
	return n, err
}

type countingReadSeeker struct {
	*countingReader
	seeker io.Seeker
}

func (r *countingReadSeeker) Seek(offset int64, whence int) (int64, error) {
	pos, err := r.seeker.Seek(offset, whence)
	if err == nil {
		r.state.Lock()
		r.transfer.done, r.transfer.started = pos, time.Now()
		r.state.Unlock()
	}
	return pos, err
}

type finishMsg struct{ err error }

type model struct {
	state    *activity
	spinner  spinner.Model
	bar      progress.Model
	width    int
	ready    chan struct{}
	finished bool
	err      error
}

func (m model) Init() tea.Cmd {
	close(m.ready)
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case finishMsg:
		m.finished, m.err = true, msg.err
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) View() tea.View {
	m.state.Lock()
	defer m.state.Unlock()
	s := m.state
	width := max(12, min(m.width-6, 88))
	clip := func(v string) string { return ansi.Truncate(clean(v), width, "…") }
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color("#B9A2FF")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#92929E"))
	status := m.spinner.View() + " " + clip(s.stage)
	if m.finished {
		status = "✓ Completed"
		if errors.Is(m.err, context.Canceled) {
			status = "■ Canceled"
		} else if m.err != nil {
			status = "✗ Failed"
		}
	}
	lines := []string{accent.Render("EXOWODUS") + muted.Render(" / "+s.title), "", status}
	if s.detail != "" && !m.finished {
		lines = append(lines, muted.Render(clip(s.detail)))
	}
	for _, c := range s.counters[max(0, len(s.counters)-3):] {
		if c.total <= 0 {
			continue
		}
		m.bar.SetWidth(max(8, width-16))
		ratio := min(1, max(0, float64(c.done)/float64(c.total)))
		lines = append(lines, "", clip(fmt.Sprintf("%s  %d / %d", c.label, c.done, c.total)), m.bar.ViewAs(ratio)+fmt.Sprintf("  %3.0f%%", ratio*100))
	}
	if t := s.transfer; t != nil && !m.finished {
		speed := float64(t.done) / max(time.Since(t.started).Seconds(), 0.001)
		label := fmt.Sprintf("%s · %s · %s/s", t.label, formatBytes(t.done), formatBytes(int64(speed)))
		if t.total > 0 {
			label = fmt.Sprintf("%s · %s / %s · %s/s", t.label, formatBytes(t.done), formatBytes(t.total), formatBytes(int64(speed)))
			m.bar.SetWidth(max(8, width-16))
			ratio := min(1, float64(t.done)/float64(t.total))
			lines = append(lines, "", m.bar.ViewAs(ratio)+fmt.Sprintf("  %3.0f%%", ratio*100))
		}
		lines = append(lines, clip(label))
		if time.Since(t.updated) >= 5*time.Second {
			lines = append(lines, muted.Render(clip("No bytes transferred for "+elapsed(t.updated))))
		}
	}
	if req := s.request; req != nil && !m.finished {
		lines = append(lines, "", muted.Render(clip(req.Method+" "+req.URL.Host+req.URL.EscapedPath())), muted.Render(clip(fmt.Sprintf("Waiting for response · %s · attempt %d", elapsed(s.requestStarted), s.attempt))))
	}
	footer := "Elapsed " + elapsed(s.started)
	if !m.finished {
		footer += " · step " + elapsed(s.changed)
	}
	if s.warnings+s.failures > 0 {
		footer += fmt.Sprintf(" · %d warnings · %d errors", s.warnings, s.failures)
	}
	lines = append(lines, "", muted.Render(clip(footer)))
	frame := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#555366")).Padding(0, 1).Width(width)
	return tea.NewView(frame.Render(strings.Join(lines, "\n")))
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, ansi.Strip(s))
}

func elapsed(start time.Time) string { return time.Since(start).Truncate(time.Second).String() }

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value, unit := float64(n), ""
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value, unit = value/1024, u
		if value < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}

// Handler displays log activity and retains messages at or above scrollback.
func (d *Display) Handler(level, scrollback slog.Level) slog.Handler {
	return &handler{display: d, level: level, scrollback: scrollback, fallback: slog.NewTextHandler(d.output, &slog.HandlerOptions{Level: level})}
}

type handler struct {
	display    *Display
	level      slog.Level
	scrollback slog.Level
	attrs      []slog.Attr
	group      string
	fallback   slog.Handler
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool { return level >= h.level }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	select {
	case <-h.display.done:
		return h.fallback.Handle(ctx, r)
	default:
	}
	attrs := append([]slog.Attr(nil), h.attrs...)
	r.Attrs(func(a slog.Attr) bool { attrs = append(attrs, flattenAttrs([]slog.Attr{a}, h.group)...); return true })
	var fields []string
	for _, a := range attrs {
		fields = append(fields, clean(a.Key+"="+a.Value.String()))
	}
	detail := strings.Join(fields, " · ")
	s := h.display.state
	s.Lock()
	if r.Level >= slog.LevelInfo {
		s.stage, s.detail, s.changed = clean(r.Message), detail, time.Now()
		s.transfer = nil
	}
	if r.Level >= slog.LevelError {
		s.failures++
	} else if r.Level >= slog.LevelWarn {
		s.warnings++
	}
	s.Unlock()
	if r.Level >= h.scrollback {
		line := r.Level.String() + " " + clean(r.Message)
		if detail != "" {
			line += " · " + detail
		}
		h.display.program.Send(tea.Println(line)())
	}
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), flattenAttrs(attrs, h.group)...)
	n.fallback = h.fallback.WithAttrs(attrs)
	return &n
}

func flattenAttrs(attrs []slog.Attr, prefix string) []slog.Attr {
	var out []slog.Attr
	for _, a := range attrs {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			continue
		}
		if a.Value.Kind() == slog.KindGroup {
			group := prefix
			if a.Key != "" {
				group += a.Key + "."
			}
			out = append(out, flattenAttrs(a.Value.Group(), group)...)
		} else {
			a.Key = prefix + a.Key
			out = append(out, a)
		}
	}
	return out
}

func (h *handler) WithGroup(name string) slog.Handler {
	n := *h
	if name != "" {
		n.group += name + "."
	}
	n.fallback = h.fallback.WithGroup(name)
	return &n
}
