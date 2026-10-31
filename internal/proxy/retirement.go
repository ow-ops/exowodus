package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"exowodus/internal/progress"
)

func (p *Proxy) retirement(ctx context.Context) ([]string, error) {
	var lines []string
	var queueErr error
	if p.rp != nil {
		devices := map[string]bool{}
		for _, session := range p.sessions {
			devices[inboxIdentity(session.UserID, session.DeviceID)] = true
		}
		lines = append(lines, fmt.Sprintf("Imported devices: %d; confirm active devices use Continuwuity logins.", len(devices)))
		if len(devices) > 0 {
			lines = append(lines, "Login totals are not a countdown. Old MAS logins may need the proxy again.")
		}
		p.mu.Lock()
		passwords := len(p.pending)
		p.mu.Unlock()
		passwordLine := fmt.Sprintf("Passwords pending: %d.", passwords)
		if passwords > 0 {
			passwordLine += " Check migrated or reset passwords directly."
		}
		lines = append(lines, passwordLine)
		messages := 0
		for _, box := range p.inboxes {
			box.mu.Lock()
			messages += len(box.messages)
			if box.state != nil {
				messages -= box.state.Acknowledged
			}
			box.mu.Unlock()
		}
		messageLine := fmt.Sprintf("Device messages pending: %d.", messages)
		if messages > 0 {
			messageLine += " Keep devices syncing until acknowledged."
		}
		lines = append(lines, messageLine)
		federation := 0
		if p.outbox != nil {
			federation, queueErr = p.outbox.store.Pending(ctx)
		}
		if queueErr != nil {
			lines = append(lines, "Federation deliveries: unknown; check the queue error before removing.")
		} else {
			line := fmt.Sprintf("Federation deliveries pending: %d.", federation)
			if federation > 0 {
				line += " Keep the proxy running until delivered."
			}
			lines = append(lines, line)
		}
		aliases := 0
		for old, current := range p.regTokens {
			if old != current {
				aliases++
			}
		}
		if aliases > 0 {
			lines = append(lines, fmt.Sprintf("Old registration tokens: %d; share the Continuwuity tokens.", aliases))
		}
		if len(p.shadowBanned) > 0 {
			lines = append(lines, fmt.Sprintf("Shadow bans: %d; replace them before removing the proxy.", len(p.shadowBanned)))
		}
	}
	if len(p.media) > 0 {
		lines = append(lines, fmt.Sprintf("Archived media files: %d; verify old links work directly.", len(p.media)))
	}
	if p.rp != nil {
		lines = append(lines, "Once checked, route traffic to Continuwuity and keep the archive.")
	} else {
		lines = append(lines, "Keep old media URLs reachable without this proxy before removing it.")
	}
	return lines, queueErr
}

// WatchRetirement keeps the removal checklist current.
func (p *Proxy) WatchRetirement(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	var previous []string
	report := func() {
		lines, err := p.retirement(ctx)
		if ctx.Err() != nil {
			return
		}
		if slices.Equal(lines, previous) {
			return
		}
		progress.Panel(ctx, "Before removing the proxy", lines)
		for _, line := range lines {
			slog.InfoContext(ctx, "before removing the proxy", "check", line)
		}
		if err != nil {
			slog.WarnContext(ctx, "could not count federation deliveries", "err", err)
		}
		previous = lines
	}
	report()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				report()
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
