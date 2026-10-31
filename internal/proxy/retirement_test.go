package proxy

import (
	"database/sql"
	"log/slog"
	"net/http/httputil"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/outbox"
)

func TestRetirementDependencies(t *testing.T) {
	queue, err := outbox.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	if err := queue.Prepare(t.Context(), func(tx *sql.Tx) (*outbox.Summary, error) {
		return &outbox.Summary{}, outbox.Enqueue(t.Context(), tx, "peer.test", "PDU", "$event", []byte(`{}`))
	}); err != nil {
		t.Fatal(err)
	}
	p := &Proxy{
		rp: &httputil.ReverseProxy{},
		sessions: map[string]archive.Session{
			"private-access":  {UserID: "@alice:example.org", DeviceID: "PHONE", Token: "private-destination"},
			"private-refresh": {UserID: "@alice:example.org", DeviceID: "PHONE", Refresh: true, OAuth: true},
			"private-desktop": {UserID: "@alice:example.org", DeviceID: "DESKTOP"},
		},
		pending: map[string]archive.PendingPassword{"@alice:example.org": {Hash: "private-hash"}},
		inboxes: map[string]*deviceInbox{
			"PHONE":   {messages: make([]archive.ToDevice, 3)},
			"DESKTOP": {messages: make([]archive.ToDevice, 2), state: &archive.ProxyInboxState{Acknowledged: 1}},
		},
		outbox:       &federationOutbox{store: queue},
		media:        map[string]mediaFile{"one": {path: "private-path"}, "two": {}},
		regTokens:    map[string]string{"private-old": "private-new", "unchanged": "unchanged"},
		shadowBanned: map[string]bool{"@banned:example.org": true},
	}
	lines, err := p.retirement(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(lines, "\n")
	for _, want := range []string{"Imported devices: 2", "not a countdown", "Passwords pending: 1", "Device messages pending: 4", "Federation deliveries pending: 1", "Old registration tokens: 1", "Shadow bans: 1", "Archived media files: 2", "active devices use Continuwuity logins"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in summary:\n%s", want, text)
		}
	}
	if strings.Contains(text, "private") || strings.Contains(text, "@alice") {
		t.Fatalf("summary exposes credentials or account details: %s", text)
	}
	p.mu.Lock()
	delete(p.pending, "@alice:example.org")
	p.mu.Unlock()
	for _, box := range p.inboxes {
		box.mu.Lock()
		box.state = &archive.ProxyInboxState{Acknowledged: len(box.messages)}
		box.mu.Unlock()
	}
	batch, err := queue.Next(t.Context(), "example.org", time.Now())
	if err != nil || batch == nil {
		t.Fatalf("pending batch = %v, err = %v", batch, err)
	}
	if err := queue.Acknowledge(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	lines, err = p.retirement(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	text = strings.Join(lines, "\n")
	for _, want := range []string{"Passwords pending: 0", "Device messages pending: 0", "Federation deliveries pending: 0", "Imported devices: 2", "active devices use Continuwuity logins", "Archived media files: 2"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q after delivery:\n%s", want, text)
		}
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	lines, err = p.retirement(t.Context())
	text = strings.Join(lines, "\n")
	if err == nil || !strings.Contains(text, "Federation deliveries: unknown") || strings.Contains(text, "Federation deliveries pending: 0") {
		t.Fatalf("unreadable queue reported as empty: %s (%v)", text, err)
	}
}

func TestRetirementMediaOnly(t *testing.T) {
	p := &Proxy{media: map[string]mediaFile{"one": {}}, pending: map[string]archive.PendingPassword{"ignored": {}}}
	lines, err := p.retirement(t.Context())
	text := strings.Join(lines, "\n")
	if err != nil || !strings.Contains(text, "Archived media files: 1") || !strings.Contains(text, "old media URLs") || strings.Contains(text, "Passwords") || strings.Contains(text, "login") {
		t.Fatalf("media-only guidance = %s (%v)", text, err)
	}
}

func TestRetirementWatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		output := captureLogs(t, slog.LevelInfo)
		p := &Proxy{rp: &httputil.ReverseProxy{}, pending: map[string]archive.PendingPassword{"alice": {}}}
		stop := p.WatchRetirement(t.Context())
		defer stop()
		synctest.Wait()
		if !strings.Contains(output.String(), "Passwords pending: 1") {
			t.Fatalf("startup guidance missing: %s", output)
		}
		output.Reset()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if output.Len() != 0 {
			t.Fatalf("unchanged guidance repeated: %s", output)
		}
		p.mu.Lock()
		delete(p.pending, "alice")
		p.mu.Unlock()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if !strings.Contains(output.String(), "Passwords pending: 0") {
			t.Fatalf("updated guidance missing: %s", output)
		}
		stop()
		output.Reset()
		time.Sleep(time.Minute)
		synctest.Wait()
		if output.Len() != 0 {
			t.Fatal("retirement watcher continued after stopping")
		}
	})
}
