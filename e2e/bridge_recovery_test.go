//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"exowodus/internal/migrate"
	"exowodus/internal/mx"
	"exowodus/internal/proxy"
)

// Run against a disposable Continuwuity, with private IPs allowed and a short
// sender retry backoff. Docker must resolve host.docker.internal to the host.
func TestBridgeRecoveryLive(t *testing.T) {
	target := os.Getenv("EXOWODUS_BRIDGE_LIVE_TARGET")
	if target == "" {
		t.Skip("set EXOWODUS_BRIDGE_LIVE_TARGET to a disposable Continuwuity")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	callbackHost := os.Getenv("EXOWODUS_BRIDGE_LIVE_CALLBACK_HOST")
	if callbackHost == "" {
		callbackHost = "host.docker.internal"
	}
	c := login(t, ctx, mx.MustNew(target, ""), "cadmin")
	admin, err := migrate.NewContinuwuityAdmin(ctx, c)
	must(t, err)
	room := createRoom(t, ctx, c, map[string]any{"preset": "private_chat", "name": "Bridge queue recovery"})
	var mu sync.Mutex
	var delivered []string
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Events []struct {
				EventID string `json:"event_id"`
			} `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		mu.Lock()
		for _, event := range payload.Events {
			delivered = append(delivered, event.EventID)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer bridge.Close()
	_, bridgePort, err := net.SplitHostPort(bridge.Listener.Addr().String())
	must(t, err)
	registration := filepath.Join(t.TempDir(), "registration.yaml")
	raw := fmt.Sprintf("id: bridge-recovery-test\nurl: http://%s:%s\nas_token: bridge-recovery-as\nhs_token: bridge-recovery-hs\nsender_localpart: bridge_recovery_bot\nnamespaces:\n  rooms:\n    - exclusive: false\n      regex: %q\n", callbackHost, bridgePort, "^"+regexp.QuoteMeta(room)+"$")
	must(t, os.WriteFile(registration, []byte(raw), 0600))
	b, err := migrate.LoadBridge(registration, nil)
	must(t, err)
	must(t, b.Hold(ctx, admin))
	old := send(t, ctx, c, room, "m.room.message", map[string]any{"msgtype": "m.text", "body": "!bridge old-command"})
	pending, err := b.DeliveriesPending(ctx, admin)
	must(t, err)
	if !pending {
		t.Fatal("held history was discarded instead of queued")
	}
	filter, err := proxy.NewBridgeFilter(bridge.URL, b.HSToken, map[string]bool{old: true})
	must(t, err)
	listener, err := net.Listen("tcp", ":0")
	must(t, err)
	srv := &http.Server{Handler: filter, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	must(t, err)
	must(t, b.Route(ctx, admin, "http://"+callbackHost+":"+port))
	// A fresh event triggers the native sender's retry after its backoff.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(3 * time.Second):
	}
	fresh := send(t, ctx, c, room, "m.room.message", map[string]any{"msgtype": "m.text", "body": "new message"})
	for {
		pending, err = b.DeliveriesPending(ctx, admin)
		must(t, err)
		if !pending {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	must(t, b.Register(ctx, admin))
	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != 1 || delivered[0] != fresh {
		t.Fatalf("bridge received %v, want only %s", delivered, fresh)
	}
	removed, forwarded := filter.Counts()
	if removed != 1 || forwarded != 1 {
		t.Fatalf("deliveries filtered=%d forwarded=%d", removed, forwarded)
	}
	var stored struct {
		EventID string `json:"event_id"`
	}
	must(t, do(ctx, c, http.MethodGet, urlPath("/_matrix/client/v3/rooms", room, "event", old), nil, nil, &stored))
	if stored.EventID != old {
		t.Fatal("history was removed from the Matrix room")
	}
}
