package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"exowodus/internal/archive"
)

func TestRepairBridgeRoutingLifecycle(t *testing.T) {
	for _, mode := range []string{"drain", "cancel", "invalid-status"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.FinishExport(nil); err != nil {
				t.Fatal(err)
			}
			registration := filepath.Join(t.TempDir(), "bridge.yaml")
			const raw = "id: bridge\nas_token: as-secret\nhs_token: hs-secret\nsender_localpart: bot\nurl: http://bridge:29317\nnamespaces: {}\n"
			if err := a.WriteServer(&archive.Server{BridgeQueuesDrained: true, AppserviceRegistrations: []string{raw}}); err != nil {
				t.Fatal(err)
			}
			if err := a.WriteImportReport(map[string]any{"complete": true, "bridge_deliveries_held": []string{"bridge"}}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(registration, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var routes []string
			var reply string
			queries := 0
			hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/whoami"):
					_, _ = io.WriteString(w, `{"user_id":"@admin:example.org"}`)
				case strings.Contains(r.URL.Path, "/directory/room/"):
					_, _ = io.WriteString(w, `{"room_id":"!admin:example.org"}`)
				case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/send/"):
					var message struct{ Body string }
					if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
						t.Error(err)
					}
					switch {
					case strings.HasPrefix(message.Body, "!admin appservices register"):
						_, body, _ := strings.Cut(message.Body, "```yaml\n")
						body, _, _ = strings.Cut(body, "```")
						var reg struct {
							URL string `yaml:"url"`
						}
						if err := yaml.Unmarshal([]byte(body), &reg); err != nil {
							t.Error(err)
						}
						if reg.URL == "http://bridge:29317" && queries < 5 {
							t.Error("restored direct delivery before draining queues")
						}
						routes = append(routes, reg.URL)
						reply = "Appservice registered"
						if mode == "cancel" {
							cancel()
						}
					case strings.HasPrefix(message.Body, "!admin query sending "):
						queries++
						reply = "Query completed in 1ms:\n\n```rs\n[]\n```"
						if queries == 1 {
							reply = "Query completed in 1ms:\n\n```rs\n[Ok(pending)]\n```"
						}
						if mode == "invalid-status" {
							reply = "Command unavailable"
						}
					default:
						t.Errorf("unexpected admin command: %s", message.Body)
					}
					_, _ = io.WriteString(w, `{"event_id":"$command"}`)
				case strings.HasSuffix(r.URL.Path, "/messages"):
					_ = json.NewEncoder(w).Encode(map[string]any{"chunk": []any{map[string]any{"type": "m.room.message", "sender": "@conduit:example.org", "content": map[string]any{"msgtype": "m.text", "body": reply, "m.relates_to": map[string]any{"m.in_reply_to": map[string]string{"event_id": "$command"}}}}}})
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer hs.Close()
			cmd := newRepairBridgeCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--archive", a.Dir, "--registration", registration, "--to", hs.URL, "--to-admin-token", "admin", "--listen", "127.0.0.1:0", "--public-url", "http://filter:8011"})
			err = cmd.ExecuteContext(ctx)
			mu.Lock()
			defer mu.Unlock()
			switch mode {
			case "drain":
				if err != nil || len(routes) != 2 || routes[0] != "http://filter:8011" || routes[1] != "http://bridge:29317" {
					t.Fatalf("routes=%v err=%v", routes, err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) || len(routes) != 1 || routes[0] != "http://filter:8011" {
					t.Fatalf("unsafe cancellation: routes=%v err=%v", routes, err)
				}
			case "invalid-status":
				if err == nil || len(routes) != 0 {
					t.Fatalf("unknown queue status changed routes: %v err=%v", routes, err)
				}
			}
			unchanged, err := os.ReadFile(registration)
			if err != nil || string(unchanged) != raw {
				t.Fatal("source registration file changed")
			}
		})
	}
}
