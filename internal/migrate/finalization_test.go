package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestCheckRelayFromDestination(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		fails       bool
	}{
		{name: "relay", reply: "Got response which took 5ms time:\n```json\n{\"name\":\"exodus relay\",\"version\":\"1\"}\n```"},
		{name: "wrong upstream", reply: "Got response:\n```json\n{\"name\":\"continuwuity\"}\n```", fails: true},
		{name: "502", reply: "Command failed with error: Failed sending federation request: HTTP 502 Bad Gateway", fails: true},
		{name: "unhealthy", reply: "Command failed with error: Remote server is currently unhealthy", fails: true},
		{name: "missing JSON", reply: "No response", fails: true},
		{name: "malformed JSON", reply: "```json\n{invalid}\n```", fails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/send/"):
					var body struct{ Body string }
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Body != "!admin debug ping relay.example.org" {
						t.Errorf("unexpected relay probe: %q error=%v", body.Body, err)
					}
					_, _ = w.Write([]byte(`{"event_id":"$probe"}`))
				case strings.HasSuffix(r.URL.Path, "/messages"):
					fmt.Fprintf(w, `{"chunk":[{"type":"m.room.message","sender":"@conduit:example.org","content":{"msgtype":"m.text","body":%q,"m.relates_to":{"m.in_reply_to":{"event_id":"$probe"}}}}]}`, tc.reply)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer api.Close()
			admin := &ContinuwuityAdmin{client: mx.MustNew(api.URL, "token"), room: "!admins:example.org", bot: "@conduit:example.org"}
			if err := admin.CheckRelay(t.Context(), "relay.example.org"); (err != nil) != tc.fails {
				t.Fatalf("relay check: %v", err)
			}
		})
	}
}

func TestAdminCommandDeadlineIncludesSend(t *testing.T) {
	c := mx.MustNew("https://example.org", "token")
	c.DefaultHTTPRetries = 0
	c.Client = &http.Client{Transport: recoveryTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > commandTimeout {
			t.Error("admin send has no command deadline")
		}
		return nil, context.DeadlineExceeded
	})}
	admin := &ContinuwuityAdmin{client: c, room: "!admins:example.org", bot: "@conduit:example.org"}
	if _, err := admin.Run(t.Context(), "!admin debug ping relay.example.org"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send error: %v", err)
	}
}

func TestSessionVerificationStopsOnCancellation(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	user := &archive.User{UserID: "@alice:example.org"}
	if err := a.WriteSecrets(user.UserID, &archive.Secrets{Tokens: []archive.Token{{Token: "old", DeviceID: "PHONE"}, {Token: "other", DeviceID: "LAPTOP"}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSessions(map[string]archive.Session{
		"old":   {UserID: user.UserID, DeviceID: "PHONE", Token: "first"},
		"other": {UserID: user.UserID, DeviceID: "LAPTOP", Token: "second"},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	requests := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		cancel()
		<-r.Context().Done()
	}))
	defer api.Close()
	im := &Importer{Archive: a, Dest: mx.MustNew(api.URL, "")}
	failures := im.VerifySessions(ctx, []*archive.User{user})
	if requests != 1 || len(failures) != 1 || failures[0].Target != "" || !strings.Contains(failures[0].Error, "interrupted") {
		t.Fatalf("requests=%d failures=%+v", requests, failures)
	}
}
