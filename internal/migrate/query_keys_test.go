package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/progress"
)

func TestKeyQueryRetriesOnlyFailedServers(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Users   map[string][]string `json:"device_keys"`
			Timeout int64               `json:"timeout"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Timeout != 10000 {
			t.Errorf("key query body: %+v, error=%v", request, err)
		}
		if calls.Add(1) == 1 {
			if len(request.Users) != 2 {
				t.Errorf("initial users = %v", request.Users)
			}
			_, _ = w.Write([]byte(`{"master_keys":{"@good:one.test":{"key":"good"},"@bad:two.test":{"key":"stale"}},"failures":{"two.test":{"status":503}}}`))
		} else {
			if len(request.Users) != 1 || len(request.Users["@bad:two.test"]) != 1 || request.Users["@bad:two.test"][0] != "PHONE" {
				t.Errorf("successful users were queried again or device filter changed: %v", request.Users)
			}
			_, _ = w.Write([]byte(`{"device_keys":{"@bad:two.test":{"PHONE":{"key":"device"}}},"master_keys":{"@bad:two.test":{"key":"fresh"}},"self_signing_keys":{"@bad:two.test":{"key":"self"}}}`))
		}
	}))
	defer server.Close()
	client := mx.MustNew(server.URL, "token")
	timeout := client.Client.Timeout
	client.Client.Transport = recoveryTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > keyQueryRequestTimeout {
			t.Error("key query has no per-request deadline")
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	result, err := queryKeys(t.Context(), client, map[string][]string{"@good:one.test": {}, "@bad:two.test": {"PHONE"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || string(result.Master["@good:one.test"]) != `{"key":"good"}` || string(result.Master["@bad:two.test"]) != `{"key":"fresh"}` || len(result.Devices["@bad:two.test"]) != 1 || len(result.SelfSigning) != 1 {
		t.Fatalf("partial retry lost or mixed keys: %+v, requests=%d", result, calls.Load())
	}
	if client.Client.Timeout != timeout {
		t.Fatal("key query modified the shared HTTP client")
	}
}

func TestKeyQueryRetryLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		calls  int32
	}{
		{"forbidden", 403, `{"errcode":"M_FORBIDDEN"}`, 1},
		{"expired token", 401, `{"errcode":"M_UNKNOWN_TOKEN"}`, 1},
		{"invalid request", 400, `{"errcode":"M_INVALID_PARAM"}`, 1},
		{"bad gateway", 502, `{}`, 3},
		{"unreachable server", 200, `{"failures":{"example.org":{"status":503}}}`, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			result, err := queryKeys(t.Context(), mx.MustNew(server.URL, "token"), map[string][]string{"@alice:example.org": {}})
			var incomplete *keyQueryIncomplete
			partial := errors.As(err, &incomplete)
			if err == nil || (result != nil) != partial || calls.Load() != tc.calls {
				t.Fatalf("result=%+v error=%v calls=%d", result, err, calls.Load())
			}
		})
	}
}

func TestKeyQueryHonorsRateLimit(t *testing.T) {
	var calls atomic.Int32
	var first time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			first = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":1200}`))
			return
		}
		if time.Since(first) < 1200*time.Millisecond {
			t.Error("retried before the server's rate limit elapsed")
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	if _, err := queryKeys(t.Context(), mx.MustNew(server.URL, "token"), map[string][]string{"@alice:example.org": {}}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("rate limit made %d requests", calls.Load())
	}
}

func TestKeyQueryCancellationDuringBackoff(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()
	started := time.Now()
	_, err := queryKeys(ctx, mx.MustNew(server.URL, "token"), map[string][]string{"@alice:example.org": {}})
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 || time.Since(started) > time.Second {
		t.Fatalf("canceled retry: error=%v calls=%d elapsed=%s", err, calls.Load(), time.Since(started))
	}
}

func TestKeyQueryRetriesInterruptedResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	if _, err := queryKeys(t.Context(), mx.MustNew(server.URL, "token"), map[string][]string{"@alice:example.org": {}}); err != nil || calls.Load() != 2 {
		t.Fatalf("interrupted response: error=%v calls=%d", err, calls.Load())
	}
}

func TestKeyQueryDoesNotShortenServerRetryDelay(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errcode":"M_LIMIT_EXCEEDED"}`))
	}))
	defer server.Close()
	_, err := queryKeys(t.Context(), mx.MustNew(server.URL, "token"), map[string][]string{"@alice:example.org": {}})
	if err == nil || !strings.Contains(err.Error(), "exceeds the batch deadline") || calls.Load() != 1 {
		t.Fatalf("rate limit beyond retry budget: error=%v calls=%d", err, calls.Load())
	}
}

func TestVerificationBatchProgress(t *testing.T) {
	const actor = "@alice:example.org"
	users := make([]string, 201)
	for i := range users {
		users[i] = fmt.Sprintf("@user%d:example.org", i)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Users map[string][]string `json:"device_keys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		n := calls.Add(1)
		want := 100
		if n == 3 {
			want = 1
		}
		if len(request.Users) != want {
			t.Errorf("batch %d queried %d users", n, len(request.Users))
		}
		keys := map[string]any{}
		for user := range request.Users {
			keys[user] = map[string]any{"user_id": user, "keys": map[string]string{"ed25519:master": "master"}, "signatures": map[string]any{actor: map[string]string{"ed25519:signer": "signature"}}, "unsigned": map[string]string{"displayname": "ignored"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"master_keys": keys})
	}))
	defer server.Close()
	var output bytes.Buffer
	ctx, display := progress.Start(t.Context(), "export", &output)
	logger := slog.Default()
	slog.SetDefault(slog.New(display.Handler(slog.LevelDebug)))
	defer slog.SetDefault(logger)
	verified, warnings, err := exportVerifications(ctx, mx.MustNew(server.URL, "token"), actor, &archive.CrossSigning{UserSigning: json.RawMessage(`{"keys":{"ed25519:signer":"signer"}}`)}, users)
	display.Stop(err)
	if err != nil || calls.Load() != 3 || len(verified) != 201 || len(warnings) != 0 {
		t.Fatalf("verification export: keys=%d calls=%d error=%v", len(verified), calls.Load(), err)
	}
	view := ansi.Strip(output.String())
	if !strings.Contains(view, "batch=3") || !strings.Contains(view, "201 / 201") {
		t.Fatalf("verification batches did not show progress: %s", view)
	}
	for _, key := range verified {
		if strings.Contains(string(key), "unsigned") || !strings.Contains(string(key), "signature") {
			t.Fatalf("verification signature changed: %s", key)
		}
	}
}
