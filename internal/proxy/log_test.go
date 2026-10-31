package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"exowodus/internal/archive"
)

func captureLogs(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &output
}

func TestProxyRequestLogs(t *testing.T) {
	const body = "grant_type=refresh_token&refresh_token=body-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if string(data) != body {
			t.Errorf("forwarded body = %q", data)
		}
		w.Header().Set("Set-Cookie", "cookie-secret")
		if r.URL.Path == "/oauth2/token" {
			w.WriteHeader(http.StatusBadRequest)
		} else if r.URL.Path == "/unavailable" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = io.WriteString(w, `{"error":"response-secret"}`)
	}))
	defer upstream.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(upstream.URL)
	p, err := New(a, u, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	for _, tc := range []struct {
		path, method, level string
		status              int
		local               bool
	}{
		{"/_matrix/client/versions", http.MethodGet, "INFO", 200, false},
		{"/oauth2/token", http.MethodPost, "WARN", 400, false},
		{"/unavailable", http.MethodPost, "ERROR", 503, false},
		{"/oauth2/token", http.MethodOptions, "INFO", 204, false},
		{"/missing", http.MethodGet, "WARN", 404, true},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			output := captureLogs(t, slog.LevelInfo)
			rp := p.rp
			if tc.local {
				p.rp = nil
				defer func() { p.rp = rp }()
			}
			req := httptest.NewRequest(tc.method, "https://auth.example.org"+tc.path+"?access_token=query-secret", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer header-secret")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatalf("expected one request log: %s (%v)", output, err)
			}
			if entry["level"] != tc.level || entry["status"] != float64(tc.status) || entry["method"] != tc.method || entry["host"] != "auth.example.org" || entry["path"] != tc.path || entry["duration"] == nil {
				t.Fatalf("request log = %s", output)
			}
			if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "access_token") {
				t.Fatalf("request log contains credentials: %s", output)
			}
		})
	}
	t.Run("verbose", func(t *testing.T) {
		output := captureLogs(t, slog.LevelDebug)
		do(p, http.MethodGet, "/_matrix/client/versions", "", body)
		if !strings.Contains(output.String(), `"msg":"proxy request started"`) || !strings.Contains(output.String(), `"msg":"proxy request"`) {
			t.Fatalf("verbose logs = %s", output)
		}
	})
	t.Run("upstream failure", func(t *testing.T) {
		output := captureLogs(t, slog.LevelInfo)
		upstream.Close()
		response := do(p, http.MethodGet, "/_matrix/client/versions?access_token=query-secret", "header-secret", body)
		if response.Code != http.StatusBadGateway || !strings.Contains(output.String(), `"cause":"connection refused"`) || !strings.Contains(output.String(), `"status":502`) || strings.Contains(output.String(), "secret") {
			t.Fatalf("response = %d; logs = %s", response.Code, output)
		}
	})
}

func TestResponseLogPreservesStreaming(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &responseLog{ResponseWriter: w}
		response.WriteHeader(http.StatusEarlyHints)
		if err := http.NewResponseController(response).Flush(); err != nil {
			t.Error(err)
		}
		if response.status != http.StatusOK {
			t.Errorf("flushed status = %d", response.status)
		}
		_, _ = io.WriteString(response, "first")
		_ = http.NewResponseController(response).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, data); err != nil || string(data) != "first" || response.StatusCode != http.StatusOK {
		t.Fatalf("streaming response = %q, status = %d, error = %v", data, response.StatusCode, err)
	}
}

func TestUpstreamErrorDoesNotLogURL(t *testing.T) {
	output := captureLogs(t, slog.LevelInfo)
	req := httptest.NewRequest(http.MethodPost, "https://auth.example.org/oauth2/token?refresh_token=query-secret", nil)
	err := &url.Error{Op: "Post", URL: req.URL.String(), Err: errors.New("transport-secret")}
	upstreamError(httptest.NewRecorder(), req, err)
	if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "refresh_token") {
		t.Fatalf("transport log contains credentials: %s", output)
	}
}

func TestOAuthLogs(t *testing.T) {
	for _, tc := range []struct {
		grant, token string
		mapped       bool
	}{
		{"refresh_token", "old-refresh", true},
		{"refresh_token", "unknown-secret", false},
		{"authorization_code", "old-refresh", false},
	} {
		t.Run(tc.grant+"/"+tc.token, func(t *testing.T) {
			output := captureLogs(t, slog.LevelDebug)
			p, _ := newTestProxy(t)
			form := url.Values{
				"grant_type": {tc.grant}, "client_id": {"public-client"},
				"refresh_token": {tc.token}, "code": {"code-secret"},
				"client_secret": {"client-secret"}, "password": {"password-secret"},
			}
			do(p, http.MethodPost, "/_continuwuity/oauth2/grant/token", "header-secret", form.Encode())
			if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "old-refresh") {
				t.Fatalf("OAuth log contains credentials: %s", output)
			}
			found := false
			for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
				var entry map[string]any
				if err := json.Unmarshal(line, &entry); err != nil {
					t.Fatal(err)
				}
				if entry["msg"] == "OAuth token request" {
					found = true
					if entry["grant_type"] != tc.grant || entry["client_id"] != "public-client" || entry["migrated_session"] != tc.mapped {
						t.Fatalf("OAuth log = %v", entry)
					}
				}
			}
			if !found {
				t.Fatal("OAuth diagnostic log missing")
			}
		})
	}
}
