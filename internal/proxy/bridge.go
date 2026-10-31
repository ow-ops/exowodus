package proxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// BridgeFilter removes imported events from appservice transactions. Failed
// forwards remain failed so the homeserver retains and retries the transaction.
type BridgeFilter struct {
	history   map[string]bool
	token     string
	upstream  *httputil.ReverseProxy
	filtered  atomic.Uint64
	forwarded atomic.Uint64
}

func NewBridgeFilter(upstream, hsToken string, history map[string]bool) (*BridgeFilter, error) {
	u, err := url.Parse(upstream)
	if err != nil || u == nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("bridge URL must be an HTTP(S) URL without credentials, query or fragment")
	}
	if hsToken == "" {
		return nil, errors.New("bridge registration is missing hs_token")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	p := &httputil.ReverseProxy{
		Rewrite:      func(r *httputil.ProxyRequest) { r.SetURL(u) },
		ErrorHandler: upstreamError,
		Transport:    transport,
	}
	return &BridgeFilter{history: history, token: hsToken, upstream: p}, nil
}

func (b *BridgeFilter) Counts() (filtered, forwarded uint64) {
	return b.filtered.Load(), b.forwarded.Load()
}

func (b *BridgeFilter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/_matrix/app/") {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("access_token")
	if auth := r.Header.Get("Authorization"); auth != "" {
		var bearer bool
		token, bearer = strings.CutPrefix(auth, "Bearer ")
		if !bearer {
			token = ""
		}
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(b.token)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	transaction := r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/_matrix/app/v1/transactions/") && strings.TrimPrefix(r.URL.Path, "/_matrix/app/v1/transactions/") != ""
	if !transaction {
		b.upstream.ServeHTTP(w, r)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<20))
	if err != nil {
		http.Error(w, "Cannot read transaction", http.StatusRequestEntityTooLarge)
		return
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil || payload == nil {
		http.Error(w, "Invalid transaction", http.StatusBadRequest)
		return
	}
	var events []json.RawMessage
	if json.Unmarshal(payload["events"], &events) != nil || events == nil {
		http.Error(w, "Invalid events", http.StatusBadRequest)
		return
	}
	kept := make([]json.RawMessage, 0, len(events))
	for _, raw := range events {
		var ev struct {
			EventID string `json:"event_id"`
		}
		if json.Unmarshal(raw, &ev) != nil || ev.EventID == "" {
			http.Error(w, "Missing event ID", http.StatusBadRequest)
			return
		}
		if !b.history[ev.EventID] {
			kept = append(kept, raw)
		}
	}
	removed := len(events) - len(kept)
	// Preserve unknown extensions and non-timeline data, including device keys.
	otherData := false
	for key, value := range payload {
		if key == "events" {
			continue
		}
		switch key {
		case "ephemeral", "to_device":
			otherData = otherData || string(bytes.TrimSpace(value)) != "[]"
		default:
			otherData = true
		}
	}
	if len(kept) == 0 && !otherData {
		b.filtered.Add(uint64(removed))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
		slog.InfoContext(r.Context(), "bridge history filtered", "events", removed)
		return
	}
	payload["events"], _ = json.Marshal(kept)
	raw, err = json.Marshal(payload)
	if err != nil {
		http.Error(w, "Cannot encode transaction", http.StatusInternalServerError)
		return
	}
	forward := r.Clone(r.Context())
	forward.Body = io.NopCloser(bytes.NewReader(raw))
	forward.ContentLength = int64(len(raw))
	forward.Header.Set("Content-Type", "application/json")
	forward.Header.Del("Content-Length")
	forward.Header.Del("Content-Encoding")
	response := &responseLog{ResponseWriter: w}
	b.upstream.ServeHTTP(response, forward)
	if response.status >= 200 && response.status < 300 {
		b.filtered.Add(uint64(removed))
		b.forwarded.Add(uint64(len(kept)))
	}
	slog.InfoContext(r.Context(), "bridge transaction", "filtered", removed, "forwarded", len(kept), "status", response.status)
}
