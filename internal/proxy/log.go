package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"
)

type responseLog struct {
	http.ResponseWriter
	status int
}

func (w *responseLog) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseLog) WriteHeader(status int) {
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseLog) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *responseLog) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	attrs := []any{"method", r.Method, "host", r.Host, "path", r.URL.EscapedPath()}
	slog.DebugContext(r.Context(), "proxy request started", attrs...)
	response := &responseLog{ResponseWriter: w}
	completed := false
	defer func() {
		status := response.status
		if status == 0 && completed {
			status = http.StatusOK
		}
		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 || !completed {
			level = slog.LevelWarn
		}
		if !completed {
			attrs = append(attrs, "aborted", true)
		}
		slog.Log(r.Context(), level, "proxy request", append(attrs, "status", status, "duration", time.Since(started))...)
	}()
	p.serveHTTP(response, r)
	completed = true
}

func upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	// Transport errors can contain URLs with credentials or tokens.
	cause := "transport error"
	var networkError net.Error
	var dnsError *net.DNSError
	switch {
	case errors.Is(err, context.Canceled):
		cause = "request canceled"
	case errors.As(err, &networkError) && networkError.Timeout():
		cause = "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		cause = "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		cause = "connection reset"
	case errors.As(err, &dnsError):
		cause = "DNS lookup failed"
	}
	slog.ErrorContext(r.Context(), "upstream request failed", "method", r.Method, "host", r.Host, "path", r.URL.EscapedPath(), "cause", cause, "error_type", fmt.Sprintf("%T", err))
	http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}
