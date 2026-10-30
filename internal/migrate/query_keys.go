package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"syscall"
	"time"

	"go.mau.fi/util/retryafter"
	"maunium.net/go/mautrix"

	"exowodus/internal/mx"
	"exowodus/internal/progress"
)

const keyQueryAttempts = 3
const keyQueryDeadline = 2 * time.Minute
const keyQueryRequestTimeout = 45 * time.Second
const keyQueryRemoteTimeout = 10 * time.Second

type keyQueryResponse struct {
	Devices     map[string]map[string]json.RawMessage `json:"device_keys"`
	Master      map[string]json.RawMessage            `json:"master_keys"`
	SelfSigning map[string]json.RawMessage            `json:"self_signing_keys"`
	UserSigning map[string]json.RawMessage            `json:"user_signing_keys"`
	Failures    map[string]json.RawMessage            `json:"failures"`
}

// queryKeys retries unavailable servers without discarding successful results.
func queryKeys(ctx context.Context, c *mautrix.Client, users map[string][]string) (*keyQueryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, keyQueryDeadline)
	defer cancel()
	client := *c.Client
	if client.Timeout == 0 || client.Timeout > keyQueryRequestTimeout {
		client.Timeout = keyQueryRequestTimeout
	}
	result := &keyQueryResponse{
		Devices:     map[string]map[string]json.RawMessage{},
		Master:      map[string]json.RawMessage{},
		SelfSigning: map[string]json.RawMessage{},
		UserSigning: map[string]json.RawMessage{},
	}
	pending := maps.Clone(users)
	var lastErr error
	for attempt := 1; attempt <= keyQueryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var page keyQueryResponse
		body, response, err := c.MakeFullRequestWithResp(progress.WithRequestAttempt(ctx, attempt), mautrix.FullRequest{
			Method: http.MethodPost, URL: c.BuildClientURL("v3", "keys", "query"),
			RequestJSON:  map[string]any{"device_keys": pending, "timeout": keyQueryRemoteTimeout.Milliseconds()},
			ResponseJSON: &page, Client: &client, MaxAttempts: 1,
		})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		delay := time.Duration(rand.Int64N(int64(time.Second) << (attempt - 1)))
		if err != nil {
			if !retryableKeyQuery(ctx, err) {
				return nil, err
			}
			lastErr = err
			delay = max(delay, keyQueryRetryAfter(body))
			if response != nil {
				delay = max(delay, retryafter.Parse(response.Header.Get("Retry-After"), 0))
			}
		} else {
			next := map[string][]string{}
			for user, devices := range pending {
				if _, failed := page.Failures[mx.ServerName(user)]; failed {
					next[user] = devices
					continue
				}
				if keys, ok := page.Devices[user]; ok {
					result.Devices[user] = keys
				}
				if key, ok := page.Master[user]; ok {
					result.Master[user] = key
				}
				if key, ok := page.SelfSigning[user]; ok {
					result.SelfSigning[user] = key
				}
				if key, ok := page.UserSigning[user]; ok {
					result.UserSigning[user] = key
				}
			}
			if len(next) == 0 {
				return result, nil
			}
			servers := slices.Sorted(maps.Keys(page.Failures))
			lastErr = fmt.Errorf("key query could not reach %v (%d users)", servers, len(next))
			for _, failure := range page.Failures {
				delay = max(delay, keyQueryRetryAfter(failure))
			}
			pending = next
		}
		if attempt == keyQueryAttempts {
			break
		}
		if deadline, ok := ctx.Deadline(); ok && delay >= time.Until(deadline) {
			return nil, fmt.Errorf("key query retry delay %s exceeds the batch deadline: %w", delay, lastErr)
		}
		slog.Warn("retrying key query", "attempt", attempt+1, "max_attempts", keyQueryAttempts, "retry_in", delay, "users", len(pending), "err", lastErr)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("key query failed after %d attempts: %w", keyQueryAttempts, lastErr)
}

func retryableKeyQuery(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return false
	}
	if status := mx.Status(err); status >= 400 {
		return retryafter.Should(status, true) || status == http.StatusInternalServerError || status == http.StatusRequestTimeout
	}
	var network net.Error
	if errors.As(err, &network) && (network.Timeout() || network.Temporary()) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}

func keyQueryRetryAfter(body []byte) time.Duration {
	var retry struct {
		Millis int64 `json:"retry_after_ms"`
	}
	if json.Unmarshal(body, &retry) != nil || retry.Millis <= 0 {
		return 0
	}
	if retry.Millis > int64(keyQueryDeadline/time.Millisecond) {
		return keyQueryDeadline
	}
	return time.Duration(retry.Millis) * time.Millisecond
}
