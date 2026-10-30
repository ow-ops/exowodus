package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"maunium.net/go/mautrix"

	"exowodus/internal/progress"
)

type masClientCredentials struct {
	sync.Mutex
	clientID, secret string
	accessToken      string
	renewAt          time.Time
}

// NewMASWithClientCredentials renews short-lived admin access tokens as needed.
// The client must be listed in MAS's policy.data.admin_clients.
func NewMASWithClientCredentials(baseURL, clientID, secret string) (*MAS, error) {
	if clientID == "" || secret == "" {
		return nil, errors.New("MAS client ID and client secret are both required")
	}
	m, err := NewMAS(baseURL, "")
	if err != nil {
		return nil, err
	}
	m.auth = &masClientCredentials{clientID: clientID, secret: secret}
	return m, nil
}

func (a *masClientCredentials) token(ctx context.Context, client *mautrix.Client, rejected string) (string, error) {
	a.Lock()
	defer a.Unlock()
	if a.accessToken != "" && a.accessToken != rejected && time.Now().Before(a.renewAt) {
		return a.accessToken, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	slog.Info("renewing MAS admin access token")
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"urn:mas:admin"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BuildURL(mautrix.BaseURLPath{"oauth2", "token"}), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(a.clientID), url.QueryEscape(a.secret))
	progress.Request(req)
	defer progress.Response(req)
	started := time.Now()
	resp, err := client.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("obtain MAS admin token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("obtain MAS admin token: HTTP %d; configure a client_secret_basic client in MAS policy.data.admin_clients", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil {
		return "", errors.New("MAS returned an invalid token response")
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > math.MaxInt64/int64(time.Second) {
		return "", errors.New("MAS returned an invalid access token type or lifetime")
	}
	lifetime := time.Duration(token.ExpiresIn) * time.Second
	a.accessToken, a.renewAt = token.AccessToken, started.Add(lifetime-min(30*time.Second, lifetime/10))
	return a.accessToken, nil
}
