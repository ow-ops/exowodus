package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"maunium.net/go/mautrix"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

// MAS is the MAS admin API. With MAS, Synapse disables "login as user", so
// MAS personal sessions are used instead.
type MAS struct {
	client *mautrix.Client
	auth   *masClientCredentials
}

// NewMAS needs a token with the urn:mas:admin scope.
func NewMAS(baseURL, token string) (*MAS, error) {
	c, err := mx.New(baseURL, token)
	if err != nil {
		return nil, err
	}
	return &MAS{client: c}, nil
}

func (m *MAS) do(ctx context.Context, method string, query map[string]string, body, out any, path ...any) error {
	u := m.client.BuildURLWithQuery(mautrix.BaseURLPath(append([]any{"api", "admin", "v1"}, path...)), query)
	if m.auth == nil {
		_, err := m.client.MakeRequest(ctx, method, u, body, out)
		if mx.IsStatus(err, http.StatusUnauthorized) {
			return fmt.Errorf("MAS admin token expired or was rejected; use --from-mas-client-id and --from-mas-client-secret for automatic renewal: %w", err)
		}
		return err
	}
	var rejected string
	for range 2 {
		token, err := m.auth.token(ctx, m.client, rejected)
		if err != nil {
			return err
		}
		_, err = m.client.MakeFullRequest(ctx, mautrix.FullRequest{Method: method, URL: u, RequestJSON: body, ResponseJSON: out, Headers: http.Header{"Authorization": {"Bearer " + token}}})
		if !mx.IsStatus(err, http.StatusUnauthorized) {
			return err
		}
		rejected = token
	}
	return errors.New("MAS rejected the renewed admin token; check the client credentials and urn:mas:admin scope")
}

func (m *MAS) userID(ctx context.Context, userID string) (string, error) {
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := m.do(ctx, http.MethodGet, nil, nil, &resp, "users", "by-username", mx.Localpart(userID)); err != nil {
		return "", fmt.Errorf("look up %s in MAS: %w", userID, err)
	}
	return resp.Data.ID, nil
}

func (m *MAS) Impersonate(ctx context.Context, synapse *mautrix.Client, u SynapseUser, validFor time.Duration) (*Session, error) {
	id, err := m.userID(ctx, u.UserID)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"actor_user_id": id,
		"human_name":    "exowodus migration",
		"scope":         "urn:matrix:client:api:*",
		"expires_in":    int(validFor.Seconds()),
	}
	var resp struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				AccessToken string `json:"access_token"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := m.do(ctx, http.MethodPost, nil, body, &resp, "personal-sessions"); err != nil {
		return nil, fmt.Errorf("create a MAS session for %s: %w", u.UserID, err)
	}
	sessionID := resp.Data.ID
	links, err := m.list(ctx, map[string]string{"filter[user]": id}, "upstream-oauth-links")
	if err != nil {
		return nil, fmt.Errorf("SSO links of %s: %w", u.UserID, err)
	}
	var external []archive.ExternalID
	for _, l := range links {
		var a struct {
			ProviderID string `json:"provider_id"`
			Subject    string `json:"subject"`
		}
		if err := json.Unmarshal(l, &a); err != nil {
			return nil, err
		}
		external = append(external, archive.ExternalID{AuthProvider: a.ProviderID, ExternalID: a.Subject})
	}
	return &Session{
		UserID: u.UserID, Client: mx.WithToken(synapse, resp.Data.Attributes.AccessToken),
		Admin: u.Admin, Locked: u.Locked, Suspended: u.Suspended, ShadowBanned: u.ShadowBanned, Guest: u.Guest, ExternalIDs: external, masUserID: id,
		close: func(ctx context.Context) error {
			return m.do(ctx, http.MethodPost, nil, struct{}{}, nil, "personal-sessions", sessionID, "revoke")
		},
	}, nil
}

// UnlockTemporarily unlocks in MAS, which owns the lock state.
func (m *MAS) UnlockTemporarily(ctx context.Context, userID string) (func(), error) {
	id, err := m.userID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := m.do(ctx, http.MethodPost, nil, struct{}{}, nil, "users", id, "unlock"); err != nil {
		return nil, fmt.Errorf("unlock %s: %w", userID, err)
	}
	return func() {
		if err := m.do(context.WithoutCancel(ctx), http.MethodPost, nil, struct{}{}, nil, "users", id, "lock"); err != nil {
			slog.Error("could not lock the account again", "user", userID, "err", err)
		}
	}, nil
}

func (m *MAS) list(ctx context.Context, q map[string]string, path ...any) ([]json.RawMessage, error) {
	q["page[first]"] = "100"
	var out []json.RawMessage
	for {
		var page struct {
			Data []struct {
				ID         string          `json:"id"`
				Attributes json.RawMessage `json:"attributes"`
			} `json:"data"`
		}
		if err := m.do(ctx, http.MethodGet, q, nil, &page, path...); err != nil {
			return nil, err
		}
		for _, d := range page.Data {
			out = append(out, d.Attributes)
		}
		if len(page.Data) < 100 {
			return out, nil
		}
		next := page.Data[len(page.Data)-1].ID
		if next == q["page[after]"] {
			return nil, fmt.Errorf("MAS pagination did not advance from %s", next)
		}
		q["page[after]"] = next
	}
}

func (m *MAS) Emails(ctx context.Context, masUserID string) ([]string, error) {
	items, err := m.list(ctx, map[string]string{"filter[user]": masUserID}, "user-emails")
	if err != nil {
		return nil, err
	}
	var emails []string
	for _, it := range items {
		var a struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(it, &a); err != nil {
			return nil, err
		}
		emails = append(emails, a.Email)
	}
	return emails, nil
}

// RegistrationTokens returns only valid tokens.
func (m *MAS) RegistrationTokens(ctx context.Context) ([]archive.RegistrationToken, error) {
	items, err := m.list(ctx, map[string]string{"filter[valid]": "true"}, "user-registration-tokens")
	if err != nil {
		return nil, err
	}
	var tokens []archive.RegistrationToken
	for _, it := range items {
		var a struct {
			Token      string     `json:"token"`
			UsageLimit *int       `json:"usage_limit"`
			TimesUsed  int        `json:"times_used"`
			ExpiresAt  *time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(it, &a); err != nil {
			return nil, err
		}
		t := archive.RegistrationToken{Token: a.Token, UsesAllowed: a.UsageLimit, Completed: a.TimesUsed}
		if a.ExpiresAt != nil {
			ms := a.ExpiresAt.UnixMilli()
			t.ExpiryTime = &ms
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}
