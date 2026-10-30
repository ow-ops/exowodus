package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/synapseadmin"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

type Session struct {
	UserID       string
	Client       *mautrix.Client
	Admin        bool
	Locked       bool
	Suspended    bool
	ShadowBanned bool
	Guest        bool
	Passwordless bool
	ExternalIDs  []archive.ExternalID
	masUserID    string
	close        func(context.Context) error
}

// NewEphemeralSession revokes the token on Close.
func NewEphemeralSession(userID string, c *mautrix.Client) *Session {
	return &Session{UserID: userID, Client: c, close: logout(c)}
}

func logout(c *mautrix.Client) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := c.Logout(ctx)
		return err
	}
}

func adminURL(c *mautrix.Client, query map[string]string, path ...any) string {
	return c.BuildURLWithQuery(mautrix.SynapseAdminURLPath(path), query)
}

// optional ignores errors from endpoints Synapse forbids to guests.
func (s *Session) optional(err error) error {
	if s.Guest && mx.IsCode(err, "M_GUEST_ACCESS_FORBIDDEN") {
		return nil
	}
	return err
}

func (s *Session) Close(ctx context.Context) {
	if s.close == nil {
		return
	}
	if err := s.optional(s.close(ctx)); err != nil {
		slog.Warn("could not revoke access token", "user", s.UserID, "err", err)
	}
}

type SynapseUser struct {
	UserID       string
	Admin        bool
	Deactivated  bool
	Locked       bool
	Suspended    bool
	ShadowBanned bool
	Guest        bool
	ExternalIDs  []archive.ExternalID
	// Passwordless is set from a Tuwunel dump, never by the admin API.
	Passwordless bool `json:",omitempty"`
}

type synapseUserDetails struct {
	Admin        bool                 `json:"admin"`
	IsGuest      bool                 `json:"is_guest"`
	Deactivated  bool                 `json:"deactivated"`
	Locked       bool                 `json:"locked"`
	Suspended    bool                 `json:"suspended"`
	ShadowBanned bool                 `json:"shadow_banned"`
	ExternalIDs  []archive.ExternalID `json:"external_ids"`
	AppserviceID *string              `json:"appservice_id"`
}

// SelectSynapseUsers returns every local account when ids is empty.
// Appservice accounts are skipped: they move with their bridge.
// includeGuests must be false when Synapse delegates authentication to MAS.
func SelectSynapseUsers(ctx context.Context, admin *mautrix.Client, ids []string, includeGuests bool) ([]SynapseUser, error) {
	if len(ids) == 0 {
		var err error
		if ids, err = listSynapseUsers(ctx, admin, includeGuests); err != nil {
			return nil, err
		}
	}
	var users []SynapseUser
	for _, userID := range ids {
		if mx.ServerName(userID) != admin.UserID.Homeserver() {
			return nil, fmt.Errorf("source account %s is not local to %s", userID, admin.UserID.Homeserver())
		}
		slog.Info("reading source account", "user", userID)
		d, err := synapseUser(ctx, admin, userID)
		if err != nil {
			return nil, err
		}
		if d.AppserviceID != nil {
			slog.Info("skipping appservice account", "user", userID, "appservice", *d.AppserviceID)
			continue
		}
		users = append(users, SynapseUser{UserID: userID, Admin: d.Admin, Deactivated: d.Deactivated, Locked: d.Locked, Suspended: d.Suspended, ShadowBanned: d.ShadowBanned, Guest: d.IsGuest, ExternalIDs: d.ExternalIDs})
	}
	return users, nil
}

func synapseUser(ctx context.Context, admin *mautrix.Client, userID string) (synapseUserDetails, error) {
	var d synapseUserDetails
	if _, err := admin.MakeRequest(ctx, http.MethodGet, adminURL(admin, nil, "v2", "users", userID), nil, &d); err != nil {
		return d, fmt.Errorf("look up %s: %w", userID, err)
	}
	return d, nil
}

func listSynapseUsers(ctx context.Context, admin *mautrix.Client, includeGuests bool) ([]string, error) {
	var ids []string
	serverName := admin.UserID.Homeserver()
	if serverName == "" {
		return nil, errors.New("source admin user ID is missing")
	}
	q := map[string]string{"guests": strconv.FormatBool(includeGuests), "deactivated": "true", "locked": "true", "limit": "500", "user_id": ":" + serverName}
	seen := map[string]bool{}
	var offset uint64
	for {
		slog.Info("listing source users", "from", offset, "local_users", len(ids))
		var page struct {
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
			NextToken *json.RawMessage `json:"next_token"`
		}
		if _, err := admin.MakeRequest(ctx, http.MethodGet, adminURL(admin, q, "v2", "users"), nil, &page); err != nil {
			return nil, err
		}
		for _, u := range page.Users {
			if seen[u.Name] {
				return nil, fmt.Errorf("duplicate source user %s", u.Name)
			}
			seen[u.Name] = true
			if mx.ServerName(u.Name) == serverName {
				ids = append(ids, u.Name)
			}
		}
		if page.NextToken == nil {
			return ids, nil
		}
		var next string
		if err := json.Unmarshal(*page.NextToken, &next); err != nil {
			next = string(*page.NextToken)
		}
		nextOffset, err := strconv.ParseUint(next, 10, 64)
		if err != nil || nextOffset <= offset || len(page.Users) == 0 {
			return nil, fmt.Errorf("source user pagination did not advance: from=%d next=%q users=%d", offset, next, len(page.Users))
		}
		offset = nextOffset
		q["from"] = next
	}
}

func Impersonate(ctx context.Context, admin *mautrix.Client, u SynapseUser, validFor time.Duration) (*Session, error) {
	body := map[string]int64{"valid_until_ms": time.Now().Add(validFor).UnixMilli()}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if _, err := admin.MakeRequest(ctx, http.MethodPost, adminURL(admin, nil, "v1", "users", u.UserID, "login"), body, &resp); err != nil {
		return nil, fmt.Errorf("log in as %s: %w", u.UserID, err)
	}
	c := mx.WithToken(admin, resp.AccessToken)
	c.UserID = id.UserID(u.UserID)
	return &Session{UserID: u.UserID, Client: c, Admin: u.Admin, Locked: u.Locked, Suspended: u.Suspended, ShadowBanned: u.ShadowBanned, Guest: u.Guest, Passwordless: u.Passwordless, ExternalIDs: u.ExternalIDs, close: logout(c)}, nil
}

// UnlockTemporarily is needed as Synapse refuses client API calls from
// locked accounts. The returned function locks it again.
func UnlockTemporarily(ctx context.Context, admin *mautrix.Client, userID string) (func(), error) {
	sa := synapseadmin.Client{Client: admin}
	if err := sa.CreateOrModifyAccount(ctx, id.UserID(userID), synapseadmin.ReqCreateOrModifyAccount{Locked: ptr.Ptr(false)}); err != nil {
		return nil, fmt.Errorf("unlock %s: %w", userID, err)
	}
	return func() {
		if err := sa.CreateOrModifyAccount(context.WithoutCancel(ctx), id.UserID(userID), synapseadmin.ReqCreateOrModifyAccount{Locked: ptr.Ptr(true)}); err != nil {
			slog.Error("could not lock the account again", "user", userID, "err", err)
		}
	}, nil
}

type synapseMedia struct {
	MediaID       string  `json:"media_id"`
	MediaType     string  `json:"media_type"`
	UploadName    *string `json:"upload_name"`
	QuarantinedBy *string `json:"quarantined_by"`
}

func listSynapseMedia(ctx context.Context, admin *mautrix.Client, userID string) ([]synapseMedia, error) {
	var all []synapseMedia
	q := map[string]string{"limit": "500"}
	for {
		var page struct {
			Media     []synapseMedia `json:"media"`
			NextToken any            `json:"next_token"`
		}
		if _, err := admin.MakeRequest(ctx, http.MethodGet, adminURL(admin, q, "v1", "users", userID, "media"), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Media...)
		if page.NextToken == nil {
			return all, nil
		}
		q["from"] = fmt.Sprint(page.NextToken)
	}
}
