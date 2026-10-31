package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"maunium.net/go/mautrix"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

// Bridge retains the source registration and credentials for its puppets.
type Bridge struct {
	ID           string
	registration string
	users        []*regexp.Regexp
	exclusive    []*regexp.Regexp
	sender       string
	client       *mautrix.Client
	held         bool
	URL          string
	HSToken      string
}

func LoadBridge(path string, dest *mautrix.Client) (*Bridge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := parseBridge(raw, dest)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// SourceSession uses appservice authentication without creating or consuming a
// bridge device session. Appservice accounts do not have MAS identities.
func (b *Bridge) SourceSession(ctx context.Context, u SynapseUser) (*Session, error) {
	if b.ID != u.AppserviceID || b.client == nil {
		return nil, errors.New("source appservice registration does not match the account")
	}
	c := mx.As(b.client, u.UserID)
	who, err := c.Whoami(ctx)
	if err != nil {
		return nil, fmt.Errorf("authenticate source bridge account %s: %w", u.UserID, err)
	}
	if string(who.UserID) != u.UserID || who.DeviceID != "" {
		return nil, errors.New("source appservice returned a different account or an existing device")
	}
	return &Session{UserID: u.UserID, AppserviceID: u.AppserviceID, Client: c, Passwordless: true, Admin: u.Admin, Locked: u.Locked, Suspended: u.Suspended, ShadowBanned: u.ShadowBanned, ExternalIDs: u.ExternalIDs}, nil
}

func (im *Importer) bridgeAccount(ctx context.Context, u *archive.User) (destAccount, error) {
	var b *Bridge
	for _, candidate := range im.Bridges {
		if candidate.ID == u.AppserviceID && (u.UserID == "@"+candidate.sender+":"+im.Archive.Manifest.ServerName || candidate.owns(u.UserID)) {
			b = candidate
			break
		}
	}
	if u.AppserviceID == "" || !u.Passwordless || im.Admin == nil || im.Admin.ServerName() != im.Archive.Manifest.ServerName || b == nil || b.client == nil || im.DestToken != "" || im.DestPassword != "" {
		return destAccount{}, errors.New("bridge accounts require their matching registration, --to-admin-token and the original server name; ordinary login overrides cannot be used")
	}
	if err := registerAppserviceUser(ctx, b.client, u.UserID); err != nil {
		return destAccount{}, err
	}
	c := mx.As(b.client, u.UserID)
	who, err := c.Whoami(ctx)
	if err != nil {
		return destAccount{}, err
	}
	if string(who.UserID) != u.UserID || who.DeviceID != "" {
		return destAccount{}, errors.New("bridge registration returned a different account or device")
	}
	return destAccount{id: u.UserID, client: c}, nil
}

func parseBridge(raw []byte, dest *mautrix.Client) (*Bridge, error) {
	var reg struct {
		ID         string `yaml:"id"`
		ASToken    string `yaml:"as_token"`
		Sender     string `yaml:"sender_localpart"`
		URL        string `yaml:"url"`
		HSToken    string `yaml:"hs_token"`
		Namespaces struct {
			Users []struct {
				Regex     string `yaml:"regex"`
				Exclusive bool   `yaml:"exclusive"`
			} `yaml:"users"`
		} `yaml:"namespaces"`
	}
	if err := yaml.Unmarshal(raw, &reg); err != nil {
		return nil, err
	}
	if reg.ID == "" || reg.ASToken == "" {
		return nil, errors.New("missing id or as_token")
	}
	b := &Bridge{ID: reg.ID, registration: string(raw), sender: reg.Sender, URL: reg.URL, HSToken: reg.HSToken}
	if dest != nil {
		b.client = mx.WithToken(dest, reg.ASToken)
	}
	for _, ns := range reg.Namespaces.Users {
		re, err := regexp.Compile(ns.Regex)
		if err != nil {
			return nil, fmt.Errorf("appservice %s user namespace: %w", reg.ID, err)
		}
		b.users = append(b.users, re)
		if ns.Exclusive {
			b.exclusive = append(b.exclusive, re)
		}
	}
	return b, nil
}

// RestoreBridges must run after account creation: registration reserves usernames.
func (im *Importer) RestoreBridges(ctx context.Context, server *archive.Server) error {
	if server == nil || len(server.AppserviceRegistrations) == 0 {
		return nil
	}
	if im.Admin == nil || im.Admin.ServerName() != im.Archive.Manifest.ServerName {
		return errors.New("restoring appservices requires --to-admin-token and the same server name")
	}
	var bridges []*Bridge
	for _, raw := range server.AppserviceRegistrations {
		b, err := parseBridge([]byte(raw), im.Dest)
		if err != nil {
			return fmt.Errorf("archived appservice registration: %w", err)
		}
		if i := slices.IndexFunc(im.Bridges, func(existing *Bridge) bool { return existing.ID == b.ID }); i >= 0 {
			if !im.Bridges[i].MatchesRegistration(b.registration) {
				return fmt.Errorf("appservice %s differs from the archived registration", b.ID)
			}
			if !im.Bridges[i].held {
				if err := im.Bridges[i].Hold(ctx, im.Admin); err != nil {
					return err
				}
			}
			continue
		}
		if slices.ContainsFunc(bridges, func(existing *Bridge) bool { return existing.ID == b.ID }) {
			return fmt.Errorf("duplicate archived appservice %s", b.ID)
		}
		bridges = append(bridges, b)
	}
	for _, b := range bridges {
		if err := b.Hold(ctx, im.Admin); err != nil {
			return fmt.Errorf("register appservice %s: %w", b.ID, err)
		}
		im.Bridges = append(im.Bridges, b)
	}
	return nil
}

func (b *Bridge) Register(ctx context.Context, admin *ContinuwuityAdmin) error {
	return admin.registerAppservice(ctx, b.registration)
}

func (b *Bridge) MatchesRegistration(raw string) bool {
	var left, right any
	return yaml.Unmarshal([]byte(b.registration), &left) == nil && yaml.Unmarshal([]byte(raw), &right) == nil && reflect.DeepEqual(left, right)
}

func (im *Importer) HeldBridges() []string {
	var ids []string
	for _, b := range im.Bridges {
		if b.held {
			ids = append(ids, b.ID)
		}
	}
	return ids
}

// Hold preserves appservice authentication while leaving deliveries queued.
func (b *Bridge) Hold(ctx context.Context, admin *ContinuwuityAdmin) error {
	if b.URL == "" || b.URL == "null" {
		return b.Register(ctx, admin)
	}
	// A null URL acknowledges and discards deliveries in Continuwuity.
	// Port zero keeps them queued without contacting the running bridge.
	if err := b.Route(ctx, admin, "http://127.0.0.1:0"); err != nil {
		return err
	}
	b.held = true
	slog.WarnContext(ctx, "bridge delivery held during import; run repair-bridge after importing", "bridge", b.ID)
	return nil
}

func (b *Bridge) Route(ctx context.Context, admin *ContinuwuityAdmin, deliveryURL string) error {
	var registration map[string]any
	if err := yaml.Unmarshal([]byte(b.registration), &registration); err != nil {
		return err
	}
	registration["url"] = deliveryURL
	raw, err := yaml.Marshal(registration)
	if err != nil {
		return err
	}
	return admin.registerAppservice(ctx, string(raw))
}

func (im *Importer) HeldBridgeNotes() []string {
	var notes []string
	for _, b := range im.Bridges {
		if b.held {
			notes = append(notes, fmt.Sprintf("Bridge %s delivery is held to prevent history replay; run repair-bridge with its registration and this archive before restarting it.", b.ID))
		}
	}
	return notes
}

// DeliveriesPending checks both queues before restoring direct bridge delivery.
func (b *Bridge) DeliveriesPending(ctx context.Context, admin *ContinuwuityAdmin) (bool, error) {
	if strings.ContainsAny(b.ID, " \t\r\n") {
		return false, errors.New("appservice ID contains whitespace")
	}
	for _, command := range []string{"queued-requests", "active-requests-for"} {
		body, err := admin.Run(ctx, "!admin query sending "+command+" --appservice-id="+b.ID)
		if err != nil {
			return false, err
		}
		_, code, found := strings.Cut(body, "```rs\n")
		if !found {
			return false, errors.New("could not read appservice queue status")
		}
		code, _, found = strings.Cut(code, "```")
		if !found {
			return false, errors.New("incomplete appservice queue status")
		}
		if strings.TrimSpace(code) != "[]" {
			return true, nil
		}
	}
	return false, nil
}

func (b *Bridge) owns(userID string) bool {
	for _, re := range b.users {
		if re.MatchString(userID) {
			return true
		}
	}
	return false
}

func (im *Importer) bridgeOwner(userID string) *Bridge {
	server := im.Archive.Manifest.ServerName
	if mx.ServerName(userID) != server {
		return nil
	}
	for _, b := range im.Bridges {
		if userID == "@"+b.sender+":"+server {
			return b
		}
	}
	// Exclusive namespaces take precedence over other services' subscriptions.
	for _, b := range im.Bridges {
		for _, re := range b.exclusive {
			if re.MatchString(userID) {
				return b
			}
		}
	}
	return nil
}

func (im *Importer) bridgeFor(userID string) *Bridge {
	if b := im.bridgeOwner(userID); b != nil {
		return b
	}
	if mx.ServerName(userID) != im.Archive.Manifest.ServerName {
		return nil
	}
	for _, b := range im.Bridges {
		if b.owns(userID) {
			return b
		}
	}
	return nil
}
