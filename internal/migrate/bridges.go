package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"

	"go.yaml.in/yaml/v3"
	"maunium.net/go/mautrix"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

// Bridge is re-registered unchanged; its token replays its puppets' messages.
type Bridge struct {
	ID           string
	registration string
	users        []*regexp.Regexp
	exclusive    []*regexp.Regexp
	sender       string
	client       *mautrix.Client
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

func parseBridge(raw []byte, dest *mautrix.Client) (*Bridge, error) {
	var reg struct {
		ID         string `yaml:"id"`
		ASToken    string `yaml:"as_token"`
		Sender     string `yaml:"sender_localpart"`
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
	b := &Bridge{ID: reg.ID, registration: string(raw), sender: reg.Sender}
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
			var existing, archived any
			if err := yaml.Unmarshal([]byte(im.Bridges[i].registration), &existing); err != nil {
				return fmt.Errorf("appservice %s registration: %w", b.ID, err)
			}
			if err := yaml.Unmarshal([]byte(b.registration), &archived); err != nil {
				return fmt.Errorf("archived appservice %s registration: %w", b.ID, err)
			}
			if !reflect.DeepEqual(existing, archived) {
				return fmt.Errorf("appservice %s differs from the archived registration", b.ID)
			}
			continue
		}
		if slices.ContainsFunc(bridges, func(existing *Bridge) bool { return existing.ID == b.ID }) {
			return fmt.Errorf("duplicate archived appservice %s", b.ID)
		}
		bridges = append(bridges, b)
	}
	for _, b := range bridges {
		if err := b.Register(ctx, im.Admin); err != nil {
			return fmt.Errorf("register appservice %s: %w", b.ID, err)
		}
		im.Bridges = append(im.Bridges, b)
	}
	return nil
}

func (b *Bridge) Register(ctx context.Context, admin *ContinuwuityAdmin) error {
	return admin.registerAppservice(ctx, b.registration)
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
