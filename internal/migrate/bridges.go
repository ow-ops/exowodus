package migrate

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"go.yaml.in/yaml/v3"
	"maunium.net/go/mautrix"

	"exodus/internal/mx"
)

// Bridge is re-registered unchanged; its token replays its puppets' messages.
type Bridge struct {
	ID           string
	registration string
	users        []*regexp.Regexp
	client       *mautrix.Client
}

func LoadBridge(path string, dest *mautrix.Client) (*Bridge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var reg struct {
		ID         string `yaml:"id"`
		ASToken    string `yaml:"as_token"`
		Namespaces struct {
			Users []struct {
				Regex string `yaml:"regex"`
			} `yaml:"users"`
		} `yaml:"namespaces"`
	}
	if err := yaml.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if reg.ID == "" || reg.ASToken == "" {
		return nil, fmt.Errorf("%s: missing id or as_token", path)
	}
	b := &Bridge{ID: reg.ID, registration: string(raw), client: mx.WithToken(dest, reg.ASToken)}
	for _, ns := range reg.Namespaces.Users {
		re, err := regexp.Compile(ns.Regex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		b.users = append(b.users, re)
	}
	return b, nil
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

func (im *Importer) bridgeFor(userID string) *Bridge {
	for _, b := range im.Bridges {
		if b.owns(userID) {
			return b
		}
	}
	return nil
}
