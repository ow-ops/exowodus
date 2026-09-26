package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/macaroon.v2"
)

// SynapseMacaroonKey follows Synapse: macaroon_secret_key, else
// registration_shared_secret, else a hash of the signing key.
func SynapseMacaroonKey(secret, signingKeyPath string) ([]byte, error) {
	if secret != "" {
		return []byte(secret), nil
	}
	if signingKeyPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return nil, err
	}
	// "ed25519 <version> <unpadded base64 seed>"
	fields := strings.Fields(string(raw))
	if len(fields) != 3 {
		return nil, fmt.Errorf("%s: not a Synapse signing key", signingKeyPath)
	}
	seed, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(fields[2], "="))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", signingKeyPath, err)
	}
	sum := sha256.Sum256(seed)
	return sum[:], nil
}

// Synapse does not store guest tokens: they are macaroons.
func guestUser(token string, key []byte, now time.Time) (string, bool) {
	if len(key) == 0 {
		return "", false
	}
	raw, err := macaroon.Base64Decode([]byte(token))
	if err != nil {
		return "", false
	}
	var m macaroon.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return "", false
	}
	var userID string
	seen := map[string]bool{}
	err = m.Verify(key, func(caveat string) error {
		switch {
		case caveat == "gen = 1", caveat == "type = access", caveat == "guest = true":
			seen[caveat] = true
		case strings.HasPrefix(caveat, "user_id = "):
			userID = strings.TrimPrefix(caveat, "user_id = ")
		case strings.HasPrefix(caveat, "nonce = "):
		case strings.HasPrefix(caveat, "time < "):
			ms, err := strconv.ParseInt(strings.TrimPrefix(caveat, "time < "), 10, 64)
			if err != nil || now.UnixMilli() >= ms {
				return errors.New("expired")
			}
		default:
			return fmt.Errorf("unknown caveat %q", caveat)
		}
		return nil
	}, nil)
	if err != nil || len(seen) != 3 || userID == "" {
		return "", false
	}
	return userID, true
}
