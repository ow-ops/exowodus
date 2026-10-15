package proxy

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/pilinux/argon2"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"

	"exodus/internal/archive"
)

// bcryptMaxLen matches Synapse, which truncates to bcrypt's input limit.
const bcryptMaxLen = 72

// MASScheme holds scheme settings not stored in the hash.
type MASScheme struct {
	UnicodeNormalization bool
	Secret               []byte
}

// LoadMASSchemes reads passwords.schemes from a MAS configuration file.
func LoadMASSchemes(path string) (map[int]MASScheme, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Passwords struct {
			Schemes []struct {
				Version              int    `yaml:"version"`
				UnicodeNormalization bool   `yaml:"unicode_normalization"`
				Secret               string `yaml:"secret"`
				SecretFile           string `yaml:"secret_file"`
			} `yaml:"schemes"`
		} `yaml:"passwords"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	schemes := map[int]MASScheme{}
	for _, s := range cfg.Passwords.Schemes {
		secret := []byte(s.Secret)
		if s.SecretFile != "" {
			if secret, err = os.ReadFile(s.SecretFile); err != nil {
				return nil, err
			}
		}
		schemes[s.Version] = MASScheme{UnicodeNormalization: s.UnicodeNormalization, Secret: secret}
	}
	return schemes, nil
}

func checkPassword(p archive.PendingPassword, password, pepper string, mas map[int]MASScheme) bool {
	if p.Scheme == archive.SchemeTuwunel {
		if !validTuwunelHash(p.Hash) {
			return false
		}
		return checkPHC(p.Hash, []byte(password), nil)
	}
	if p.Scheme == archive.SchemeMAS {
		scheme := mas[p.Version]
		if scheme.UnicodeNormalization {
			password = norm.NFKC.String(password)
		}
		return checkPHC(p.Hash, []byte(password), scheme.Secret)
	}
	return checkSynapsePassword(p.Hash, password, pepper)
}

func validTuwunelHash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := map[string]uint64{}
	for _, field := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(field, "=")
		n, err := strconv.ParseUint(val, 10, 32)
		if !ok || err != nil || params[key] != 0 || n == 0 {
			return false
		}
		params[key] = n
	}
	return len(params) == 3 && params["t"] > 0 && params["p"] > 0 && params["p"] <= 255 && params["m"] >= 8*params["p"]
}

// Like Synapse: NFKC, then the pepper, truncated to bcrypt's 72 bytes.
func checkSynapsePassword(hash, password, pepper string) bool {
	b := []byte(norm.NFKC.String(password) + pepper)
	if len(b) > bcryptMaxLen {
		b = b[:bcryptMaxLen]
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), b) == nil
}

// MAS appends the secret to the password for bcrypt and PBKDF2, and uses it
// as argon2's secret input.
func checkPHC(encoded string, password, secret []byte) bool {
	peppered := append(slices.Clone(password), secret...)
	if strings.HasPrefix(encoded, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(encoded), peppered) == nil
	}
	// $<algorithm>$[v=<version>$]<params>$<salt>$<hash>
	parts := strings.Split(strings.TrimPrefix(encoded, "$"), "$")
	if len(parts) == 5 {
		parts = append(parts[:1], parts[2:]...)
	}
	if len(parts) != 4 {
		return false
	}
	params := map[string]string{}
	for _, kv := range strings.Split(parts[1], ",") {
		k, v, _ := strings.Cut(kv, "=")
		params[k] = v
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	num := func(k string) uint32 {
		n, _ := strconv.ParseUint(params[k], 10, 32)
		return uint32(n)
	}

	var got []byte
	switch parts[0] {
	case "argon2id":
		got = argon2.IDKeyWithSecret(password, salt, secret, num("t"), num("m"), uint8(num("p")), uint32(len(want)))
	case "pbkdf2-sha256":
		got = pbkdf2Key(sha256.New, peppered, salt, int(num("i")), len(want))
	case "pbkdf2-sha512":
		got = pbkdf2Key(sha512.New, peppered, salt, int(num("i")), len(want))
	default:
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2Key[H hash.Hash](h func() H, password, salt []byte, iter, keyLen int) []byte {
	key, err := pbkdf2.Key(h, string(password), salt, iter, keyLen)
	if err != nil {
		return nil
	}
	return key
}
