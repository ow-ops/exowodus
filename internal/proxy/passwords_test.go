package proxy

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	vargon2 "github.com/pilinux/argon2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"exodus/internal/archive"
)

func TestCheckPassword(t *testing.T) {
	b64 := base64.RawStdEncoding.EncodeToString
	salt := []byte("0123456789abcdef")

	synapseHash, err := bcrypt.GenerateFromPassword([]byte("pässword"+"pepper"), 4)
	if err != nil {
		t.Fatal(err)
	}
	masBcrypt, err := bcrypt.GenerateFromPassword([]byte("secret"), 4)
	if err != nil {
		t.Fatal(err)
	}
	argon := fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", b64(salt), b64(argon2.IDKey([]byte("secret"), salt, 2, 19456, 1, 32)))
	keyed := fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", b64(salt), b64(vargon2.IDKeyWithSecret([]byte("secret"), salt, []byte("pepper2"), 2, 19456, 1, 32)))
	pepperedBcrypt, err := bcrypt.GenerateFromPassword([]byte("secretpepper2"), 4)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := bcrypt.GenerateFromPassword([]byte("p\u00e4ss"), 4)
	if err != nil {
		t.Fatal(err)
	}
	mas := map[int]MASScheme{2: {Secret: []byte("pepper2")}, 3: {UnicodeNormalization: true}}
	pbkdf, err := pbkdf2.Key(sha256.New, "secret", salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	pbkdfHash := fmt.Sprintf("$pbkdf2-sha256$i=1000,l=32$%s$%s", b64(salt), b64(pbkdf))

	tests := []struct {
		name     string
		pending  archive.PendingPassword
		password string
		want     bool
	}{
		{"synapse bcrypt with pepper", archive.PendingPassword{Hash: string(synapseHash)}, "pässword", true},
		{"synapse NFKC normalisation", archive.PendingPassword{Hash: string(synapseHash)}, "pässword", true},
		{"synapse wrong password", archive.PendingPassword{Hash: string(synapseHash)}, "password", false},
		{"mas argon2id", archive.PendingPassword{Hash: argon, Scheme: archive.SchemeMAS}, "secret", true},
		{"mas argon2id wrong", archive.PendingPassword{Hash: argon, Scheme: archive.SchemeMAS}, "Secret", false},
		{"mas pbkdf2", archive.PendingPassword{Hash: pbkdfHash, Scheme: archive.SchemeMAS}, "secret", true},
		{"mas bcrypt", archive.PendingPassword{Hash: string(masBcrypt), Scheme: archive.SchemeMAS}, "secret", true},
		{"mas unknown scheme", archive.PendingPassword{Hash: "$scrypt$x$y$z", Scheme: archive.SchemeMAS}, "secret", false},
		{"mas argon2id with secret", archive.PendingPassword{Hash: keyed, Scheme: archive.SchemeMAS, Version: 2}, "secret", true},
		{"mas argon2id secret missing", archive.PendingPassword{Hash: keyed, Scheme: archive.SchemeMAS}, "secret", false},
		{"mas bcrypt with secret", archive.PendingPassword{Hash: string(pepperedBcrypt), Scheme: archive.SchemeMAS, Version: 2}, "secret", true},
		{"mas NFKC normalisation", archive.PendingPassword{Hash: string(normalized), Scheme: archive.SchemeMAS, Version: 3}, "pa\u0308ss", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkPassword(tt.pending, tt.password, "pepper", mas); got != tt.want {
				t.Fatalf("checkPassword = %v, want %v", got, tt.want)
			}
		})
	}
}
