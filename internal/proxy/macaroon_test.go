package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func packet(name string, value []byte) []byte {
	body := append(append([]byte(name+" "), value...), '\n')
	return append([]byte(fmt.Sprintf("%04x", len(body)+4)), body...)
}

// guestToken builds a macaroon like Synapse's generate_guest_access_token.
func guestToken(key []byte, caveats ...string) string {
	sig := hmacSHA256(hmacSHA256([]byte("macaroons-key-generator"), key), []byte("key"))
	raw := append(packet("location", []byte("example.org")), packet("identifier", []byte("key"))...)
	for _, c := range caveats {
		raw = append(raw, packet("cid", []byte(c))...)
		sig = hmacSHA256(sig, []byte(c))
	}
	raw = append(raw, packet("signature", sig)...)
	return base64.URLEncoding.EncodeToString(raw)
}

func TestGuestUser(t *testing.T) {
	key := []byte("secret")
	now := time.UnixMilli(1000)
	guest := []string{"gen = 1", "type = access", "user_id = @1:example.org", "nonce = abc", "guest = true"}
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"valid guest token", guestToken(key, guest...), true},
		{"wrong key", guestToken([]byte("other"), guest...), false},
		{"not a guest", guestToken(key, "gen = 1", "type = access", "user_id = @1:example.org"), false},
		{"expired", guestToken(key, append(guest, "time < 999")...), false},
		{"not expired", guestToken(key, append(guest, "time < 2000")...), true},
		{"unknown caveat", guestToken(key, append(guest, "admin = true")...), false},
		{"not a macaroon", "syt_abc_def", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, ok := guestUser(tt.token, key, now)
			if ok != tt.want || ok && user != "@1:example.org" {
				t.Fatalf("guestUser = %q, %v, want %v", user, ok, tt.want)
			}
		})
	}
}
