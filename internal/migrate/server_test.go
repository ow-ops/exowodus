package migrate

import (
	"testing"
	"time"

	"exodus/internal/archive"
)

func TestTokenLimit(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	ptr := func(v int) *int { return &v }
	ts := func(v int64) *int64 { return &v }
	tests := []struct {
		name    string
		token   archive.RegistrationToken
		want    string
		wantErr bool
	}{
		{name: "unlimited", want: "--immortal"},
		{name: "remaining uses", token: archive.RegistrationToken{UsesAllowed: ptr(5), Completed: 2}, want: "--max-uses 3"},
		{name: "used up", token: archive.RegistrationToken{UsesAllowed: ptr(2), Completed: 2}, wantErr: true},
		{name: "remaining lifetime", token: archive.RegistrationToken{ExpiryTime: ts(1_060_000)}, want: "--max-age 60s"},
		{name: "expired", token: archive.RegistrationToken{ExpiryTime: ts(999_000)}, wantErr: true},
		{name: "uses win over expiry", token: archive.RegistrationToken{UsesAllowed: ptr(1), ExpiryTime: ts(1_060_000)}, want: "--max-uses 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenLimit(tt.token, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
