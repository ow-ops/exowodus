package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

func TestVerificationExportWithUnreachablePeers(t *testing.T) {
	const actor = "@alice:example.org"
	const cached = "@cached:offline.test"
	const missing = "@missing:offline.test"
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint("lossless=", strict), func(t *testing.T) {
			members := map[string]any{actor: map[string]any{}, cached: map[string]any{}, missing: map[string]any{}}
			for i := range 100 {
				members[fmt.Sprintf("@user%03d:z.test", i)] = map[string]any{}
			}
			var verificationCalls, backups atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/joined_rooms"):
					_, _ = fmt.Fprint(w, `{"joined_rooms":["!room:example.org"]}`)
				case strings.HasSuffix(r.URL.Path, "/joined_members"):
					_ = json.NewEncoder(w).Encode(map[string]any{"joined": members})
				case strings.HasSuffix(r.URL.Path, "/keys/query"):
					var request struct {
						Users map[string][]string `json:"device_keys"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					if _, own := request.Users[actor]; own {
						_, _ = fmt.Fprint(w, `{"master_keys":{"@alice:example.org":{"keys":{"ed25519:master":"master"}}},"user_signing_keys":{"@alice:example.org":{"keys":{"ed25519:signer":"signer"}}}}`)
						return
					}
					call := verificationCalls.Add(1)
					if (call == 2 || call == 3) && len(request.Users) != 2 {
						t.Errorf("retry included healthy users: %v", request.Users)
					}
					keys := map[string]any{}
					failures := map[string]any{}
					for user := range request.Users {
						if mx.ServerName(user) == "offline.test" {
							failures["offline.test"] = map[string]any{"status": 503}
						}
						if user != missing && (call == 1 || user != cached) {
							keys[user] = map[string]any{"keys": map[string]string{"ed25519:master": "master"}, "signatures": map[string]any{actor: map[string]string{"ed25519:signer": "signature"}}}
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"master_keys": keys, "failures": failures})
				case strings.HasSuffix(r.URL.Path, "/dehydrated_device"):
					w.WriteHeader(404)
					_, _ = fmt.Fprint(w, `{"errcode":"M_NOT_FOUND"}`)
				case strings.HasSuffix(r.URL.Path, "/room_keys/version"):
					backups.Add(1)
					_, _ = fmt.Fprint(w, `{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","version":"1","auth_data":{}}`)
				case strings.HasSuffix(r.URL.Path, "/room_keys/keys"):
					_, _ = fmt.Fprint(w, `{"rooms":{}}`)
				default:
					_, _ = fmt.Fprint(w, `{}`)
				}
			}))
			defer server.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			if strict {
				if err := a.RequireLossless(); err != nil {
					t.Fatal(err)
				}
			}
			exp := &Exporter{Archive: a}
			_, err = exp.ExportUser(t.Context(), &Session{UserID: actor, Client: mx.MustNew(server.URL, "token")})
			if strict {
				if err == nil || !strings.Contains(err.Error(), "lossless export requires complete lookups") || backups.Load() != 0 {
					t.Fatalf("strict export: error=%v backups=%d", err, backups.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			u, err := a.ReadUser(actor)
			if err != nil {
				t.Fatal(err)
			}
			if verificationCalls.Load() != 4 || backups.Load() != 1 || len(u.Verified) != 101 || len(u.Verified[cached]) == 0 || len(u.VerificationWarnings) != 1 || !strings.Contains(u.VerificationWarnings[0], "offline.test") {
				t.Fatalf("partial export: keys=%d warnings=%v requests=%d backups=%d", len(u.Verified), u.VerificationWarnings, verificationCalls.Load(), backups.Load())
			}
			// Warnings survive both account preparation and resumed final status.
			u.Deactivated = true
			im := &Importer{Archive: a, sessions: map[string]destAccount{actor: {id: actor}}}
			job, err := im.PrepareUser(t.Context(), u)
			if err != nil || !slices.Equal(job.Report.Warnings, u.VerificationWarnings) {
				t.Fatalf("preparation lost warnings: job=%+v error=%v", job, err)
			}
			job.state.Status = true
			if err := job.save(a); err != nil {
				t.Fatal(err)
			}
			job, err = im.PrepareUser(t.Context(), u)
			if err != nil || !slices.Equal(job.Report.Warnings, u.VerificationWarnings) {
				t.Fatalf("resumed preparation lost warnings: job=%+v error=%v", job, err)
			}
		})
	}
}

func TestVerificationSourceErrorsRemainFatal(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					_, _ = fmt.Fprint(w, `{"failures":{"offline.test":{}}}`)
					return
				}
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"errcode":"M_UNKNOWN"}`)
			}))
			defer server.Close()
			_, warnings, err := exportVerifications(t.Context(), mx.MustNew(server.URL, "token"), "@alice:example.org", &archive.CrossSigning{UserSigning: json.RawMessage(`{"keys":{"ed25519:signer":"signer"}}`)}, []string{"@bob:offline.test"})
			if err == nil || len(warnings) != 0 {
				t.Fatalf("source failure became a warning: warnings=%v error=%v", warnings, err)
			}
		})
	}
}

func TestSuccessfulKeyQueryDoesNotKeepRemovedCachedKeys(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = fmt.Fprint(w, `{"master_keys":{"@bob:offline.test":{"keys":{"ed25519:old":"old"}}},"failures":{"offline.test":{}}}`)
		} else {
			_, _ = fmt.Fprint(w, `{}`)
		}
	}))
	defer server.Close()
	keys, err := queryKeys(t.Context(), mx.MustNew(server.URL, "token"), map[string][]string{"@bob:offline.test": {}})
	if err != nil || len(keys.Master) != 0 {
		t.Fatalf("removed cached key retained: keys=%+v error=%v", keys, err)
	}
}

func TestOwnKeysRejectUnreachableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"master_keys":{"@alice:example.org":{"keys":{"ed25519:master":"master"}}},"failures":{"example.org":{"retry_after_ms":120000}}}`)
	}))
	defer server.Close()
	_, _, err := exportKeys(t.Context(), mx.MustNew(server.URL, "token"), "@alice:example.org", false)
	if err == nil {
		t.Fatal("account keys accepted an incomplete query")
	}
}
