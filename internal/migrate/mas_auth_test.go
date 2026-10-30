package migrate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMASClientCredentialsRenewal(t *testing.T) {
	var grants atomic.Int32
	var reject atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != "migration-client" || secret != "migration-secret" {
				t.Error("missing client authentication")
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "urn:mas:admin" {
				t.Errorf("invalid token grant: %v", err)
			}
			n := grants.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("token-%d", n), "token_type": "Bearer", "expires_in": 300})
			return
		}
		if r.URL.Path != "/api/admin/v1/users/by-username/alice" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		if reject.Swap(false) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer token-%d", grants.Load()) {
			t.Error("request used a stale access token")
		}
		_, _ = w.Write([]byte(`{"data":{"id":"alice-id"}}`))
	}))
	defer server.Close()
	m, err := NewMASWithClientCredentials(server.URL, "migration-client", "migration-secret")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func() {
		t.Helper()
		id, err := m.userID(t.Context(), "@alice:example.org")
		if err != nil || id != "alice-id" {
			t.Errorf("MAS lookup: id=%q error=%v", id, err)
		}
	}
	lookup()
	lookup()
	if grants.Load() != 1 {
		t.Fatalf("valid token was not reused: %d grants", grants.Load())
	}
	m.auth.Lock()
	m.auth.renewAt = time.Now().Add(-time.Second)
	m.auth.Unlock()
	var requests sync.WaitGroup
	for range 8 {
		requests.Go(lookup)
	}
	requests.Wait()
	if grants.Load() != 2 {
		t.Fatalf("concurrent expiry caused %d grants", grants.Load())
	}
	reject.Store(true)
	lookup()
	if grants.Load() != 3 {
		t.Fatalf("rejected token was not renewed: %d grants", grants.Load())
	}
}

func TestMASCredentialsFailureDoesNotExposeSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","client_secret":"private-secret"}`))
	}))
	defer server.Close()
	m, err := NewMASWithClientCredentials(server.URL, "client", "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.userID(t.Context(), "@alice:example.org"); err == nil || strings.Contains(err.Error(), "private-secret") || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("token exchange error = %v", err)
	}
	static, err := NewMAS(server.URL, "old-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := static.userID(t.Context(), "@alice:example.org"); err == nil || !strings.Contains(err.Error(), "--from-mas-client-id") {
		t.Fatalf("expired static token error = %v", err)
	}
}

func TestMASRevokedCredentialsDoNotLoop(t *testing.T) {
	var grants, requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants.Add(1)
			_, _ = w.Write([]byte(`{"access_token":"rejected","token_type":"Bearer","expires_in":300}`))
			return
		}
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	m, err := NewMASWithClientCredentials(server.URL, "client", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.userID(t.Context(), "@alice:example.org"); err == nil {
		t.Fatal("rejected credentials accepted")
	}
	if grants.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("unbounded authentication retry: grants=%d requests=%d", grants.Load(), requests.Load())
	}
}

func TestMASListStopsWhenPaginationRepeats(t *testing.T) {
	var requests atomic.Int32
	page := `{"data":[` + strings.TrimSuffix(strings.Repeat(`{"id":"same","attributes":{}},`, 100), ",") + `]}`
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 3 {
			t.Error("MAS pagination kept requesting the same page")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, page)
	}))
	defer api.Close()
	m, err := NewMAS(api.URL, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Emails(t.Context(), "user"); err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("err = %v", err)
	}
}
