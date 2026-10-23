package mx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadCached(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "stored", true: "missing"}[missing], func(t *testing.T) {
			calls := 0
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/_matrix/media/v3/download/remote.org/file" ||
					r.URL.Query().Get("allow_remote") != "false" ||
					r.URL.Query().Get("allow_redirect") != "false" ||
					r.URL.Query().Get("timeout_ms") != "0" ||
					r.Header.Get("Authorization") != "Bearer token" {
					t.Errorf("unexpected media request: %s", r.URL)
				}
				if missing {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"not cached"}`))
					return
				}
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Disposition", `inline; filename="image.png"`)
				_, _ = w.Write([]byte("cached media"))
			}))
			defer source.Close()
			path := filepath.Join(t.TempDir(), "media")
			contentType, filename, err := DownloadCached(t.Context(), MustNew(source.URL, "token"), "mxc://remote.org/file", path)
			if calls != 1 {
				t.Fatalf("made %d requests; cache-only downloads must not fall back", calls)
			}
			if missing {
				if !IsCode(err, "M_NOT_FOUND") || !IsStatus(err, http.StatusNotFound) {
					t.Fatalf("missing media error: %v", err)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("missing download created a file: %v", err)
				}
				return
			}
			if err != nil || contentType != "image/png" || filename != "image.png" {
				t.Fatalf("download metadata: type=%q name=%q err=%v", contentType, filename, err)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "cached media" {
				t.Fatalf("download body: %q err=%v", body, err)
			}
		})
	}
}

func TestRetriesRateLimit(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"user_id":"@a:b"}`))
	}))
	defer srv.Close()

	who, err := MustNew(srv.URL, "tok").Whoami(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if who.UserID != "@a:b" || calls != 2 {
		t.Fatalf("id = %q after %d calls", who.UserID, calls)
	}
}

func TestMatrixError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"no"}`))
	}))
	defer srv.Close()

	_, err := MustNew(srv.URL, "").Whoami(context.Background())
	if !IsCode(err, "M_FORBIDDEN") || !IsStatus(err, http.StatusForbidden) {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterWithToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Auth map[string]string `json:"auth"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Auth == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"session":"s1","flows":[{"stages":["m.login.recaptcha"]},{"stages":["m.login.registration_token"]}]}`))
			return
		}
		if body.Auth["type"] != "m.login.registration_token" || body.Auth["token"] != "secret" || body.Auth["session"] != "s1" {
			t.Errorf("auth = %v", body.Auth)
		}
		_, _ = w.Write([]byte(`{"user_id":"@alice:new","access_token":"at"}`))
	}))
	defer srv.Close()

	c, err := Register(context.Background(), MustNew(srv.URL, ""), "alice", "pw", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID != "@alice:new" || c.AccessToken != "at" {
		t.Fatalf("id = %q token = %q", c.UserID, c.AccessToken)
	}
}

func TestRegisterWithoutTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"session":"s1","flows":[{"stages":["m.login.registration_token"]}]}`))
	}))
	defer srv.Close()

	if _, err := Register(context.Background(), MustNew(srv.URL, ""), "alice", "pw", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestDoWithPassword(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			Auth map[string]any `json:"auth"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Auth == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"session":"s1","flows":[{"stages":["m.login.password"]}]}`))
			return
		}
		if body.Auth["session"] != "s1" || body.Auth["password"] != "pw" {
			t.Errorf("auth = %v", body.Auth)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := MustNew(srv.URL, "tok")
	if err := DoWithPassword(context.Background(), c, http.MethodPost, c.BuildClientURL("v3", "account", "password"), map[string]any{}, "@a:b", "pw"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("%d calls", calls)
	}
}

func TestWithServer(t *testing.T) {
	for in, want := range map[string]string{"@alice:old": "@alice:new", "#room:old": "#room:new"} {
		if got := WithServer(in, "new"); got != want {
			t.Errorf("WithServer(%q) = %q, want %q", in, got, want)
		}
	}
}
