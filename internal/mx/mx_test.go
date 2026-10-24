package mx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadDeadline(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/_matrix/client/v1/media/download/example.org/file" {
			t.Errorf("unexpected media request: %s", r.URL)
		}
		_, _ = w.Write([]byte("media"))
	}))
	defer srv.Close()
	client := MustNew(srv.URL, "token")
	client.RequestHook = func(r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 3*time.Minute {
			t.Errorf("download deadline missing or exceeds three minutes: %v", deadline)
		}
	}
	path := filepath.Join(t.TempDir(), "file")
	if _, _, err := Download(t.Context(), client, "mxc://example.org/file", path); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("download made %d requests", requests)
	}
}

func TestDownloadCancellation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers bool
	}{{"before headers", false}, {"during body", true}} {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.headers {
					_, _ = w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
				}
				close(started)
				<-r.Context().Done()
			}))
			defer srv.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			path := filepath.Join(t.TempDir(), "file")
			done := make(chan error, 1)
			go func() {
				_, _, err := Download(ctx, MustNew(srv.URL, "token"), "mxc://example.org/file", path)
				done <- err
			}()
			<-started
			if tc.headers {
				deadline := time.Now().Add(time.Second)
				for {
					if info, err := os.Stat(path + ".part"); err == nil && info.Size() > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("response body was not written")
					}
					time.Sleep(time.Millisecond)
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled download: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("download kept retrying after cancellation")
			}
			for _, file := range []string{path, path + ".part"} {
				if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("canceled download left %s: %v", file, err)
				}
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
