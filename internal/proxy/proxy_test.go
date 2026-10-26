package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestTuwunelLoginsThroughProxy(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	const user = "@alice:example.org"
	const originalPassword = "pa\u0308ssword"
	salt := []byte("0123456789abcdef")
	b64 := base64.RawStdEncoding.EncodeToString
	hash := fmt.Sprintf("$argon2id$v=19$m=64,t=1,p=1$%s$%s", b64(salt), b64(argon2.IDKey([]byte(originalPassword), salt, 1, 64, 1, 32)))
	if err := a.AddCredential(archive.Credential{SourceUserID: user, DestUserID: user, Password: "generated"}); err != nil {
		t.Fatal(err)
	}
	if err := a.WritePendingPasswords(map[string]archive.PendingPassword{user: {SourceUserID: user, Scheme: archive.SchemeTuwunel, Hash: hash}}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSessions(map[string]archive.Session{
		"original-access":  {UserID: user, DeviceID: "PHONE", Token: "destination-device"},
		"original-refresh": {UserID: user, DeviceID: "PHONE", Token: "destination-device", Refresh: true},
	}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	password := "generated"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/_matrix/client/v3/account/whoami":
			if r.Header.Get("Authorization") != "Bearer destination-device" {
				w.WriteHeader(401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"user_id": user, "device_id": "PHONE"})
		case "/_matrix/client/v3/login":
			var body struct {
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password != password {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"user_id": user, "device_id": "LOGIN", "access_token": "login-token"})
		case "/_matrix/client/v3/account/password":
			var body struct {
				NewPassword   string `json:"new_password"`
				LogoutDevices bool   `json:"logout_devices"`
				Auth          *struct {
					Password string `json:"password"`
				} `json:"auth"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if body.Auth == nil {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"session":"uia","flows":[{"stages":["m.login.password"]}]}`))
				return
			}
			if body.Auth.Password != password || body.LogoutDevices || body.NewPassword != originalPassword {
				t.Error("password change did not preserve credentials and devices")
				w.WriteHeader(403)
				return
			}
			password = body.NewPassword
			_, _ = w.Write([]byte(`{}`))
		case "/_matrix/client/v3/logout":
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected upstream request: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	loginBody, _ := json.Marshal(map[string]any{"type": "m.login.password", "identifier": map[string]string{"type": "m.id.user", "user": "alice"}, "password": originalPassword})
	for _, phase := range []string{"initial", "restart"} {
		p, err := New(a, u, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		who := do(p, http.MethodGet, "/_matrix/client/v3/account/whoami", "original-access", "")
		if who.Code != 200 || !strings.Contains(who.Body.String(), `"device_id":"PHONE"`) {
			t.Fatalf("%s original session failed: %d %s", phase, who.Code, who.Body)
		}
		refresh := do(p, http.MethodPost, "/_matrix/client/v3/refresh", "", `{"refresh_token":"original-refresh"}`)
		var refreshed struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(refresh.Body.Bytes(), &refreshed); err != nil || refreshed.AccessToken != "destination-device" {
			t.Fatalf("%s refresh failed: %s", phase, refresh.Body)
		}
		login := do(p, http.MethodPost, "/_matrix/client/v3/login", "", string(loginBody))
		if login.Code != 200 {
			t.Fatalf("%s original password failed: %d %s", phase, login.Code, login.Body)
		}
		pending, err := a.PendingPasswords()
		if err != nil || len(pending) != 0 {
			t.Fatal("password restoration was not saved")
		}
		if restored, err := a.PasswordRestored(user); err != nil || !restored {
			t.Fatal("password restoration marker missing")
		}
	}
}

func TestProxyServesDatabaseInventoriedMedia(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join("server", "media", "example.org", "orphan")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(a.Dir, file)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.Dir, file), []byte("original unowned bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteServer(&archive.Server{Media: []archive.Media{{MXC: "mxc://example.org/orphan", File: file, ContentType: "application/octet-stream"}}}); err != nil {
		t.Fatal(err)
	}
	p, err := New(a, nil, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := do(p, http.MethodGet, "/_matrix/media/v3/download/example.org/orphan", "", "")
	if response.Code != 200 || response.Body.String() != "original unowned bytes" {
		t.Fatalf("archived media response = %d %s", response.Code, response.Body.String())
	}
	// Browsers preflight authenticated media without a token.
	authenticated := "/_matrix/client/v1/media/download/example.org/orphan"
	preflight := do(p, http.MethodOptions, authenticated, "", "")
	missing := do(p, http.MethodGet, "/_matrix/media/v3/download/example.org/missing", "", "")
	for name, rec := range map[string]*httptest.ResponseRecorder{"media": response, "preflight": preflight, "error": missing} {
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
			t.Fatalf("%s response lacks CORS headers: %v", name, rec.Header())
		}
	}
	if preflight.Code != http.StatusNoContent || preflight.Body.Len() != 0 || missing.Code != http.StatusNotFound {
		t.Fatalf("preflight=%d error=%d", preflight.Code, missing.Code)
	}
}

// fakeUpstream answers whoami for "banned-token" and "user-token" and records other requests.
type fakeUpstream struct {
	paths  []string
	bodies []string
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/_matrix/client/v3/account/whoami" {
		users := map[string]string{"Bearer banned-token": "@banned:ex", "Bearer user-token": "@user:ex"}
		_ = json.NewEncoder(w).Encode(map[string]string{"user_id": users[r.Header.Get("Authorization")]})
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.paths = append(f.paths, r.URL.RequestURI())
	f.bodies = append(f.bodies, string(body))
	_, _ = w.Write([]byte(`{"event_id":"$real"}`))
}

func newTestProxy(t *testing.T) (*Proxy, *fakeUpstream) {
	t.Helper()
	up := &fakeUpstream{}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p := &Proxy{
		upstream:     mx.MustNew(srv.URL, ""),
		rp:           &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(u) }},
		sessions:     map[string]archive.Session{"old-refresh": {Token: "new-token", Refresh: true, OAuth: true}},
		media:        map[string]mediaFile{},
		regTokens:    map[string]string{"old-reg": "new-reg"},
		shadowBanned: map[string]bool{"@banned:ex": true},
		pending:      map[string]archive.PendingPassword{},
	}
	return p, up
}

func do(p *Proxy, method, target, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

func TestShadowBan(t *testing.T) {
	p, up := newTestProxy(t)

	rec := do(p, http.MethodPut, "/_matrix/client/v3/rooms/!r:ex/send/m.room.message/1", "banned-token", `{"body":"hi"}`)
	var resp struct {
		EventID string `json:"event_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !strings.HasPrefix(resp.EventID, "$") || resp.EventID == "$real" {
		t.Fatalf("banned send: %d %s", rec.Code, rec.Body)
	}
	do(p, http.MethodPost, "/_matrix/client/v3/rooms/!r:ex/invite", "banned-token", `{"user_id":"@x:ex"}`)
	do(p, http.MethodPost, "/_matrix/client/v3/createRoom", "banned-token", `{"name":"n","invite":["@x:ex"]}`)
	do(p, http.MethodPut, "/_matrix/client/v3/rooms/!r:ex/send/m.room.message/2", "user-token", `{"body":"hi"}`)

	if len(up.paths) != 2 {
		t.Fatalf("upstream got %v, want only createRoom and the other user's message", up.paths)
	}
	if strings.Contains(up.bodies[0], "invite") || !strings.Contains(up.bodies[0], `"name"`) {
		t.Fatalf("createRoom forwarded as %s, want invites dropped", up.bodies[0])
	}
}

func TestRegistrationTokenTranslation(t *testing.T) {
	p, up := newTestProxy(t)
	do(p, http.MethodPost, "/_matrix/client/v3/register", "",
		`{"username":"u","auth":{"type":"m.login.registration_token","token":"old-reg","session":"s"}}`)
	do(p, http.MethodGet, "/_matrix/client/v1/register/m.login.registration_token/validity?token=old-reg", "", "")
	if !strings.Contains(up.bodies[0], `"token":"new-reg"`) || !strings.Contains(up.paths[1], "token=new-reg") {
		t.Fatalf("upstream got %v %v", up.paths, up.bodies)
	}
}

func TestOAuthRefresh(t *testing.T) {
	p, up := newTestProxy(t)
	rec := do(p, http.MethodPost, "/oauth2/token", "", "grant_type=refresh_token&refresh_token=old-refresh")
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AccessToken != "new-token" || resp.RefreshToken != "old-refresh" || len(up.paths) != 0 {
		t.Fatalf("refresh: %s, upstream %v", rec.Body, up.paths)
	}
	do(p, http.MethodPost, "/oauth2/token", "", "grant_type=refresh_token&refresh_token=unknown")
	if len(up.paths) != 1 {
		t.Fatal("unknown refresh tokens must be forwarded")
	}
}

func TestNativeTuwunelOIDCRefresh(t *testing.T) {
	for _, oauth := range []bool{false, true} {
		t.Run(fmt.Sprintf("oauth=%t", oauth), func(t *testing.T) {
			p, upstream := newTestProxy(t)
			p.sessions["native-refresh"] = archive.Session{UserID: "@alice:example.org", DeviceID: "PHONE", Token: "destination-access", Refresh: true, OAuth: oauth}
			response := do(p, http.MethodPost, "/_tuwunel/oidc/token", "", "grant_type=refresh_token&refresh_token=native-refresh&client_id=existing-client")
			var body struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.AccessToken != "destination-access" || body.RefreshToken != "native-refresh" || len(upstream.paths) != 0 {
				t.Fatalf("native refresh: %s, upstream %v", response.Body, upstream.paths)
			}
			for _, request := range []string{"grant_type=refresh_token&refresh_token=unknown", "grant_type=authorization_code&code=code", "grant_type=refresh_token&refresh_token=access"} {
				p.sessions["access"] = archive.Session{Token: "access", OAuth: true}
				do(p, http.MethodPost, "/_tuwunel/oidc/token", "", request)
			}
			if len(upstream.paths) != 3 {
				t.Fatal("unsupported or unknown OAuth credentials were intercepted")
			}
		})
	}
}

func TestPasswordRestorationResponseLoss(t *testing.T) {
	const user = "@alice:example.org"
	var attempts, logouts int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			attempts++
			var body struct {
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Password != "restored" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`))
				return
			}
			fmt.Fprintf(w, `{"user_id":%q,"device_id":"TEMPORARY","access_token":"temporary"}`, user)
		case strings.HasSuffix(r.URL.Path, "/logout"):
			logouts++
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("already restored password was changed again")
		}
	}))
	defer api.Close()
	p := &Proxy{upstream: mx.MustNew(api.URL, ""), creds: map[string]archive.Credential{user: {Password: "generated"}}}
	if err := p.setPassword(t.Context(), user, "restored"); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || logouts != 1 {
		t.Fatalf("attempts=%d logouts=%d", attempts, logouts)
	}
}
