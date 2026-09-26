package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

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
