// Package proxy keeps pre-migration tokens, passwords and media working on Continuwuity.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"exodus/internal/archive"
	"exodus/internal/mx"

	"maunium.net/go/mautrix"
)

const (
	maxBody       = 64 << 10
	authCacheTTL  = 5 * time.Minute
	loginInterval = time.Second
)

var (
	clientMedia     = regexp.MustCompile(`^/_matrix/client/v1/media/(?:download|thumbnail)/([^/]+)/([^/]+)`)
	legacyMedia     = regexp.MustCompile(`^/_matrix/media/(?:r0|v1|v3)/(?:download|thumbnail)/([^/]+)/([^/]+)`)
	federationMedia = regexp.MustCompile(`^/_matrix/federation/v1/media/(?:download|thumbnail)/([^/]+)$`)
	loginPath       = regexp.MustCompile(`^/_matrix/client/(?:r0|v3)/login$`)
	refreshPath     = regexp.MustCompile(`^/_matrix/client/(?:v1|v3)/refresh$`)
	registerPath    = regexp.MustCompile(`^/_matrix/client/(?:r0|v3)/register$`)
	tokenValidity   = regexp.MustCompile(`^/_matrix/client/v1/register/m\.login\.registration_token/validity$`)
	oauthTokenPath  = regexp.MustCompile(`/oauth2/token$`)
	// Shadow-banned users' events and invites are silently dropped.
	shadowSend   = regexp.MustCompile(`^/_matrix/client/(?:r0|v3)/rooms/[^/]+/(?:send|state)/`)
	shadowIgnore = regexp.MustCompile(`^/_matrix/client/(?:r0|v3)/rooms/[^/]+/(?:invite|typing/[^/]+)$`)
	createRoom   = regexp.MustCompile(`^/_matrix/client/(?:r0|v3)/createRoom$`)
)

type mediaFile struct {
	path, contentType, filename string
}

type Proxy struct {
	outbox    *federationOutbox
	inboxes   map[string]*deviceInbox
	inboxLock io.Closer
	archive   *archive.Archive
	upstream  *mautrix.Client
	rp        *httputil.ReverseProxy
	pepper    string
	// serverName owns the archived media; destServer is the accounts' server.
	serverName, destServer string

	sessions  map[string]archive.Session
	media     map[string]mediaFile
	creds     map[string]archive.Credential
	regTokens map[string]string
	// shadowBanned holds destination user IDs.
	shadowBanned map[string]bool
	macaroonKey  []byte
	masSchemes   map[int]MASScheme

	mu        sync.Mutex
	pending   map[string]archive.PendingPassword
	lastLogin map[string]time.Time
	auth      sync.Map
}

// A nil upstream only serves archived media, e.g. for a retired server name.
func New(a *archive.Archive, upstream *url.URL, pepper string, macaroonKey []byte, masSchemes map[int]MASScheme) (*Proxy, error) {
	p := &Proxy{
		archive: a, pepper: pepper, serverName: a.Manifest.ServerName, destServer: a.Manifest.ServerName,
		macaroonKey: macaroonKey, masSchemes: masSchemes, media: map[string]mediaFile{},
		creds: map[string]archive.Credential{}, shadowBanned: map[string]bool{}, lastLogin: map[string]time.Time{},
	}
	var err error
	if p.sessions, err = a.Sessions(); err != nil {
		return nil, err
	}
	if p.pending, err = a.PendingPasswords(); err != nil {
		return nil, err
	}
	creds, err := a.Credentials()
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		p.creds[c.DestUserID] = c
		p.destServer = mx.ServerName(c.DestUserID)
	}
	users, err := a.Users()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		p.addMedia(a.UserDir(u.UserID), u.Media)
		if !u.ShadowBanned {
			continue
		}
		st, err := a.ReadImportState(u.UserID)
		if err != nil {
			return nil, err
		}
		if st.DestUserID != "" {
			p.shadowBanned[st.DestUserID] = true
		}
	}
	srvState, err := a.ReadServerState()
	if err != nil {
		return nil, err
	}
	p.regTokens = srvState.Tokens
	rooms, err := a.Rooms()
	if err != nil {
		return nil, err
	}
	for _, r := range rooms {
		p.addMedia(a.RoomDir(r.RoomID), r.Media)
	}
	serverData, err := a.ReadServer()
	if err != nil {
		return nil, err
	}
	if serverData != nil {
		p.addMedia(a.Dir, serverData.Media)
		if upstream != nil && p.destServer == p.serverName {
			if err := p.loadInboxes(serverData.ToDevice); err != nil {
				return nil, err
			}
		}
	}
	if upstream != nil {
		if err := p.loadOutbox(); err != nil {
			p.Close()
			return nil, err
		}
		if p.upstream, err = mx.New(upstream.String(), ""); err != nil {
			p.Close()
			return nil, err
		}
		p.rp = &httputil.ReverseProxy{ModifyResponse: p.inboxResponse, Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.SetXForwarded()
			pr.Out.Host = pr.In.Host
		}}
	}
	slog.Info("proxy ready", "sessions", len(p.sessions), "pending_passwords", len(p.pending), "media", len(p.media))
	return p, nil
}

func (p *Proxy) addMedia(dir string, media []archive.Media) {
	for _, m := range media {
		server, id, err := mx.ParseMXC(m.MXC)
		if err != nil {
			continue
		}
		p.media[server+"/"+id] = mediaFile{path: filepath.Join(dir, m.File), contentType: m.ContentType, filename: m.Filename}
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.translateToken(r)

	path := r.URL.Path
	if m := federationMedia.FindStringSubmatch(path); m != nil {
		if f, ok := p.media[p.serverName+"/"+m[1]]; ok {
			p.serveFederationMedia(w, f)
			return
		}
	}
	if m := legacyMedia.FindStringSubmatch(path); m != nil {
		if f, ok := p.media[m[1]+"/"+m[2]]; ok {
			serveFile(w, r, f)
			return
		}
	}
	if m := clientMedia.FindStringSubmatch(path); m != nil {
		if f, ok := p.media[m[1]+"/"+m[2]]; ok {
			if !p.authenticated(r) {
				writeError(w, http.StatusUnauthorized, "M_MISSING_TOKEN", "Missing or invalid access token")
				return
			}
			serveFile(w, r, f)
			return
		}
	}

	if p.rp == nil {
		writeError(w, http.StatusNotFound, "M_NOT_FOUND", "Not found")
		return
	}
	if r.Method == http.MethodPost && refreshPath.MatchString(path) && p.refresh(w, r) {
		return
	}
	if r.Method == http.MethodPost && oauthTokenPath.MatchString(path) && p.oauthRefresh(w, r) {
		return
	}
	if len(p.shadowBanned) > 0 && p.shadowBan(w, r) {
		return
	}
	p.translateRegistrationToken(r)
	if r.Method == http.MethodPost && loginPath.MatchString(path) {
		p.interceptLogin(r)
	}
	var err error
	if r, err = p.inboxRequest(r); err != nil {
		if errors.Is(err, errInboxStorage) {
			slog.Error("could not save device inbox", "err", err)
			writeError(w, http.StatusInternalServerError, "M_UNKNOWN", "Could not save device message acknowledgements")
			return
		}
		writeError(w, http.StatusBadRequest, "M_UNKNOWN_POS", err.Error())
		return
	}
	p.rp.ServeHTTP(w, r)
}

func (p *Proxy) translateToken(r *http.Request) {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if s, ok := p.session(token); ok {
			r.Header.Set("Authorization", "Bearer "+s.Token)
		}
		return
	}
	q := r.URL.Query()
	if s, ok := p.session(q.Get("access_token")); ok {
		q.Set("access_token", s.Token)
		r.URL.RawQuery = q.Encode()
	}
}

func (p *Proxy) session(token string) (archive.Session, bool) {
	if token == "" {
		return archive.Session{}, false
	}
	if s, ok := p.sessions[token]; ok {
		return s, !s.Refresh
	}
	if user, ok := guestUser(token, p.macaroonKey, time.Now()); ok {
		s, ok := p.sessions[archive.GuestSessionKey(user)]
		return s, ok
	}
	return archive.Session{}, false
}

// refresh answers old Synapse refreshes with the device's non-expiring token.
func (p *Proxy) refresh(w http.ResponseWriter, r *http.Request) bool {
	body, err := readBody(r)
	if err != nil {
		return false
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(body, &req) != nil {
		return false
	}
	s, ok := p.sessions[req.RefreshToken]
	if !ok || !s.Refresh {
		return false
	}
	writeJSON(w, map[string]string{"access_token": s.Token})
	return true
}

type cachedUser struct {
	userID   string
	deviceID string
	expires  time.Time
}

// userOf returns the user of the request's access token, or "".
func (p *Proxy) userOf(r *http.Request) string {
	return p.identityOf(r).userID
}

func (p *Proxy) identityOf(r *http.Request) cachedUser {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		token = r.URL.Query().Get("access_token")
	}
	if token == "" || p.upstream == nil {
		return cachedUser{}
	}
	if c, ok := p.auth.Load(token); ok {
		if time.Now().Before(c.(cachedUser).expires) {
			return c.(cachedUser)
		}
		p.auth.Delete(token)
	}
	who, err := mx.WithToken(p.upstream, token).Whoami(r.Context())
	if err != nil {
		return cachedUser{}
	}
	identity := cachedUser{userID: string(who.UserID), deviceID: string(who.DeviceID), expires: time.Now().Add(authCacheTTL)}
	p.auth.Store(token, identity)
	return identity
}

func (p *Proxy) Close() error {
	err := p.outbox.close()
	if p.inboxLock != nil {
		err = errors.Join(err, p.inboxLock.Close())
	}
	return err
}

func (p *Proxy) authenticated(r *http.Request) bool {
	return p.upstream == nil || p.userOf(r) != ""
}

// shadowBan fakes success for shadow-banned users' writes; true when answered.
func (p *Proxy) shadowBan(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	send := r.Method == http.MethodPut && shadowSend.MatchString(path)
	ignore := (r.Method == http.MethodPost || r.Method == http.MethodPut) && shadowIgnore.MatchString(path)
	create := r.Method == http.MethodPost && createRoom.MatchString(path)
	if !send && !ignore && !create {
		return false
	}
	if !p.shadowBanned[p.userOf(r)] {
		return false
	}
	switch {
	case send:
		writeJSON(w, map[string]string{"event_id": "$" + rand.Text()})
		return true
	case ignore:
		writeJSON(w, struct{}{})
		return true
	}
	// Rooms are created, but nobody is invited.
	body, err := readBody(r)
	var req map[string]json.RawMessage
	if err != nil || json.Unmarshal(body, &req) != nil {
		return false
	}
	delete(req, "invite")
	delete(req, "invite_3pid")
	setJSONBody(r, req)
	return false
}

func (p *Proxy) translateRegistrationToken(r *http.Request) {
	if len(p.regTokens) == 0 {
		return
	}
	if r.Method == http.MethodGet && tokenValidity.MatchString(r.URL.Path) {
		q := r.URL.Query()
		if n, ok := p.regTokens[q.Get("token")]; ok {
			q.Set("token", n)
			r.URL.RawQuery = q.Encode()
		}
		return
	}
	if r.Method != http.MethodPost || !registerPath.MatchString(r.URL.Path) {
		return
	}
	body, err := readBody(r)
	var req map[string]json.RawMessage
	if err != nil || json.Unmarshal(body, &req) != nil {
		return
	}
	var auth map[string]any
	if json.Unmarshal(req["auth"], &auth) != nil || auth["type"] != "m.login.registration_token" {
		return
	}
	if n, ok := p.regTokens[fmt.Sprint(auth["token"])]; ok {
		auth["token"] = n
		req["auth"], _ = json.Marshal(auth)
		setJSONBody(r, req)
	}
}

// oauthRefresh answers refreshes sent to MAS's token endpoint. The refresh
// token is returned unchanged so later refreshes keep working.
func (p *Proxy) oauthRefresh(w http.ResponseWriter, r *http.Request) bool {
	body, err := readBody(r)
	if err != nil {
		return false
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || form.Get("grant_type") != "refresh_token" {
		return false
	}
	s, ok := p.sessions[form.Get("refresh_token")]
	if !ok || !s.OAuth || !s.Refresh {
		return false
	}
	writeJSON(w, map[string]any{
		"access_token":  s.Token,
		"token_type":    "Bearer",
		"refresh_token": form.Get("refresh_token"),
		"expires_in":    int((365 * 24 * time.Hour).Seconds()),
	})
	return true
}

func setJSONBody(r *http.Request, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func serveFile(w http.ResponseWriter, r *http.Request, f mediaFile) {
	file, err := os.Open(f.path)
	if err != nil {
		writeError(w, http.StatusNotFound, "M_NOT_FOUND", "Media not found")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "M_UNKNOWN", "Could not read media")
		return
	}
	setMediaHeaders(w.Header(), f)
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; object-src 'self';")
	http.ServeContent(w, r, "", info.ModTime(), file)
}

func setMediaHeaders(h interface{ Set(string, string) }, f mediaFile) {
	ct := f.contentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	disposition := "attachment"
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") {
		disposition = "inline"
	}
	if f.filename != "" {
		disposition = mime.FormatMediaType(disposition, map[string]string{"filename": f.filename})
	}
	h.Set("Content-Disposition", disposition)
}

// The federation media API returns multipart/mixed: JSON metadata, then content.
func (p *Proxy) serveFederationMedia(w http.ResponseWriter, f mediaFile) {
	file, err := os.Open(f.path)
	if err != nil {
		writeError(w, http.StatusNotFound, "M_NOT_FOUND", "Media not found")
		return
	}
	defer file.Close()
	mw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	meta, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
	if err != nil {
		return
	}
	_, _ = meta.Write([]byte("{}"))
	h := textproto.MIMEHeader{}
	setMediaHeaders(h, f)
	part, err := mw.CreatePart(h)
	if err != nil {
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		return
	}
	_ = mw.Close()
}

// interceptLogin sets the password on Continuwuity when it matches the old hash.
func (p *Proxy) interceptLogin(r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		return
	}
	var req struct {
		Type       string `json:"type"`
		User       string `json:"user"`
		Password   string `json:"password"`
		Identifier struct {
			Type string `json:"type"`
			User string `json:"user"`
		} `json:"identifier"`
	}
	if json.Unmarshal(body, &req) != nil || req.Type != "m.login.password" || req.Password == "" {
		return
	}
	user := req.Identifier.User
	if user == "" {
		user = req.User
	}
	if user == "" {
		return
	}
	if !strings.HasPrefix(user, "@") {
		user = "@" + strings.ToLower(user) + ":" + p.destServer
	}

	p.mu.Lock()
	pending, ok := p.pending[user]
	throttled := time.Since(p.lastLogin[user]) < loginInterval
	if ok {
		p.lastLogin[user] = time.Now()
	}
	p.mu.Unlock()
	if !ok || throttled || !checkPassword(pending, req.Password, p.pepper, p.masSchemes) {
		return
	}

	if err := p.setPassword(r.Context(), user, req.Password); err != nil {
		slog.Error("password migration failed", "user", user, "err", err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, user)
	if err := p.archive.WritePendingPasswords(p.pending); err != nil {
		slog.Error("could not save pending passwords", "err", err)
	}
	slog.Info("migrated password", "user", user)
}

// Uses the user's own session so the password never appears in the admin room.
func (p *Proxy) setPassword(ctx context.Context, userID, password string) error {
	cred, ok := p.creds[userID]
	if !ok {
		return errors.New("no generated credentials for this user")
	}
	c, err := mx.Login(ctx, p.upstream, mx.Localpart(userID), cred.Password)
	if err != nil {
		return fmt.Errorf("log in with the generated password: %w", err)
	}
	defer func() { _, _ = c.Logout(context.WithoutCancel(ctx)) }()

	body := map[string]any{"new_password": password, "logout_devices": false}
	return mx.DoWithPassword(ctx, c, http.MethodPost, c.BuildClientURL("v3", "account", "password"), body, userID, cred.Password)
}

// readBody reads up to maxBody bytes and restores the full body for forwarding.
func readBody(r *http.Request) ([]byte, error) {
	orig := r.Body
	body, err := io.ReadAll(io.LimitReader(orig, maxBody+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), orig), orig}
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, errors.New("body too large")
	}
	return body, nil
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"errcode": code, "error": msg})
}
