// Package relay is a minimal federation server that serves the original
// events of local-only rooms, so Continuwuity can backfill them unchanged.
package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/eventauth"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

const certValidity = 7 * 24 * time.Hour

type Relay struct {
	// Name must be resolvable by Continuwuity.
	Name      string
	key       *federation.SigningKey
	origin    string
	originKey *federation.SigningKey
	// cachedKeys are other servers' key responses, by server name.
	cachedKeys map[string][]json.RawMessage
	// peer is the only server allowed to make federation requests.
	peer   string
	auth   *federation.ServerAuth
	sender *federation.Client
	remote *federation.Client

	mu    sync.Mutex
	rooms map[string]*room
	srv   *http.Server
}

func New(name, origin string, originKey *federation.SigningKey, cachedKeys map[string][]json.RawMessage) *Relay {
	key := federation.GenerateSigningKey()
	// Matrix signing key versions allow alphanumeric characters and underscores.
	key.ID = id.NewKeyID(id.KeyAlgorithmEd25519, rand.Text())
	return &Relay{
		Name: name, key: key, origin: origin, originKey: originKey,
		cachedKeys: cachedKeys, rooms: map[string]*room{},
		remote: federation.NewClient(name, key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings),
	}
}

// Trust restricts federation requests to peer, whose key is fetched from keyURL.
func (rl *Relay) Trust(ctx context.Context, peer, keyURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch the keys of %s: %w", peer, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch the keys of %s: HTTP %d", peer, resp.StatusCode)
	}
	var keys federation.ServerKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return fmt.Errorf("keys of %s: %w", peer, err)
	}
	if keys.ServerName != peer {
		return fmt.Errorf("%s serves the keys of %s", keyURL, keys.ServerName)
	}
	if err := keys.VerifySelfSignature(); err != nil {
		return fmt.Errorf("keys of %s: %w", peer, err)
	}
	cache := federation.NewInMemoryCache()
	cache.StoreKeys(&keys)
	client := federation.NewClient(rl.Name, rl.key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
	client.HTTP.Transport = peerTransport{peer: peer, scheme: req.URL.Scheme, host: req.URL.Host}
	rl.peer = peer
	rl.auth = federation.NewServerAuth(client, cache, func(federation.XMatrixAuth) string { return rl.Name })
	rl.sender = client
	return nil
}

// peerTransport sends signed requests to the destination URL already verified by Trust.
type peerTransport struct{ peer, scheme, host string }

func (t peerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "matrix-federation" || req.URL.Host != t.peer {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("relay request is not addressed to its destination")
	}
	forward := req.Clone(req.Context())
	target := *req.URL
	target.Scheme, target.Host = t.scheme, t.host
	forward.URL, forward.Host = &target, t.host
	return http.DefaultTransport.RoundTrip(forward)
}

func (rl *Relay) UserID() string { return "@exodus:" + rl.Name }

func (rl *Relay) AddRoom(roomID, version string, data RoomData) error {
	r, err := newRoom(roomID, version, data)
	if err != nil {
		return err
	}
	rl.mu.Lock()
	rl.rooms[roomID] = r
	rl.mu.Unlock()
	return nil
}

// AddRoomFile loads a room archived as RoomData JSON, keeping archived event
// bodies in the file until they are served. RemoveRoom closes the file.
func (rl *Relay) AddRoomFile(roomID, version, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	r, err := readRoomFile(roomID, version, f)
	if err != nil {
		f.Close()
		return err
	}
	rl.mu.Lock()
	rl.rooms[roomID] = r
	rl.mu.Unlock()
	return nil
}

// OfferEvents makes the next backfills of the room return these archived
// events, which Continuwuity places before its earliest event in the timeline.
func (rl *Relay) OfferEvents(roomID string, eventIDs []string) {
	r := rl.room(roomID)
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offered = map[string]bool{}
	for _, eventID := range eventIDs {
		if _, ok := r.events[eventID]; ok {
			r.offered[eventID] = true
		}
	}
}

// RemoveRoom releases the room after an import attempt.
func (rl *Relay) RemoveRoom(roomID string) {
	rl.mu.Lock()
	r := rl.rooms[roomID]
	delete(rl.rooms, roomID)
	rl.mu.Unlock()
	if r != nil && r.source != nil {
		r.mu.Lock()
		r.source.Close()
		r.mu.Unlock()
	}
}

// Enter joins the relay through a source member's invitation or a permitted public join.
func (rl *Relay) Enter(roomID, inviter string) error {
	r := rl.room(roomID)
	if r == nil {
		return fmt.Errorf("unknown room %s", roomID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := rl.checkEnter(r, inviter)
	if err != nil || entry == nil {
		return err
	}
	if entry.Sender == id.UserID(rl.UserID()) {
		return r.sign(entry, rl.Name, rl.key)
	}
	if err := r.sign(entry, rl.origin, rl.originKey); err != nil {
		return err
	}
	join, err := r.template(rl.UserID(), "m.room.member", rl.UserID(), map[string]string{"membership": "join"}, rl.Name)
	if err != nil {
		return err
	}
	if err := authorizeEvent(r, join); err != nil {
		return err
	}
	return r.sign(join, rl.Name, rl.key)
}

// CheckEnter checks room admission without changing the room.
func (rl *Relay) CheckEnter(roomID, inviter string) error {
	r := rl.room(roomID)
	if r == nil {
		return fmt.Errorf("unknown room %s", roomID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := rl.checkEnter(r, inviter)
	return err
}

func (rl *Relay) checkEnter(r *room, inviter string) (*pdu.PDU, error) {
	if ev, ok := r.events[r.current[StateKey("m.room.member", rl.UserID())]]; ok {
		var member struct {
			Content struct{ Membership string } `json:"content"`
		}
		raw, err := r.eventJSON(ev)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &member); err != nil {
			return nil, err
		}
		if member.Content.Membership == "join" {
			return nil, nil
		}
	}
	if ev, ok := r.events[r.current[StateKey("m.room.create", "")]]; ok {
		var create struct {
			Content struct {
				Federate *bool `json:"m.federate"`
			} `json:"content"`
		}
		raw, err := r.eventJSON(ev)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &create); err != nil {
			return nil, err
		}
		if create.Content.Federate != nil && !*create.Content.Federate {
			return nil, errors.New("room disables federation; the relay cannot join")
		}
	}
	invite, err := rl.checkedEvent(r, inviter, "m.room.member", rl.UserID(), map[string]string{"membership": "invite"})
	if err == nil {
		return invite, nil
	}
	// A public room may allow joining even when this member cannot invite.
	join, joinErr := r.template(rl.UserID(), "m.room.member", rl.UserID(), map[string]string{"membership": "join"}, rl.Name)
	if joinErr == nil && authorizeEvent(r, join) == nil {
		return join, nil
	}
	return nil, err
}

// Leave sends the relay's own signed leave, without requiring a local member to kick it.
// CheckAuthor checks a source member's state event without changing the room.
func (rl *Relay) CheckAuthor(roomID, sender, typ, stateKey string, content any) error {
	r := rl.room(roomID)
	if r == nil {
		return fmt.Errorf("unknown room %s", roomID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := rl.checkedEvent(r, sender, typ, stateKey, content)
	return err
}

// Author adds a state event from a source member, signed with the source key.
func (rl *Relay) Author(roomID, sender, typ, stateKey string, content any) error {
	r := rl.room(roomID)
	if r == nil {
		return fmt.Errorf("unknown room %s", roomID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := rl.checkedEvent(r, sender, typ, stateKey, content)
	if err != nil {
		return err
	}
	return r.sign(p, rl.origin, rl.originKey)
}

func (rl *Relay) checkedEvent(r *room, sender, typ, stateKey string, content any) (*pdu.PDU, error) {
	if id.UserID(sender).Homeserver() != rl.origin {
		return nil, fmt.Errorf("cannot author an event as %s with the source signing key", sender)
	}
	p, err := r.template(sender, typ, stateKey, content, rl.origin)
	if err != nil {
		return nil, err
	}
	if err := authorizeEvent(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func authorizeEvent(r *room, p *pdu.PDU) error {
	getEvents := func(ids []id.EventID) ([]*pdu.PDU, error) {
		out := make([]*pdu.PDU, len(ids))
		for i, eventID := range ids {
			stored, ok := r.events[string(eventID)]
			if !ok {
				return nil, fmt.Errorf("missing auth event %s", eventID)
			}
			raw, err := r.eventJSON(stored)
			if err != nil {
				return nil, err
			}
			parsed, err := ParsePDU(raw)
			if err != nil {
				return nil, err
			}
			out[i] = parsed
		}
		return out, nil
	}
	if err := eventauth.Authorize(r.version, p, nil, getEvents, nil); err != nil {
		return fmt.Errorf("%s from %s is not authorized: %w", p.Type, p.Sender, err)
	}
	return nil
}

func (rl *Relay) Content(roomID, typ, stateKey string) map[string]any {
	r := rl.room(roomID)
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ev, ok := r.events[r.current[StateKey(typ, stateKey)]]
	if !ok {
		return nil
	}
	var stored struct {
		Content map[string]any `json:"content"`
	}
	raw, err := r.eventJSON(ev)
	if err != nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&stored) != nil {
		return nil
	}
	return stored.Content
}

func (rl *Relay) room(roomID string) *room {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.rooms[roomID]
}

// Start serves federation over TLS, self-signed when no certificate is given.
func (rl *Relay) Start(addr, certFile, keyFile string) error {
	if rl.auth == nil {
		return errors.New("relay: Trust must be called before Start")
	}
	var cert tls.Certificate
	var err error
	if certFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	} else {
		cert, err = selfSigned(rl.Name)
	}
	if err != nil {
		return err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	// No write timeout: backfill and state responses can be large.
	rl.srv = &http.Server{Handler: rl.handler(), ReadHeaderTimeout: 30 * time.Second, ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	go func() {
		if err := rl.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("relay stopped", "err", err)
		}
	}()
	slog.Info("relay listening", "addr", addr, "server_name", rl.Name, "peer", rl.peer)
	return nil
}

func (rl *Relay) Stop(ctx context.Context) error {
	if rl.srv == nil {
		return nil
	}
	return rl.srv.Shutdown(ctx)
}

func selfSigned(name string) (tls.Certificate, error) {
	host, _, err := net.SplitHostPort(name)
	if err != nil {
		host = name
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certValidity),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func (rl *Relay) handler() http.Handler {
	keys := &federation.KeyServer{
		KeyProvider: &federation.StaticServerKey{ServerName: rl.Name, Key: rl.key},
		Version:     federation.ServerVersion{Name: "exodus relay", Version: "1"},
		OtherKeys:   notaryKeys{rl},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_matrix/federation/v1/version", keys.GetServerVersion)
	mux.HandleFunc("GET /_matrix/key/v2/server", rl.serverKeys)
	mux.HandleFunc("GET /_matrix/key/v2/query/{serverName}", rl.queryKeys)
	mux.HandleFunc("POST /_matrix/key/v2/query", rl.postKeyResponses)

	fed := http.NewServeMux()
	fed.HandleFunc("GET /_matrix/federation/v1/make_join/{roomID}/{userID}", rl.makeJoin)
	fed.HandleFunc("PUT /_matrix/federation/v2/send_join/{roomID}/{eventID}", rl.sendJoin)
	fed.HandleFunc("PUT /_matrix/federation/v2/invite/{roomID}/{eventID}", rl.invite)
	fed.HandleFunc("GET /_matrix/federation/v1/backfill/{roomID}", rl.backfill)
	fed.HandleFunc("GET /_matrix/federation/v1/event/{eventID}", rl.event)
	fed.HandleFunc("GET /_matrix/federation/v1/state_ids/{roomID}", rl.stateIDs)
	fed.HandleFunc("GET /_matrix/federation/v1/state/{roomID}", rl.state)
	fed.HandleFunc("GET /_matrix/federation/v1/event_auth/{roomID}/{eventID}", rl.eventAuth)
	fed.HandleFunc("POST /_matrix/federation/v1/get_missing_events/{roomID}", rl.missingEvents)
	fed.HandleFunc("PUT /_matrix/federation/v1/send/{txnID}", rl.receive)
	fed.HandleFunc("POST /_matrix/federation/v1/user/keys/query", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"device_keys": map[string]any{}})
	})
	fed.HandleFunc("POST /_matrix/federation/v1/user/keys/claim", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"one_time_keys": map[string]any{}})
	})
	fed.HandleFunc("GET /_matrix/federation/v1/user/devices/{userID}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"user_id": r.PathValue("userID"), "stream_id": 0, "devices": []any{}})
	})
	fed.HandleFunc("GET /_matrix/federation/v1/query/profile", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"displayname": "exodus"})
	})
	mux.Handle("/_matrix/federation/", rl.auth.AuthenticateMiddleware(rl.onlyPeer(fed)))
	return mux
}

// onlyPeer rejects other servers: the relay serves private room history.
func (rl *Relay) onlyPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := federation.OriginServerName(r.Context()); origin != rl.peer {
			mautrix.MForbidden.WithMessage("%s may not use this server", origin).Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// notaryKeys serves the source key and the keys the source had cached.
type notaryKeys struct{ rl *Relay }

func (n notaryKeys) LoadKeys(serverName string) (*federation.ServerKeyResponse, error) {
	if serverName == n.rl.origin {
		return n.rl.sourceKeys()
	}
	var latest *federation.ServerKeyResponse
	for _, raw := range n.rl.cachedKeys[serverName] {
		var k federation.ServerKeyResponse
		if json.Unmarshal(raw, &k) == nil && (latest == nil || k.ValidUntilTS.After(latest.ValidUntilTS.Time)) {
			latest = &k
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no keys for %s", serverName)
	}
	if latest.Signatures == nil {
		latest.Signatures = map[string]map[id.KeyID]string{}
	}
	return latest, nil
}

func (rl *Relay) sourceKeys() (*federation.ServerKeyResponse, error) {
	old := map[id.KeyID]federation.OldVerifyKey{}
	retired := map[id.KeyID]bool{}
	var cached []federation.ServerKeyResponse
	for _, raw := range rl.cachedKeys[rl.origin] {
		var keys federation.ServerKeyResponse
		if err := json.Unmarshal(raw, &keys); err != nil {
			return nil, fmt.Errorf("archived source signing keys: %w", err)
		}
		if keys.ServerName != rl.origin {
			return nil, fmt.Errorf("archived source signing keys belong to %s", keys.ServerName)
		}
		cached = append(cached, keys)
		for keyID, key := range keys.OldVerifyKeys {
			retired[keyID] = true
			if previous, ok := old[keyID]; ok {
				if previous.Key != key.Key {
					return nil, fmt.Errorf("conflicting archived source signing key %s", keyID)
				}
				if !key.ExpiredTS.After(previous.ExpiredTS.Time) {
					continue
				}
			}
			old[keyID] = key
		}
	}
	for _, keys := range cached {
		for keyID, key := range keys.VerifyKeys {
			if previous, ok := old[keyID]; ok {
				if previous.Key != key.Key {
					return nil, fmt.Errorf("conflicting archived source signing key %s", keyID)
				}
				if retired[keyID] || !keys.ValidUntilTS.After(previous.ExpiredTS.Time) {
					continue
				}
			}
			old[keyID] = federation.OldVerifyKey{Key: key.Key, ExpiredTS: keys.ValidUntilTS}
		}
	}
	if key, ok := old[rl.originKey.ID]; ok && key.Key != rl.originKey.Pub {
		return nil, fmt.Errorf("archived source signing key %s conflicts with the current key", rl.originKey.ID)
	}
	delete(old, rl.originKey.ID)
	return rl.originKey.GenerateKeyResponse(rl.origin, old), nil
}

func (notaryKeys) StoreKeys(*federation.ServerKeyResponse) {}
func (notaryKeys) StoreFetchError(string, error)           {}
func (notaryKeys) ShouldReQuery(string) bool               { return false }

func (rl *Relay) withRoom(w http.ResponseWriter, r *http.Request, fn func(*room) (any, error)) {
	rm := rl.room(r.PathValue("roomID"))
	if rm == nil {
		mautrix.MNotFound.WithMessage("Unknown room").Write(w)
		return
	}
	rm.mu.Lock()
	resp, err := fn(rm)
	rm.mu.Unlock()
	if err != nil {
		mautrix.MUnknown.WithMessage("%v", err).Write(w)
		return
	}
	writeJSON(w, resp)
}

func toEventIDs(ids []string) []id.EventID {
	out := make([]id.EventID, len(ids))
	for i, e := range ids {
		out[i] = id.EventID(e)
	}
	return out
}

func (rl *Relay) makeJoin(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	rl.withRoom(w, r, func(rm *room) (any, error) {
		origin := id.UserID(userID).Homeserver()
		p, err := rm.template(userID, "m.room.member", userID, map[string]string{"membership": "join"}, origin)
		if err != nil {
			return nil, err
		}
		raw, err := jsonv2.Marshal(p)
		if err != nil {
			return nil, err
		}
		return federation.RespMakeJoin{RoomVersion: rm.version, Event: raw}, nil
	})
}

func (rl *Relay) sendJoin(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	p, err := ParsePDU(raw)
	if err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	eventID := r.PathValue("eventID")
	rl.withRoom(w, r, func(rm *room) (any, error) {
		state := stateIDs(rm.current)
		auth := make([]string, 0, len(p.AuthEvents))
		for _, a := range p.AuthEvents {
			auth = append(auth, string(a))
		}
		statePDUs, err := rm.pdus(state)
		if err != nil {
			return nil, err
		}
		chainPDUs, err := rm.pdus(rm.authChain(append(state, auth...)))
		if err != nil {
			return nil, err
		}
		rm.add(eventID, p, raw)
		return federation.RespSendJoin{
			State:         statePDUs,
			AuthChain:     chainPDUs,
			Event:         raw,
			ServersInRoom: []string{rl.Name},
		}, nil
	})
}

func (rl *Relay) backfill(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	from := r.URL.Query()["v"]
	rl.withRoom(w, r, func(rm *room) (any, error) {
		pdus, err := rm.pdus(rm.backfill(from, max(limit, 1)))
		if err != nil {
			return nil, err
		}
		return federation.RespBackfill{Origin: rl.Name, OriginServerTS: jsontime.UnixMilliNow(), PDUs: pdus}, nil
	})
}

func (rl *Relay) event(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventID")
	rl.mu.Lock()
	rooms := make([]*room, 0, len(rl.rooms))
	for _, rm := range rl.rooms {
		rooms = append(rooms, rm)
	}
	rl.mu.Unlock()
	for _, rm := range rooms {
		rm.mu.Lock()
		ev, ok := rm.events[eventID]
		var raw json.RawMessage
		var err error
		if ok {
			raw, err = rm.eventJSON(ev)
		}
		rm.mu.Unlock()
		if err != nil {
			mautrix.MUnknown.WithMessage("%v", err).Write(w)
			return
		}
		if ok {
			writeJSON(w, federation.RespBackfill{Origin: rl.Name, OriginServerTS: jsontime.UnixMilliNow(), PDUs: []federation.PDU{federation.PDU(raw)}})
			return
		}
	}
	mautrix.MNotFound.WithMessage("Unknown event").Write(w)
}

func (rl *Relay) stateIDs(w http.ResponseWriter, r *http.Request) {
	eventID := r.URL.Query().Get("event_id")
	rl.withRoom(w, r, func(rm *room) (any, error) {
		before, err := rm.stateBefore(eventID)
		if err != nil {
			return nil, err
		}
		state := stateIDs(before)
		return federation.RespGetStateIDs{PDUs: toEventIDs(state), AuthChain: toEventIDs(rm.authChain(state))}, nil
	})
}

func (rl *Relay) state(w http.ResponseWriter, r *http.Request) {
	eventID := r.URL.Query().Get("event_id")
	rl.withRoom(w, r, func(rm *room) (any, error) {
		before, err := rm.stateBefore(eventID)
		if err != nil {
			return nil, err
		}
		state := stateIDs(before)
		statePDUs, err := rm.pdus(state)
		if err != nil {
			return nil, err
		}
		chainPDUs, err := rm.pdus(rm.authChain(state))
		if err != nil {
			return nil, err
		}
		return federation.RespGetState{PDUs: statePDUs, AuthChain: chainPDUs}, nil
	})
}

func (rl *Relay) eventAuth(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventID")
	rl.withRoom(w, r, func(rm *room) (any, error) {
		chain, err := rm.pdus(rm.authChain([]string{eventID}))
		if err != nil {
			return nil, err
		}
		return federation.RespGetEventAuthChain{AuthChain: chain}, nil
	})
}

func (rl *Relay) missingEvents(w http.ResponseWriter, r *http.Request) {
	var req federation.ReqGetMissingEvents
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	rl.withRoom(w, r, func(rm *room) (any, error) {
		stop := map[string]bool{}
		for _, e := range req.EarliestEvents {
			stop[string(e)] = true
		}
		var from []string
		for _, l := range req.LatestEvents {
			if ev, ok := rm.events[string(l)]; ok {
				for _, p := range ev.meta.PrevEvents {
					from = append(from, string(p))
				}
			}
		}
		ids := rm.before(from, max(req.Limit, 10), func(eventID string) bool { return stop[eventID] })
		slices.Reverse(ids)
		events, err := rm.pdus(ids)
		if err != nil {
			return nil, err
		}
		return federation.RespGetMissingEvents{Events: events}, nil
	})
}

// receive keeps the relay's view of the room current.
func (rl *Relay) receive(w http.ResponseWriter, r *http.Request) {
	var txn federation.ReqSendTransaction
	if err := json.NewDecoder(r.Body).Decode(&txn); err != nil {
		mautrix.MBadJSON.WithMessage("%v", err).Write(w)
		return
	}
	results := map[id.EventID]federation.PDUProcessingResult{}
	for _, raw := range txn.PDUs {
		p, err := ParsePDU(raw)
		if err != nil {
			continue
		}
		rm := rl.room(string(p.RoomID))
		if rm == nil {
			continue
		}
		rm.mu.Lock()
		if eventID, err := EventID(p, rm.version); err == nil {
			rm.add(string(eventID), p, json.RawMessage(raw))
			results[eventID] = federation.PDUProcessingResult{}
		}
		rm.mu.Unlock()
	}
	writeJSON(w, map[string]any{"pdus": results})
}

func writeJSON(w http.ResponseWriter, v any) {
	if e, ok := v.(mautrix.RespError); ok {
		e.Write(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err := jsonv2.MarshalWrite(w, v, json.DefaultOptionsV1())
	if err == nil {
		_, err = io.WriteString(w, "\n")
	}
	if err != nil {
		slog.Warn("relay response failed", "err", err)
	}
}
