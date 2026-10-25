package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

const inboxTokenPrefix = "exodus-inbox-v1."
const inboxBatchSize = 100
const maxSyncRequestBody = 2 << 20

var classicSyncPath = regexp.MustCompile(`^/_matrix/client/(?:r0|v3)/sync$`)
var slidingSyncPath = regexp.MustCompile(`^/_matrix/client/(?:v[45]|unstable/org\.matrix\.(?:simplified_)?msc3575)/sync$`)
var errInboxStorage = errors.New("could not save migration inbox")

type deviceInbox struct {
	mu                   sync.Mutex
	user, device, digest string
	messages             []archive.ToDevice
	state                *archive.ProxyInboxState
}

type inboxContextKey struct{}
type inboxSync struct {
	inbox    *deviceInbox
	end      int
	secret   []byte
	messages []archive.ToDevice
	sliding  bool
}

func inboxIdentity(user, device string) string { return user + "\x00" + device }

func (p *Proxy) loadInboxes(messages []archive.ToDevice) error {
	p.inboxes = map[string]*deviceInbox{}
	for _, m := range messages {
		if mx.ServerName(m.Sender) == p.serverName {
			continue
		}
		if err := archive.ValidateProxyInboxMessage(m, p.serverName); err != nil {
			return err
		}
		key := inboxIdentity(m.Recipient, m.DeviceID)
		box := p.inboxes[key]
		if box == nil {
			box = &deviceInbox{user: m.Recipient, device: m.DeviceID}
			p.inboxes[key] = box
		}
		box.messages = append(box.messages, m)
	}
	if len(p.inboxes) == 0 {
		return nil
	}
	lock, err := p.archive.LockProxyInbox()
	if err != nil {
		return err
	}
	for _, box := range p.inboxes {
		h := sha256.New()
		enc := json.NewEncoder(h)
		for _, m := range box.messages {
			if err := enc.Encode(m); err != nil {
				lock.Close()
				return err
			}
		}
		box.digest = hex.EncodeToString(h.Sum(nil))
		state, err := p.archive.ReadProxyInboxState(box.user, box.device)
		if err != nil {
			lock.Close()
			return err
		}
		if state != nil && (state.Digest != box.digest || len(state.Secret) != 32 || state.Acknowledged < 0 || state.Acknowledged > len(box.messages)) {
			lock.Close()
			return errors.New("proxy inbox state does not match archived messages")
		}
		box.state = state
	}
	p.inboxLock = lock
	slog.Info("queued device messages ready", "devices", len(p.inboxes))
	return nil
}

func (b *deviceInbox) sync(p *Proxy, sliding bool, tokens map[string]string, enabled bool) (map[string]string, *inboxSync, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == nil {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, nil, err
		}
		state := &archive.ProxyInboxState{UserID: b.user, DeviceID: b.device, Digest: b.digest, Secret: secret}
		if err := p.archive.WriteProxyInboxState(state); err != nil {
			return nil, nil, errors.Join(errInboxStorage, err)
		}
		b.state = state
	}
	ack := b.state.Acknowledged
	for kind, token := range tokens {
		if !strings.HasPrefix(token, inboxTokenPrefix) {
			continue
		}
		end, native, err := decodeInboxToken(b.state.Secret, kind, token)
		if err != nil || end < 0 || end > len(b.messages) {
			return nil, nil, errors.New("invalid migration sync token for this device")
		}
		tokens[kind] = native
		ack = max(ack, end)
	}
	if ack != b.state.Acknowledged {
		state := *b.state
		state.Acknowledged = ack
		if err := p.archive.WriteProxyInboxState(&state); err != nil {
			return nil, nil, errors.Join(errInboxStorage, err)
		}
		b.state = &state
		slog.Info("queued device messages acknowledged", "user", b.user, "device", b.device, "acknowledged", ack, "remaining", len(b.messages)-ack)
	}
	if !enabled || ack == len(b.messages) {
		return tokens, nil, nil
	}
	end := min(ack+inboxBatchSize, len(b.messages))
	return tokens, &inboxSync{inbox: b, end: end, secret: b.state.Secret, messages: b.messages[ack:end], sliding: sliding}, nil
}

func encodeInboxToken(secret []byte, kind string, end int, native string) string {
	value := strconv.Itoa(end) + "." + base64.RawURLEncoding.EncodeToString([]byte(native))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(kind + "\x00" + value))
	return inboxTokenPrefix + value + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func decodeInboxToken(secret []byte, kind, token string) (int, string, error) {
	parts := strings.Split(strings.TrimPrefix(token, inboxTokenPrefix), ".")
	if len(parts) != 3 {
		return 0, "", errors.New("invalid sync token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(kind + "\x00" + parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return 0, "", errors.New("invalid sync token signature")
	}
	end, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", err
	}
	native, err := base64.RawURLEncoding.DecodeString(parts[1])
	return end, string(native), err
}

func (p *Proxy) inboxRequest(r *http.Request) (*http.Request, error) {
	classic := r.Method == http.MethodGet && classicSyncPath.MatchString(r.URL.Path)
	sliding := r.Method == http.MethodPost && slidingSyncPath.MatchString(r.URL.Path)
	if len(p.inboxes) == 0 || (!classic && !sliding) {
		return r, nil
	}
	identity := p.identityOf(r)
	box := p.inboxes[inboxIdentity(identity.userID, identity.deviceID)]
	if box == nil {
		for _, key := range []string{"since", "pos"} {
			if strings.HasPrefix(r.URL.Query().Get(key), inboxTokenPrefix) {
				return r, errors.New("migration sync token belongs to another device")
			}
		}
		return r, nil
	}
	query := r.URL.Query()
	key := "since"
	if sliding {
		key = "pos"
	}
	tokens := map[string]string{key: query.Get(key)}
	var body map[string]json.RawMessage
	var extensions map[string]json.RawMessage
	var toDevice map[string]json.RawMessage
	enabled := true
	if sliding {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxSyncRequestBody+1))
		r.Body.Close()
		if err != nil {
			return r, err
		}
		if len(raw) > maxSyncRequestBody {
			return r, errors.New("sliding sync request exceeds migration inbox limit")
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return r, err
		}
		if body == nil {
			return r, errors.New("sliding sync request must be an object")
		}
		if raw := body["extensions"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &extensions); err != nil {
				return r, err
			}
		}
		if raw := extensions["to_device"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &toDevice); err != nil {
				return r, err
			}
		}
		var on *bool
		if err := json.Unmarshal(toDevice["enabled"], &on); err != nil && len(toDevice["enabled"]) > 0 {
			return r, err
		}
		enabled = on != nil && *on
		if len(toDevice["since"]) > 0 {
			var since string
			if err := json.Unmarshal(toDevice["since"], &since); err != nil {
				return r, err
			}
			tokens["device"] = since
		}
		if on == nil && (strings.HasPrefix(tokens["pos"], inboxTokenPrefix) || strings.HasPrefix(tokens["device"], inboxTokenPrefix)) {
			enabled = true
		}
	}
	tokens, batch, err := box.sync(p, sliding, tokens, enabled)
	if err != nil {
		return r, err
	}
	if query.Has(key) {
		query.Set(key, tokens[key])
	}
	if batch != nil {
		query.Set("timeout", "0")
		r.Header.Set("Accept-Encoding", "identity")
		r = r.WithContext(context.WithValue(r.Context(), inboxContextKey{}, batch))
	}
	r.URL.RawQuery = query.Encode()
	if sliding {
		if _, ok := tokens["device"]; ok {
			toDevice["since"], err = json.Marshal(tokens["device"])
			if err != nil {
				return r, err
			}
			extensions["to_device"], err = json.Marshal(toDevice)
			if err != nil {
				return r, err
			}
			body["extensions"], err = json.Marshal(extensions)
			if err != nil {
				return r, err
			}
		}
		setJSONBody(r, body)
	}
	return r, nil
}

func (p *Proxy) inboxResponse(resp *http.Response) error {
	batch, _ := resp.Request.Context().Value(inboxContextKey{}).(*inboxSync)
	if batch == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return fmt.Errorf("unexpected sync content encoding %q", encoding)
	}
	body := resp.Body
	rd, wr := io.Pipe()
	resp.Body = &inboxResponseBody{PipeReader: rd, upstream: body}
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("ETag")
	go func() {
		defer body.Close()
		err := rewriteInboxSync(wr, body, batch)
		if err != nil {
			slog.Warn("could not attach queued device messages", "user", batch.inbox.user, "device", batch.inbox.device, "err", err)
		}
		wr.CloseWithError(err)
	}()
	return nil
}

type inboxResponseBody struct {
	*io.PipeReader
	upstream io.ReadCloser
}

func (b *inboxResponseBody) Close() error {
	return errors.Join(b.PipeReader.Close(), b.upstream.Close())
}
