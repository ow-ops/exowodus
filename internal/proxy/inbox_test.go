package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"exowodus/internal/archive"
)

type inboxEvent struct {
	Sender  string          `json:"sender"`
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type inboxReply struct {
	NextBatch string `json:"next_batch"`
	Pos       string `json:"pos"`
	ToDevice  struct {
		Events []inboxEvent `json:"events"`
	} `json:"to_device"`
	Extensions struct {
		ToDevice struct {
			NextBatch string       `json:"next_batch"`
			Events    []inboxEvent `json:"events"`
		} `json:"to_device"`
	} `json:"extensions"`
}

func inboxArchive(t *testing.T, count int) *archive.Archive {
	t.Helper()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	var messages []archive.ToDevice
	for i := range count {
		messages = append(messages, archive.ToDevice{
			Key: fmt.Sprint(i), Sender: "@remote:other.org", Recipient: "@alice:example.org", DeviceID: "PHONE", Type: "m.room.encrypted",
			Content: json.RawMessage(fmt.Sprintf(`{"ciphertext":"encrypted-%d","number":9007199254740993}`, i)),
		})
	}
	if err := a.WriteServer(&archive.Server{ToDevice: messages}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSessions(map[string]archive.Session{"old-phone": {UserID: "@alice:example.org", DeviceID: "PHONE", Token: "phone"}}); err != nil {
		t.Fatal(err)
	}
	return a
}

func inboxUpstream(t *testing.T, serveSync http.HandlerFunc) *url.URL {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/_matrix/client/v3/account/whoami" {
			user, device := "@alice:example.org", "PHONE"
			switch r.Header.Get("Authorization") {
			case "Bearer phone":
			case "Bearer tablet":
				device = "TABLET"
			case "Bearer bob":
				user = "@bob:example.org"
			default:
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"user_id": user, "device_id": device})
			return
		}
		serveSync(w, r)
	}))
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func openInboxProxy(t *testing.T, a *archive.Archive, upstream *url.URL) *Proxy {
	t.Helper()
	p, err := New(a, upstream, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func requestInbox(t *testing.T, p *Proxy, token, path, body string) (int, inboxReply) {
	t.Helper()
	method := http.MethodGet
	if body != "" {
		method = http.MethodPost
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	var reply inboxReply
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, reply
}

func TestProxyInboxAcknowledgementAndRestart(t *testing.T) {
	a := inboxArchive(t, 102)
	upstream := inboxUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if since := r.URL.Query().Get("since"); since != "" && since != "native" {
			t.Errorf("upstream received wrapped cursor: %q", since)
		}
		_, _ = io.WriteString(w, `{"next_batch":"native","rooms":{"join":{}},"to_device":{"events":[{"sender":"@new:example.org","type":"new","content":{}}]}}`)
	})
	p := openInboxProxy(t, a, upstream)
	for _, token := range []string{"tablet", "bob", "invalid"} {
		_, reply := requestInbox(t, p, token, "/_matrix/client/v3/sync", "")
		if len(reply.ToDevice.Events) > 1 || strings.HasPrefix(reply.NextBatch, inboxTokenPrefix) {
			t.Fatalf("queued messages exposed to %s", token)
		}
	}
	status, first := requestInbox(t, p, "old-phone", "/_matrix/client/v3/sync?timeout=30000", "")
	if status != 200 || len(first.ToDevice.Events) != 101 || !strings.HasPrefix(first.NextBatch, inboxTokenPrefix) {
		t.Fatalf("first batch: status=%d events=%d", status, len(first.ToDevice.Events))
	}
	m := first.ToDevice.Events[1]
	if m.Sender != "@remote:other.org" || m.Type != "m.room.encrypted" || string(m.Content) != `{"ciphertext":"encrypted-0","number":9007199254740993}` {
		t.Fatalf("archived event changed: %+v", m)
	}
	_, retry := requestInbox(t, p, "phone", "/_matrix/client/v3/sync", "")
	if retry.NextBatch != first.NextBatch || len(retry.ToDevice.Events) != 101 {
		t.Fatal("unacknowledged batch was lost")
	}
	for _, token := range []string{"tablet", "bob"} {
		status, _ := requestInbox(t, p, token, "/_matrix/client/v3/sync?since="+url.QueryEscape(first.NextBatch), "")
		if status != http.StatusBadRequest {
			t.Fatal("another device accepted a cursor")
		}
	}
	status, _ = requestInbox(t, p, "phone", "/_matrix/client/v3/sync?since="+url.QueryEscape(first.NextBatch+"x"), "")
	if status != http.StatusBadRequest {
		t.Fatal("tampered cursor accepted")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p = openInboxProxy(t, a, upstream)
	_, retry = requestInbox(t, p, "phone", "/_matrix/client/v3/sync", "")
	if retry.NextBatch != first.NextBatch {
		t.Fatal("restart changed an unacknowledged cursor")
	}
	_, second := requestInbox(t, p, "phone", "/_matrix/client/v3/sync?since="+url.QueryEscape(first.NextBatch), "")
	if len(second.ToDevice.Events) != 3 || !strings.Contains(string(second.ToDevice.Events[1].Content), "encrypted-100") {
		t.Fatal("acknowledgement did not advance the batch")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p = openInboxProxy(t, a, upstream)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			r := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/sync?since="+url.QueryEscape(second.NextBatch), nil)
			r.Header.Set("Authorization", "Bearer phone")
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			var last inboxReply
			if json.Unmarshal(w.Body.Bytes(), &last) != nil || w.Code != 200 || len(last.ToDevice.Events) != 1 || last.NextBatch != "native" {
				t.Error("completed queue was delivered again")
			}
		})
	}
	wg.Wait()
	state, err := a.ReadProxyInboxState("@alice:example.org", "PHONE")
	if err != nil || state.Acknowledged != 102 {
		t.Fatalf("acknowledgement not persisted: %+v %v", state, err)
	}
	_, last := requestInbox(t, p, "phone", "/_matrix/client/v3/sync?since="+url.QueryEscape(first.NextBatch), "")
	if len(last.ToDevice.Events) != 1 {
		t.Fatal("old cursor rewound acknowledged messages")
	}
}

func TestProxyInboxSlidingSync(t *testing.T) {
	a := inboxArchive(t, 101)
	upstream := inboxUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if pos := r.URL.Query().Get("pos"); pos != "" && pos != "42" {
			t.Errorf("upstream received wrapped pos %q", pos)
		}
		raw, _ := io.ReadAll(r.Body)
		if bytes.Contains(raw, []byte(inboxTokenPrefix)) {
			t.Error("upstream received wrapped to-device cursor")
		}
		_, _ = io.WriteString(w, `{"pos":"42","lists":{},"extensions":{"to_device":{"next_batch":"43","events":[]}}}`)
	})
	p := openInboxProxy(t, a, upstream)
	const path = "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"
	_, disabled := requestInbox(t, p, "phone", path, `{"extensions":{"to_device":{"enabled":false}}}`)
	if disabled.Pos != "42" || len(disabled.Extensions.ToDevice.Events) != 0 {
		t.Fatal("disabled extension delivered messages")
	}
	_, first := requestInbox(t, p, "phone", path, `{"extensions":{"to_device":{"enabled":true}}}`)
	if len(first.Extensions.ToDevice.Events) != 100 || !strings.HasPrefix(first.Pos, inboxTokenPrefix) || !strings.HasPrefix(first.Extensions.ToDevice.NextBatch, inboxTokenPrefix) {
		t.Fatal("sliding sync did not wrap both cursors")
	}
	body := fmt.Sprintf(`{"extensions":{"to_device":{"since":%q}}}`, first.Extensions.ToDevice.NextBatch)
	_, second := requestInbox(t, p, "phone", path+"?pos="+url.QueryEscape(first.Pos), body)
	if len(second.Extensions.ToDevice.Events) != 1 {
		t.Fatal("sliding sync acknowledgement did not advance")
	}
	_, last := requestInbox(t, p, "phone", path+"?pos="+url.QueryEscape(second.Pos), `{}`)
	if last.Pos != "42" || len(last.Extensions.ToDevice.Events) != 0 {
		t.Fatal("sliding sync queue was not acknowledged by pos")
	}
}

func TestProxyInboxUpstreamFailure(t *testing.T) {
	a := inboxArchive(t, 1)
	upstream := inboxUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fail") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN"}`)
			return
		}
		_, _ = io.WriteString(w, `{"next_batch":"native"}`)
	})
	p := openInboxProxy(t, a, upstream)
	status, _ := requestInbox(t, p, "phone", "/_matrix/client/v3/sync?fail=true", "")
	if status != http.StatusUnauthorized {
		t.Fatal("upstream authentication failure was hidden")
	}
	_, reply := requestInbox(t, p, "phone", "/_matrix/client/v3/sync", "")
	if len(reply.ToDevice.Events) != 1 {
		t.Fatal("failed response consumed the queue")
	}
}

func TestProxyInboxStorageFailureDoesNotAcknowledge(t *testing.T) {
	a := inboxArchive(t, 1)
	upstream := inboxUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"next_batch":"native"}`)
	})
	p := openInboxProxy(t, a, upstream)
	_, first := requestInbox(t, p, "phone", "/_matrix/client/v3/sync", "")
	dir := filepath.Join(a.Dir, "proxy-inbox")
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("inbox state missing: %v", err)
	}
	blocked := filepath.Join(dir, files[0].Name()+".tmp")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	status, _ := requestInbox(t, p, "phone", "/_matrix/client/v3/sync?since="+url.QueryEscape(first.NextBatch), "")
	if status != http.StatusInternalServerError {
		t.Fatal("state write failure was hidden")
	}
	_, retry := requestInbox(t, p, "phone", "/_matrix/client/v3/sync", "")
	if len(retry.ToDevice.Events) != 1 {
		t.Fatal("failed state write acknowledged messages")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	status, last := requestInbox(t, p, "phone", "/_matrix/client/v3/sync?since="+url.QueryEscape(first.NextBatch), "")
	if status != 200 || len(last.ToDevice.Events) != 0 {
		t.Fatal("could not retry acknowledgement after storage recovered")
	}
}

func TestProxyInboxRejectsIncompleteSync(t *testing.T) {
	batch := &inboxSync{end: 1, secret: make([]byte, 32), messages: []archive.ToDevice{{Sender: "@remote:other.org", Type: "m.test", Content: json.RawMessage(`{}`)}}}
	for _, tc := range []struct {
		body    string
		sliding bool
	}{
		{`{"rooms":{}}`, false},
		{`{"next_batch":"native","to_device":{"events":[`, false},
		{`{"pos":"42","extensions":{}}`, true},
		{`{"pos":"42","extensions":{"to_device":{"events":[]}}}`, true},
	} {
		batch.sliding = tc.sliding
		var out bytes.Buffer
		if err := rewriteInboxSync(&out, strings.NewReader(tc.body), batch); err == nil {
			t.Fatal("incomplete sync accepted")
		}
		if json.Valid(out.Bytes()) {
			t.Fatal("failed sync emitted a usable acknowledgement")
		}
	}
}

func TestProxyInboxStreamsRooms(t *testing.T) {
	batch := &inboxSync{end: 1, secret: make([]byte, 32), messages: []archive.ToDevice{{Sender: "@remote:other.org", Type: "m.test", Content: json.RawMessage(`{}`)}}}
	in, writer := io.Pipe()
	out, reader := io.Pipe()
	defer in.Close()
	defer out.Close()
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		err := rewriteInboxSync(reader, in, batch)
		_ = reader.CloseWithError(err)
		done <- err
	}()
	go func() {
		_, _ = io.WriteString(writer, `{"next_batch":"native","rooms":{"join":[`)
		for range 10000 {
			if _, err := io.WriteString(writer, `{"id":9007199254740993},`); err != nil {
				break
			}
		}
		<-release
		_, _ = io.WriteString(writer, `{}]}}`)
		_ = writer.Close()
	}()
	first := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(out, make([]byte, 4096))
		first <- err
	}()
	select {
	case err := <-first:
		close(release)
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("proxy buffered the response before sending room data")
	}
	if _, err := io.Copy(io.Discard, out); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
