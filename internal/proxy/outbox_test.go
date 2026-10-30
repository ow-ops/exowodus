package proxy

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/outbox"
	"maunium.net/go/mautrix/federation"
)

func TestProxyOutboxRefusesAnotherSigningKey(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	source := federation.GenerateSigningKey()
	_, version, _ := strings.Cut(string(source.ID), ":")
	if err := a.WriteSigningKey("ed25519 " + version + " " + base64.RawStdEncoding.EncodeToString(source.Priv.Seed())); err != nil {
		t.Fatal(err)
	}
	s, err := outbox.Open(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Prepare(t.Context(), func(tx *sql.Tx) (*outbox.Summary, error) {
		return &outbox.Summary{ServerName: "example.org"}, outbox.Enqueue(t.Context(), tx, "peer.test", "PDU", "$event", []byte(`{}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wrong := federation.GenerateSigningKey()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(wrong.GenerateKeyResponse("example.org", nil))
	}))
	defer api.Close()
	u, err := url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(a, u, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.StartOutbox(t.Context()); err == nil {
		t.Fatal("outbox used a different server identity")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = outbox.Open(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if pending, err := s.Pending(t.Context()); err != nil || pending != 1 {
		t.Fatal("identity failure consumed the queue")
	}
}
