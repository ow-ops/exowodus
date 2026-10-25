package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"go.mau.fi/util/exhttp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

type senderFunc func(context.Context, *federation.ReqSendTransaction) (*federation.RespSendTransaction, error)

func (f senderFunc) SendTransaction(ctx context.Context, r *federation.ReqSendTransaction) (*federation.RespSendTransaction, error) {
	return f(ctx, r)
}

func TestOutboxRelativeArchivePath(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("archive?#", 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open("archive?#")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Prepare(t.Context(), func(*sql.Tx) (*Summary, error) { return &Summary{}, nil }); err != nil {
		t.Fatal(err)
	}
	if summary, err := s.Summary(t.Context()); err != nil || summary == nil {
		t.Fatal("relative archive could not be read")
	}
}

type localTransport func(*http.Request) (*http.Response, error)

func (f localTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOutboxSignedFederationDelivery(t *testing.T) {
	key := federation.GenerateSigningKey()
	raw, err := json.Marshal(key.GenerateKeyResponse("origin.test", nil))
	if err != nil {
		t.Fatal(err)
	}
	var keys federation.ServerKeyResponse
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	cache := federation.NewInMemoryCache()
	cache.StoreKeys(&keys)
	auth := federation.NewServerAuth(nil, cache, func(federation.XMatrixAuth) string { return "peer.test" })
	peer := httptest.NewServer(auth.AuthenticateMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body federation.ReqSendTransaction
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if body.Origin != "origin.test" || len(body.PDUs) != 1 || string(body.PDUs[0]) != `{"content":{"body":"original"}}` {
			t.Errorf("unexpected transaction: %+v", body)
		}
		_ = json.NewEncoder(w).Encode(federation.RespSendTransaction{PDUs: map[id.EventID]federation.PDUProcessingResult{"$event": {}}})
	})))
	defer peer.Close()
	local, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := federation.NewClient("origin.test", key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
	client.HTTP.Transport = localTransport(func(r *http.Request) (*http.Response, error) {
		forward := r.Clone(r.Context())
		endpoint := *r.URL
		endpoint.Scheme = local.Scheme
		endpoint.Host = local.Host
		forward.URL = &endpoint
		return http.DefaultTransport.RoundTrip(forward)
	})
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Prepare(t.Context(), func(tx *sql.Tx) (*Summary, error) {
		return &Summary{}, Enqueue(t.Context(), tx, "peer.test", "PDU", "$event", []byte(`{"content":{"body":"original"}}`))
	}); err != nil {
		t.Fatal(err)
	}
	if delivered, err := s.Deliver(t.Context(), "origin.test", client); err != nil || !delivered {
		t.Fatalf("signed delivery failed: %v", err)
	}
	if count, err := s.Pending(t.Context()); err != nil || count != 0 {
		t.Fatal("signed transaction was not acknowledged")
	}
}

func TestOutboxDurableRetryAndBackoff(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Prepare(t.Context(), func(tx *sql.Tx) (*Summary, error) {
		for range 52 {
			if err := Enqueue(t.Context(), tx, "a.test", "PDU", "$test", []byte(`{"type":"m.test","content":{"number":9007199254740993}}`)); err != nil {
				return nil, err
			}
		}
		if err := Enqueue(t.Context(), tx, "b.test", "EDU", "", []byte(`{"edu_type":"m.device_list_update","content":{}}`)); err != nil {
			return nil, err
		}
		return &Summary{Rows: map[string]int{"source": 53}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Next(t.Context(), "origin.test", time.Now())
	if err != nil || len(first.Request.PDUs) != 50 {
		t.Fatalf("batch=%+v err=%v", first, err)
	}
	want, _ := json.Marshal(first.Request)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resumed, err := s.Next(t.Context(), "origin.test", time.Now())
	got, _ := json.Marshal(resumed.Request)
	if err != nil || resumed.Request.TxnID != first.Request.TxnID || string(got) != string(want) {
		t.Fatal("unacknowledged transaction changed on restart")
	}
	if err := s.Retry(t.Context(), resumed, time.Now(), errors.New("offline"), false); err != nil {
		t.Fatal(err)
	}
	next, err := s.Next(t.Context(), "origin.test", time.Now())
	if err != nil || next.Request.Destination != "b.test" || len(next.Request.EDUs) != 1 {
		t.Fatal("an offline destination blocked other destinations")
	}
	if err := s.Acknowledge(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	retry, err := s.Next(t.Context(), "origin.test", time.Now().Add(2*time.Minute))
	if err != nil || retry.Request.TxnID != first.Request.TxnID {
		t.Fatal("network retry changed transaction ID")
	}
	if err := s.Retry(t.Context(), retry, time.Now(), errors.New("PDU rejected"), true); err != nil {
		t.Fatal(err)
	}
	retry, err = s.Next(t.Context(), "origin.test", time.Now().Add(5*time.Minute))
	if err != nil || retry.Request.TxnID == first.Request.TxnID {
		t.Fatal("PDU rejection reused a cached failed transaction")
	}
	if err := s.Acknowledge(t.Context(), retry); err != nil {
		t.Fatal(err)
	}
	remaining, err := s.Next(t.Context(), "origin.test", time.Now())
	if err != nil || len(remaining.Request.PDUs) != 2 {
		t.Fatal("batch acknowledgement deleted undelivered events")
	}
	if err := s.Acknowledge(t.Context(), remaining); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.Pending(t.Context()); err != nil || pending != 0 {
		t.Fatalf("pending=%d %v", pending, err)
	}
}

func TestOutboxFailedPreparationIsNotPublished(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.Prepare(t.Context(), func(tx *sql.Tx) (*Summary, error) {
		if err := Enqueue(t.Context(), tx, "peer.test", "PDU", "$event", []byte(`{}`)); err != nil {
			return nil, err
		}
		return nil, errors.New("source scan interrupted")
	})
	if err == nil {
		t.Fatal("interrupted preparation succeeded")
	}
	if summary, err := s.Summary(t.Context()); err != nil || summary != nil {
		t.Fatal("incomplete queue published")
	}
	if count, err := s.Pending(t.Context()); err != nil || count != 0 {
		t.Fatal("partial preparation retained")
	}
}

func TestOutboxPDUErrorRetainsWholeBatch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.Prepare(t.Context(), func(tx *sql.Tx) (*Summary, error) {
		return &Summary{}, Enqueue(t.Context(), tx, "peer.test", "PDU", "$event", []byte(`{"content":{"number":9007199254740993}}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	var request federation.ReqSendTransaction
	delivered, err := s.Deliver(t.Context(), "origin.test", senderFunc(func(_ context.Context, r *federation.ReqSendTransaction) (*federation.RespSendTransaction, error) {
		request = *r
		return &federation.RespSendTransaction{PDUs: map[id.EventID]federation.PDUProcessingResult{"$event": {Error: "missing auth"}}}, nil
	}))
	if err == nil || delivered {
		t.Fatal("rejected PDU acknowledged")
	}
	retry, err := s.Next(t.Context(), "origin.test", time.Now().Add(2*time.Minute))
	if err != nil || retry.Request.TxnID == request.TxnID || !reflect.DeepEqual(retry.Request.PDUs, request.PDUs) {
		t.Fatal("PDU retry lost original content")
	}
}

func TestOutboxRequiresEveryPDUAcknowledgement(t *testing.T) {
	for _, resumed := range []bool{false, true} {
		for _, result := range []struct {
			name string
			pdus map[id.EventID]federation.PDUProcessingResult
		}{
			{"empty", nil},
			{"partial", map[id.EventID]federation.PDUProcessingResult{"$first": {}}},
			{"unrelated", map[id.EventID]federation.PDUProcessingResult{"$first": {}, "$other": {}}},
		} {
			name := result.name
			if resumed {
				name += "/resumed"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				s, err := Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Prepare(t.Context(), func(tx *sql.Tx) (*Summary, error) {
					for _, eventID := range []string{"$first", "$second"} {
						if err := Enqueue(t.Context(), tx, "peer.test", "PDU", eventID, []byte(`{"content":{}}`)); err != nil {
							return nil, err
						}
					}
					return &Summary{}, Enqueue(t.Context(), tx, "peer.test", "EDU", "", []byte(`{"edu_type":"m.receipt","content":{}}`))
				}); err != nil {
					s.Close()
					t.Fatal(err)
				}
				if resumed {
					if _, err := s.Next(t.Context(), "origin.test", time.Now()); err != nil {
						t.Fatal(err)
					}
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					s, err = Open(dir)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer s.Close()
				var attempted federation.ReqSendTransaction
				delivered, err := s.Deliver(t.Context(), "origin.test", senderFunc(func(_ context.Context, r *federation.ReqSendTransaction) (*federation.RespSendTransaction, error) {
					attempted = *r
					return &federation.RespSendTransaction{PDUs: result.pdus}, nil
				}))
				if err == nil || delivered {
					t.Fatal("incomplete PDU results acknowledged")
				}
				if pending, err := s.Pending(t.Context()); err != nil || pending != 3 {
					t.Fatalf("pending=%d err=%v", pending, err)
				}
				retry, err := s.Next(t.Context(), "origin.test", time.Now().Add(2*time.Minute))
				if err != nil || retry.Request.TxnID == attempted.TxnID || !reflect.DeepEqual(retry.Request.PDUs, attempted.PDUs) || !reflect.DeepEqual(retry.Request.EDUs, attempted.EDUs) {
					t.Fatalf("incomplete response did not retain a fresh retry: %v", err)
				}
				if _, err := s.db.Exec(`UPDATE destinations SET next_attempt=0`); err != nil {
					t.Fatal(err)
				}
				delivered, err = s.Deliver(t.Context(), "origin.test", senderFunc(func(context.Context, *federation.ReqSendTransaction) (*federation.RespSendTransaction, error) {
					return &federation.RespSendTransaction{PDUs: map[id.EventID]federation.PDUProcessingResult{"$first": {}, "$second": {}}}, nil
				}))
				if err != nil || !delivered {
					t.Fatalf("complete retry failed: %v", err)
				}
				if pending, err := s.Pending(t.Context()); err != nil || pending != 0 {
					t.Fatalf("acknowledged batch retained: pending=%d err=%v", pending, err)
				}
			})
		}
	}
}

func TestOutboxEDUOnlyResponseNeedsNoPDUResults(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Prepare(t.Context(), func(tx *sql.Tx) (*Summary, error) {
		return &Summary{}, Enqueue(t.Context(), tx, "peer.test", "EDU", "", []byte(`{"edu_type":"m.receipt","content":{}}`))
	}); err != nil {
		t.Fatal(err)
	}
	delivered, err := s.Deliver(t.Context(), "origin.test", senderFunc(func(context.Context, *federation.ReqSendTransaction) (*federation.RespSendTransaction, error) {
		return &federation.RespSendTransaction{}, nil
	}))
	if err != nil || !delivered {
		t.Fatalf("EDU-only transaction failed: %v", err)
	}
}
