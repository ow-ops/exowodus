package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBridgeFilterMixedTransaction(t *testing.T) {
	var bodies [][]byte
	status := http.StatusServiceUnavailable
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bridge/_matrix/app/v1/transactions/retry-id" || r.URL.Query().Get("access_token") != "secret" {
			t.Errorf("transaction route or authentication changed: %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		w.WriteHeader(status)
	}))
	defer bridge.Close()
	filter, err := NewBridgeFilter(bridge.URL+"/bridge", "secret", map[string]bool{"$old-command": true, "$old-encrypted": true})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"events":[
{"event_id":"$old-command","type":"m.room.message","content":{"body":"!bridge dangerous-command"}},
{"event_id":"$new","origin_server_ts":1,"type":"m.room.message","content":{"body":"!bridge link"}},
{"event_id":"$new-encrypted","type":"m.room.encrypted","content":{"ciphertext":"keep-new-message"}},
{"event_id":"$old-encrypted","type":"m.room.encrypted","content":{"ciphertext":"old"}}
],"to_device":[{"type":"m.room.encrypted","content":{"ciphertext":"keep"}}],"ephemeral":[{"type":"m.receipt"}],"device_lists":{"changed":["@user:test"]},"extension":{"unknown":true}}`
	send := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/_matrix/app/v1/transactions/retry-id?access_token=secret", strings.NewReader(body))
		w := httptest.NewRecorder()
		filter.ServeHTTP(w, r)
		return w
	}
	if w := send(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed bridge transaction acknowledged: %d", w.Code)
	}
	if removed, forwarded := filter.Counts(); removed != 0 || forwarded != 0 {
		t.Fatal("failed transaction counted as delivered")
	}
	status = http.StatusOK
	if w := send(); w.Code != http.StatusOK {
		t.Fatalf("retry failed: %d", w.Code)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("retry changed the filtered transaction")
	}
	var got, original map[string]json.RawMessage
	_ = json.Unmarshal(bodies[1], &got)
	_ = json.Unmarshal([]byte(body), &original)
	var events []struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(got["events"], &events); err != nil || len(events) != 2 || events[0].EventID != "$new" || events[1].EventID != "$new-encrypted" || !bytes.Contains(got["events"], []byte(`"ciphertext":"keep-new-message"`)) {
		t.Fatalf("new event was lost or historical events forwarded: %s", got["events"])
	}
	for _, key := range []string{"to_device", "ephemeral", "device_lists", "extension"} {
		if !bytes.Equal(got[key], original[key]) {
			t.Errorf("%s changed: %s", key, got[key])
		}
	}
	if removed, forwarded := filter.Counts(); removed != 2 || forwarded != 2 {
		t.Fatalf("counts=%d,%d", removed, forwarded)
	}
}

func TestBridgeFilterHistoryOnlyAndValidation(t *testing.T) {
	filter, err := NewBridgeFilter("http://127.0.0.1:0", "secret", map[string]bool{"$old": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, token, body string
		status            int
	}{
		{"history", "secret", `{"events":[{"event_id":"$old"}],"ephemeral":[],"to_device":[]}`, 200},
		{"unauthenticated", "", `{"events":[{"event_id":"$old"}]}`, 401},
		{"wrong token", "other", `{"events":[{"event_id":"$old"}]}`, 401},
		{"missing events", "secret", `{}`, 400},
		{"null events", "secret", `{"events":null}`, 400},
		{"missing id", "secret", `{"events":[{"content":{"body":"keep"}}]}`, 400},
		{"malformed", "secret", `{"events":[`, 400},
		{"nonobject", "secret", `null`, 400},
		{"trailing document", "secret", `{"events":[]} {}`, 400},
		{"new event offline", "secret", `{"events":[{"event_id":"$new"}]}`, 502},
		{"extension offline", "secret", `{"events":[{"event_id":"$old"}],"extension":null}`, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/_matrix/app/v1/transactions/txn", strings.NewReader(tc.body))
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			filter.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
	if removed, forwarded := filter.Counts(); removed != 1 || forwarded != 0 {
		t.Fatalf("failed transactions acknowledged: %d,%d", removed, forwarded)
	}
}

func TestBridgeFilterForwardsQueries(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("lost authorization")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer bridge.Close()
	filter, err := NewBridgeFilter(bridge.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/_matrix/app/v1/users/@ghost:test", "/_matrix/app/v1/rooms/%23room:test", "/_matrix/app/v1/ping", "/_matrix/app/v1/thirdparty/protocol/discord", "/_matrix/app/unstable/org.matrix.msc3984/keys/query", "/_matrix/app/unstable/org.matrix.msc3983/keys/claim"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "/ping") || strings.Contains(path, "/keys/") {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		filter.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}
