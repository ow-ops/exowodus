package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestAppserviceInboxUsesAuthenticatedDeviceScope(t *testing.T) {
	a := inboxArchive(t, 1)
	var revoked atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/_matrix/client/v3/account/whoami" {
			_, _ = w.Write([]byte(`{"next_batch":"native","to_device":{"events":[]}}`))
			return
		}
		q := r.URL.Query()
		if r.Header.Get("Authorization") != "Bearer shared-as-token" || revoked.Load() || len(q["user_id"]) != 1 || q.Get("user_id") != "@alice:example.org" {
			w.WriteHeader(403)
			return
		}
		device := q.Get("device_id")
		if device == "" {
			device = q.Get("org.matrix.msc3202.device_id")
		}
		if device != "PHONE" && device != "TABLET" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"user_id": "@alice:example.org", "device_id": device})
	}))
	defer up.Close()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := openInboxProxy(t, a, u)
	for _, param := range []string{"device_id", "org.matrix.msc3202.device_id"} {
		path := "/_matrix/client/v3/sync?user_id=@alice:example.org&" + param + "="
		_, tablet := requestInbox(t, p, "shared-as-token", path+"TABLET", "")
		if len(tablet.ToDevice.Events) != 0 {
			t.Fatal("another device received phone encryption messages")
		}
		_, phone := requestInbox(t, p, "shared-as-token", path+"PHONE", "")
		if len(phone.ToDevice.Events) != 1 {
			t.Fatal("appservice device lost its encryption inbox")
		}
		_, invalid := requestInbox(t, p, "shared-as-token", path+"MISSING", "")
		if len(invalid.ToDevice.Events) != 0 {
			t.Fatal("unknown device obtained encryption messages")
		}
	}
	for _, scope := range []string{"user_id=@bob:example.org&device_id=PHONE", "user_id=@alice:example.org&user_id=@bob:example.org&device_id=PHONE"} {
		_, reply := requestInbox(t, p, "shared-as-token", "/_matrix/client/v3/sync?"+scope, "")
		if len(reply.ToDevice.Events) != 0 {
			t.Fatal("rejected masquerade obtained encryption messages")
		}
	}
	revoked.Store(true)
	_, reply := requestInbox(t, p, "shared-as-token", "/_matrix/client/v3/sync?user_id=@alice:example.org&device_id=PHONE", "")
	if len(reply.ToDevice.Events) != 0 {
		t.Fatal("cached masquerade bypassed revocation")
	}
}
