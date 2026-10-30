package migrate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/outbox"
	"exowodus/internal/relay"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

func writeScan(t *testing.T, dir, table string, rows map[string][]byte) {
	t.Helper()
	var data strings.Builder
	for key, value := range rows {
		fmt.Fprintf(&data, "0x%x ==> 0x%x\n", key, value)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, table+".txt"), []byte(data.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareOutboxFindsV12RoomVersionInOutliers(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	key := federation.GenerateSigningKey()
	_, version, _ := strings.Cut(string(key.ID), ":")
	if err := a.WriteSigningKey("ed25519 " + version + " " + base64.RawStdEncoding.EncodeToString(key.Priv.Seed())); err != nil {
		t.Fatal(err)
	}
	create, err := relay.ParsePDU([]byte(`{"type":"m.room.create","sender":"@alice:example.org","state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],"content":{"room_version":"12"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := create.Sign(id.RoomVersion("12"), "example.org", key.ID, key.Priv); err != nil {
		t.Fatal(err)
	}
	createID, err := create.GetEventID(id.RoomVersion("12"))
	if err != nil {
		t.Fatal(err)
	}
	createRaw, err := json.Marshal(create)
	if err != nil {
		t.Fatal(err)
	}
	roomID := "!" + strings.TrimPrefix(string(createID), "$")
	message := signedAuth(t, key, roomID, "example.org", "12", []string{string(createID)})
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(message.PDU, &stored); err != nil {
		t.Fatal(err)
	}
	stored["event_id"], _ = json.Marshal(message.EventID)
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(a.Dir, "source", "tuwunel")
	writeScan(t, dir, "servercurrentevent_data", map[string][]byte{"peer.test\xffpdu": nil})
	writeScan(t, dir, "servernameevent_data", nil)
	writeScan(t, dir, "pduid_pdu", map[string][]byte{"pdu": raw})
	writeScan(t, dir, "eventid_outlierpdu", map[string][]byte{string(createID): createRaw})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(key.GenerateKeyResponse("example.org", nil))
	}))
	defer api.Close()
	im := &Importer{Archive: a, Dest: mx.MustNew(api.URL, ""), Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
	srv := &archive.Server{Limitations: []string{"servercurrentevent_data has 1 pending deliveries; source queues must drain before lossless cutover"}}
	if err := im.PrepareOutbox(t.Context(), srv, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareFederationOutboxFromRetainedDump(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	key := federation.GenerateSigningKey()
	text := "ed25519 " + strings.SplitN(string(key.ID), ":", 2)[1] + " " + base64.RawStdEncoding.EncodeToString(key.Priv.Seed())
	if err := a.WriteSigningKey(text); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_matrix/key/v2/server" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(key.GenerateKeyResponse("example.org", nil))
	}))
	defer api.Close()
	im := &Importer{Archive: a, Dest: mx.MustNew(api.URL, "admin"), Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}}
	event := signedAuth(t, key, "!room:example.org", "example.org", "11", nil)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(event.PDU, &object); err != nil {
		t.Fatal(err)
	}
	object["event_id"], _ = json.Marshal(event.EventID)
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(a.Dir, "source", "tuwunel")
	writeScan(t, dir, "servercurrentevent_data", map[string][]byte{"peer.test\xffpdu-key": nil})
	writeScan(t, dir, "servernameevent_data", map[string][]byte{
		"peer.test\xfftyping":  []byte(`{"edu_type":"m.typing","content":{"typing":true}}`),
		"peer.test\xffreceipt": []byte(`{"edu_type":"m.receipt","content":{}}`),
		"peer.test\xffdevice":  []byte(`{"edu_type":"m.device_list_update","content":{"stream_id":9007199254740993}}`),
	})
	writeScan(t, dir, "pduid_pdu", map[string][]byte{"pdu-key": raw})
	writeScan(t, dir, "eventid_outlierpdu", nil)
	srv := &archive.Server{Limitations: []string{
		"servercurrentevent_data has 1 pending deliveries; source queues must drain before lossless cutover",
		"servernameevent_data has 3 pending deliveries; source queues must drain before lossless cutover",
	}}
	rooms := []*archive.ArchivedRoom{{RoomID: "!room:example.org", Version: "11"}}
	if err := im.PrepareOutbox(t.Context(), srv, rooms); err != nil {
		t.Fatal(err)
	}
	if im.outboxSummary == nil || im.outboxSummary.ExpiredTyping != 1 {
		t.Fatal("typing notifications retained")
	}
	s, err := outbox.Open(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	batch, err := s.Next(t.Context(), "example.org", time.Now())
	if err != nil || len(batch.Request.PDUs) != 1 || len(batch.Request.EDUs) != 2 {
		t.Fatalf("batch=%+v err=%v", batch, err)
	}
	if strings.Contains(string(batch.Request.PDUs[0]), `"event_id"`) {
		t.Fatal("storage-only event ID sent on the wire")
	}
	if !strings.Contains(string(batch.Request.PDUs[0]), `"membership":"join"`) {
		t.Fatal("original event content changed")
	}
	if err := s.Acknowledge(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if err := im.PrepareOutbox(t.Context(), srv, rooms); err != nil {
		t.Fatal(err)
	}
	if count, err := s.Pending(t.Context()); err != nil || count != 0 {
		t.Fatal("resume requeued delivered events")
	}
	writeScan(t, dir, "servernameevent_data", map[string][]byte{"peer.test\xffchanged": []byte(`{"edu_type":"m.receipt","content":{}}`)})
	if err := im.PrepareOutbox(t.Context(), srv, rooms); err == nil {
		t.Fatal("a changed source checkpoint reused the queue")
	}
}
