package migrate

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestTuwunelSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  []byte
		want string
	}{
		{name: "supported", row: tuwunelSchemaRow},
		{name: "missing", want: "no schema version"},
		{name: "newer", row: binary.BigEndian.AppendUint64(nil, 18), want: "version 18 is unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			scans := map[string]string{"userid_password": "", "token_userdeviceid": "", "global": ""}
			if tc.row != nil {
				scans["global"] = fmt.Sprintf("0x%x ==> 0x%x\n", "version", tc.row)
			}
			for name, scan := range scans {
				if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(scan), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := OpenTuwunelDump(t.Context(), dir)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestTuwunelDumpSessions(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, rows map[string][]byte) {
		t.Helper()
		var body string
		for k, v := range rows {
			body += fmt.Sprintf("0x%s ==> 0x%s\n", hex.EncodeToString([]byte(k)), hex.EncodeToString(v))
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	user := "@alice:example.org"
	record := func(expiry uint64) []byte {
		b := []byte(user + "\xffPHONE\xff")
		return binary.BigEndian.AppendUint64(b, expiry)
	}
	write("userid_password", map[string][]byte{user: []byte("$argon2id$v=19$m=19456,t=2,p=1$salt$hash"), "@disabled:example.org": []byte("*")})
	write("token_userdeviceid", map[string][]byte{
		"legacy":        []byte(user + "\xffPHONE"),
		"unlimited":     []byte(user + "\xffPHONE\xff"),
		"live":          record(uint64(time.Now().Add(time.Hour).Unix())),
		"binary-ff":     record(0x7fffffffffffffff),
		"expired":       record(1),
		"refresh_live":  record(uint64(time.Now().Add(time.Hour).Unix())),
		"refresh_stale": record(uint64(time.Now().Add(time.Hour).Unix())),
	})
	write("userdeviceid_refresh", map[string][]byte{user + "\xffPHONE": []byte("refresh_live")})
	d, err := OpenTuwunelDump(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.Secrets(user)
	if err != nil {
		t.Fatal(err)
	}
	if s.PasswordScheme != archive.SchemeTuwunel || len(s.Tokens) != 5 {
		t.Fatalf("secrets = %+v", s)
	}
	for _, tok := range s.Tokens {
		if tok.DeviceID != "PHONE" || tok.Refresh != (tok.Token == "refresh_live") || tok.OAuth != tok.Refresh {
			t.Fatalf("token = %+v", tok)
		}
	}
	if _, err := d.Secrets("@missing:example.org"); err == nil {
		t.Fatal("missing user accepted")
	}
	s, err = d.Secrets("@disabled:example.org")
	if err != nil || s.PasswordHash != "" {
		t.Fatalf("disabled password = %+v, %v", s, err)
	}
	if err := os.Remove(filepath.Join(dir, "userdeviceid_refresh.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTuwunelDump(t.Context(), dir); err == nil {
		t.Fatal("missing refresh index accepted")
	}
}

func TestTuwunelDumpRetainsUnknownTablesExactly(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("0x00ff20 ==> 0xff000a\n")
	if err := os.WriteFile(filepath.Join(dir, "unimplemented.txt"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	d := &TuwunelDump{dir: dir}
	if err := d.Retain(a); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.Dir, "source", "tuwunel", "unimplemented.txt")
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("raw source data was changed or omitted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("sensitive scan permissions incorrect")
	}
}

func TestTuwunelSnapshotAccountInventory(t *testing.T) {
	d := &TuwunelDump{passwords: map[string][]byte{"@alice:example.org": nil, "@conduit:example.org": nil, "@remote:elsewhere.org": []byte("*")}}
	if err := d.CheckUserInventory(map[string]bool{"@alice:example.org": true}, "@conduit:example.org", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckUserInventory(map[string]bool{}, "@conduit:example.org", nil); err == nil {
		t.Fatal("deleted account missing from source API accepted")
	}
	if err := d.CheckUserInventory(map[string]bool{"@alice:example.org": true, "@new:example.org": true}, "@conduit:example.org", nil); err == nil ||
		!strings.Contains(err.Error(), "userid_password.txt") || !strings.Contains(err.Error(), "new backup") {
		t.Fatalf("missing account error: %v", err)
	}
	const bridgeUser = "@discord_123:example.org"
	d.passwords[bridgeUser] = nil
	if err := d.CheckUserInventory(map[string]bool{"@alice:example.org": true, bridgeUser: true}, "@conduit:example.org", nil); err != nil {
		t.Fatalf("passwordless bridge account rejected: %v", err)
	}
}

func TestTuwunelDumpDeviceAndServerData(t *testing.T) {
	user, device := "@alice:example.org", "PHONE"
	prefix := user + "\xff" + device
	ordered := string(binary.BigEndian.AppendUint64([]byte(prefix+"\xff"), 0xffff)) + "\xffsigned_curve25519:ordered"
	queued := string(binary.BigEndian.AppendUint64([]byte(prefix+"\xff"), 0xffff))
	dir := t.TempDir()
	maps := map[string]map[string][]byte{
		"userid_password": {user: []byte("*")}, "token_userdeviceid": {},
		"userdeviceid_metadata":    {prefix: []byte(`{"device_id":"PHONE","display_name":"Phone"}`)},
		"onetimekeyid4225_otk":     {ordered: []byte(`{"key":"ordered","signatures":{"@alice:example.org":{}}}`)},
		"onetimekeyid_onetimekeys": {prefix + "\xff\"signed_curve25519:legacy\"": []byte(`{"key":"legacy"}`)},
		"userdeviceidalgorithm_fallback": {
			prefix + "\xffsigned_curve25519": []byte(`{"key_id":"signed_curve25519:fallback","key":{"key":"fallback"},"used":false}`),
			prefix + "\xffcurve25519":        []byte(`{"key_id":"curve25519:used","key":"used","used":true}`),
		},
		"senderkey_pusher":  {user + "\xffpushkey": []byte(`{"pushkey":"pushkey","app_id":"app","kind":"http","data":{"url":"https://push.example.org"}}`)},
		"pushkey_deviceid":  {"pushkey": []byte(device)},
		"todeviceid_events": {queued: []byte(`{"sender":"@alice:example.org","type":"m.room.encrypted","content":{"ciphertext":"encrypted"}}`)},
		"bannedroomids":     {"!blocked:example.org": {}},
		"alias_roomid":      {"chat": []byte("!room:example.org")},
	}
	for name, rows := range maps {
		var body string
		for key, value := range rows {
			body += fmt.Sprintf("0x%x ==> 0x%x\n", key, value)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := OpenTuwunelDump(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.Secrets(user)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Devices) != 1 || s.Devices[0] != device || len(s.OneTimeKeys[device]) != 2 || len(s.FallbackKeys[device]) != 1 || len(s.Pushers) != 1 || s.Pushers[0].DeviceID != device {
		t.Fatalf("device data = %+v", s)
	}
	if string(s.OneTimeKeys[device]["signed_curve25519:ordered"]) != string(maps["onetimekeyid4225_otk"][ordered]) {
		t.Fatal("signed key bytes changed")
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_synapse/admin/v1/registration_tokens" {
			t.Errorf("unexpected API %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"registration_tokens":[]}`))
	}))
	defer admin.Close()
	exp := &Exporter{Archive: a, Admin: mx.MustNew(admin.URL, "admin"), TuwunelDump: d}
	if err := exp.ExportServer(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := a.ReadServer()
	if err != nil {
		t.Fatal(err)
	}
	if len(server.BlockedRooms) != 1 || server.Aliases["#chat:example.org"] != "!room:example.org" || len(server.ToDevice) != 1 {
		t.Fatalf("server data = %+v", server)
	}
	m := server.ToDevice[0]
	var content map[string]string
	if err := json.Unmarshal(m.Content, &content); err != nil {
		t.Fatal(err)
	}
	if m.Recipient != user || m.DeviceID != device || m.Sender != user || m.Type != "m.room.encrypted" || content["ciphertext"] != "encrypted" {
		t.Fatalf("queued event = %+v", m)
	}
	delivered := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Query().Get("user_id") != user {
			t.Errorf("queued message sent with wrong sender: %s", r.URL)
		}
		var body struct {
			Messages map[string]map[string]map[string]string `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Messages[user][device]["ciphertext"] != "encrypted" {
			t.Errorf("queued message content = %+v", body)
		}
		delivered++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer destination.Close()
	im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Appservice: &Appservice{client: mx.MustNew(destination.URL, "as-token")}, Migrated: map[string]bool{user: true}}
	state := &archive.ServerImportState{ToDevice: map[string]bool{}}
	if err := a.WriteImportState(user, &archive.ImportState{DestUserID: user, Devices: map[string]bool{device: true}}); err != nil {
		t.Fatal(err)
	}
	var failures []Failure
	im.deliverToDevice(t.Context(), server.ToDevice, state, &failures)
	im.deliverToDevice(t.Context(), server.ToDevice, state, &failures)
	if delivered != 1 || len(failures) != 0 {
		t.Fatalf("delivered=%d failures=%+v", delivered, failures)
	}
}

func TestTuwunelDumpRejectsMalformedExtraRecords(t *testing.T) {
	user := "@alice:example.org"
	for name, record := range map[string]struct {
		key   string
		value []byte
	}{
		"onetimekeyid4225_otk":           {user + "\xffPHONE\xffshort", []byte(`{"key":"x"}`)},
		"userdeviceidalgorithm_fallback": {user + "\xffPHONE\xffcurve25519", []byte(`{"key_id":"signed_curve25519:x","key":"x","used":false}`)},
		"userdeviceid_metadata":          {user + "\xffPHONE", []byte(`not json`)},
		"senderkey_pusher":               {user + "\xffpushkey", []byte(`{}`)},
		"todeviceid_events":              {user + "\xffPHONE\xffshort", []byte(`{}`)},
		"alias_roomid":                   {"chat", []byte("invalid-room")},
		"bannedroomids":                  {"invalid-room", nil},
	} {
		t.Run(name, func(t *testing.T) {
			d := &TuwunelDump{passwords: map[string][]byte{user: nil}, maps: map[string]map[string][]byte{name: {record.key: record.value}}}
			_, err1 := d.Secrets(user)
			err2 := d.AddServer(&archive.Server{}, "example.org")
			if err1 == nil && err2 == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
}

func TestTuwunelScanRejectsMalformedData(t *testing.T) {
	for _, body := range []string{"secret plaintext", "0xgg ==> 0x00", "0x61 ==> 0x00\n0x61 ==> 0x01"} {
		path := filepath.Join(t.TempDir(), "dump.txt")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTuwunelScan(t.Context(), path); err == nil {
			t.Fatal("malformed dump accepted")
		}
	}
}
