package migrate

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

const recoveryUser = "@discordbot:example.org"

func accountRecoveryFixture(t *testing.T) (*archive.Archive, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell")
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RequireLossless(); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteUser(&archive.User{UserID: recoveryUser, Deactivated: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteRoom(&archive.ArchivedRoom{RoomID: "!room:example.org", State: []json.RawMessage{json.RawMessage(`{"type":"m.room.member","state_key":"` + recoveryUser + `","content":{"membership":"join","displayname":"Room bot"}}`)}}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	native := t.TempDir()
	if err := os.WriteFile(filepath.Join(native, "CURRENT"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	rows := map[string]map[string][]byte{}
	for _, table := range append(slices.Clone(accountCheckpointTables), accountRecoveryTables...) {
		rows[table] = map[string][]byte{}
	}
	device := recoveryUser + "\xffDEVICE"
	rows["userid_password"][recoveryUser] = nil
	rows["userdeviceid_metadata"][device] = []byte(`{"device_id":"DEVICE","display_name":"Discord"}`)
	rows["token_userdeviceid"]["old-access"] = []byte(device)
	rows["token_userdeviceid"]["refresh_live"] = []byte(device)
	rows["userdeviceid_refresh"][device] = []byte("refresh_live")
	rows["keyid_key"][device] = []byte(`{"user_id":"` + recoveryUser + `","device_id":"DEVICE","keys":{"ed25519:DEVICE":"device-public"}}`)
	rows["userid_masterkeyid"][recoveryUser] = []byte(recoveryUser + "\xffmaster")
	rows["keyid_key"][recoveryUser+"\xffmaster"] = []byte(`{"user_id":"` + recoveryUser + `","usage":["master"],"keys":{"ed25519:master":"master"}}`)
	rows["userid_usersigningkeyid"][recoveryUser] = []byte(recoveryUser + "\xffuser-signing")
	rows["keyid_key"][recoveryUser+"\xffuser-signing"] = []byte(`{"user_id":"` + recoveryUser + `","usage":["user_signing"],"keys":{"ed25519:signing":"user-signing"}}`)
	rows["keyid_key"]["@alice:example.org\xffmaster"] = []byte(`{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:alice":"alice"},"signatures":{"` + recoveryUser + `":{"ed25519:signing":"signed"}}}`)
	rows["useridprofilekey_value"][recoveryUser+"\xffdisplayname"] = []byte(`"Discord bot"`)
	rows["userid_locked"][recoveryUser] = nil
	rows["userroomid_joinedcount"][recoveryUser+"\xff!room:example.org"] = make([]byte, 8)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], 255)
	primary := "\xff" + recoveryUser + "\xff" + string(counter[:]) + "\xffm.secret_storage.key.test"
	rows["roomusertype_roomuserdataid"]["\xff"+recoveryUser+"\xffm.secret_storage.key.test"] = []byte(primary)
	rows["roomuserdataid_accountdata"][primary] = []byte(`{"type":"m.secret_storage.key.test","content":{"algorithm":"m.secret_storage.v1.aes-hmac-sha2","iv":"encrypted"}}`)
	for _, version := range []string{"9", "10"} {
		rows["backupid_algorithm"][recoveryUser+"\xff"+version] = []byte(`{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"backup-` + version + `"}}`)
	}
	rows["backupkeyid_backup"][recoveryUser+"\xff10\xff!room:example.org\xffsession"] = []byte(`{"first_message_index":0,"forwarded_count":0,"is_verified":true,"session_data":{"ciphertext":"encrypted"}}`)
	otk := device + "\xff" + string(counter[:]) + "\xffsigned_curve25519:one"
	rows["onetimekeyid4225_otk"][otk] = []byte(`{"key":"one-time-key"}`)
	rows["onetimekeyid4225_otk"][recoveryUser+"\xffDELETED\xff"+string(counter[:])+"\xffsigned_curve25519:orphan"] = []byte(`{"key":"unused"}`)
	source := filepath.Join(a.Dir, "source", "tuwunel")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	for table, entries := range rows {
		var raw strings.Builder
		for _, key := range slices.Sorted(maps.Keys(entries)) {
			fmt.Fprintf(&raw, "0x%x ==> 0x%x\n", key, entries[key])
		}
		if err := os.WriteFile(filepath.Join(native, table+".txt"), []byte(raw.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(accountCheckpointTables, table) {
			upper := strings.ReplaceAll(strings.ToUpper(raw.String()), "0X", "0x")
			if err := os.WriteFile(filepath.Join(source, table+".txt"), []byte(upper), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	list := "{" + strings.Join(slices.Sorted(maps.Keys(rows)), ", ") + "}\n"
	if err := os.WriteFile(filepath.Join(native, "families"), []byte(list), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXODUS_ACCOUNT_FIXTURE", native)
	ldb := filepath.Join(t.TempDir(), "ldb")
	script := `#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    list_column_families) cat "$EXODUS_ACCOUNT_FIXTURE/families"; exit 0 ;;
    --column_family=*) table=${arg#--column_family=} ;;
    scan) cat "$EXODUS_ACCOUNT_FIXTURE/$table.txt"; exit 0 ;;
  esac
done
exit 2
`
	if err := os.WriteFile(ldb, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return a, native, ldb
}

func TestRepairTuwunelAccounts(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	users, err := RepairTuwunelAccounts(t.Context(), a, database, ldb)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(users, []string{recoveryUser}) {
		t.Fatal(users)
	}
	u, err := a.ReadUser(recoveryUser)
	if err != nil {
		t.Fatal(err)
	}
	if u.Deactivated || !u.Passwordless || !u.Locked || u.DisplayName != "Discord bot" || len(u.Devices) != 1 || !strings.Contains(string(u.Devices[0].Keys), "device-public") || u.CrossSigning == nil || len(u.Verified) != 1 || len(u.AccountData) != 1 || len(u.Rooms) != 1 || !strings.Contains(string(u.Rooms[0].Member), "Room bot") {
		t.Fatalf("account state not recovered: %+v", u)
	}
	secrets, err := a.ReadSecrets(recoveryUser)
	if err != nil || len(secrets.Tokens) != 2 || len(secrets.OneTimeKeys) != 1 || len(secrets.OneTimeKeys["DEVICE"]) != 1 || secrets.PasswordHash != "" {
		t.Fatal("device sessions or prekeys were not preserved")
	}
	backup, err := a.ReadKeyBackup(recoveryUser)
	if err != nil || backup == nil || !strings.Contains(string(backup.AuthData), "backup-10") || len(backup.Rooms) != 1 {
		t.Fatal("latest encrypted backup was not recovered")
	}
	if err := a.CheckExport(); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := a.WriteImportState(recoveryUser, &archive.ImportState{}); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb); err == nil {
		t.Fatal("overwrote an account being imported")
	}
}

func TestAccountRepairRefusesDifferentSnapshot(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	path := filepath.Join(database, "token_userdeviceid.txt")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb); err == nil || !strings.Contains(err.Error(), "differs from the archived checkpoint") {
		t.Fatal(err)
	}
	u, _ := a.ReadUser(recoveryUser)
	secrets, _ := a.ReadSecrets(recoveryUser)
	if !u.Deactivated || secrets != nil {
		t.Fatal("failed repair modified account artifacts")
	}
}

func TestAccountRepairRefusesWrongDeviceKeys(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	path := filepath.Join(database, "keyid_key.txt")
	wrong := fmt.Sprintf("0x%x ==> 0x%x\n", recoveryUser+"\xffDEVICE", `{"user_id":"@other:example.org","device_id":"DEVICE","keys":{}}`)
	if err := os.WriteFile(path, []byte(wrong), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb); err == nil || !strings.Contains(err.Error(), "device key identity differs") {
		t.Fatal(err)
	}
	u, _ := a.ReadUser(recoveryUser)
	secrets, _ := a.ReadSecrets(recoveryUser)
	if !u.Deactivated || secrets != nil {
		t.Fatal("invalid device keys modified account artifacts")
	}
}

func TestAccountRepairRocksDB(t *testing.T) {
	ldb := os.Getenv("EXODUS_TEST_LDB")
	if ldb == "" {
		t.Skip("set EXODUS_TEST_LDB to exercise a real RocksDB database")
	}
	a, fixture, _ := accountRecoveryFixture(t)
	database := filepath.Join(t.TempDir(), "rocksdb")
	run := func(input []byte, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), ldb, append([]string{"--db=" + database}, args...)...)
		cmd.Stdin = strings.NewReader(string(input))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("seed RocksDB: %v: %s", err, output)
		}
	}
	run(nil, "put", "fixture", "true", "--create_if_missing")
	for _, table := range append(slices.Clone(accountCheckpointTables), accountRecoveryTables...) {
		run(nil, "create_column_family", table)
		rows, err := os.ReadFile(filepath.Join(fixture, table+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		run(rows, "--column_family="+table, "load", "--hex")
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb); err != nil {
		t.Fatal(err)
	}
	u, err := a.ReadUser(recoveryUser)
	if err != nil || u.Deactivated || !u.Passwordless || len(u.Devices) != 1 {
		t.Fatal("native RocksDB recovery failed")
	}
}

func TestRecoveredAccountUsesPasswordlessRegistration(t *testing.T) {
	var calls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["type"] != "m.login.application_service" || body["password"] != nil {
			t.Error("passwordless account changed to password authentication")
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/register") {
			fmt.Fprintf(w, `{"user_id":%q}`, recoveryUser)
		} else {
			fmt.Fprintf(w, `{"user_id":%q,"device_id":"EXODUS","access_token":"migration"}`, recoveryUser)
		}
	}))
	defer api.Close()
	a, _ := archive.Create(t.TempDir(), "example.org")
	c := mx.MustNew(api.URL, "as-token")
	im := &Importer{Archive: a, Dest: c, Appservice: &Appservice{Bot: "@exodus:example.org", client: c}}
	account, err := im.destSession(t.Context(), &archive.User{UserID: recoveryUser, Passwordless: true})
	if err != nil || calls != 2 || account.generated || account.password != "" {
		t.Fatalf("passwordless login: %v", err)
	}
}
