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
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

const recoveryUser = "@discordbot:example.org"

func tuwunel194Families(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("testdata/tuwunel-v1.9.4-column-families.txt")
	if err != nil {
		t.Fatal(err)
	}
	families := map[string]bool{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			families[line] = true
		}
	}
	return families
}

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
	for table := range tuwunel194Families(t) {
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
	rows["userid_masterkeyid"]["@alice:example.org"] = []byte("@alice:example.org\xffmaster")
	rows["useridprofilekey_value"][recoveryUser+"\xffdisplayname"] = []byte(`"Discord bot"`)
	rows["userid_locked"][recoveryUser] = nil
	rows["userroomid_joined"][recoveryUser+"\xff!room:example.org"] = make([]byte, 8)
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
	users, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false)
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
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := a.WriteImportState(recoveryUser, &archive.ImportState{}); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err == nil {
		t.Fatal("overwrote an account being imported")
	}
}

func TestAccountRepairRefusesDifferentSnapshot(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	path := filepath.Join(database, "token_userdeviceid.txt")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err == nil || !strings.Contains(err.Error(), "differs from the archived checkpoint") {
		t.Fatal(err)
	}
	u, _ := a.ReadUser(recoveryUser)
	secrets, _ := a.ReadSecrets(recoveryUser)
	if !u.Deactivated || secrets != nil {
		t.Fatal("failed repair modified account artifacts")
	}
}

func TestAccountRepairReportsMissingTablesBeforeScanning(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	families := tuwunel194Families(t)
	delete(families, "keyid_key")
	delete(families, "backupkeyid_backup")
	list := "{" + strings.Join(slices.Sorted(maps.Keys(families)), ", ") + "}\n"
	if err := os.WriteFile(filepath.Join(database, "families"), []byte(list), 0600); err != nil {
		t.Fatal(err)
	}
	// A scan would fail here if validation did not run first.
	if err := os.Remove(filepath.Join(database, "userid_password.txt")); err != nil {
		t.Fatal(err)
	}
	_, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false)
	if err == nil || !strings.Contains(err.Error(), "keyid_key") || !strings.Contains(err.Error(), "backupkeyid_backup") || !strings.Contains(err.Error(), "missing required tables") {
		t.Fatalf("missing tables were not reported together before scanning: %v", err)
	}
	u, err := a.ReadUser(recoveryUser)
	if err != nil || !u.Deactivated {
		t.Fatal("schema check changed the archived account")
	}
	secrets, err := a.ReadSecrets(recoveryUser)
	if err != nil || secrets != nil {
		t.Fatal("schema check changed the archived secrets")
	}
}

func TestAccountRepairKeepsArchivedAppservices(t *testing.T) {
	for _, retainedScan := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained_scan=%t", retainedScan), func(t *testing.T) {
			a, database, ldb := accountRecoveryFixture(t)
			if err := a.WriteServer(&archive.Server{AppserviceRegistrations: []string{testBridgeRegistration}}); err != nil {
				t.Fatal(err)
			}
			const table = "id_appserviceregistrations"
			nativeRegistration := strings.ReplaceAll(testBridgeRegistration, "bridge-test-token", "changed-test-token")
			nativeRow := fmt.Sprintf("0x%x ==> 0x%x\n", "example-bridge", nativeRegistration)
			if err := os.WriteFile(filepath.Join(database, table+".txt"), []byte(nativeRow), 0600); err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(a.Dir, "source", "tuwunel", table+".txt")
			originalRow := []byte(fmt.Sprintf("0x%x ==> 0x%x\n", "example-bridge", testBridgeRegistration))
			if retainedScan {
				if err := os.WriteFile(sourcePath, originalRow, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err != nil {
				t.Fatal(err)
			}
			server, err := a.ReadServer()
			if err != nil || server == nil || !slices.Equal(server.AppserviceRegistrations, []string{testBridgeRegistration}) {
				t.Fatal("recovery changed the archived appservice registration")
			}
			retained, err := os.ReadFile(sourcePath)
			if retainedScan {
				if err != nil || string(retained) != string(originalRow) {
					t.Fatal("recovery changed the retained registration scan")
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("recovery added a registration scan to the checkpoint")
			}
		})
	}
}

func TestAccountRepairRefusesWrongDeviceKeys(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	path := filepath.Join(database, "keyid_key.txt")
	wrong := fmt.Sprintf("0x%x ==> 0x%x\n", recoveryUser+"\xffDEVICE", `{"user_id":"@other:example.org","device_id":"DEVICE","keys":{}}`)
	if err := os.WriteFile(path, []byte(wrong), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err == nil || !strings.Contains(err.Error(), "device key identity differs") {
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
		rows, err := os.ReadFile(filepath.Join(fixture, table+".txt"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		run(nil, "create_column_family", table)
		run(rows, "--column_family="+table, "load", "--hex")
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err != nil {
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

func TestExportDeactivatedPreservesRepairedAccount(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err != nil {
		t.Fatal(err)
	}
	before, err := a.ReadUser(recoveryUser)
	if err != nil || !before.Passwordless || before.Deactivated || len(before.Devices) == 0 || before.CrossSigning == nil {
		t.Fatal("fixture repair failed")
	}
	exp := &Exporter{Archive: a}
	if _, err := exp.ExportDeactivated(recoveryUser); err != nil {
		t.Fatal(err)
	}
	after, err := a.ReadUser(recoveryUser)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("resumed export replaced repaired account")
	}
}

func TestRecoveredVerificationsUseCurrentMaster(t *testing.T) {
	for _, currentSigned := range []bool{false, true} {
		t.Run(fmt.Sprintf("current_signed=%t", currentSigned), func(t *testing.T) {
			dir := t.TempDir()
			const peer = "@peer:example.org"
			rows := map[string][]byte{}
			makeKey := func(public string, signed bool) []byte {
				signatures := map[string]map[string]string{}
				if signed {
					signatures[recoveryUser] = map[string]string{"ed25519:signing": "signature"}
				}
				raw, err := json.Marshal(map[string]any{"user_id": peer, "usage": []string{"master"}, "keys": map[string]string{"ed25519:" + public: public}, "signatures": signatures})
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			rows[peer+"\xffa-current"] = makeKey("a-current", currentSigned)
			rows[peer+"\xffz-retired"] = makeKey("z-retired", true)
			var scan strings.Builder
			for _, key := range slices.Sorted(maps.Keys(rows)) {
				fmt.Fprintf(&scan, "0x%x ==> 0x%x\n", key, rows[key])
			}
			if err := os.WriteFile(filepath.Join(dir, "keyid_key.txt"), []byte(scan.String()), 0600); err != nil {
				t.Fatal(err)
			}
			pointer := fmt.Sprintf("0x%x ==> 0x%x\n", peer, peer+"\xffa-current")
			if err := os.WriteFile(filepath.Join(dir, "userid_masterkeyid.txt"), []byte(pointer), 0600); err != nil {
				t.Fatal(err)
			}
			user := &archive.User{UserID: recoveryUser, CrossSigning: &archive.CrossSigning{UserSigning: json.RawMessage(`{"keys":{"ed25519:signing":"signing"}}`)}}
			if err := recoverVerifications(t.Context(), dir, user); err != nil {
				t.Fatal(err)
			}
			got := string(user.Verified[peer])
			if !currentSigned {
				if got != "" {
					t.Fatal("recovery restored retired-master trust although current master is unsigned")
				}
			} else if !strings.Contains(got, "ed25519:a-current") || strings.Contains(got, "ed25519:z-retired") {
				t.Fatal("recovery selected retired master instead of the active master pointer")
			}
		})
	}
}

func TestRepairTuwunelAccountWithoutDevices(t *testing.T) {
	for _, tc := range []struct {
		name, password             string
		sender, include, recovered bool
	}{
		{name: "ambiguous sender", sender: true},
		{name: "confirmed sender", sender: true, include: true, recovered: true},
		{name: "unrelated deactivated account", include: true},
		{name: "active sender sentinel", password: "*", sender: true, recovered: true},
		{name: "active account sentinel", password: "*", recovered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, database, ldb := accountRecoveryFixture(t)
			source := filepath.Join(a.Dir, "source", "tuwunel")
			for _, table := range []string{"userdeviceid_metadata", "token_userdeviceid", "userdeviceid_refresh", "onetimekeyid4225_otk"} {
				for _, dir := range []string{source, database} {
					if err := os.WriteFile(filepath.Join(dir, table+".txt"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			password := []byte(fmt.Sprintf("0x%x ==> 0x%x\n", recoveryUser, tc.password))
			for _, dir := range []string{source, database} {
				if err := os.WriteFile(filepath.Join(dir, "userid_password.txt"), password, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.sender {
				registration := strings.ReplaceAll(testBridgeRegistration, "sender_localpart: puppet_bot", "sender_localpart: discordbot")
				if err := a.WriteServer(&archive.Server{AppserviceRegistrations: []string{registration}}); err != nil {
					t.Fatal(err)
				}
			}
			users, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, tc.include)
			if err != nil || (len(users) == 1) != tc.recovered {
				t.Fatalf("recovered=%v err=%v", users, err)
			}
			u, err := a.ReadUser(recoveryUser)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.recovered {
				if !u.Deactivated || u.Passwordless {
					t.Fatal("unconfirmed account activated")
				}
				return
			}
			if u.Deactivated || !u.Passwordless || u.DisplayName != "Discord bot" || len(u.Devices) != 0 || len(u.AccountData) != 1 || u.CrossSigning == nil {
				t.Fatalf("recovered account=%+v", u)
			}
			if backup, err := a.ReadKeyBackup(recoveryUser); err != nil || backup == nil || len(backup.Rooms) != 1 {
				t.Fatalf("recovered backup=%v err=%v", backup, err)
			}
		})
	}
}

func TestRepairTuwunelActiveSentinelWithDevices(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	row := []byte(fmt.Sprintf("0x%x ==> 0x%x\n", recoveryUser, "*"))
	for _, dir := range []string{database, filepath.Join(a.Dir, "source", "tuwunel")} {
		if err := os.WriteFile(filepath.Join(dir, "userid_password.txt"), row, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false); err != nil {
		t.Fatal(err)
	}
	u, err := a.ReadUser(recoveryUser)
	if err != nil || u.Deactivated || !u.Passwordless || len(u.Devices) != 1 {
		t.Fatalf("recovered active sentinel account=%v err=%v", u, err)
	}
}

func TestAmbiguousAppserviceSenderDoesNotBlockOtherRepairs(t *testing.T) {
	a, database, ldb := accountRecoveryFixture(t)
	const sender = "@puppet_bot:example.org"
	if err := a.WriteUser(&archive.User{UserID: sender, Deactivated: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteServer(&archive.Server{AppserviceRegistrations: []string{testBridgeRegistration}}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{database, filepath.Join(a.Dir, "source", "tuwunel")} {
		path := filepath.Join(dir, "userid_password.txt")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintf(f, "0x%x ==> 0x\n", sender)
		if closeErr := f.Close(); err != nil || closeErr != nil {
			t.Fatalf("append sender: %v %v", err, closeErr)
		}
	}
	users, err := RepairTuwunelAccounts(t.Context(), a, database, ldb, false)
	if err != nil || !slices.Equal(users, []string{recoveryUser}) {
		t.Fatalf("recovered=%v err=%v", users, err)
	}
	u, err := a.ReadUser(sender)
	if err != nil || !u.Deactivated || u.Passwordless {
		t.Fatalf("ambiguous sender changed: %v %v", u, err)
	}
}

func TestRegisteredAppserviceSenderStatus(t *testing.T) {
	for _, password := range []string{"", "*"} {
		t.Run(fmt.Sprintf("password=%q", password), func(t *testing.T) {
			a, _, _ := accountRecoveryFixture(t)
			const sender = "@puppet_bot:example.org"
			u := &archive.User{UserID: sender, Deactivated: true}
			if err := a.WriteUser(u); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(a.Dir, "source", "tuwunel")
			path := filepath.Join(source, "userid_password.txt")
			row := []byte(fmt.Sprintf("0x%x ==> 0x%x\n", sender, password))
			if err := os.WriteFile(path, row, 0600); err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Migrated: map[string]bool{sender: true}, DeactivatedIDOnly: true}
			users, err := im.FilterBridgeAccounts(t.Context(), []*archive.User{u}, &archive.Server{AppserviceRegistrations: []string{testBridgeRegistration}})
			if password == "*" {
				if err == nil || !strings.Contains(err.Error(), "active in the checkpoint") {
					t.Fatalf("active sender allowed ID-only deactivation: %v", err)
				}
				return
			}
			if err != nil || len(users) != 1 || !slices.Equal(im.deactivatedAppserviceSenders, []string{sender}) {
				t.Fatalf("deactivated sender=%v notes=%v err=%v", users, im.deactivatedAppserviceSenders, err)
			}
			if err := im.CheckLosslessImport(users, nil, nil, false); err != nil {
				t.Fatalf("explicit deactivated ID policy refused: %v", err)
			}
		})
	}
}

func TestTuwunelTablesExistInV194(t *testing.T) {
	families := tuwunel194Families(t)
	tables := slices.Concat([]string{"userid_password", "token_userdeviceid", "userdeviceid_refresh"},
		tuwunelExtraMaps, tuwunelRelayMaps, accountCheckpointTables, accountRecoveryTables)
	docs, err := os.ReadFile("../../docs/tuwunel.md")
	if err != nil {
		t.Fatal(err)
	}
	_, script, _ := strings.Cut(string(docs), "for table in \\\n")
	script, _, _ = strings.Cut(script, "\ndo\n")
	scripted := strings.Fields(strings.ReplaceAll(script, "\\", ""))
	if len(scripted) < 20 {
		t.Fatal("extraction script not found in docs/tuwunel.md")
	}
	tables = append(tables, scripted...)
	for _, table := range tables {
		if !families[table] {
			t.Errorf("%s is not a Tuwunel v1.9.4 column family", table)
		}
	}
}
