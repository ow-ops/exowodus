package migrate

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"exodus/internal/archive"
	"maunium.net/go/mautrix/federation"
)

func TestRestoreSigningKeyRocksDB(t *testing.T) {
	ldb := os.Getenv("EXODUS_TEST_LDB")
	if ldb == "" {
		t.Skip("set EXODUS_TEST_LDB to run the real RocksDB key-transfer check")
	}
	db := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command(ldb, append([]string{"--db=" + db}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("ldb command failed: %v", err)
		}
		return out
	}
	run("--create_if_missing", "put", "bootstrap", "value")
	run("create_column_family", "global")
	old := federation.GenerateSigningKey()
	der, err := x509.MarshalPKCS8PrivateKey(old.Priv)
	if err != nil {
		t.Fatal(err)
	}
	_, version, _ := strings.Cut(string(old.ID), ":")
	record := append(append([]byte(version), 0xff), der...)
	run("--column_family=global", "put", "--hex", "0x6b657970616972", "0x"+hex.EncodeToString(record))
	run("--column_family=global", "put", "unrelated", "keep-me")
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	source := federation.GenerateSigningKey()
	_, version, _ = strings.Cut(string(source.ID), ":")
	if err := a.WriteSigningKey("ed25519 " + version + " " + base64.RawStdEncoding.EncodeToString(source.Priv.Seed())); err != nil {
		t.Fatal(err)
	}
	config, err := RestoreSigningKey(t.Context(), a, db, ldb)
	if err != nil {
		t.Fatal(err)
	}
	if config == "" {
		t.Fatal("missing old verification-key configuration")
	}
	public, err := os.ReadFile(config)
	if err != nil || !bytes.Contains(public, []byte(old.Pub)) {
		t.Fatal("previous public key was not retained")
	}
	backup := filepath.Join(a.Dir, "continuwuity-signing-key-backup.txt")
	private, err := os.ReadFile(backup)
	if err != nil || string(private) != fmt.Sprintf("0x6b657970616972 ==> 0x%x\n", record) {
		t.Fatal("previous private key was not backed up")
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private key backup is not private")
	}
	stored := strings.TrimSpace(string(run("--column_family=global", "get", "--hex", "0x6b657970616972")))
	value, err := hex.DecodeString(strings.TrimPrefix(stored, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	d := &TuwunelDump{maps: map[string]map[string][]byte{"global": {"keypair": value}}}
	keyText, err := d.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := federation.ParseSynapseKey(keyText)
	if err != nil || restored.ID != source.ID || restored.Pub != source.Pub {
		t.Fatal("destination identity changed")
	}
	if got := strings.TrimSpace(string(run("--column_family=global", "get", "unrelated"))); got != "keep-me" {
		t.Fatal("unrelated database entry changed")
	}
	if _, err := RestoreSigningKey(t.Context(), a, db, ldb); err != nil {
		t.Fatalf("key transfer is not idempotent: %v", err)
	}
}
