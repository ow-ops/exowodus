package archive

import (
	"encoding/csv"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialUpsert(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	first := Credential{SourceUserID: "@alice:example.org", DestUserID: "@alice:example.org", Password: "old"}
	other := Credential{SourceUserID: "@bob:example.org", DestUserID: "@bob:example.org", Password: "with,comma\nand newline"}
	for _, credential := range []Credential{first, other} {
		if err := a.AddCredential(credential); err != nil {
			t.Fatal(err)
		}
	}
	first.Password = "replacement"
	if err := a.AddCredential(first); err != nil {
		t.Fatal(err)
	}
	got, err := a.Credentials()
	if err != nil || !reflect.DeepEqual(got, map[string]Credential{first.SourceUserID: first, other.SourceUserID: other}) {
		t.Fatalf("credentials=%v err=%v", got, err)
	}
	raw, err := os.ReadFile(a.CredentialsPath())
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil || len(records) != 3 {
		t.Fatalf("CSV records=%d err=%v", len(records), err)
	}
	info, err := os.Stat(a.CredentialsPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential file permissions: %v %v", info, err)
	}
}

func TestCredentialUpsertPreservesUnreadableCSV(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	const malformed = "source_user_id,dest_user_id,password\n\"unfinished"
	if err := os.WriteFile(a.CredentialsPath(), []byte(malformed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.AddCredential(Credential{SourceUserID: "@alice:example.org", Password: "new"}); err == nil {
		t.Fatal("overwrote malformed credentials")
	}
	raw, err := os.ReadFile(a.CredentialsPath())
	if err != nil || string(raw) != malformed {
		t.Fatalf("original credentials changed: %v", err)
	}
}
