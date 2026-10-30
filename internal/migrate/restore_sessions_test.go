package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"exowodus/internal/archive"
)

func TestRestoreSessions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell")
	}
	const alice, bob = "@alice:example.org", "@bob:example.org"
	const argon = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
	database := t.TempDir()
	if err := os.WriteFile(filepath.Join(database, "CURRENT"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[string]archive.Session{
		"old-phone":   {UserID: alice, DeviceID: "PHONE", Token: "new-phone"},
		"old-laptop":  {UserID: alice, DeviceID: "LAPTOP", Token: "new-laptop"},
		"old-tab-1":   {UserID: bob, DeviceID: "TAB", Token: "new-tab"},
		"old-tab-2":   {UserID: bob, DeviceID: "TAB", Token: "new-tab"},
		"old-refresh": {UserID: bob, DeviceID: "DESK", Token: "new-desk", Refresh: true},
		archive.GuestSessionKey("@guest:example.org"): {UserID: "@guest:example.org", DeviceID: "G", Token: "new-guest"},
	}
	if err := a.WriteSessions(sessions); err != nil {
		t.Fatal(err)
	}
	if err := a.WritePendingPasswords(map[string]archive.PendingPassword{
		alice: {SourceUserID: alice, Hash: argon, Scheme: archive.SchemeTuwunel},
		bob:   {SourceUserID: bob, Hash: "$2b$12$synapse"},
	}); err != nil {
		t.Fatal(err)
	}
	row := func(key, value string) string { return fmt.Sprintf("0x%x ==> 0x%x", key, value) }
	scans := map[string]string{
		"userdeviceid_token": strings.Join([]string{
			row(alice+"\xffPHONE", "new-phone"),
			// Logged in again since the import.
			row(alice+"\xffLAPTOP", "changed"),
			row(bob+"\xffTAB", "new-tab"),
		}, "\n"),
		"userdeviceid_tokenexpires": row(alice+"\xffPHONE", "\x00\x00\x00\x00\x00\x00\x00\x01"),
	}
	out := t.TempDir()
	for family, rows := range scans {
		if err := os.WriteFile(filepath.Join(out, "scan-"+family), []byte(rows+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ldb := filepath.Join(t.TempDir(), "ldb")
	script := fmt.Sprintf(`#!/bin/sh
out=%q
family=""
for arg in "$@"; do
  case "$arg" in
    --column_family=*) family="${arg#--column_family=}" ;;
    scan) cat "$out/scan-$family" 2>/dev/null; exit 0 ;;
    load) cat >> "$out/load-$family"; exit 0 ;;
    delete) shift $(($# - 1)); echo "$1" >> "$out/delete-$family"; exit 0 ;;
  esac
done
exit 2
`, out)
	if err := os.WriteFile(ldb, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	tokens, passwords, kept, err := RestoreSessions(t.Context(), a, database, ldb)
	if err != nil || tokens != 1 || passwords != 1 || kept != 3 {
		t.Fatalf("tokens=%d passwords=%d kept=%d err=%v", tokens, passwords, kept, err)
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(out, name))
		return string(data)
	}
	for name, want := range map[string]string{
		"load-token_userdeviceid":          row("old-phone", alice+"\xffPHONE") + "\n",
		"load-userdeviceid_token":          row(alice+"\xffPHONE", "old-phone") + "\n",
		"load-userid_password":             row(alice, argon) + "\n",
		"delete-token_userdeviceid":        fmt.Sprintf("0x%x\n", "new-phone"),
		"delete-userdeviceid_tokenexpires": fmt.Sprintf("0x%x\n", alice+"\xffPHONE"),
	} {
		if got := read(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	left, err := a.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := left["old-phone"]; ok || len(left) != len(sessions)-1 {
		t.Fatalf("sessions left for the proxy: %v", left)
	}
	pending, err := a.PendingPasswords()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pending[alice]; ok || len(pending) != 1 {
		t.Fatalf("pending passwords: %v", pending)
	}
	if restored, err := a.PasswordRestored(alice); err != nil || !restored {
		t.Fatalf("alice's password not marked restored: %v", err)
	}

	// A rerun after the tokens were written but before the cleanup finishes
	// still removes the import's token.
	if err := a.WriteSessions(map[string]archive.Session{"old-phone": sessions["old-phone"]}); err != nil {
		t.Fatal(err)
	}
	scans["userdeviceid_token"] = row(alice+"\xffPHONE", "old-phone")
	if err := os.WriteFile(filepath.Join(out, "scan-userdeviceid_token"), []byte(scans["userdeviceid_token"]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tokens, _, _, err := RestoreSessions(t.Context(), a, database, ldb); err != nil || tokens != 1 {
		t.Fatalf("rerun restored %d: %v", tokens, err)
	}
	if got := read("delete-token_userdeviceid"); strings.Count(got, fmt.Sprintf("%x", "new-phone")) != 2 {
		t.Fatalf("rerun did not delete the import's token: %q", got)
	}
}
