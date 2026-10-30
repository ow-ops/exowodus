package migrate

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"exowodus/internal/archive"
)

func TestRestoreMedia(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell")
	}
	for _, tc := range []struct {
		name     string
		loadFail bool
	}{{name: "restored"}, {name: "write fails", loadFail: true}} {
		t.Run(tc.name, func(t *testing.T) {
			database := t.TempDir()
			if err := os.WriteFile(filepath.Join(database, "CURRENT"), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			write := func(base, rel, body string) {
				path := filepath.Join(base, rel)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(a.Dir, "server/media/png", "png bytes")
			write(a.Dir, "server/media/remote", "remote bytes")
			write(a.Dir, "server/media/present", "archived copy")
			if err := a.WriteServer(&archive.Server{Media: []archive.Media{
				{MXC: "mxc://example.org/png", File: "server/media/png", ContentType: "image/png", Filename: "photo.png"},
				{MXC: "mxc://matrix.org/remote", File: "server/media/remote", ContentType: "text/plain"},
				{MXC: "mxc://example.org/present", File: "server/media/present", ContentType: "image/png"},
			}}); err != nil {
				t.Fatal(err)
			}
			const user = "@alice:example.org"
			write(a.UserDir(user), "media/txt", "text bytes")
			if err := a.WriteUser(&archive.User{UserID: user, Media: []archive.Media{{MXC: "mxc://example.org/txt", File: "media/txt", ContentType: "text/plain"}}}); err != nil {
				t.Fatal(err)
			}
			loads := t.TempDir()
			existing := fmt.Sprintf("0x%x ==> 0x", append([]byte("mxc://example.org/present"), 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff))
			ldb := filepath.Join(t.TempDir(), "ldb")
			script := fmt.Sprintf(`#!/bin/sh
family=""
for arg in "$@"; do
  case "$arg" in
    --column_family=*) family="${arg#--column_family=}" ;;
    scan) printf '%%s\n' '%s'; exit 0 ;;
    load) [ %t = true ] && { echo 'Failed: IO error' >&2; exit 1; }; cat > "%s/$family"; exit 0 ;;
  esac
done
exit 2
`, existing, tc.loadFail, loads)
			if err := os.WriteFile(ldb, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			restored, kept, err := RestoreMedia(t.Context(), a, database, ldb)
			mediaDir := filepath.Join(database, "media")
			if tc.loadFail {
				entries, _ := os.ReadDir(mediaDir)
				if err == nil || len(entries) != 0 {
					t.Fatalf("failed write left %d files: %v", len(entries), err)
				}
				return
			}
			if err != nil || restored != 2 || kept != 1 {
				t.Fatalf("restored=%d kept=%d err=%v", restored, kept, err)
			}
			rows, _ := os.ReadFile(filepath.Join(loads, "mediaid_file"))
			owners, _ := os.ReadFile(filepath.Join(loads, "mediaid_user"))
			for mxc, want := range map[string]struct{ disposition, contentType, body string }{
				"mxc://example.org/png": {"inline; filename=photo.png", "image/png", "png bytes"},
				"mxc://example.org/txt": {"", "text/plain", "text bytes"},
			} {
				key := append(append([]byte(mxc), 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0xff), want.disposition...)
				key = append(append(key, 0xff), want.contentType...)
				if !strings.Contains(string(rows), fmt.Sprintf("0x%x ==> 0x\n", key)) {
					t.Fatalf("missing row for %s in %q", mxc, rows)
				}
				digest := sha256.Sum256(key)
				body, err := os.ReadFile(filepath.Join(mediaDir, base64.RawURLEncoding.EncodeToString(digest[:])))
				if err != nil || string(body) != want.body {
					t.Fatalf("%s file = %q, %v", mxc, body, err)
				}
			}
			if strings.Contains(string(rows), fmt.Sprintf("%x", "mxc://matrix.org")) || strings.Contains(string(rows), fmt.Sprintf("%x", "mxc://example.org/present")) {
				t.Fatal("remote or existing media was written")
			}
			if want := fmt.Sprintf("0x%x ==> 0x%x\n", "mxc://example.org/txt\xff"+user, user); string(owners) != want {
				t.Fatalf("owner rows = %q, want %q", owners, want)
			}
		})
	}
}
