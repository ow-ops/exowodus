package main

import (
	"os"
	"path/filepath"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/migrate"
)

func TestTuwunelResumeIdentity(t *testing.T) {
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	dump := t.TempDir()
	path := filepath.Join(dump, "global.txt")
	if err := os.WriteFile(path, []byte("snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	f := sourceFlags{url: "https://matrix.example.org", kind: "tuwunel", tuwunelDump: dump, allUsers: true, requireLossless: true, adminToken: "first"}
	source := &source{dump: &migrate.TuwunelDump{}, adminID: "@admin:example.org", users: []migrate.SynapseUser{{UserID: "@alice:example.org"}}}
	resume, err := f.exportResume(t.Context(), source, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := resume.Close(); err != nil {
		t.Fatal(err)
	}
	f.adminToken = "refreshed"
	resume, err = f.exportResume(t.Context(), source, a)
	if err != nil {
		t.Fatal(err)
	}
	resume.Close()
	original := f
	f.url = "https://different.example.org"
	if resume, err := f.exportResume(t.Context(), source, a); err == nil {
		resume.Close()
		t.Fatal("different source accepted")
	}
	f = original
	f.historyAtCheckpoint = true
	if resume, err := f.exportResume(t.Context(), source, a); err == nil {
		resume.Close()
		t.Fatal("checkpoint history reused an archive with a different history policy")
	}
	f = original
	source.users = append(source.users, migrate.SynapseUser{UserID: "@bob:example.org"})
	if resume, err := f.exportResume(t.Context(), source, a); err == nil {
		resume.Close()
		t.Fatal("different inventory accepted")
	}
	source.users = source.users[:1]
	source.users[0].Locked = true
	if resume, err := f.exportResume(t.Context(), source, a); err == nil {
		resume.Close()
		t.Fatal("changed account status accepted")
	}
	source.users[0].Locked = false
	if err := os.WriteFile(path, []byte("different snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	if resume, err := f.exportResume(t.Context(), source, a); err == nil {
		resume.Close()
		t.Fatal("different snapshot accepted")
	}
	f.allUsers = false
	if resume, err := f.exportResume(t.Context(), source, a); err == nil {
		if resume != nil {
			resume.Close()
		}
		t.Fatal("archive reused for a different export mode")
	}
	fresh, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if resume, err := f.exportResume(t.Context(), source, fresh); err != nil || resume != nil {
		t.Fatalf("single-account resume=%v error=%v", resume, err)
	}
}
