package archive

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestExportCheckpoints(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	source := ExportSource{Fingerprint: "source", Dump: map[string]string{"global.txt": "hash"}}
	r, err := a.OpenExportResume(t.Context(), source, false)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(a.Dir, "artifact")
	if err := os.WriteFile(artifact, []byte("complete"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(t.Context(), "rooms", "!room:example.org", []string{artifact}, ExportCheckpoint{Tip: "$event"}); err != nil {
		t.Fatal(err)
	}
	if other, err := a.OpenExportResume(t.Context(), source, false); err == nil {
		other.Close()
		t.Fatal("concurrent export accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = a.OpenExportResume(t.Context(), source, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	checkpoint, err := r.Load(t.Context(), "rooms", "!room:example.org")
	if err != nil || checkpoint == nil || checkpoint.Tip != "$event" {
		t.Fatalf("checkpoint=%+v error=%v", checkpoint, err)
	}
	if err := os.WriteFile(artifact, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if checkpoint, err := r.Load(t.Context(), "rooms", "!room:example.org"); err != nil || checkpoint != nil {
		t.Fatalf("modified artifact accepted: %+v %v", checkpoint, err)
	}
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if checkpoint, err := r.Load(t.Context(), "rooms", "!room:example.org"); err != nil || checkpoint != nil {
		t.Fatalf("missing artifact accepted: %+v %v", checkpoint, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.Save(ctx, "rooms", "room", []string{filepath.Join(a.Dir, "manifest.json")}, ExportCheckpoint{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	if err := r.Save(t.Context(), "rooms", "outside", []string{filepath.Join(t.TempDir(), "file")}, ExportCheckpoint{}); err == nil {
		t.Fatal("outside path accepted")
	}
}

func TestExportSourceCannotChange(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	source := ExportSource{Fingerprint: "first", Dump: map[string]string{"global.txt": "first"}}
	r, err := a.OpenExportResume(t.Context(), source, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []ExportSource{
		{Fingerprint: "second", Dump: source.Dump},
		{Fingerprint: source.Fingerprint, Dump: map[string]string{"global.txt": "second"}},
	} {
		if r, err := a.OpenExportResume(t.Context(), changed, false); err == nil {
			r.Close()
			t.Fatal("changed source accepted")
		}
	}
	r, err = a.OpenExportResume(t.Context(), source, false)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

func TestLegacyExportRequiresMatchingRetainedDump(t *testing.T) {
	for _, match := range []bool{true, false} {
		t.Run(map[bool]string{true: "matching", false: "changed"}[match], func(t *testing.T) {
			a, err := Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			dump := t.TempDir()
			if err := os.WriteFile(filepath.Join(dump, "global.txt"), []byte("source"), 0600); err != nil {
				t.Fatal(err)
			}
			hashes, err := HashExportDump(t.Context(), dump)
			if err != nil {
				t.Fatal(err)
			}
			retained := filepath.Join(a.Dir, "source", "tuwunel")
			if err := os.MkdirAll(retained, 0700); err != nil {
				t.Fatal(err)
			}
			body := "source"
			if !match {
				body = "changed"
			}
			if err := os.WriteFile(filepath.Join(retained, "global.txt"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(a.RoomDir("!room:example.org"), 0700); err != nil {
				t.Fatal(err)
			}
			r, err := a.OpenExportResume(t.Context(), ExportSource{Fingerprint: "source", Dump: hashes}, true)
			if !match {
				if err == nil {
					r.Close()
					t.Fatal("changed retained dump accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if !r.CanReuseLegacyHistory() {
				t.Fatal("matching retained dump rejected")
			}
			if err := r.RetainDump(t.Context(), dump); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dump, "global.txt"), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := r.RetainDump(t.Context(), dump); err == nil {
				t.Fatal("dump changed during export accepted")
			}
		})
	}
}

func TestExportLockReleasedAfterCrash(t *testing.T) {
	if dir := os.Getenv("EXODUS_EXPORT_LOCK_HELPER"); dir != "" {
		a, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		r, err := a.OpenExportResume(t.Context(), ExportSource{Fingerprint: "source"}, false)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := os.WriteFile(filepath.Join(dir, "locked"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExportLockReleasedAfterCrash$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "EXODUS_EXPORT_LOCK_HELPER="+a.Dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(a.Dir, "locked")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not acquire the export lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if r, err := a.OpenExportResume(t.Context(), ExportSource{Fingerprint: "source"}, false); err == nil {
		r.Close()
		t.Fatal("concurrent export accepted")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	r, err := a.OpenExportResume(t.Context(), ExportSource{Fingerprint: "source"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
