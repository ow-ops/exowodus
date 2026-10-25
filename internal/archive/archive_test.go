package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIncompleteExportCannotImport(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckExport(); err == nil {
		t.Fatal("export without a completion report accepted")
	}
	if err := a.BeginExport(); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckExport(); err == nil {
		t.Fatal("interrupted export accepted")
	}
	if err := a.FinishExport(errors.New("missing media")); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckExport(); err == nil || !strings.Contains(err.Error(), "missing media") {
		t.Fatalf("missing durable failure: %v", err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckExport(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyExportWithoutReport(t *testing.T) {
	for v := 1; v <= version; v++ {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			dir := t.TempDir()
			if err := writeJSON(filepath.Join(dir, "manifest.json"), Manifest{Version: v, ServerName: "example.org"}); err != nil {
				t.Fatal(err)
			}
			a, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			err = a.CheckExport()
			if (err == nil) != (v == 1) {
				t.Fatalf("version %d missing report: %v", v, err)
			}
		})
	}
}

func TestStreamRoomEventsFailure(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	room := "!room:example.org"
	original := []json.RawMessage{json.RawMessage(`{"event_id":"$old"}`)}
	if err := a.WriteRoomEvents(room, original); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("page failed")
	err = a.WriteRoomEventsFrom(room, func(yield func(json.RawMessage, error) bool) {
		if !yield(json.RawMessage(`{"event_id":"$partial"}`), nil) {
			return
		}
		yield(nil, failure)
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error=%v", err)
	}
	got, err := a.RoomEvents(room)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("replaced complete timeline with %s", got)
	}
	missing := a.RoomEventsIter("!missing:example.org")
	for _, err := range missing {
		if err == nil {
			t.Fatal("missing timeline accepted")
		}
	}
}

func TestStreamJSONCompatibility(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data.json")
	value := map[string]any{"raw": json.RawMessage(`{"body":"<hello>","n":9007199254740993}`), "empty": []string(nil), "map": map[string]int{"z": 2, "a": 1}}
	if err := writeJSON(p, value); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("format changed:\n%s\nwant:\n%s", got, want)
	}
	var decoded map[string]any
	if err := readJSON(p, &decoded); err != nil {
		t.Fatal(err)
	}
	invalid := map[string]json.RawMessage{"bad": json.RawMessage(`{`)}
	if err := writeJSON(p, invalid); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, want) {
		t.Fatal("failed write replaced file")
	}
	if err := os.WriteFile(p, []byte("{} {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(p, &decoded); err == nil {
		t.Fatal("accepted trailing JSON value")
	}
}

func TestArchiveVersionCompatibility(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	for _, old := range []int{1, 2, 3, 4, 5, 6, 7} {
		if err := writeJSON(path, Manifest{Version: old, ServerName: "example.org", RequireLossless: true}); err != nil {
			t.Fatal(err)
		}
		a, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.WriteRoomPDUs("!room:example.org", map[string]any{"events": []any{}}); err != nil {
			t.Fatal(err)
		}
		upgraded, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if upgraded.Manifest.Version != version || !upgraded.Manifest.RequireLossless {
			t.Fatalf("manifest=%+v", upgraded.Manifest)
		}
		if old == 1 {
			if err := upgraded.CheckExport(); err != nil {
				t.Fatalf("legacy PDU upgrade lost export status: %v", err)
			}
		}
	}
	if err := writeJSON(path, Manifest{Version: version + 1, ServerName: "example.org"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("future archive version accepted")
	}
}

func TestLegacyExportUpgradePreservesCompletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report *ExportReport
	}{
		{name: "missing legacy report"},
		{name: "complete", report: &ExportReport{Complete: true}},
		{name: "interrupted", report: &ExportReport{}},
		{name: "failed", report: &ExportReport{Error: "media failed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			a.Manifest.Version = 1
			if err := writeJSON(filepath.Join(a.Dir, "manifest.json"), a.Manifest); err != nil {
				t.Fatal(err)
			}
			if tc.report != nil {
				if err := writeJSON(filepath.Join(a.Dir, "export-report.json"), tc.report); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.UpgradeFormat(); err != nil {
				t.Fatal(err)
			}
			a, err = Open(a.Dir)
			if err != nil {
				t.Fatal(err)
			}
			want := ExportReport{Complete: true}
			if tc.report != nil {
				want = *tc.report
			}
			var got ExportReport
			if err := readJSON(filepath.Join(a.Dir, "export-report.json"), &got); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("report=%+v want=%+v err=%v", got, want, err)
			}
			if err := a.CheckExport(); (err == nil) != want.Complete {
				t.Fatalf("export status changed: %v", err)
			}
		})
	}
}
