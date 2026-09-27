package archive

import (
	"errors"
	"strings"
	"testing"
)

func TestIncompleteExportCannotImport(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
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
