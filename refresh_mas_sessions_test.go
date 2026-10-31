package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRefreshMASSessionsHidesDatabaseCredentials(t *testing.T) {
	t.Setenv("EXOWODUS_MAS_DB", "postgres://mas:private-password@localhost/mas")
	root := newRootCmd()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"refresh-mas-sessions", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private-password") || !strings.Contains(output.String(), "--mas-db") {
		t.Fatalf("unsafe or incomplete help: %s", &output)
	}
}
