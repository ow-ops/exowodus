//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"exodus/internal/migrate"
	"exodus/internal/mx"
)

func TestKnockFailureReportsIncompleteMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	src := mx.MustNew(synapseURL, "")
	admin := login(t, ctx, src, "admin")
	for _, u := range []string{"knocker", "knockowner"} {
		must(t, do(ctx, admin, http.MethodPut, "/_synapse/admin/v2/users/@"+u+":synapse", nil, map[string]any{"password": u + "-password"}, nil))
	}
	owner := login(t, ctx, src, "knockowner")
	user := login(t, ctx, src, "knocker")
	room := createRoom(t, ctx, owner, map[string]any{"preset": "private_chat", "initial_state": []map[string]any{{"type": "m.room.join_rules", "state_key": "", "content": map[string]string{"join_rule": "knock"}}}})
	must(t, do(ctx, user, http.MethodPost, urlPath("/_matrix/client/v3/knock", room), nil, map[string]string{"reason": "hi"}, nil))
	dir := t.TempDir()
	cmd := exec.CommandContext(ctx, exodusBin, "migrate", "--from", synapseURL, "--from-token", user.AccessToken, "--to", continuURL, "--to-password", "knocker-password", "--registration-token", regToken, "--archive", dir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected incomplete migration from upstream knock failure: %s", output)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "import-report.json"))
	must(t, err)
	var report struct {
		Users    []*migrate.Report `json:"users"`
		Failures []migrate.Failure `json:"failures"`
	}
	must(t, json.Unmarshal(raw, &report))
	if len(report.Users) != 1 || len(report.Users[0].Failures) != 0 || len(report.Failures) != 1 || report.Failures[0].Step != "knock" {
		t.Fatalf("unexpected migration failure: %s\n%s", raw, output)
	}
	var knock struct {
		Membership string `json:"membership"`
	}
	must(t, do(ctx, owner, http.MethodGet, urlPath("/_matrix/client/v3/rooms", room, "state", "m.room.member", "@knocker:continuwuity"), nil, nil, &knock))
	if knock.Membership != "knock" {
		t.Fatalf("upstream knock = %q", knock.Membership)
	}
}
