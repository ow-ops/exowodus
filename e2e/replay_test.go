//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"exowodus/internal/mx"
)

func TestReplayEncryptedHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	src := mx.MustNew(synapseURL, "")
	admin := login(t, ctx, src, "admin")
	must(t, do(ctx, admin, http.MethodPut, "/_synapse/admin/v2/users/@replayuser:synapse", nil, map[string]string{"password": "replayuser-password"}, nil))
	user := login(t, ctx, src, "replayuser")
	device, _ := uploadDeviceKeys(t, ctx, user, "@replayuser:synapse")
	room := createRoom(t, ctx, user, map[string]any{"preset": "private_chat", "room_version": "10"})
	backup := createKeyBackup(t, ctx, user, room)
	dir := t.TempDir()
	exowodus(t, "export", "--from", synapseURL, "--from-token", user.AccessToken, "--synapse-db", filepath.Join(workDir(t), "synapse", "homeserver.db"), "--archive", dir)
	cmd := exec.CommandContext(ctx, "./continuwuity.sh", "exowodus-replay", "synapse", "38022")
	cmd.Env = append(os.Environ(), "NETWORK_ALIAS=exowodus-replay")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start replay destination: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "exowodus-replay").Run() })
	const destURL = "http://127.0.0.1:38022"
	dst := mx.MustNew(destURL, "")
	cadmin := login(t, ctx, dst, "cadmin")
	for range 2 {
		exowodus(t, "import", "--to", destURL, "--registration-token", regToken, "--to-admin-token", cadmin.AccessToken, "--archive", dir)
	}
	migrated, err := mx.Login(ctx, dst, "replayuser", password(t, dir, "@replayuser:synapse"))
	must(t, err)
	assertKeyBackup(t, ctx, migrated, room, backup)
	var keys struct {
		Devices map[string]map[string]any `json:"device_keys"`
	}
	must(t, do(ctx, migrated, http.MethodPost, "/_matrix/client/v3/keys/query", nil, map[string]any{"device_keys": map[string][]string{"@replayuser:synapse": {}}}, &keys))
	if _, ok := keys.Devices["@replayuser:synapse"][device]; !ok {
		t.Fatal("source token's device keys were lost")
	}
}
