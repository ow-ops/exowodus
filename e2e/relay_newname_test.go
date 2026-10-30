//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"exowodus/internal/mx"
)

// TestRelayNewServerName moves a local-only room to a new server name through the relay.
func TestRelayNewServerName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	src := mx.MustNew(synapseURL, "")
	admin := login(t, ctx, src, "admin")
	for _, u := range []string{"carl", "dina"} {
		must(t, do(ctx, admin, http.MethodPut, "/_synapse/admin/v2/users/@"+u+":synapse", nil,
			map[string]any{"password": u + "-password"}, nil))
	}
	carl := login(t, ctx, src, "carl")
	dina := login(t, ctx, src, "dina")
	room := createRoom(t, ctx, carl, map[string]any{"preset": "private_chat", "name": "Old local room", "invite": []string{"@dina:synapse"}})
	must(t, do(ctx, dina, http.MethodPost, urlPath("/_matrix/client/v3/join", room), nil, struct{}{}, nil))
	carlMsg := send(t, ctx, carl, room, "m.room.message", map[string]any{"msgtype": "m.text", "body": "carl history"})
	dinaMsg := send(t, ctx, dina, room, "m.room.message", map[string]any{"msgtype": "m.text", "body": "dina history"})
	must(t, do(ctx, carl, http.MethodPut, urlPath("/_matrix/client/v3/directory/room", "#oldlocal:synapse"), nil,
		map[string]string{"room_id": room}, nil))
	must(t, do(ctx, carl, http.MethodPut, urlPath("/_matrix/client/v3/rooms", room, "state", "m.room.canonical_alias"), nil,
		map[string]string{"alias": "#oldlocal:synapse"}, nil))

	w := filepath.Join(workDir(t), "synapse")
	dir := t.TempDir()
	exowodus(t, "export", "--from", synapseURL, "--from-admin-token", admin.AccessToken, "--users", "@carl:synapse,@dina:synapse",
		"--synapse-db", filepath.Join(w, "homeserver.db"), "--synapse-signing-key", filepath.Join(w, "synapse.signing.key"),
		"--archive", dir)

	cadmin := login(t, ctx, mx.MustNew(continuURL, ""), "cadmin")
	out := exowodus(t, "import", "--to", continuURL, "--registration-token", regToken, "--to-admin-token", cadmin.AccessToken,
		"--relay-name", "host.docker.internal:38021", "--relay-listen", "0.0.0.0:38021", "--archive", dir)
	t.Log(out)
	for _, want := range []string{
		"room " + room + " -> " + room + ":",
		"@carl:synapse -> @carl:continuwuity: 1/1 rooms joined, 0 failures",
		"@dina:synapse -> @dina:continuwuity: 1/1 rooms joined, 0 failures",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q", want)
		}
	}

	newCarl, err := mx.Login(ctx, mx.MustNew(continuURL, ""), "carl", password(t, dir, "@carl:synapse"))
	must(t, err)
	events := roomEvents(t, ctx, newCarl, room)
	for id, sender := range map[string]string{carlMsg: "@carl:synapse", dinaMsg: "@dina:synapse"} {
		if !slices.ContainsFunc(events, func(ev timelineEvent) bool { return ev.EventID == id && ev.Sender == sender }) {
			t.Fatalf("original event %s from %s missing", id, sender)
		}
	}
	var pl struct {
		Users map[string]int `json:"users"`
	}
	must(t, do(ctx, newCarl, http.MethodGet, urlPath("/_matrix/client/v3/rooms", room, "state", "m.room.power_levels"), nil, nil, &pl))
	if pl.Users["@carl:continuwuity"] != 100 {
		t.Fatalf("power levels = %v", pl.Users)
	}
	resolved := resolveAlias(t, ctx, newCarl, "#oldlocal:continuwuity")
	if resolved != room {
		t.Fatalf("#oldlocal:continuwuity -> %s, want %s", resolved, room)
	}
}
