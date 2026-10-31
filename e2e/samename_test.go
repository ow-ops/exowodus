//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"exowodus/internal/archive"
	"exowodus/internal/migrate"
	"exowodus/internal/mx"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

const samenameURL = "http://127.0.0.1:38010"

// TestSameServerName replaces the "samename" Synapse with Continuwuity.
func TestSameServerName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	src := mx.MustNew(samenameURL, "")
	sadmin := login(t, ctx, src, "sadmin")
	dave := login(t, ctx, src, "dave")
	erin := login(t, ctx, src, "erin")
	alice := login(t, ctx, mx.MustNew(synapseURL, ""), "alice")

	// A room only samename participates in, with history to replay.
	local := createRoom(t, ctx, dave, map[string]any{"preset": "private_chat", "name": "Local", "invite": []string{"@erin:samename"}})
	must(t, do(ctx, erin, http.MethodPost, urlPath("/_matrix/client/v3/join", local), nil, struct{}{}, nil))
	hello := send(t, ctx, dave, local, "m.room.message", map[string]any{"msgtype": "m.text", "body": "hello"})
	reply := send(t, ctx, erin, local, "m.room.message", map[string]any{
		"msgtype": "m.text", "body": "hi dave",
		"m.relates_to": map[string]any{"m.in_reply_to": map[string]string{"event_id": hello}},
	})
	send(t, ctx, dave, local, "m.reaction", map[string]any{
		"m.relates_to": map[string]string{"rel_type": "m.annotation", "event_id": reply, "key": "+1"},
	})
	send(t, ctx, dave, local, "m.room.message", map[string]any{
		"msgtype": "m.text", "body": "* hello!",
		"m.new_content": map[string]string{"msgtype": "m.text", "body": "hello!"},
		"m.relates_to":  map[string]string{"rel_type": "m.replace", "event_id": hello},
	})
	image := upload(t, ctx, dave, avatarBytes, "image/png")
	send(t, ctx, dave, local, "m.room.message", map[string]any{"msgtype": "m.image", "body": "pic.png", "url": image})
	backup := createKeyBackup(t, ctx, dave, local)

	// A user of another server posts, then leaves: the room is local-only again.
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", local, "invite"), nil,
		map[string]string{"user_id": "@alice:synapse"}, nil))
	waitForInvite(t, ctx, alice, local)
	must(t, do(ctx, alice, http.MethodPost, urlPath("/_matrix/client/v3/join", local), url.Values{"via": {"samename"}}, struct{}{}, nil))
	remoteMsg := send(t, ctx, alice, local, "m.room.message", map[string]any{"msgtype": "m.text", "body": "from another server"})
	waitForEvent(t, ctx, dave, local, remoteMsg)
	must(t, do(ctx, alice, http.MethodPost, urlPath("/_matrix/client/v3/rooms", local, "leave"), nil, struct{}{}, nil))
	oops := send(t, ctx, dave, local, "m.room.message", map[string]any{"msgtype": "m.text", "body": "oops"})
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/rooms", local, "redact", oops, "r1"), nil,
		map[string]string{"reason": "typo"}, nil))

	// A user who posted, then was deactivated.
	must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v2/users/@frank:samename", nil,
		map[string]any{"password": "frank-password", "displayname": "Frank"}, nil))
	frank := login(t, ctx, src, "frank")
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", local, "invite"), nil,
		map[string]string{"user_id": "@frank:samename"}, nil))
	must(t, do(ctx, frank, http.MethodPost, urlPath("/_matrix/client/v3/join", local), nil, struct{}{}, nil))
	send(t, ctx, frank, local, "m.room.message", map[string]any{"msgtype": "m.text", "body": "frank was here"})
	must(t, do(ctx, sadmin, http.MethodPost, "/_synapse/admin/v1/deactivate/@frank:samename", nil, map[string]bool{"erase": false}, nil))
	var erinJoin struct {
		OriginServerTS int64 `json:"origin_server_ts"`
	}
	must(t, do(ctx, dave, http.MethodGet, urlPath("/_matrix/client/v3/rooms", local, "state", "m.room.member", "@erin:samename"), url.Values{"format": {"event"}}, nil, &erinJoin))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/rooms", local, "state", "m.room.topic"), nil,
		map[string]string{"topic": "local topic"}, nil))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/directory/room", "#local:samename"), nil,
		map[string]string{"room_id": local}, nil))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/rooms", local, "state", "m.room.canonical_alias"), nil,
		map[string]string{"alias": "#local:samename"}, nil))
	var helloEvent struct {
		OriginServerTS int64 `json:"origin_server_ts"`
	}
	must(t, do(ctx, dave, http.MethodGet, urlPath("/_matrix/client/v3/rooms", local, "event", hello), nil, nil, &helloEvent))

	putAccountData(t, ctx, dave, "@dave:samename", "m.direct", map[string][]string{"@erin:samename": {local}})
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/user", "@dave:samename", "rooms", local, "tags", "m.favourite"), nil,
		map[string]float64{"order": 0.1}, nil))

	// A version 12 room, whose ID is the hash of its create event.
	v12 := createRoom(t, ctx, dave, map[string]any{"preset": "private_chat", "name": "V12", "room_version": "12"})
	send(t, ctx, dave, v12, "m.room.encrypted", map[string]any{
		"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "v12-cipher", "device_id": "D", "sender_key": "k", "session_id": "s12",
	})
	var localCreate struct {
		OriginServerTS int64 `json:"origin_server_ts"`
	}
	must(t, do(ctx, dave, http.MethodGet, urlPath("/_matrix/client/v3/rooms", local, "state", "m.room.create", ""), url.Values{"format": {"event"}}, nil, &localCreate))

	// A bridge portal room with a puppet.
	bridge := mx.MustNew(samenameURL, "fake-bridge-as-token")
	must(t, do(ctx, bridge, http.MethodPost, "/_matrix/client/v3/register", nil,
		map[string]any{"type": "m.login.application_service", "username": "fake_alice", "inhibit_login": true}, nil))
	portal := createRoom(t, ctx, dave, map[string]any{"preset": "private_chat", "name": "Portal", "invite": []string{"@fake_alice:samename"}})
	puppet := mx.As(bridge, "@fake_alice:samename")
	must(t, do(ctx, puppet, http.MethodPost, urlPath("/_matrix/client/v3/join", portal), nil, struct{}{}, nil))
	send(t, ctx, puppet, portal, "m.room.message", map[string]any{"msgtype": "m.text", "body": "from the bridge"})

	// A federated room, rejoined through synapse after the switch.
	fed := createRoom(t, ctx, alice, map[string]any{"preset": "private_chat", "name": "Federated", "invite": []string{"@dave:samename"}})
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/join", fed), url.Values{"via": {"synapse"}}, struct{}{}, nil))

	// Account-level details.
	must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v2/users/@dave:samename", nil,
		map[string]any{"threepids": []map[string]string{{"medium": "email", "address": "dave@example.org"}}}, nil))
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", local, "read_markers"), nil,
		map[string]string{"m.fully_read": hello}, nil))
	fedMsg := send(t, ctx, alice, fed, "m.room.message", map[string]any{"msgtype": "m.text", "body": "fed message"})
	waitForEvent(t, ctx, dave, fed, fedMsg)
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", fed, "read_markers"), nil,
		map[string]string{"m.fully_read": fedMsg}, nil))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/rooms", fed, "state", "m.room.member", "@dave:samename"), nil,
		map[string]string{"membership": "join", "displayname": "Dave in fed"}, nil))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/directory/room", "#fed:samename"), nil,
		map[string]string{"room_id": fed}, nil))
	must(t, do(ctx, alice, http.MethodPut, urlPath("/_matrix/client/v3/rooms", fed, "state", "m.room.power_levels"), nil,
		map[string]any{"users": map[string]int{"@alice:synapse": 100, "@dave:samename": 100}}, nil))
	waitForPower(t, ctx, dave, fed, "@dave:samename")
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/directory/list/room", fed), nil,
		map[string]string{"visibility": "public"}, nil))

	// Server-wide state.
	var synapseToken struct {
		Token string `json:"token"`
	}
	must(t, do(ctx, sadmin, http.MethodPost, "/_synapse/admin/v1/registration_tokens/new", nil, map[string]int{"uses_allowed": 3}, &synapseToken))
	must(t, do(ctx, sadmin, http.MethodPut, urlPath("/_synapse/admin/v1/rooms", "!blocked:samename", "block"), nil, map[string]bool{"block": true}, nil))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/directory/list/room", local), nil,
		map[string]string{"visibility": "public"}, nil))
	pusher := map[string]any{
		"kind": "http", "app_id": "org.example.app", "app_display_name": "Example", "device_display_name": "Phone",
		"pushkey": "pushkey-1", "lang": "en", "data": map[string]string{"url": "https://push.example.org/_matrix/push/v1/notify"},
	}
	must(t, do(ctx, dave, http.MethodPost, "/_matrix/client/v3/pushers/set", nil, pusher, nil))
	for _, u := range []string{"gina", "hank", "ivy"} {
		must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v2/users/@"+u+":samename", nil,
			map[string]any{"password": u + "-password"}, nil))
	}
	must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v2/users/@gina:samename", nil, map[string]bool{"locked": true}, nil))
	must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v1/suspend/@hank:samename", nil, map[string]bool{"suspend": true}, nil))
	must(t, do(ctx, sadmin, http.MethodPost, "/_synapse/admin/v1/deactivate/@ivy:samename", nil, map[string]bool{"erase": false}, nil))

	// A guest, and a shadow-banned user.
	var guest struct {
		UserID      string `json:"user_id"`
		AccessToken string `json:"access_token"`
	}
	must(t, do(ctx, src, http.MethodPost, "/_matrix/client/v3/register", url.Values{"kind": {"guest"}}, struct{}{}, &guest))
	must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v2/users/@kim:samename", nil, map[string]any{"password": "kim-password"}, nil))
	kim := login(t, ctx, src, "kim")
	must(t, do(ctx, sadmin, http.MethodPost, "/_synapse/admin/v1/users/@kim:samename/shadow_ban", nil, struct{}{}, nil))

	daveCS := uploadCrossSigning(t, ctx, dave, "@dave:samename", "dave-password")
	erinCS := uploadCrossSigning(t, ctx, erin, "@erin:samename", "erin-password")
	verify(t, ctx, dave, "@dave:samename", daveCS, erinCS, "@erin:samename")
	masterID := daveCS.masterID

	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/profile", "@dave:samename", "m.tz"), nil,
		map[string]string{"m.tz": "Europe/Paris"}, nil))
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", local, "receipt", "m.read", reply), nil, struct{}{}, nil))

	// A pending invite from a migrated user in a federated room.
	fed2 := createRoom(t, ctx, alice, map[string]any{"preset": "private_chat", "name": "Pending", "invite": []string{"@erin:samename"}})
	must(t, do(ctx, erin, http.MethodPost, urlPath("/_matrix/client/v3/join", fed2), url.Values{"via": {"synapse"}}, struct{}{}, nil))
	must(t, do(ctx, erin, http.MethodPost, urlPath("/_matrix/client/v3/rooms", fed2, "invite"), nil, map[string]string{"user_id": "@dave:samename"}, nil))
	daveDevice, daveDeviceKey := uploadDeviceKeys(t, ctx, dave, "@dave:samename")
	must(t, do(ctx, dave, http.MethodPost, "/_matrix/client/v3/keys/upload", nil, map[string]any{
		"one_time_keys": map[string]any{"signed_curve25519:AAAAAQ": map[string]any{
			"key": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo", "signatures": map[string]any{},
		}},
	}, nil))
	dehydratedKeys, _ := deviceKeys(t, "@dave:samename", "DEHYDRATED1")
	must(t, do(ctx, dave, http.MethodPut, "/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device", nil, map[string]any{
		"device_id": "DEHYDRATED1", "initial_device_display_name": "Dehydrated",
		"device_data":   map[string]string{"algorithm": "m.dehydration.v1.olm", "device_pickle": "pickle"},
		"device_keys":   dehydratedKeys,
		"one_time_keys": map[string]any{}, "fallback_keys": map[string]any{},
	}, nil))
	must(t, do(ctx, dave, http.MethodPut, urlPath("/_matrix/client/v3/presence", "@dave:samename", "status"), nil,
		map[string]string{"presence": "online", "status_msg": "on holiday"}, nil))
	must(t, do(ctx, sadmin, http.MethodPut, "/_synapse/admin/v2/users/@erin:samename", nil,
		map[string]any{"external_ids": []map[string]string{{"auth_provider": "oidc-test", "external_id": "erin-sub"}}}, nil))

	// Private receipt, reports and an undelivered to-device message.
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", fed, "receipt", "m.read.private", fedMsg), nil, struct{}{}, nil))
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", local, "report", hello), nil,
		map[string]string{"reason": "spam event"}, nil))
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", fed, "report"), nil,
		map[string]string{"reason": "spam room"}, nil))
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/users", "@erin:samename", "report"), nil,
		map[string]string{"reason": "spam user"}, nil))
	must(t, do(ctx, erin, http.MethodPut, urlPath("/_matrix/client/v3/sendToDevice", "com.example.pending", "t1"), nil,
		map[string]any{"messages": map[string]any{"@dave:samename": map[string]any{daveDevice: map[string]string{"secret": "in flight"}}}}, nil))

	closed := createRoom(t, ctx, dave, map[string]any{"preset": "private_chat", "room_version": "10"})
	closedEvent := send(t, ctx, dave, closed, "m.room.message", map[string]string{"msgtype": "m.text", "body": "closed history"})
	must(t, do(ctx, dave, http.MethodPost, urlPath("/_matrix/client/v3/rooms", closed, "leave"), nil, struct{}{}, nil))

	synapseDB := filepath.Join(workDir(t), "samename", "homeserver.db")
	dir := t.TempDir()
	signingKey := filepath.Join(workDir(t), "samename", "samename.signing.key")
	exowodus(t, "export", "--from", samenameURL, "--from-admin-token", sadmin.AccessToken, "--all-users",
		"--synapse-db", synapseDB, "--synapse-signing-key", signingKey, "--from-appservice-registration", "bridge.yaml", "--archive", dir)
	if _, err := os.Stat(filepath.Join(dir, "rooms", url.PathEscape(local), "events.jsonl")); err != nil {
		t.Fatalf("local room history not exported: %v", err)
	}

	a, err := archive.Open(dir)
	must(t, err)
	archived, err := a.Rooms()
	must(t, err)
	if !slices.ContainsFunc(archived, func(r *archive.ArchivedRoom) bool { return r.RoomID == closed && r.ArchiveOnly }) {
		t.Fatal("closed room missing from server inventory export")
	}
	closedEvents, err := a.RoomEvents(closed)
	must(t, err)
	if !slices.ContainsFunc(closedEvents, func(raw json.RawMessage) bool { return strings.Contains(string(raw), closedEvent) }) {
		t.Fatal("closed-room history missing from archive")
	}

	switchCmd := exec.Command("./switch.sh")
	if out, err := switchCmd.CombinedOutput(); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}

	cadmin := login(t, ctx, mx.MustNew(samenameURL, ""), "cadmin")
	out := exowodus(t, "import", "--to", samenameURL, "--registration-token", regToken, "--to-admin-token", cadmin.AccessToken,
		"--appservice-registration", "bridge.yaml", "--relay-name", "host.docker.internal:38020", "--relay-listen", "0.0.0.0:38020",
		"--archive", dir)
	t.Log(out)
	for _, want := range []string{
		"@dave:samename -> @dave:samename: 4/4 rooms joined, 0 failures",
		"@gina:samename -> @gina:samename: 0/0 rooms joined, 0 failures",
		"@hank:samename -> @hank:samename: 0/0 rooms joined, 0 failures",
		"@ivy:samename -> @ivy:samename: 0/0 rooms joined, 0 failures",
		"@erin:samename -> @erin:samename: 2/2 rooms joined, 0 failures",
		"0 encrypted skipped, 0 failures",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Restore server admin rights") {
		t.Fatalf("admin rights were not granted:\n%s", out)
	}
	if !isServerAdmin(t, ctx, cadmin, "@sadmin:samename") {
		t.Fatal("@sadmin:samename is not a server admin")
	}

	dst := mx.MustNew(samenameURL, "")
	newDave, err := mx.Login(ctx, dst, "dave", password(t, dir, "@dave:samename"))
	must(t, err)
	joined := joinedRooms(t, ctx, newDave)
	for _, r := range []string{fed, local, portal, v12} {
		if !slices.Contains(joined, r) {
			t.Fatalf("joined rooms = %v, missing %s", joined, r)
		}
	}
	if !slices.ContainsFunc(roomEvents(t, ctx, newDave, v12), func(ev timelineEvent) bool {
		return ev.Type == "m.room.encrypted" && strings.Contains(string(ev.Content), "v12-cipher")
	}) {
		t.Fatal("encrypted message of the version 12 room not replayed")
	}
	var newCreate struct {
		OriginServerTS int64 `json:"origin_server_ts"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/rooms", local, "state", "m.room.create", ""), url.Values{"format": {"event"}}, nil, &newCreate))
	if newCreate.OriginServerTS != localCreate.OriginServerTS {
		t.Fatalf("create event ts = %d, want %d", newCreate.OriginServerTS, localCreate.OriginServerTS)
	}
	if !slices.ContainsFunc(roomEvents(t, ctx, newDave, portal), func(ev timelineEvent) bool {
		return ev.Sender == "@fake_alice:samename" && strings.Contains(string(ev.Content), "from the bridge")
	}) {
		t.Fatal("puppet message not replayed as the puppet")
	}

	resolved := resolveAlias(t, ctx, newDave, "#local:samename")
	if resolved != local {
		t.Fatalf("#local:samename -> %s, want %s", resolved, local)
	}
	var topic struct {
		Topic string `json:"topic"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/rooms", local, "state", "m.room.topic"), nil, nil, &topic))
	if topic.Topic != "local topic" {
		t.Fatalf("topic = %q", topic.Topic)
	}

	events := roomEvents(t, ctx, newDave, local)
	var newHello, newReply string
	var sawReaction, sawEdit, sawImage, sawEncrypted, sawFrank, sawRedacted, sawRedaction, sawErinJoin, sawRemote bool
	for _, ev := range events {
		var c struct {
			Body      string `json:"body"`
			URL       string `json:"url"`
			RelatesTo struct {
				RelType   string `json:"rel_type"`
				EventID   string `json:"event_id"`
				InReplyTo struct {
					EventID string `json:"event_id"`
				} `json:"m.in_reply_to"`
			} `json:"m.relates_to"`
		}
		_ = json.Unmarshal(ev.Content, &c)
		switch {
		case ev.Type == "m.room.encrypted":
			var enc struct {
				Ciphertext string `json:"ciphertext"`
				SessionID  string `json:"session_id"`
			}
			_ = json.Unmarshal(ev.Content, &enc)
			sawEncrypted = ev.Sender == "@dave:samename" && enc.Ciphertext == backup.ciphertext && enc.SessionID == backup.sessionID
		case ev.Type == "m.room.member" && ev.StateKey == "@erin:samename" && strings.Contains(string(ev.Content), `"join"`):
			sawErinJoin = ev.OriginServerTS == erinJoin.OriginServerTS
		case c.Body == "frank was here":
			sawFrank = ev.Sender == "@frank:samename"
		case ev.Type == "m.room.message" && string(ev.Content) == "{}":
			// Deleted, under its original ID.
			sawRedacted = ev.Sender == "@dave:samename" && ev.EventID == oops
		case ev.Type == "m.room.redaction":
			sawRedaction = ev.Redacts == oops || strings.Contains(string(ev.Content), oops)
		case c.Body == "from another server":
			sawRemote = ev.Sender == "@alice:synapse" && ev.EventID == remoteMsg
		case ev.Type == "m.room.message" && c.Body == "hello":
			newHello = ev.EventID
			if newHello != hello {
				t.Fatalf("hello has event ID %s, want the original %s", newHello, hello)
			}
			if ev.Sender != "@dave:samename" || ev.OriginServerTS != helloEvent.OriginServerTS {
				t.Fatalf("hello: sender %s ts %d, want @dave:samename ts %d", ev.Sender, ev.OriginServerTS, helloEvent.OriginServerTS)
			}
		case c.Body == "hi dave":
			newReply = ev.EventID
			if ev.Sender != "@erin:samename" || c.RelatesTo.InReplyTo.EventID != newHello {
				t.Fatalf("reply: sender %s in reply to %s, want %s", ev.Sender, c.RelatesTo.InReplyTo.EventID, newHello)
			}
		case ev.Type == "m.reaction":
			sawReaction = c.RelatesTo.EventID == newReply
		case c.RelatesTo.RelType == "m.replace":
			sawEdit = c.RelatesTo.EventID == newHello
		case c.URL != "":
			// Original events keep their media links, served by the proxy.
			sawImage = c.URL == image
		}
	}
	if newHello == "" || newReply == "" || !sawReaction || !sawEdit || !sawImage || !sawEncrypted || !sawFrank || !sawRedacted || !sawRedaction || !sawErinJoin || !sawRemote {
		t.Fatalf("history incomplete: hello=%q reply=%q reaction=%v edit=%v image=%v encrypted=%v frank=%v redacted=%v erinJoin=%v remote=%v redaction=%v",
			newHello, newReply, sawReaction, sawEdit, sawImage, sawEncrypted, sawFrank, sawRedacted, sawErinJoin, sawRemote, sawRedaction)
	}

	var direct map[string][]string
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/user", "@dave:samename", "account_data", "m.direct"), nil, nil, &direct))
	if !slices.Equal(direct["@erin:samename"], []string{local}) {
		t.Fatalf("m.direct = %v, want erin -> %s", direct, local)
	}
	var tags struct {
		Tags map[string]json.RawMessage `json:"tags"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/user", "@dave:samename", "rooms", local, "tags"), nil, nil, &tags))
	if _, ok := tags.Tags["m.favourite"]; !ok {
		t.Fatalf("tags = %v", tags.Tags)
	}

	var keys struct {
		Master map[string]struct {
			Keys map[string]string `json:"keys"`
		} `json:"master_keys"`
	}
	must(t, do(ctx, newDave, http.MethodPost, "/_matrix/client/v3/keys/query", nil,
		map[string]any{"device_keys": map[string][]string{"@dave:samename": {}}}, &keys))
	if _, ok := keys.Master["@dave:samename"].Keys[masterID]; !ok {
		t.Fatalf("master key %s not restored: %+v", masterID, keys.Master)
	}
	assertKeyBackup(t, ctx, newDave, local, backup)

	var devKeys struct {
		DeviceKeys map[string]map[string]struct {
			Keys map[string]string `json:"keys"`
		} `json:"device_keys"`
	}
	must(t, do(ctx, newDave, http.MethodPost, "/_matrix/client/v3/keys/query", nil,
		map[string]any{"device_keys": map[string][]string{"@dave:samename": {}}}, &devKeys))
	if got := devKeys.DeviceKeys["@dave:samename"][daveDevice].Keys["ed25519:"+daveDevice]; got != daveDeviceKey {
		t.Fatalf("device %s key = %q, want %q", daveDevice, got, daveDeviceKey)
	}

	stop := startProxy(t, dir, "127.0.0.1:38011", samenameURL, "--synapse-macaroon-secret", "e2e-shared-secret")
	defer stop()
	viaProxy := mx.MustNew(proxyURL, dave.AccessToken)
	var who struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
	}
	must(t, do(ctx, viaProxy, http.MethodGet, "/_matrix/client/v3/account/whoami", nil, nil, &who))
	type toDeviceEvent struct {
		Sender  string            `json:"sender"`
		Type    string            `json:"type"`
		Content map[string]string `json:"content"`
	}
	var toDevice struct {
		ToDevice struct {
			Events []toDeviceEvent `json:"events"`
		} `json:"to_device"`
	}
	must(t, do(ctx, viaProxy, http.MethodGet, "/_matrix/client/v3/sync", url.Values{"timeout": {"0"}}, nil, &toDevice))
	if !slices.ContainsFunc(toDevice.ToDevice.Events, func(e toDeviceEvent) bool {
		return e.Sender == "@erin:samename" && e.Type == "com.example.pending" && e.Content["secret"] == "in flight"
	}) {
		t.Fatalf("undelivered to-device message not restored: %+v", toDevice.ToDevice.Events)
	}
	if who.UserID != "@dave:samename" || who.DeviceID != daveDevice {
		t.Fatalf("old token resolves to %+v, want @dave:samename on %s", who, daveDevice)
	}
	if _, err := mx.Login(ctx, mx.MustNew(proxyURL, ""), "dave", "dave-password"); err != nil {
		t.Fatalf("login with the Synapse password through the proxy: %v", err)
	}
	if _, err := mx.Login(ctx, mx.MustNew(samenameURL, ""), "dave", "dave-password"); err != nil {
		t.Fatalf("Synapse password not set on Continuwuity: %v", err)
	}
	oldImage := filepath.Join(t.TempDir(), "old")
	_, _, err = mx.Download(ctx, viaProxy, image, oldImage)
	must(t, err)
	if got, _ := os.ReadFile(oldImage); string(got) != avatarBytes {
		t.Fatalf("old media through the proxy = %q", got)
	}
	_, imageID, _ := mx.ParseMXC(image)
	resp, err := http.Get(proxyURL + "/_matrix/federation/v1/media/download/" + imageID)
	must(t, err)
	fedBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "multipart/mixed") || !strings.Contains(string(fedBody), avatarBytes) {
		t.Fatalf("federation media: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	adm, err := migrate.NewContinuwuityAdmin(ctx, cadmin)
	must(t, err)
	list, err := adm.Run(ctx, "!admin appservices list")
	must(t, err)
	if strings.Contains(list, "exodus") || !strings.Contains(list, "fakebridge") {
		t.Fatalf("appservices after import: %s", list)
	}
	for m, want := range map[string][]string{
		"userid_deactivated": {"@frank:samename", "@ivy:samename"},
		"userid_lock":        {"@gina:samename"},
		"userid_suspension":  {"@hank:samename"},
	} {
		keys, err := adm.Run(ctx, "!admin query raw raw-keys "+m)
		must(t, err)
		for _, u := range want {
			if !strings.Contains(keys, u) {
				t.Fatalf("%s missing from %s: %s", u, m, keys)
			}
		}
	}
	email, err := adm.Run(ctx, "!admin users get-email @dave:samename")
	must(t, err)
	if !strings.Contains(email, "dave@example.org") {
		t.Fatalf("email not restored: %s", email)
	}

	var marker struct {
		EventID string `json:"event_id"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/user", "@dave:samename", "rooms", local, "account_data", "m.fully_read"), nil, nil, &marker))
	if marker.EventID != newHello {
		t.Fatalf("local read marker = %s, want %s", marker.EventID, newHello)
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/user", "@dave:samename", "rooms", fed, "account_data", "m.fully_read"), nil, nil, &marker))
	if marker.EventID != fedMsg {
		t.Fatalf("federated read marker = %s, want %s", marker.EventID, fedMsg)
	}
	var member struct {
		DisplayName string `json:"displayname"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/rooms", fed, "state", "m.room.member", "@dave:samename"), nil, nil, &member))
	if member.DisplayName != "Dave in fed" {
		t.Fatalf("per-room name in federated room = %q", member.DisplayName)
	}
	resolved = resolveAlias(t, ctx, newDave, "#fed:samename")
	if resolved != fed {
		t.Fatalf("#fed:samename -> %s, want %s", resolved, fed)
	}
	type publicRoom struct {
		RoomID string `json:"room_id"`
	}
	var public struct {
		Chunk []publicRoom `json:"chunk"`
	}
	must(t, do(ctx, newDave, http.MethodGet, "/_matrix/client/v3/publicRooms", nil, nil, &public))
	for _, r := range []string{local, fed} {
		if !slices.ContainsFunc(public.Chunk, func(c publicRoom) bool {
			return c.RoomID == r
		}) {
			t.Fatalf("%s not in the public directory: %+v", r, public.Chunk)
		}
	}

	prefix := "registration token " + synapseToken.Token + " is now "
	i := strings.Index(out, prefix)
	if i < 0 {
		t.Fatalf("registration token not migrated:\n%s", out)
	}
	newRegToken, _, _ := strings.Cut(out[i+len(prefix):], "\n")
	if _, err := mx.Register(ctx, mx.MustNew(samenameURL, ""), "newcomer", "newcomer-password", newRegToken); err != nil {
		t.Fatalf("register with the migrated token: %v", err)
	}
	bannedList, err := adm.Run(ctx, "!admin rooms moderation list-banned-rooms")
	must(t, err)
	if !strings.Contains(bannedList, "!blocked:samename") {
		t.Fatalf("blocked room not banned: %s", bannedList)
	}
	var tz struct {
		TZ string `json:"m.tz"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/profile", "@dave:samename", "m.tz"), nil, nil, &tz))
	if tz.TZ != "Europe/Paris" {
		t.Fatalf("m.tz = %q", tz.TZ)
	}
	if got := ownReceipt(t, ctx, newDave, local, "@dave:samename", "m.read"); got != newReply {
		t.Fatalf("read receipt = %s, want %s", got, newReply)
	}
	if got := ownReceipt(t, ctx, newDave, fed, "@dave:samename", "m.read"); got != "" {
		t.Fatalf("private read receipt was made public at %s", got)
	}
	reports := adminRoomText(t, ctx, cadmin)
	for _, want := range []string{"event report received from @dave:samename", "room report received from @dave:samename",
		"user report received from @dave:samename", "spam event (reported on", "- Reported User ID: `@erin:samename`"} {
		if !strings.Contains(reports, want) {
			t.Fatalf("admin room missing %q:\n%s", want, reports)
		}
	}
	var erinKeys struct {
		Master map[string]struct {
			Signatures map[string]map[string]string `json:"signatures"`
		} `json:"master_keys"`
	}
	must(t, do(ctx, newDave, http.MethodPost, "/_matrix/client/v3/keys/query", nil,
		map[string]any{"device_keys": map[string][]string{"@erin:samename": {}}}, &erinKeys))
	if _, ok := erinKeys.Master["@erin:samename"].Signatures["@dave:samename"][daveCS.uskID]; !ok {
		t.Fatalf("dave's verification of erin not restored: %+v", erinKeys.Master)
	}
	newErin, err := mx.Login(ctx, dst, "erin", password(t, dir, "@erin:samename"))
	must(t, err)
	var invite struct {
		Membership string `json:"membership"`
	}
	must(t, do(ctx, newErin, http.MethodGet, urlPath("/_matrix/client/v3/rooms", fed2, "state", "m.room.member", "@dave:samename"), nil, nil, &invite))
	if invite.Membership != "invite" {
		t.Fatalf("dave's membership in the pending room = %q, want invite", invite.Membership)
	}

	var guestWho struct {
		UserID string `json:"user_id"`
	}
	must(t, do(ctx, mx.MustNew(proxyURL, guest.AccessToken), http.MethodGet, "/_matrix/client/v3/account/whoami", nil, nil, &guestWho))
	if guestWho.UserID != guest.UserID {
		t.Fatalf("guest session resolves to %q, want %s", guestWho.UserID, guest.UserID)
	}

	kimProxy := mx.MustNew(proxyURL, kim.AccessToken)
	kimRoom := createRoom(t, ctx, kimProxy, map[string]any{"preset": "private_chat", "name": "Kim"})
	send(t, ctx, kimProxy, kimRoom, "m.room.message", map[string]any{"msgtype": "m.text", "body": "kim's hidden message"})
	for _, ev := range roomEvents(t, ctx, kimProxy, kimRoom) {
		if strings.Contains(string(ev.Content), "kim's hidden message") {
			t.Fatal("shadow-banned message was sent")
		}
	}

	if _, err := mx.Register(ctx, mx.MustNew(proxyURL, ""), "latecomer", "latecomer-password", synapseToken.Token); err != nil {
		t.Fatalf("register with the old Synapse token through the proxy: %v", err)
	}

	var counts struct {
		Counts map[string]int `json:"one_time_key_counts"`
	}
	must(t, do(ctx, viaProxy, http.MethodPost, "/_matrix/client/v3/keys/upload", nil, map[string]any{}, &counts))
	if counts.Counts["signed_curve25519"] != 1 {
		t.Fatalf("one-time keys on the migrated device = %v", counts.Counts)
	}
	var dehydrated struct {
		DeviceID   string `json:"device_id"`
		DeviceData struct {
			Pickle string `json:"device_pickle"`
		} `json:"device_data"`
	}
	must(t, do(ctx, newDave, http.MethodGet, "/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device", nil, nil, &dehydrated))
	if dehydrated.DeviceID != "DEHYDRATED1" || dehydrated.DeviceData.Pickle != "pickle" {
		t.Fatalf("dehydrated device = %+v", dehydrated)
	}
	var status struct {
		StatusMsg string `json:"status_msg"`
	}
	must(t, do(ctx, newDave, http.MethodGet, urlPath("/_matrix/client/v3/presence", "@dave:samename", "status"), nil, nil, &status))
	if status.StatusMsg != "on holiday" {
		t.Fatalf("status message = %q", status.StatusMsg)
	}

	var pushers struct {
		Pushers []struct {
			Pushkey string `json:"pushkey"`
		} `json:"pushers"`
	}
	must(t, do(ctx, viaProxy, http.MethodGet, "/_matrix/client/v3/pushers", nil, nil, &pushers))
	if len(pushers.Pushers) != 1 || pushers.Pushers[0].Pushkey != "pushkey-1" {
		t.Fatalf("pushers = %+v", pushers.Pushers)
	}

	// SSO links need OIDC, which turns off password logins: done last.
	stop()
	if out, err := exec.Command("./enable-oidc.sh").CombinedOutput(); err != nil {
		t.Fatalf("enable OIDC: %v\n%s", err, out)
	}
	if out := exowodus(t, "link-sso", "--to", samenameURL, "--to-admin-token", cadmin.AccessToken, "--archive", dir); !strings.Contains(out, "1 users linked") {
		t.Fatalf("link-sso: %s", out)
	}
	subjects, err := adm.Run(ctx, "!admin query raw raw-keys openidsubject_localpart")
	must(t, err)
	if !strings.Contains(subjects, "erin-sub") {
		t.Fatalf("SSO subject not linked: %s", subjects)
	}
}

func send(t *testing.T, ctx context.Context, c *mautrix.Client, roomID, typ string, content any) string {
	t.Helper()
	var resp struct {
		EventID string `json:"event_id"`
	}
	path := urlPath("/_matrix/client/v3/rooms", roomID, "send", typ, rand.Text())
	must(t, do(ctx, c, http.MethodPut, path, nil, content, &resp))
	return resp.EventID
}

type timelineEvent struct {
	Type           string          `json:"type"`
	Sender         string          `json:"sender"`
	EventID        string          `json:"event_id"`
	StateKey       string          `json:"state_key"`
	Redacts        string          `json:"redacts"`
	OriginServerTS int64           `json:"origin_server_ts"`
	Content        json.RawMessage `json:"content"`
}

func roomEvents(t *testing.T, ctx context.Context, c *mautrix.Client, roomID string) []timelineEvent {
	t.Helper()
	var page struct {
		Chunk []timelineEvent `json:"chunk"`
	}
	q := url.Values{"dir": {"f"}, "limit": {"200"}}
	must(t, do(ctx, c, http.MethodGet, urlPath("/_matrix/client/v3/rooms", roomID, "messages"), q, nil, &page))
	return page.Chunk
}

func adminRoomText(t *testing.T, ctx context.Context, cadmin *mautrix.Client) string {
	t.Helper()
	room, err := cadmin.ResolveAlias(ctx, id.RoomAlias("#admins:"+cadmin.UserID.Homeserver()))
	must(t, err)
	page, err := cadmin.Messages(ctx, room.RoomID, "", "", mautrix.DirectionBackward, nil, 200)
	must(t, err)
	var b strings.Builder
	for _, ev := range page.Chunk {
		var content struct {
			Body string `json:"body"`
		}
		_ = json.Unmarshal(ev.Content.VeryRaw, &content)
		b.WriteString(content.Body + "\n")
	}
	return b.String()
}

func ownReceipt(t *testing.T, ctx context.Context, c *mautrix.Client, roomID, userID, typ string) string {
	t.Helper()
	filter := `{"room":{"rooms":["` + roomID + `"],"timeline":{"limit":1},"state":{"not_types":["*"]},"ephemeral":{"types":["m.receipt"]}}}`
	var sync struct {
		Rooms struct {
			Join map[string]struct {
				Ephemeral struct {
					Events []struct {
						Type    string          `json:"type"`
						Content json.RawMessage `json:"content"`
					} `json:"events"`
				} `json:"ephemeral"`
			} `json:"join"`
		} `json:"rooms"`
	}
	must(t, do(ctx, c, http.MethodGet, "/_matrix/client/v3/sync", url.Values{"filter": {filter}, "timeout": {"0"}}, nil, &sync))
	for _, ev := range sync.Rooms.Join[roomID].Ephemeral.Events {
		var content map[string]map[string]map[string]json.RawMessage
		if ev.Type != "m.receipt" || json.Unmarshal(ev.Content, &content) != nil {
			continue
		}
		for eventID, receipts := range content {
			if _, ok := receipts[typ][userID]; ok {
				return eventID
			}
		}
	}
	return ""
}

func waitForInvite(t *testing.T, ctx context.Context, c *mautrix.Client, roomID string) {
	t.Helper()
	for range 100 {
		var sync struct {
			Rooms struct {
				Invite map[string]json.RawMessage `json:"invite"`
			} `json:"rooms"`
		}
		if do(ctx, c, http.MethodGet, "/_matrix/client/v3/sync", url.Values{"timeout": {"0"}}, nil, &sync) == nil {
			if _, ok := sync.Rooms.Invite[roomID]; ok {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("invite to %s never arrived", roomID)
}

func waitForPower(t *testing.T, ctx context.Context, c *mautrix.Client, roomID, userID string) {
	t.Helper()
	path := urlPath("/_matrix/client/v3/rooms", roomID, "state", "m.room.power_levels")
	for range 100 {
		var pl struct {
			Users map[string]int `json:"users"`
		}
		if do(ctx, c, http.MethodGet, path, nil, nil, &pl) == nil && pl.Users[userID] == 100 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never got power in %s", userID, roomID)
}

func waitForEvent(t *testing.T, ctx context.Context, c *mautrix.Client, roomID, eventID string) {
	t.Helper()
	path := urlPath("/_matrix/client/v3/rooms", roomID, "event", eventID)
	for range 100 {
		if do(ctx, c, http.MethodGet, path, nil, nil, nil) == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("event %s never reached the server", eventID)
}

const proxyURL = "http://127.0.0.1:38011"

// startProxy runs exowodus proxy on addr; upstream may be empty.
func startProxy(t *testing.T, dir, addr, upstream string, extra ...string) func() {
	t.Helper()
	args := []string{"proxy", "--archive", dir, "--listen", addr}
	if upstream != "" {
		args = append(args, "--upstream", upstream)
	}
	args = append(args, extra...)
	cmd := exec.Command(exowodusBin, args...)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	for range 50 {
		if resp, err := http.Get("http://" + addr + "/_matrix/client/versions"); err == nil {
			resp.Body.Close()
			return stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatalf("proxy on %s did not start", addr)
	return nil
}

// deviceKeys returns signed device keys and the device's ed25519 key.
func deviceKeys(t *testing.T, userID, deviceID string) (map[string]any, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	b64 := base64.RawStdEncoding.EncodeToString
	keys := map[string]any{
		"user_id": userID, "device_id": deviceID,
		"algorithms": []string{"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"},
		"keys":       map[string]string{"curve25519:" + deviceID: b64(pub), "ed25519:" + deviceID: b64(pub)},
	}
	canonical, err := json.Marshal(keys)
	must(t, err)
	keys["signatures"] = map[string]any{userID: map[string]string{"ed25519:" + deviceID: b64(ed25519.Sign(priv, canonical))}}
	return keys, b64(pub)
}

func uploadDeviceKeys(t *testing.T, ctx context.Context, c *mautrix.Client, userID string) (deviceID, ed25519Key string) {
	t.Helper()
	who, err := c.Whoami(ctx)
	must(t, err)
	keys, pub := deviceKeys(t, userID, string(who.DeviceID))
	must(t, do(ctx, c, http.MethodPost, "/_matrix/client/v3/keys/upload", nil, map[string]any{"device_keys": keys}, nil))
	return string(who.DeviceID), pub
}

type crossSigning struct {
	masterID string
	master   map[string]any
	uskID    string
	usk      ed25519.PrivateKey
}

func uploadCrossSigning(t *testing.T, ctx context.Context, c *mautrix.Client, userID, password string) crossSigning {
	t.Helper()
	b64 := base64.RawStdEncoding.EncodeToString
	masterPub, masterPriv, _ := ed25519.GenerateKey(nil)
	cs := crossSigning{masterID: "ed25519:" + b64(masterPub)}
	key := func(usage string, pub ed25519.PublicKey) map[string]any {
		k := map[string]any{"user_id": userID, "usage": []string{usage}, "keys": map[string]string{"ed25519:" + b64(pub): b64(pub)}}
		if usage != "master" {
			canonical, err := json.Marshal(k)
			must(t, err)
			k["signatures"] = map[string]any{userID: map[string]string{cs.masterID: b64(ed25519.Sign(masterPriv, canonical))}}
		}
		return k
	}
	sskPub, _, _ := ed25519.GenerateKey(nil)
	uskPub, uskPriv, _ := ed25519.GenerateKey(nil)
	cs.uskID, cs.usk = "ed25519:"+b64(uskPub), uskPriv
	cs.master = key("master", masterPub)
	body := map[string]any{"master_key": cs.master, "self_signing_key": key("self_signing", sskPub), "user_signing_key": key("user_signing", uskPub)}
	must(t, mx.DoWithPassword(ctx, c, http.MethodPost, c.BuildClientURL("v3", "keys", "device_signing", "upload"), body, userID, password))
	return cs
}

// verify signs other's master key with the user's user-signing key.
func verify(t *testing.T, ctx context.Context, c *mautrix.Client, userID string, cs, other crossSigning, otherID string) {
	t.Helper()
	key := map[string]any{"user_id": otherID, "usage": other.master["usage"], "keys": other.master["keys"]}
	canonical, err := json.Marshal(key)
	must(t, err)
	key["signatures"] = map[string]any{userID: map[string]string{cs.uskID: base64.RawStdEncoding.EncodeToString(ed25519.Sign(cs.usk, canonical))}}
	body := map[string]any{otherID: map[string]any{strings.TrimPrefix(other.masterID, "ed25519:"): key}}
	var resp struct {
		Failures map[string]any `json:"failures"`
	}
	must(t, do(ctx, c, http.MethodPost, "/_matrix/client/v3/keys/signatures/upload", nil, body, &resp))
	if len(resp.Failures) > 0 {
		t.Fatalf("signature upload failures: %v", resp.Failures)
	}
}
