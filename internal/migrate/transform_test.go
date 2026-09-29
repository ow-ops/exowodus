package migrate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"exodus/internal/mx"
	"maunium.net/go/mautrix/event"
)

func mapper(m map[string]string) func(string) string {
	return func(id string) string {
		if v, ok := m[id]; ok {
			return v
		}
		return id
	}
}

func TestTransformAccountData(t *testing.T) {
	mapID := mapper(map[string]string{"@bob:old": "@bob:new"})
	mapRoom := mapper(map[string]string{"!a:old": "!a:new"})

	tests := []struct {
		name         string
		typ          string
		content      string
		keepIdentity bool
		want         string
		skip         bool
	}{
		{name: "copied verbatim", typ: "im.vector.setting", content: `{"a":1}`, want: `{"a":1}`},
		{name: "push rules skipped", typ: "m.push_rules", content: `{}`, skip: true},
		{name: "cross signing skipped for new identity", typ: "m.cross_signing.master", content: `{}`, skip: true},
		{name: "cross signing kept for same identity", typ: "m.cross_signing.master", content: `{"x":1}`, keepIdentity: true, want: `{"x":1}`},
		{name: "secret storage copied", typ: "m.secret_storage.default_key", content: `{"key":"k"}`, want: `{"key":"k"}`},
		{name: "backup key copied", typ: "m.megolm_backup.v1", content: `{"x":1}`, want: `{"x":1}`},
		{
			name:    "direct remapped",
			typ:     "m.direct",
			content: `{"@bob:old":["!a:old"],"@eve:other":["!b:old"]}`,
			want:    `{"@bob:new":["!a:new"],"@eve:other":["!b:old"]}`,
		},
		{
			name:    "ignored users remapped",
			typ:     "m.ignored_user_list",
			content: `{"ignored_users":{"@bob:old":{}}}`,
			want:    `{"ignored_users":{"@bob:new":{}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := transformAccountData(tt.typ, json.RawMessage(tt.content), mapID, mapRoom, tt.keepIdentity)
			if err != nil {
				t.Fatal(err)
			}
			if ok == tt.skip {
				t.Fatalf("copied = %v, want %v", ok, !tt.skip)
			}
			if !tt.skip {
				assertJSONEqual(t, got, tt.want)
			}
		})
	}
}

func TestPushRuleOps(t *testing.T) {
	raw := `{"global":{
		"override":[
			{"rule_id":".m.rule.master","default":true,"enabled":false,"actions":[]},
			{"rule_id":"mine","default":false,"enabled":true,"actions":["notify"],"conditions":[{"kind":"event_match","key":"type","pattern":"x"}]},
			{"rule_id":"mine2","default":false,"enabled":false,"actions":[]}
		],
		"content":[{"rule_id":"word","default":false,"enabled":true,"actions":["notify"],"pattern":"cake"}],
		"room":[{"rule_id":"!r:old","default":false,"enabled":true,"actions":[]}],
		"sender":[{"rule_id":"@bob:old","default":false,"enabled":true,"actions":[]}]
	}}`
	ops, err := pushRuleOps(json.RawMessage(raw), mapper(map[string]string{"@bob:old": "@bob:new"}), mapper(map[string]string{"!r:old": "!r:new"}))
	if err != nil {
		t.Fatal(err)
	}

	c := mx.MustNew("http://hs", "")
	var got []string
	for _, op := range ops {
		got = append(got, strings.TrimPrefix(op.url(c), "http://hs"))
	}
	want := []string{
		"/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled",
		"/_matrix/client/v3/pushrules/global/override/.m.rule.master/actions",
		"/_matrix/client/v3/pushrules/global/override/mine",
		"/_matrix/client/v3/pushrules/global/override/mine2?after=mine",
		"/_matrix/client/v3/pushrules/global/override/mine2/enabled",
		"/_matrix/client/v3/pushrules/global/content/word",
		"/_matrix/client/v3/pushrules/global/room/%21r:new",
		"/_matrix/client/v3/pushrules/global/sender/@bob:new",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths:\n got %q\nwant %q", got, want)
	}
	if !ops[0].Optional || ops[2].Optional {
		t.Fatal("only default rule ops should be optional")
	}
	if body := ops[5].Body.(map[string]any); body["pattern"] != "cake" {
		t.Fatalf("content rule body = %v", body)
	}
}

func TestRaisePower(t *testing.T) {
	tests := []struct {
		name    string
		content string
		changed bool
		want    int64
	}{
		{name: "grants old level", content: `{"users":{"@a:old":100}}`, changed: true, want: 100},
		{name: "string levels", content: `{"users":{"@a:old":"50"},"users_default":"0"}`, changed: true, want: 50},
		{name: "default level only", content: `{"users":{},"users_default":10}`},
		{name: "already granted", content: `{"users":{"@a:old":50,"@a:new":50}}`},
		{name: "missing users", content: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var content map[string]any
			if err := json.Unmarshal([]byte(tt.content), &content); err != nil {
				t.Fatal(err)
			}
			if got := raisePower(content, "@a:old", "@a:new"); got != tt.changed {
				t.Fatalf("changed = %v, want %v", got, tt.changed)
			}
			if tt.changed {
				if got := powerValue(content["users"].(map[string]any)["@a:new"]); got != tt.want {
					t.Fatalf("level = %d, want %d", got, tt.want)
				}
			}
		})
	}
}

func assertJSONEqual(t *testing.T, got json.RawMessage, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRemapRelations(t *testing.T) {
	events := map[string]string{"$old": "$new"}
	tests := []struct {
		name    string
		content string
		keep    bool
		want    string
	}{
		{name: "no relation", content: `{"body":"x"}`, keep: true, want: `{"body":"x"}`},
		{name: "reply remapped", content: `{"m.relates_to":{"m.in_reply_to":{"event_id":"$old"}}}`, keep: true, want: `{"m.relates_to":{"m.in_reply_to":{"event_id":"$new"}}}`},
		{name: "unknown reply dropped", content: `{"body":"x","m.relates_to":{"m.in_reply_to":{"event_id":"$gone"}}}`, keep: true, want: `{"body":"x"}`},
		{name: "edit remapped", content: `{"m.relates_to":{"rel_type":"m.replace","event_id":"$old"}}`, keep: true, want: `{"m.relates_to":{"rel_type":"m.replace","event_id":"$new"}}`},
		{name: "edit of unknown skipped", content: `{"m.relates_to":{"rel_type":"m.replace","event_id":"$gone"}}`},
		{name: "reaction to unknown skipped", content: `{"m.relates_to":{"rel_type":"m.annotation","event_id":"$gone","key":"x"}}`},
		{name: "thread to unknown flattened", content: `{"body":"x","m.relates_to":{"rel_type":"m.thread","event_id":"$gone","is_falling_back":true}}`, keep: true, want: `{"body":"x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var content map[string]any
			if err := json.Unmarshal([]byte(tt.content), &content); err != nil {
				t.Fatal(err)
			}
			if got := remapRelations(content, events); got != tt.keep {
				t.Fatalf("keep = %v, want %v", got, tt.keep)
			}
			if tt.keep {
				got, _ := json.Marshal(content)
				assertJSONEqual(t, got, tt.want)
			}
		})
	}
}

func TestRewriteMXC(t *testing.T) {
	var content any
	raw := `{"url":"mxc://old/a","info":{"thumbnail_url":"mxc://old/b"},"list":["mxc://old/a","keep"]}`
	if err := json.Unmarshal([]byte(raw), &content); err != nil {
		t.Fatal(err)
	}
	media := map[string]string{"mxc://old/a": "mxc://new/1", "mxc://old/b": "mxc://new/2"}
	got, _ := json.Marshal(rewriteMXC(content, media))
	assertJSONEqual(t, got, `{"url":"mxc://new/1","info":{"thumbnail_url":"mxc://new/2"},"list":["mxc://new/1","keep"]}`)
}

func TestV12Creator(t *testing.T) {
	creator := &event.Event{
		Type:    event.StateCreate,
		Sender:  "@founder:example.org",
		Content: event.Content{VeryRaw: json.RawMessage(`{"room_version":"12"}`)},
	}
	if !isV12Creator([]*event.Event{creator}, "@founder:example.org") {
		t.Fatal("v12 creator not detected")
	}
	if isV12Creator([]*event.Event{creator}, "@other:example.org") {
		t.Fatal("non-creator detected as creator")
	}
}

func TestTransferPowerGrantsV12CreatorAdmin(t *testing.T) {
	var powerLevels map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/state/m.room.power_levels/"):
			_, _ = w.Write([]byte(`{"users_default":0}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/state"):
			_, _ = w.Write([]byte(`[{"type":"m.room.create","sender":"@founder:example.org","content":{"room_version":"12"}}]`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/state/m.room.power_levels/"):
			if err := json.NewDecoder(r.Body).Decode(&powerLevels); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{"event_id":"$power"}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	if err := transferPower(t.Context(), mx.MustNew(srv.URL, "token"), "!room:example.org", "@founder:example.org", "@founder:new.org"); err != nil {
		t.Fatal(err)
	}
	users, _ := powerLevels["users"].(map[string]any)
	if got := users["@founder:new.org"]; got != float64(100) {
		t.Fatalf("new creator power = %v", got)
	}
}
