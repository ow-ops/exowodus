package migrate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"exowodus/internal/mx"
)

func TestListSynapseUsersPagination(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pages   []string
		offsets []string
		want    []string
		fail    string
	}{
		{name: "local accounts only", pages: []string{`{"users":[{"name":"@alice:example.org"},{"name":"@remote:elsewhere.org"},{"name":"@looks:example.org.evil"}],"next_token":"3"}`, `{"users":[{"name":"@gone:example.org"}],"next_token":null}`}, offsets: []string{"", "3"}, want: []string{"@alice:example.org", "@gone:example.org"}},
		{name: "numeric token", pages: []string{`{"users":[{"name":"@alice:example.org"}],"next_token":9007199254740993}`, `{"users":[{"name":"@bob:example.org"}]}`}, offsets: []string{"", "9007199254740993"}, want: []string{"@alice:example.org", "@bob:example.org"}},
		{name: "empty inventory", pages: []string{`{"users":[]}`}, offsets: []string{""}},
		{name: "repeated offset", pages: []string{`{"users":[{"name":"@alice:example.org"}],"next_token":"1"}`, `{"users":[{"name":"@bob:example.org"}],"next_token":"1"}`}, offsets: []string{"", "1"}, fail: "did not advance"},
		{name: "empty page with next token", pages: []string{`{"users":[],"next_token":"500"}`}, offsets: []string{""}, fail: "did not advance"},
		{name: "duplicate account", pages: []string{`{"users":[{"name":"@alice:example.org"}],"next_token":"1"}`, `{"users":[{"name":"@alice:example.org"}],"next_token":"2"}`}, offsets: []string{"", "1"}, fail: "duplicate source user"},
		{name: "invalid token", pages: []string{`{"users":[{"name":"@alice:example.org"}],"next_token":true}`}, offsets: []string{""}, fail: "did not advance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(calls.Add(1)) - 1
				if n >= len(tc.pages) {
					t.Error("pagination did not stop")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if r.URL.Path != "/_synapse/admin/v2/users" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				q := r.URL.Query()
				if q.Get("user_id") != ":example.org" || q.Get("deactivated") != "true" || q.Get("locked") != "true" || q.Get("guests") != "true" {
					t.Errorf("query=%s", r.URL.RawQuery)
				}
				if q.Get("from") != tc.offsets[n] {
					t.Errorf("from=%s want=%s", q.Get("from"), tc.offsets[n])
				}
				_, _ = fmt.Fprint(w, tc.pages[n])
			}))
			defer server.Close()
			admin := mx.MustNew(server.URL, "token")
			admin.UserID = "@admin:example.org"
			got, err := listSynapseUsers(t.Context(), admin, true)
			if tc.fail != "" {
				if err == nil || !strings.Contains(err.Error(), tc.fail) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("users=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestListSynapseMediaStopsWhenPaginationRepeats(t *testing.T) {
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 3 {
			t.Error("media pagination kept requesting the same page")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"media":[{"media_id":"m"}],"next_token":1}`)
	}))
	defer api.Close()
	_, err := listSynapseMedia(t.Context(), mx.MustNew(api.URL, "admin"), "@alice:example.org")
	if err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("err = %v", err)
	}
}
