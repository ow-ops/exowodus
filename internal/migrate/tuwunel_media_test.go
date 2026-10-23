package migrate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"exodus/internal/archive"
	"exodus/internal/mx"
)

func TestTuwunelUnavailableMedia(t *testing.T) {
	for _, tc := range []struct {
		name, server, code string
		status             int
		skip, fail         bool
	}{
		{"missing remote", "remote.org", "M_NOT_FOUND", 404, true, false},
		{"missing local", "example.org", "M_NOT_FOUND", 404, false, true},
		{"remote forbidden", "remote.org", "M_FORBIDDEN", 403, false, true},
		{"invalid token", "remote.org", "M_UNKNOWN_TOKEN", 401, false, true},
		{"remote unavailable", "remote.org", "M_UNKNOWN", 503, false, true},
		{"wrong route", "remote.org", "M_UNRECOGNIZED", 404, false, true},
		{"available remote", "remote.org", "", 200, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_matrix/media/v3/config" {
					_, _ = fmt.Fprint(w, `{"m.upload.size":1000000}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/versions") {
					_, _ = fmt.Fprint(w, `{"versions":["v1.11"]}`)
					return
				}
				if r.URL.Path != "/_matrix/media/v3/download/"+tc.server+"/file" ||
					r.URL.Query().Get("allow_remote") != "false" ||
					r.URL.Query().Get("allow_redirect") != "false" ||
					r.URL.Query().Get("timeout_ms") != "0" {
					t.Errorf("media request can fetch remotely: %s", r.URL)
				}
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					_, _ = fmt.Fprint(w, "media")
					return
				}
				_, _ = fmt.Fprintf(w, `{"errcode":%q,"error":"unavailable"}`, tc.code)
			}))
			defer source.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			mxc := "mxc://" + tc.server + "/file"
			client := mx.MustNew(source.URL, "token")
			client.DefaultHTTPRetries = 0
			e := Exporter{Archive: a, Admin: client, TuwunelDump: &TuwunelDump{maps: map[string]map[string][]byte{"mediaid_file": {mxc: nil}}}}
			server := &archive.Server{}
			err = e.exportTuwunelMedia(t.Context(), server)
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v", err)
			}
			if tc.skip {
				if !reflect.DeepEqual(server.UnavailableMedia, []string{mxc}) || len(server.Media) != 0 {
					t.Fatalf("server=%+v", server)
				}
				if err := a.WriteServer(server); err != nil {
					t.Fatal(err)
				}
				saved, err := a.ReadServer()
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(saved.UnavailableMedia, server.UnavailableMedia) {
					t.Fatal("missing media was not recorded")
				}
			} else if len(server.UnavailableMedia) != 0 {
				t.Fatal("unexpected skipped media")
			}
			if tc.status == 200 && len(server.Media) != 1 {
				t.Fatal("available media omitted")
			}
		})
	}
}

func TestTuwunelLegacyMediaDisabled(t *testing.T) {
	for _, skipMissing := range []bool{false, true} {
		t.Run(fmt.Sprint(skipMissing), func(t *testing.T) {
			requests := 0
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path != "/_matrix/media/v3/config" {
					t.Errorf("download attempted without cache-only support: %s", r.URL)
				}
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, `{"errcode":"M_NOT_FOUND","error":"disabled"}`)
			}))
			defer source.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			e := Exporter{
				Archive: a, Admin: mx.MustNew(source.URL, "token"), SkipMissingMedia: skipMissing,
				TuwunelDump: &TuwunelDump{maps: map[string]map[string][]byte{"mediaid_file": {"mxc://remote.org/file": nil}}},
			}
			server := &archive.Server{}
			err = e.exportTuwunelMedia(t.Context(), server)
			if err == nil || !strings.Contains(err.Error(), "allow_legacy_media = true") {
				t.Fatalf("missing cache-only API: %v", err)
			}
			if requests != 1 || len(server.UnavailableMedia) != 0 {
				t.Fatalf("disabled API was treated as missing media: requests=%d unavailable=%v", requests, server.UnavailableMedia)
			}
		})
	}
}
