package migrate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

func TestSkipRemoteDatabaseMedia(t *testing.T) {
	for _, missingLocal := range []bool{false, true} {
		t.Run(fmt.Sprint(missingLocal), func(t *testing.T) {
			downloads := 0
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/versions") {
					_, _ = fmt.Fprint(w, `{"versions":["v1.11"]}`)
					return
				}
				downloads++
				if r.URL.Path != "/_matrix/client/v1/media/download/example.org/local" {
					t.Errorf("remote media or legacy API requested: %s", r.URL)
				}
				if missingLocal {
					w.WriteHeader(http.StatusNotFound)
					_, _ = fmt.Fprint(w, `{"errcode":"M_NOT_FOUND","error":"missing local upload"}`)
					return
				}
				_, _ = fmt.Fprint(w, "local upload")
			}))
			defer source.Close()
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			e := Exporter{Archive: a, Admin: mx.MustNew(source.URL, "token"),
				TuwunelDump: &TuwunelDump{maps: map[string]map[string][]byte{"mediaid_file": {
					"mxc://remote.org/cached": nil, "mxc://example.org/local": nil,
				}}},
			}
			srv := &archive.Server{}
			err = e.exportTuwunelMedia(t.Context(), srv)
			if (err != nil) != missingLocal {
				t.Fatalf("local upload error: %v", err)
			}
			if downloads != 1 || !srv.SkippedRemoteMedia || len(srv.UnavailableMedia) != 0 {
				t.Fatalf("downloads=%d server=%+v", downloads, srv)
			}
			if !missingLocal && (len(srv.Media) != 1 || srv.Media[0].MXC != "mxc://example.org/local") {
				t.Fatalf("local upload not preserved: %+v", srv.Media)
			}
		})
	}
}

func TestSkipRemoteAvatar(t *testing.T) {
	downloads := 0
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			_, _ = fmt.Fprint(w, `{"versions":["v1.11"]}`)
			return
		}
		downloads++
		if r.URL.Path != "/_matrix/client/v1/media/download/example.org/avatar" {
			t.Errorf("remote avatar or legacy API requested: %s", r.URL)
		}
		_, _ = fmt.Fprint(w, "avatar")
	}))
	defer source.Close()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	e := Exporter{Archive: a, TuwunelDump: &TuwunelDump{}}
	session := &Session{UserID: "@alice:example.org", Client: mx.MustNew(source.URL, "token")}
	media, err := e.exportMedia(t.Context(), session, "mxc://remote.org/avatar")
	if err != nil || len(media) != 0 || downloads != 0 {
		t.Fatalf("remote avatar was downloaded: media=%v downloads=%d err=%v", media, downloads, err)
	}
	media, err = e.exportMedia(t.Context(), session, "mxc://example.org/avatar")
	if err != nil || len(media) != 1 || downloads != 1 {
		t.Fatalf("local avatar not preserved: media=%v downloads=%d err=%v", media, downloads, err)
	}
}
