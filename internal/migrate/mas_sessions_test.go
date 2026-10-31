package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
	"exowodus/internal/proxy"
)

const masRecoveryUser = "@alice:example.org"

func masRecoveryArchive(t *testing.T) *archive.Archive {
	t.Helper()
	a, err := archive.Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteUser(&archive.User{UserID: masRecoveryUser, Devices: []archive.Device{{ID: "PHONE"}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteImportState(masRecoveryUser, &archive.ImportState{DestUserID: masRecoveryUser, Devices: map[string]bool{"PHONE": true}, DeviceTokens: map[string]string{"PHONE": "destination-token"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishExport(nil); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRefreshMASSessions(t *testing.T) {
	a := masRecoveryArchive(t)
	existing := archive.Session{UserID: masRecoveryUser, DeviceID: "PHONE", Token: "destination-token", Refresh: true, OAuth: true}
	if err := a.WriteSessions(map[string]archive.Session{"exported-refresh": existing}); err != nil {
		t.Fatal(err)
	}
	checks := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/_matrix/client/v3/account/whoami" || r.Header.Get("Authorization") != "Bearer destination-token" {
			t.Errorf("unexpected destination request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		checks++
		fmt.Fprintf(w, `{"user_id":%q,"device_id":"PHONE"}`, masRecoveryUser)
	}))
	defer api.Close()
	source := func(_ context.Context, user string) ([]archive.Token, error) {
		if user != masRecoveryUser {
			t.Fatalf("source user = %s", user)
		}
		return []archive.Token{
			{Token: "exported-refresh", DeviceID: "PHONE", Refresh: true, OAuth: true},
			{Token: "rotated-refresh", DeviceID: "PHONE", Refresh: true, OAuth: true},
			{Token: "current-access", DeviceID: "PHONE", OAuth: true},
			{Token: "unrestored-refresh", DeviceID: "NEW", Refresh: true, OAuth: true},
		}, nil
	}
	for _, want := range []int{2, 0} {
		updated, failures, err := refreshMASSessions(t.Context(), a, mx.MustNew(api.URL, ""), source)
		if err != nil || updated != want || len(failures) != 1 || failures[0].Target != masRecoveryUser+"/NEW" {
			t.Fatalf("updated=%d failures=%v err=%v", updated, failures, err)
		}
	}
	if checks != 2 {
		t.Fatalf("destination checks = %d, want one per device per run", checks)
	}
	sessions, err := a.Sessions()
	if err != nil || len(sessions) != 3 || sessions["exported-refresh"] != existing || sessions["rotated-refresh"] != existing || sessions["current-access"].Refresh {
		t.Fatalf("recovered mappings = %v, err = %v", sessions, err)
	}
	upstream, _ := url.Parse(api.URL)
	p, err := proxy.New(a, upstream, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	req := httptest.NewRequest(http.MethodPost, "/_continuwuity/oauth2/grant/token", strings.NewReader("grant_type=refresh_token&refresh_token=rotated-refresh&client_id=old-mas-client"))
	response := httptest.NewRecorder()
	p.ServeHTTP(response, req)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || response.Code != http.StatusOK || token.AccessToken != "destination-token" {
		t.Fatalf("recovered refresh failed: %d %s (%v)", response.Code, response.Body, err)
	}
}

func TestRefreshMASSessionsRejectsUnverifiedDevices(t *testing.T) {
	for _, tc := range []struct {
		name, returnedUser, returnedDevice string
		status                             int
		changeState                        func(*archive.ImportState)
	}{
		{name: "wrong user", returnedUser: "@bob:example.org", returnedDevice: "PHONE"},
		{name: "wrong device", returnedUser: masRecoveryUser, returnedDevice: "OTHER"},
		{name: "expired destination token", status: http.StatusUnauthorized},
		{name: "different server", changeState: func(s *archive.ImportState) { s.DestUserID = "@alice:elsewhere.org" }},
		{name: "incomplete device", changeState: func(s *archive.ImportState) { s.Devices["PHONE"] = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := masRecoveryArchive(t)
			if tc.changeState != nil {
				state, err := a.ReadImportState(masRecoveryUser)
				if err != nil {
					t.Fatal(err)
				}
				tc.changeState(state)
				if err := a.WriteImportState(masRecoveryUser, state); err != nil {
					t.Fatal(err)
				}
			}
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.changeState != nil {
					t.Error("unrestored device reached destination")
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
					return
				}
				fmt.Fprintf(w, `{"user_id":%q,"device_id":%q}`, tc.returnedUser, tc.returnedDevice)
			}))
			defer api.Close()
			source := func(context.Context, string) ([]archive.Token, error) {
				return []archive.Token{{Token: "source-token", DeviceID: "PHONE", Refresh: true, OAuth: true}}, nil
			}
			updated, failures, err := refreshMASSessions(t.Context(), a, mx.MustNew(api.URL, ""), source)
			if err != nil || updated != 0 || len(failures) != 1 {
				t.Fatalf("updated=%d failures=%v err=%v", updated, failures, err)
			}
			sessions, err := a.Sessions()
			if err != nil || len(sessions) != 0 {
				t.Fatal("unverified session was saved")
			}
		})
	}
}

func TestRefreshMASSessionsDoesNotWriteAfterSourceFailure(t *testing.T) {
	a := masRecoveryArchive(t)
	const bob = "@bob:example.org"
	if err := a.WriteUser(&archive.User{UserID: bob}); err != nil {
		t.Fatal(err)
	}
	before := map[string]archive.Session{"existing": {UserID: masRecoveryUser, DeviceID: "PHONE", Token: "destination-token"}}
	if err := a.WriteSessions(before); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"user_id":%q,"device_id":"PHONE"}`, masRecoveryUser)
	}))
	defer api.Close()
	source := func(_ context.Context, user string) ([]archive.Token, error) {
		if user == bob {
			return nil, errors.New("database unavailable")
		}
		return []archive.Token{{Token: "new-token", DeviceID: "PHONE", Refresh: true, OAuth: true}}, nil
	}
	updated, _, err := refreshMASSessions(t.Context(), a, mx.MustNew(api.URL, ""), source)
	if err == nil || updated != 0 {
		t.Fatalf("updated=%d err=%v", updated, err)
	}
	after, err := a.Sessions()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("source failure changed the archive")
	}
}

func TestRefreshMASSessionsRefusesTokenCollision(t *testing.T) {
	a := masRecoveryArchive(t)
	before := map[string]archive.Session{"collision": {UserID: "@bob:example.org", DeviceID: "PHONE", Token: "bob-token", Refresh: true, OAuth: true}}
	if err := a.WriteSessions(before); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"user_id":%q,"device_id":"PHONE"}`, masRecoveryUser)
	}))
	defer api.Close()
	source := func(context.Context, string) ([]archive.Token, error) {
		return []archive.Token{{Token: "collision", DeviceID: "PHONE", Refresh: true, OAuth: true}}, nil
	}
	if _, _, err := refreshMASSessions(t.Context(), a, mx.MustNew(api.URL, ""), source); err == nil {
		t.Fatal("conflicting token accepted")
	}
	after, err := a.Sessions()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("conflicting token changed the archive")
	}
}

func TestRefreshMASSessionsRequiresCompleteExport(t *testing.T) {
	a := masRecoveryArchive(t)
	if err := a.BeginExport(); err != nil {
		t.Fatal(err)
	}
	source := func(context.Context, string) ([]archive.Token, error) {
		t.Fatal("incomplete archive queried MAS")
		return nil, nil
	}
	if _, _, err := refreshMASSessions(t.Context(), a, mx.MustNew("https://example.org", ""), source); err == nil {
		t.Fatal("incomplete archive accepted")
	}
	if _, err := os.Stat(a.Dir + "/sessions.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("incomplete archive was changed")
	}
}
