// Package mx extends mautrix-go.
package mx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// mautrix does not define this auth stage.
const authTypeRegistrationToken mautrix.AuthType = "m.login.registration_token"

func New(baseURL, token string) (*mautrix.Client, error) {
	c, err := mautrix.NewClient(strings.TrimRight(baseURL, "/"), "", token)
	if err != nil {
		return nil, err
	}
	c.Log = zerolog.Nop()
	c.DefaultHTTPRetries = 5
	return c, nil
}

// MustNew is New for URLs already validated.
func MustNew(baseURL, token string) *mautrix.Client {
	c, err := New(baseURL, token)
	if err != nil {
		panic(err)
	}
	return c
}

func WithToken(c *mautrix.Client, token string) *mautrix.Client {
	n := MustNew(c.HomeserverURL.String(), token)
	n.SpecVersions = c.SpecVersions
	return n
}

func As(c *mautrix.Client, userID string) *mautrix.Client {
	n := WithToken(c, c.AccessToken)
	n.UserID = id.UserID(userID)
	n.SetAppServiceUserID = true
	return n
}

func code(err error) string {
	var he mautrix.HTTPError
	if errors.As(err, &he) && he.RespError != nil {
		return he.RespError.ErrCode
	}
	var re mautrix.RespError
	if errors.As(err, &re) {
		return re.ErrCode
	}
	return ""
}

func IsCode(err error, errCode string) bool { return code(err) == errCode }

// Status returns the HTTP status of err, or 0.
func Status(err error) int {
	var he mautrix.HTTPError
	if errors.As(err, &he) && he.Response != nil {
		return he.Response.StatusCode
	}
	return 0
}

func IsStatus(err error, status int) bool { return Status(err) == status }

func uia(body []byte, err error) (*mautrix.RespUserInteractive, bool) {
	if !IsStatus(err, http.StatusUnauthorized) {
		return nil, false
	}
	var r mautrix.RespUserInteractive
	if json.Unmarshal(body, &r) != nil || r.Session == "" {
		return nil, false
	}
	return &r, true
}

// DoWithPassword completes user-interactive auth with the user's password.
func DoWithPassword(ctx context.Context, c *mautrix.Client, method, url string, body map[string]any, userID, password string) error {
	resp, err := c.MakeRequest(ctx, method, url, body, nil)
	state, ok := uia(resp, err)
	if !ok {
		return err
	}
	body["auth"] = map[string]any{
		"type":       mautrix.AuthTypePassword,
		"identifier": mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: userID},
		"password":   password,
		"session":    state.Session,
	}
	_, err = c.MakeRequest(ctx, method, url, body, nil)
	return err
}

func Login(ctx context.Context, c *mautrix.Client, user, password string) (*mautrix.Client, error) {
	resp, err := c.Login(ctx, &mautrix.ReqLogin{
		Type:                     mautrix.AuthTypePassword,
		Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: user},
		Password:                 password,
		InitialDeviceDisplayName: "exodus",
	})
	if err != nil {
		return nil, err
	}
	n := WithToken(c, resp.AccessToken)
	n.UserID, n.DeviceID = resp.UserID, resp.DeviceID
	return n, nil
}

// Register completes the registration token and dummy auth stages.
func Register(ctx context.Context, c *mautrix.Client, username, password, regToken string) (*mautrix.Client, error) {
	req := &mautrix.ReqRegister[any]{Username: username, Password: password, InitialDeviceDisplayName: "exodus"}
	for range 4 {
		resp, state, err := c.Register(ctx, req)
		if err == nil && resp != nil {
			n := WithToken(c, resp.AccessToken)
			n.UserID, n.DeviceID = resp.UserID, resp.DeviceID
			return n, nil
		}
		if state == nil {
			if err == nil {
				err = errors.New("no registration response")
			}
			return nil, err
		}
		stage, err := nextStage(state, regToken != "")
		if err != nil {
			return nil, fmt.Errorf("register %s: %w", username, err)
		}
		auth := map[string]any{"type": stage, "session": state.Session}
		if stage == authTypeRegistrationToken {
			auth["token"] = regToken
		}
		req.Auth = auth
	}
	return nil, fmt.Errorf("register %s: too many auth rounds", username)
}

func nextStage(state *mautrix.RespUserInteractive, haveToken bool) (mautrix.AuthType, error) {
	done := map[string]bool{}
	for _, s := range state.Completed {
		done[s] = true
	}
	var offered []string
flows:
	for _, f := range state.Flows {
		var next mautrix.AuthType
		for _, s := range f.Stages {
			if done[string(s)] {
				continue
			}
			switch {
			case s == mautrix.AuthTypeDummy, s == authTypeRegistrationToken && haveToken:
				if next == "" {
					next = s
				}
			default:
				var names []string
				for _, st := range f.Stages {
					names = append(names, string(st))
				}
				offered = append(offered, strings.Join(names, "+"))
				continue flows
			}
		}
		if next != "" {
			return next, nil
		}
	}
	return "", fmt.Errorf("no supported registration flow (offered: %s); pass --registration-token", strings.Join(offered, ", "))
}

const mediaDownloadTimeout = 3 * time.Minute

func Download(ctx context.Context, c *mautrix.Client, mxc, path string) (contentType, filename string, err error) {
	// Use one deadline for all download attempts.
	ctx, cancel := context.WithTimeout(ctx, mediaDownloadTimeout)
	defer cancel()
	uri, err := id.ParseContentURI(mxc)
	if err != nil {
		return "", "", err
	}
	resp, err := c.Download(ctx, uri)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	slog.Info("receiving source media", "mxc", mxc, "size", resp.ContentLength)
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return "", "", err
	}
	if err := f.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", "", err
	}
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		filename = params["filename"]
	}
	return resp.Header.Get("Content-Type"), filename, nil
}

func Upload(ctx context.Context, c *mautrix.Client, path, contentType, filename string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	resp, err := c.UploadMedia(ctx, mautrix.ReqUploadMedia{Content: f, ContentLength: info.Size(), ContentType: contentType, FileName: filename})
	if err != nil {
		return "", err
	}
	return resp.ContentURI.String(), nil
}

func ServerName(userID string) string { return id.UserID(userID).Homeserver() }

func Localpart(userID string) string {
	local, _, _ := strings.Cut(strings.TrimPrefix(userID, "@"), ":")
	return local
}

// WithServer moves a user ID or room alias to another server name.
func WithServer(identifier, server string) string {
	local, _, _ := strings.Cut(identifier[1:], ":")
	return identifier[:1] + local + ":" + server
}

func ParseMXC(mxc string) (server, mediaID string, err error) {
	uri, err := id.ParseContentURI(mxc)
	if err != nil {
		return "", "", err
	}
	return uri.Homeserver, uri.FileID, nil
}
