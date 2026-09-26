//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

var exodusBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "exodus-bin")
	if err != nil {
		panic(err)
	}
	exodusBin = filepath.Join(dir, "exodus")
	if out, err := exec.Command("go", "build", "-o", exodusBin, "..").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build exodus: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// workDir is the directory ./up.sh keeps the servers' data in.
func workDir(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(".workdir")
	must(t, err)
	return strings.TrimSpace(string(b))
}

// do sends a raw request to path, relative to the homeserver.
func do(ctx context.Context, c *mautrix.Client, method, path string, query url.Values, in, out any) error {
	q := url.Values{}
	maps.Copy(q, query)
	if c.SetAppServiceUserID {
		q.Set("user_id", string(c.UserID))
	}
	u := strings.TrimRight(c.HomeserverURL.String(), "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	_, err := c.MakeRequest(ctx, method, u, in, out)
	return err
}

func joinedRooms(t *testing.T, ctx context.Context, c *mautrix.Client) []string {
	t.Helper()
	resp, err := c.JoinedRooms(ctx)
	must(t, err)
	var rooms []string
	for _, r := range resp.JoinedRooms {
		rooms = append(rooms, string(r))
	}
	return rooms
}

func resolveAlias(t *testing.T, ctx context.Context, c *mautrix.Client, alias string) string {
	t.Helper()
	resp, err := c.ResolveAlias(ctx, id.RoomAlias(alias))
	must(t, err)
	return string(resp.RoomID)
}

// urlPath appends each escaped segment to the raw prefix.
func urlPath(prefix string, segments ...string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}
