package archive

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProxyInboxStateAndLock(t *testing.T) {
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := a.LockProxyInbox()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := a.LockProxyInbox(); err == nil {
		second.Close()
		t.Fatal("concurrent proxy accepted")
	}
	state := &ProxyInboxState{UserID: "@alice:example.org", DeviceID: "PHONE/../", Digest: "digest", Secret: bytes.Repeat([]byte{1}, 32), Acknowledged: 100}
	if err := a.WriteProxyInboxState(state); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := reopened.ReadProxyInboxState(state.UserID, state.DeviceID)
	if err != nil || stored.Acknowledged != 100 || !bytes.Equal(stored.Secret, state.Secret) {
		t.Fatalf("state not preserved: %+v %v", stored, err)
	}
	info, err := os.Stat(a.proxyInboxPath(state.UserID, state.DeviceID))
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("inbox state is not private")
	}
	if state, err := a.ReadProxyInboxState("@bob:example.org", "PHONE/../"); err != nil || state != nil {
		t.Fatal("read another user's inbox state")
	}
	if err := writeJSON(filepath.Join(a.Dir, "manifest.json"), Manifest{Version: 5, ServerName: "example.org", RequireLossless: true}); err != nil {
		t.Fatal(err)
	}
	old, err := Open(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.UpgradeFormat(); err != nil {
		t.Fatal(err)
	}
	updated, err := Open(a.Dir)
	if err != nil || updated.Manifest.Version != version || !updated.Manifest.RequireLossless {
		t.Fatal("old archive was not upgraded")
	}
}

func TestProxyInboxRejectsInvalidRecipient(t *testing.T) {
	message := ToDevice{Key: "inbox/1", Sender: "@remote:other.org", Recipient: "@alice:example.org", DeviceID: "PHONE", Type: "m.room.encrypted", Content: json.RawMessage(`{}`)}
	for _, recipient := range []string{"@alice:other.org", "@alice:other.org:example.org", "@:example.org", ""} {
		message.Recipient = recipient
		if err := ValidateProxyInboxMessage(message, "example.org"); err == nil {
			t.Fatalf("accepted recipient %q", recipient)
		}
	}
}
