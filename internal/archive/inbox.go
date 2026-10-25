package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ValidateProxyInboxMessage(m ToDevice, server string) error {
	content := bytes.TrimSpace(m.Content)
	sender, senderServer, _ := strings.Cut(m.Sender, ":")
	recipient, recipientServer, _ := strings.Cut(m.Recipient, ":")
	validSender := strings.HasPrefix(sender, "@") && len(sender) > 1 && senderServer != ""
	validRecipient := strings.HasPrefix(recipient, "@") && len(recipient) > 1 && recipientServer == server && server != ""
	if m.Key == "" || !validSender || !validRecipient || m.Type == "" || m.DeviceID == "" || m.DeviceID == "*" || len(content) == 0 || content[0] != '{' || !json.Valid(content) {
		return fmt.Errorf("queued message %s has no valid local recipient, device or payload", m.Key)
	}
	return nil
}

type ProxyInboxState struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	Digest       string `json:"digest"`
	Secret       []byte `json:"secret"`
	Acknowledged int    `json:"acknowledged"`
}

func (a *Archive) proxyInboxPath(user, device string) string {
	hash := sha256.Sum256([]byte(user + "\x00" + device))
	return filepath.Join(a.Dir, "proxy-inbox", hex.EncodeToString(hash[:])+".json")
}

func (a *Archive) ReadProxyInboxState(user, device string) (*ProxyInboxState, error) {
	var state ProxyInboxState
	if err := readJSON(a.proxyInboxPath(user, device), &state); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if state.UserID != user || state.DeviceID != device {
		return nil, errors.New("proxy inbox belongs to another device")
	}
	return &state, nil
}

func (a *Archive) WriteProxyInboxState(state *ProxyInboxState) error {
	return writeJSONFile(a.proxyInboxPath(state.UserID, state.DeviceID), state, true)
}

func (a *Archive) EnableProxyInbox() error {
	if a.Manifest.Version >= version {
		return nil
	}
	manifest := a.Manifest
	manifest.Version = version
	if err := writeJSON(filepath.Join(a.Dir, "manifest.json"), manifest); err != nil {
		return err
	}
	a.Manifest = manifest
	return nil
}

func (a *Archive) LockProxyInbox() (io.Closer, error) {
	f, err := os.OpenFile(filepath.Join(a.Dir, "proxy-inbox.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockExportFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("proxy inbox already in use: %w", err)
	}
	return f, nil
}
