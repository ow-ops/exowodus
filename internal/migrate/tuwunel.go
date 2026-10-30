package migrate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"exowodus/internal/archive"
	"exowodus/internal/mx"
)

// TuwunelDump reads offline ldb scan --hex output.
type TuwunelDump struct {
	disk        map[string]*tuwunelDiskTable
	dir         string
	passwords   map[string][]byte
	tokens      map[string][]byte
	refresh     map[string][]byte
	maps        map[string]map[string][]byte
	relayOnce   sync.Once
	relayErr    error
	relayRooms  map[string]*tuwunelRoomIndex
	shortEvents map[string]string
}

var tuwunelExtraMaps = []string{
	"id_appserviceregistrations",
	"userdeviceid_metadata", "onetimekeyid4225_otk", "onetimekeyid_onetimekeys",
	"userdeviceidalgorithm_fallback", "senderkey_pusher", "pushkey_deviceid",
	"todeviceid_events", "bannedroomids", "alias_roomid",
	"global", "server_signingkeys", "pduid_pdu", "eventid_outlierpdu",
	"shorteventid_eventid", "shortstatekey_statekey", "shorteventid_shortstatehash",
	"roomid_shortstatehash", "shortstatehash_statediff", "roomid_pduleaves",
	"servercurrentevent_data", "servernameevent_data",
	"mediaid_file", "mediaid_lazy", "mediaid_lazycontent",
	"readreceiptid_readreceipt", "roomuserid_privateread",
}

func OpenTuwunelDump(ctx context.Context, dir string) (*TuwunelDump, error) {
	slog.Info("opening Tuwunel dump", "path", dir)
	d := &TuwunelDump{dir: dir, disk: map[string]*tuwunelDiskTable{}}
	var err error
	if d.passwords, err = readTuwunelScan(ctx, filepath.Join(dir, "userid_password.txt")); err != nil {
		return nil, err
	}
	if d.tokens, err = readTuwunelScan(ctx, filepath.Join(dir, "token_userdeviceid.txt")); err != nil {
		return nil, err
	}
	d.refresh, err = readTuwunelScan(ctx, filepath.Join(dir, "userdeviceid_refresh.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if d.refresh == nil {
		for token := range d.tokens {
			if strings.HasPrefix(token, "refresh_") {
				return nil, errors.New("Tuwunel refresh tokens require userdeviceid_refresh.txt")
			}
		}
	}
	d.maps = map[string]map[string][]byte{}
	var missing []string
	for _, name := range tuwunelExtraMaps {
		slog.Info("reading Tuwunel dump", "table", name)
		var rows map[string][]byte
		var err error
		switch name {
		case "pduid_pdu", "eventid_outlierpdu", "shortstatehash_statediff":
			var table *tuwunelDiskTable
			table, err = indexTuwunelScan(ctx, filepath.Join(dir, name+".txt"))
			if err == nil {
				d.disk[name] = table
				rows = map[string][]byte{}
			}
		case "mediaid_file", "mediaid_lazy", "mediaid_lazycontent":
			rows, err = readTuwunelKeys(ctx, filepath.Join(dir, name+".txt"))
		default:
			rows, err = readTuwunelScan(ctx, filepath.Join(dir, name+".txt"))
		}
		if errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, name)
			continue
		}
		if err != nil {
			return nil, err
		}
		d.maps[name] = rows
	}
	if len(missing) != 0 {
		slog.Info("optional Tuwunel maps omitted from export", "maps", missing)
	}
	if global := d.maps["global"]; global != nil {
		if err := checkTuwunelSchema(global["version"]); err != nil {
			return nil, err
		}
	}
	if d.maps["senderkey_pusher"] != nil && d.maps["pushkey_deviceid"] == nil {
		return nil, errors.New("Tuwunel pushers require pushkey_deviceid.txt")
	}
	if d.HasRelayData() {
		if err := d.indexRelayData(ctx); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// tuwunelSchemaVersion is DATABASE_VERSION in Tuwunel's migrations, unchanged
// from v1.5 through v1.9.4. Other versions may store rows in other layouts.
const tuwunelSchemaVersion = 17

func checkTuwunelSchema(raw []byte) error {
	if len(raw) != 8 {
		return errors.New("Tuwunel dump has no schema version in global.txt; extract it from a database opened by Tuwunel")
	}
	if version := binary.BigEndian.Uint64(raw); version != tuwunelSchemaVersion {
		return fmt.Errorf("Tuwunel schema version %d is unsupported; this Exowodus reads version %d", version, tuwunelSchemaVersion)
	}
	return nil
}

func readTuwunelScan(ctx context.Context, path string) (map[string][]byte, error) {
	rows := map[string][]byte{}
	err := walkTuwunelScan(ctx, path, func(key string, value []byte, _ tuwunelValueRef) error {
		if _, ok := rows[key]; ok {
			return errors.New("duplicate key")
		}
		rows[key] = bytes.Clone(value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func readTuwunelKeys(ctx context.Context, path string) (map[string][]byte, error) {
	rows := map[string][]byte{}
	err := walkTuwunelScan(ctx, path, func(key string, _ []byte, _ tuwunelValueRef) error {
		if _, ok := rows[key]; ok {
			return errors.New("duplicate key")
		}
		rows[key] = nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Retain copies all supplied scans into the archive, including unknown tables.
func (d *TuwunelDump) Retain(a *archive.Archive) error {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return err
	}
	dest := filepath.Join(a.Dir, "source", "tuwunel")
	if err := os.MkdirAll(dest, 0700); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		if err := retainTuwunelFile(filepath.Join(d.dir, entry.Name()), filepath.Join(dest, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func retainTuwunelFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	return os.Rename(destination+".tmp", destination)
}

func (d *TuwunelDump) Secrets(userID string) (*archive.Secrets, error) {
	hash, ok := d.passwords[userID]
	if !ok {
		return nil, fmt.Errorf("Tuwunel dump has no account %s", userID)
	}
	s := &archive.Secrets{}
	if len(hash) != 0 && string(hash) != "*" {
		if !strings.HasPrefix(string(hash), "$argon2id$") {
			return nil, fmt.Errorf("unsupported Tuwunel password scheme for %s", userID)
		}
		s.PasswordHash, s.PasswordScheme = string(hash), archive.SchemeTuwunel
	}
	for token, value := range d.tokens {
		// Split only the two string fields: the binary expiry can contain 0xff.
		parts := bytes.SplitN(value, []byte{0xff}, 3)
		if len(parts) < 2 || !utf8.Valid(parts[0]) || !utf8.Valid(parts[1]) || len(parts[1]) == 0 {
			return nil, errors.New("invalid Tuwunel token record")
		}
		if string(parts[0]) != userID {
			continue
		}
		if len(parts) == 3 && len(parts[2]) != 0 {
			if len(parts[2]) != 8 {
				return nil, fmt.Errorf("invalid Tuwunel token expiry for %s", userID)
			}
			if binary.BigEndian.Uint64(parts[2]) <= uint64(time.Now().Unix()) {
				continue
			}
		}
		refresh := strings.HasPrefix(token, "refresh_")
		if refresh && string(d.refresh[string(parts[0])+"\xff"+string(parts[1])]) != token {
			continue
		}
		// Native OIDC and client /refresh share Tuwunel's refresh-token store.
		s.Tokens = append(s.Tokens, archive.Token{Token: token, DeviceID: string(parts[1]), Refresh: refresh, OAuth: refresh})
	}
	slices.SortFunc(s.Tokens, func(a, b archive.Token) int { return strings.Compare(a.Token, b.Token) })
	if err := d.addDeviceData(userID, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (d *TuwunelDump) CheckUserInventory(users map[string]bool, bot string, bridgeUsers map[string]bool) error {
	serverName := mx.ServerName(bot)
	for user := range d.passwords {
		if mx.ServerName(user) != serverName {
			continue
		}
		if user != bot && !bridgeUsers[user] && !users[user] {
			return fmt.Errorf("snapshot account %s missing from source API inventory", user)
		}
	}
	for user := range users {
		if bridgeUsers[user] {
			continue
		}
		if mx.ServerName(user) != serverName {
			return fmt.Errorf("source account %s is not local to %s", user, serverName)
		}
		if _, ok := d.passwords[user]; !ok {
			return fmt.Errorf("source account %s missing from %s; pause writes, take a new backup and extract all tables", user, filepath.Join(d.dir, "userid_password.txt"))
		}
	}
	return nil
}

// PasswordlessUsers returns accounts with an empty password and live devices.
// Tuwunel's admin API reports every empty password as deactivated, but
// deactivation removes all devices before clearing the password.
func (d *TuwunelDump) PasswordlessUsers() (map[string]bool, error) {
	users := map[string]bool{}
	for key := range d.maps["userdeviceid_metadata"] {
		user, _, _, err := tuwunelDeviceKey(key)
		if err != nil {
			return nil, fmt.Errorf("userdeviceid_metadata: %w", err)
		}
		if password, ok := d.passwords[user]; ok && len(password) == 0 {
			users[user] = true
		}
	}
	return users, nil
}

// Binary fields after the second separator may contain 0xff.
func tuwunelDeviceKey(key string) (user, device string, tail []byte, err error) {
	parts := bytes.SplitN([]byte(key), []byte{0xff}, 3)
	if len(parts) < 2 || len(parts[0]) == 0 || len(parts[1]) == 0 || !utf8.Valid(parts[0]) || !utf8.Valid(parts[1]) {
		return "", "", nil, errors.New("invalid Tuwunel device key")
	}
	if len(parts) == 3 {
		tail = parts[2]
	}
	return string(parts[0]), string(parts[1]), tail, nil
}

func (d *TuwunelDump) addDeviceData(userID string, s *archive.Secrets) error {
	s.OneTimeKeys = map[string]map[string]json.RawMessage{}
	s.FallbackKeys = map[string]map[string]json.RawMessage{}
	for _, name := range []string{"userdeviceid_metadata", "onetimekeyid4225_otk", "onetimekeyid_onetimekeys", "userdeviceidalgorithm_fallback", "senderkey_pusher"} {
		for key, value := range d.maps[name] {
			user, device, tail, err := tuwunelDeviceKey(key)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if user != userID {
				continue
			}
			if !json.Valid(value) {
				return fmt.Errorf("%s: invalid JSON for %s", name, userID)
			}
			switch name {
			case "userdeviceid_metadata":
				if tail != nil {
					return errors.New("invalid Tuwunel device metadata key")
				}
				var metadata struct {
					ID string `json:"device_id"`
				}
				if err := json.Unmarshal(value, &metadata); err != nil || metadata.ID != device {
					return errors.New("Tuwunel device metadata ID mismatch")
				}
				s.Devices = append(s.Devices, device)
			case "onetimekeyid4225_otk", "onetimekeyid_onetimekeys":
				id := tail
				if name == "onetimekeyid4225_otk" {
					// The key ID starts after the eight-byte count and its separator.
					if len(tail) < 10 || tail[8] != 0xff {
						return errors.New("invalid Tuwunel ordered one-time key")
					}
					id = tail[9:]
				} else {
					// Older Conduit-lineage databases store a JSON-quoted key ID.
					var decoded string
					if err := json.Unmarshal(id, &decoded); err != nil {
						return errors.New("invalid Tuwunel legacy one-time key ID")
					}
					id = []byte(decoded)
				}
				if err := putTuwunelKey(s.OneTimeKeys, device, string(id), value); err != nil {
					return err
				}
			case "userdeviceidalgorithm_fallback":
				var entry struct {
					ID   string          `json:"key_id"`
					Key  json.RawMessage `json:"key"`
					Used *bool           `json:"used"`
				}
				if err := json.Unmarshal(value, &entry); err != nil || entry.Used == nil || !json.Valid(entry.Key) {
					return errors.New("invalid Tuwunel fallback key record")
				}
				if *entry.Used {
					continue
				}
				if !strings.HasPrefix(entry.ID, string(tail)+":") {
					return errors.New("Tuwunel fallback algorithm mismatch")
				}
				if err := putTuwunelKey(s.FallbackKeys, device, entry.ID, entry.Key); err != nil {
					return err
				}
			case "senderkey_pusher":
				// The second string here is the pushkey, rather than a device ID.
				if tail != nil {
					return errors.New("invalid Tuwunel pusher key")
				}
				deviceID := d.maps["pushkey_deviceid"][device]
				if len(deviceID) == 0 || !utf8.Valid(deviceID) {
					return errors.New("Tuwunel pusher device missing")
				}
				s.Pushers = append(s.Pushers, archive.Pusher{DeviceID: string(deviceID), Body: json.RawMessage(value)})
			}
		}
	}
	slices.Sort(s.Devices)
	slices.SortFunc(s.Pushers, func(a, b archive.Pusher) int { return bytes.Compare(a.Body, b.Body) })
	return nil
}

func putTuwunelKey(keys map[string]map[string]json.RawMessage, device, id string, value []byte) error {
	algorithm, name, ok := strings.Cut(id, ":")
	if !ok || algorithm == "" || name == "" || !utf8.ValidString(id) || !json.Valid(value) || string(value) == "null" {
		return errors.New("invalid Tuwunel encryption key record")
	}
	if keys[device] == nil {
		keys[device] = map[string]json.RawMessage{}
	}
	if previous, exists := keys[device][id]; exists && !bytes.Equal(previous, value) {
		return errors.New("conflicting Tuwunel encryption key records")
	}
	keys[device][id] = json.RawMessage(value)
	return nil
}

func (d *TuwunelDump) AddServer(s *archive.Server, serverName string) error {
	return d.addServer(s, serverName, nil)
}

func (d *TuwunelDump) addServer(s *archive.Server, serverName string, skip func(string) bool) error {
	skipped := func(key string) bool {
		roomID, _, ok := strings.Cut(key, "\xff")
		return ok && skip != nil && skip(roomID)
	}
	for _, table := range []string{"servercurrentevent_data", "servernameevent_data"} {
		if len(d.maps[table]) != 0 {
			s.Limitations = append(s.Limitations, fmt.Sprintf("%s has %d pending deliveries; source queues must drain before lossless cutover", table, len(d.maps[table])))
		}
	}
	for key, raw := range d.maps["readreceiptid_readreceipt"] {
		if skipped(key) {
			continue
		}
		var receipt map[string]any
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return errors.New("invalid Tuwunel receipt record")
		}
		if hasThreadReceipt(receipt) {
			s.Limitations = append(s.Limitations, "threaded read receipts are not supported by the destination")
			break
		}
	}
	for key := range d.maps["roomuserid_privateread"] {
		if !skipped(key) {
			s.Limitations = append(s.Limitations, "private read receipts on backfilled events cannot currently be restored")
			break
		}
	}
	for key := range d.maps["bannedroomids"] {
		if !validTuwunelRoomID(key) {
			return errors.New("invalid Tuwunel banned room ID")
		}
		s.BlockedRooms = append(s.BlockedRooms, key)
	}
	slices.Sort(s.BlockedRooms)
	if len(d.maps["alias_roomid"]) != 0 {
		s.Aliases = map[string]string{}
	}
	for localpart, room := range d.maps["alias_roomid"] {
		if localpart == "" || !utf8.ValidString(localpart) || strings.Contains(localpart, ":") || !validTuwunelRoomID(string(room)) {
			return errors.New("invalid Tuwunel alias record")
		}
		s.Aliases["#"+localpart+":"+serverName] = string(room)
	}
	for key, value := range d.maps["todeviceid_events"] {
		user, device, count, err := tuwunelDeviceKey(key)
		if err != nil || len(count) != 8 {
			return errors.New("invalid Tuwunel to-device key")
		}
		var event struct {
			Sender  string          `json:"sender"`
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(value, &event); err != nil || event.Sender == "" || event.Type == "" || !json.Valid(event.Content) || string(event.Content) == "null" {
			return errors.New("invalid Tuwunel to-device event")
		}
		s.ToDevice = append(s.ToDevice, archive.ToDevice{
			Key:    "tuwunel/inbox/" + hex.EncodeToString([]byte(key)),
			Sender: event.Sender, Type: event.Type, Content: event.Content,
			Recipient: user, DeviceID: device,
		})
	}
	slices.SortFunc(s.ToDevice, func(a, b archive.ToDevice) int { return strings.Compare(a.Key, b.Key) })
	return nil
}

func validTuwunelRoomID(id string) bool {
	// Room version 12 IDs are hashes without a server-name suffix.
	return utf8.ValidString(id) && len(id) > 1 && strings.HasPrefix(id, "!") && !strings.ContainsAny(id, " \t\r\n")
}
