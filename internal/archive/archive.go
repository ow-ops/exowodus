// Package archive stores exported homeserver data on disk.
package archive

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const version = 3

type Manifest struct {
	RequireLossless bool      `json:"require_lossless,omitempty"`
	Version         int       `json:"version"`
	ServerName      string    `json:"server_name"`
	CreatedAt       time.Time `json:"created_at"`
}

// RequireLossless saves the import policy in the manifest.
func (a *Archive) RequireLossless() error {
	a.Manifest.RequireLossless = true
	return writeJSON(filepath.Join(a.Dir, "manifest.json"), a.Manifest)
}

type User struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"displayname,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	Admin       bool   `json:"admin,omitempty"`
	Locked      bool   `json:"locked,omitempty"`
	Suspended   bool   `json:"suspended,omitempty"`
	// Deactivated accounts are recreated deactivated to keep their ID reserved.
	Deactivated bool     `json:"deactivated,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	// ExternalIDs are SSO subjects, linked on Continuwuity's OIDC login.
	ExternalIDs []ExternalID `json:"external_ids,omitempty"`
	StatusMsg   string       `json:"status_msg,omitempty"`
	Dehydrated  *Dehydrated  `json:"dehydrated_device,omitempty"`
	// Guests become passwordless appservice accounts; the proxy keeps their sessions.
	Guest bool `json:"guest,omitempty"`
	// Enforced by the proxy: Continuwuity has no shadow bans.
	ShadowBanned bool `json:"shadow_banned,omitempty"`
	// Excludes the display name and avatar.
	ProfileFields map[string]json.RawMessage `json:"profile_fields,omitempty"`
	// Other users' master keys signed by this user, by user ID.
	Verified     map[string]json.RawMessage `json:"verified,omitempty"`
	Invites      []Invite                   `json:"invites,omitempty"`
	Knocks       []Knock                    `json:"knocks,omitempty"`
	AccountData  map[string]json.RawMessage `json:"account_data"`
	PushRules    json.RawMessage            `json:"push_rules,omitempty"`
	Rooms        []Room                     `json:"rooms"`
	Media        []Media                    `json:"media"`
	CrossSigning *CrossSigning              `json:"cross_signing,omitempty"`
	Devices      []Device                   `json:"devices,omitempty"`
}

type Device struct {
	ID          string          `json:"device_id"`
	DisplayName string          `json:"display_name,omitempty"`
	Keys        json.RawMessage `json:"keys,omitempty"`
}

// Secrets come from the database: no API exposes them.
type Secrets struct {
	PasswordHash   string `json:"password_hash,omitempty"`
	PasswordScheme string `json:"password_scheme,omitempty"`
	// MAS hashing scheme version.
	PasswordVersion int      `json:"password_version,omitempty"`
	Tokens          []Token  `json:"tokens,omitempty"`
	Pushers         []Pusher `json:"pushers,omitempty"`
	// Unclaimed keys by device, then "algorithm:key_id".
	OneTimeKeys map[string]map[string]json.RawMessage `json:"one_time_keys,omitempty"`
	// Includes devices the API hides from guests.
	Devices      []string                              `json:"devices,omitempty"`
	FallbackKeys map[string]map[string]json.RawMessage `json:"fallback_keys,omitempty"`
}

type Pusher struct {
	DeviceID string          `json:"device_id"`
	Body     json.RawMessage `json:"body"`
}

type Token struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	Refresh  bool   `json:"refresh,omitempty"`
	// MAS OAuth 2.0 tokens, refreshed at MAS's token endpoint, not /refresh.
	OAuth bool `json:"oauth,omitempty"`
}

// Synapse guest tokens are macaroons, verified rather than looked up.
func GuestSessionKey(userID string) string { return "guest:" + userID }

type Session struct {
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	Refresh  bool   `json:"refresh,omitempty"`
	OAuth    bool   `json:"oauth,omitempty"`
}

// Verified by the proxy on first login, then set on Continuwuity.
type PendingPassword struct {
	SourceUserID string `json:"source_user_id"`
	Hash         string `json:"hash"`
	Scheme       string `json:"scheme,omitempty"`
	Version      int    `json:"version,omitempty"`
}

// Synapse bcrypt by default, else MAS PHC strings.
const SchemeMAS = "mas"

const SchemeTuwunel = "tuwunel"

type CrossSigning struct {
	Master      json.RawMessage `json:"master_key"`
	SelfSigning json.RawMessage `json:"self_signing_key,omitempty"`
	UserSigning json.RawMessage `json:"user_signing_key,omitempty"`
}

// Session keys are encrypted with a key only the user holds.
type KeyBackup struct {
	Algorithm string                     `json:"algorithm"`
	AuthData  json.RawMessage            `json:"auth_data"`
	Rooms     map[string]json.RawMessage `json:"rooms"`
}

// ArchivedRoom holds exported history and state. ArchiveOnly rooms stay offline.
type ArchivedRoom struct {
	ArchiveOnly bool              `json:"archive_only,omitempty"`
	RoomID      string            `json:"room_id"`
	Version     string            `json:"room_version"`
	Public      bool              `json:"public"`
	State       []json.RawMessage `json:"state"`
	Media       []Media           `json:"media"`
	// Set when other servers were ever in the room: they may reject the recreated one.
	RemoteParticipants bool `json:"remote_participants"`
	// Unmigrated local senders, recreated for the replay then deactivated.
	Ghosts []string `json:"ghosts,omitempty"`
}

type RoomImportState struct {
	NewRoomID string            `json:"new_room_id"`
	Replayed  int               `json:"replayed"`
	Events    map[string]string `json:"events"`
	Media     map[string]string `json:"media"`
	Done      bool              `json:"done"`
}

type ExternalID struct {
	AuthProvider string `json:"auth_provider"`
	ExternalID   string `json:"external_id"`
}

type Dehydrated struct {
	DeviceID   string          `json:"device_id"`
	DeviceData json.RawMessage `json:"device_data"`
	Keys       json.RawMessage `json:"keys,omitempty"`
}

type Knock struct {
	RoomID string   `json:"room_id"`
	Reason string   `json:"reason,omitempty"`
	Via    []string `json:"via,omitempty"`
}

type Invite struct {
	RoomID  string `json:"room_id"`
	Inviter string `json:"inviter"`
}

type Room struct {
	Receipt        string                     `json:"receipt,omitempty"`
	PrivateReceipt string                     `json:"private_receipt,omitempty"`
	RoomID         string                     `json:"room_id"`
	Via            []string                   `json:"via,omitempty"`
	AccountData    map[string]json.RawMessage `json:"account_data,omitempty"`
	// Membership content, which holds the per-room profile.
	Member  json.RawMessage `json:"member,omitempty"`
	Aliases []string        `json:"aliases,omitempty"`
	Public  bool            `json:"public,omitempty"`
}

type Media struct {
	MXC         string `json:"mxc"`
	ContentType string `json:"content_type,omitempty"`
	Filename    string `json:"filename,omitempty"`
	// File is relative to the owning user or room directory.
	File string `json:"file"`
}

// ImportState records progress so an interrupted import can resume.
type ImportState struct {
	DestUserID   string            `json:"dest_user_id"`
	Media        map[string]string `json:"media"`
	Rooms        map[string]bool   `json:"rooms"`
	KeyBackup    string            `json:"key_backup_version,omitempty"`
	KeysDone     bool              `json:"key_backup_done,omitempty"`
	Signing      bool              `json:"cross_signing_done,omitempty"`
	Admin        bool              `json:"admin_done,omitempty"`
	Devices      map[string]bool   `json:"devices,omitempty"`
	DeviceTokens map[string]string `json:"device_tokens,omitempty"`
	PowerPending map[string]bool   `json:"power_pending,omitempty"`
	Dehydrated   bool              `json:"dehydrated_done,omitempty"`
	SSO          bool              `json:"sso_done,omitempty"`
	Pushers      bool              `json:"pushers_done,omitempty"`
	Email        bool              `json:"email_done,omitempty"`
	Status       bool              `json:"status_done,omitempty"`
	Verified     bool              `json:"verified_done,omitempty"`
	Knocks       map[string]bool   `json:"knocks_done,omitempty"`
}

type Credential struct {
	SourceUserID string
	DestUserID   string
	Password     string
}

type Archive struct {
	Dir      string
	Manifest Manifest
}

func Create(dir, serverName string) (*Archive, error) {
	a, err := Open(dir)
	if err == nil {
		if a.Manifest.ServerName != serverName {
			return nil, fmt.Errorf("archive %s belongs to %s, not %s", dir, a.Manifest.ServerName, serverName)
		}
		return a, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	a = &Archive{Dir: dir, Manifest: Manifest{Version: version, ServerName: serverName, CreatedAt: time.Now().UTC()}}
	if err := os.MkdirAll(filepath.Join(dir, "users"), 0o700); err != nil {
		return nil, err
	}
	return a, writeJSON(filepath.Join(dir, "manifest.json"), a.Manifest)
}

func Open(dir string) (*Archive, error) {
	a := &Archive{Dir: dir}
	if err := readJSON(filepath.Join(dir, "manifest.json"), &a.Manifest); err != nil {
		return nil, err
	}
	if a.Manifest.Version < 1 || a.Manifest.Version > version {
		return nil, fmt.Errorf("archive %s: unsupported version %d", dir, a.Manifest.Version)
	}
	return a, nil
}

func (a *Archive) UserDir(userID string) string {
	return filepath.Join(a.Dir, "users", url.PathEscape(userID))
}

func (a *Archive) WriteUser(u *User) error {
	return writeJSON(filepath.Join(a.UserDir(u.UserID), "user.json"), u)
}

func (a *Archive) ReadUser(id string) (*User, error) {
	user := &User{}
	if err := readJSON(filepath.Join(a.UserDir(id), "user.json"), user); err != nil {
		return nil, err
	}
	return user, nil
}

func (a *Archive) Users() ([]*User, error) {
	entries, err := os.ReadDir(filepath.Join(a.Dir, "users"))
	if err != nil {
		return nil, err
	}
	var users []*User
	for _, e := range entries {
		u := &User{}
		err := readJSON(filepath.Join(a.Dir, "users", e.Name(), "user.json"), u)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (a *Archive) ReadImportState(userID string) (*ImportState, error) {
	s := &ImportState{}
	err := readJSON(filepath.Join(a.UserDir(userID), "import.json"), s)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if s.Media == nil {
		s.Media = map[string]string{}
	}
	if s.Rooms == nil {
		s.Rooms = map[string]bool{}
	}
	if s.DeviceTokens == nil {
		s.DeviceTokens = map[string]string{}
	}
	if s.PowerPending == nil {
		s.PowerPending = map[string]bool{}
	}
	if s.Devices == nil {
		s.Devices = map[string]bool{}
	}
	return s, nil
}

func (a *Archive) WriteImportState(userID string, s *ImportState) error {
	return writeJSON(filepath.Join(a.UserDir(userID), "import.json"), s)
}

func (a *Archive) WriteKeyBackup(userID string, kb *KeyBackup) error {
	return writeJSON(filepath.Join(a.UserDir(userID), "key_backup.json"), kb)
}

// ReadKeyBackup returns nil when the user had no key backup.
func (a *Archive) ReadKeyBackup(userID string) (*KeyBackup, error) {
	kb := &KeyBackup{}
	err := readJSON(filepath.Join(a.UserDir(userID), "key_backup.json"), kb)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return kb, err
}

func (a *Archive) RoomDir(roomID string) string {
	return filepath.Join(a.Dir, "rooms", url.PathEscape(roomID))
}

func (a *Archive) WriteRoom(r *ArchivedRoom) error {
	return writeJSON(filepath.Join(a.RoomDir(r.RoomID), "room.json"), r)
}

func (a *Archive) WriteRoomWithState(r *ArchivedRoom, state iter.Seq2[json.RawMessage, error]) error {
	return writeJSON(filepath.Join(a.RoomDir(r.RoomID), "room.json"), struct {
		*ArchivedRoom
		State roomStateStream `json:"state"`
	}{r, roomStateStream(state)})
}

type roomStateStream iter.Seq2[json.RawMessage, error]

func (state roomStateStream) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	for raw, err := range state {
		if err != nil {
			return err
		}
		if err := enc.WriteValue(raw); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndArray)
}

func (a *Archive) Rooms() ([]*ArchivedRoom, error) {
	entries, err := os.ReadDir(filepath.Join(a.Dir, "rooms"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rooms []*ArchivedRoom
	for _, e := range entries {
		r := &ArchivedRoom{}
		err := readJSON(filepath.Join(a.Dir, "rooms", e.Name(), "room.json"), r)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		rooms = append(rooms, r)
	}
	return rooms, nil
}

// WriteRoomEvents stores the timeline, oldest first.
func (a *Archive) WriteRoomEvents(roomID string, events []json.RawMessage) error {
	return a.WriteRoomEventsFrom(roomID, func(yield func(json.RawMessage, error) bool) {
		for _, ev := range events {
			if !yield(ev, nil) {
				return
			}
		}
	})
}

// WriteRoomEventsFrom replaces the timeline only after the iterator succeeds.
func (a *Archive) WriteRoomEventsFrom(roomID string, events iter.Seq2[json.RawMessage, error]) error {
	path := filepath.Join(a.RoomDir(roomID), "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	defer f.Close()
	for ev, err := range events {
		if err != nil {
			return err
		}
		if _, err := w.Write(ev); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (a *Archive) RoomEvents(roomID string) ([]json.RawMessage, error) {
	var events []json.RawMessage
	for raw, err := range a.RoomEventsIter(roomID) {
		if err != nil {
			return nil, err
		}
		events = append(events, raw)
	}
	return events, nil
}

// RoomEventsIter reads the timeline one event at a time.
func (a *Archive) RoomEventsIter(roomID string) iter.Seq2[json.RawMessage, error] {
	return func(yield func(json.RawMessage, error) bool) {
		f, err := os.Open(filepath.Join(a.RoomDir(roomID), "events.jsonl"))
		if err != nil {
			yield(nil, err)
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 64<<20)
		for scanner.Scan() {
			if !yield(append(json.RawMessage(nil), scanner.Bytes()...), nil) {
				return
			}
		}
		if err := scanner.Err(); err != nil {
			yield(nil, err)
		}
	}
}

func (a *Archive) WriteRoomPDUs(roomID string, pdus any) error {
	if a.Manifest.Version < version {
		a.Manifest.Version = version
		if err := writeJSON(filepath.Join(a.Dir, "manifest.json"), a.Manifest); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(a.RoomDir(roomID), "pdus.json"), pdus)
}

// ReadRoomPDUs returns false when no events were exported.
func (a *Archive) ReadRoomPDUs(roomID string, v any) (bool, error) {
	err := readJSON(filepath.Join(a.RoomDir(roomID), "pdus.json"), v)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (a *Archive) WriteSigningKey(key string) error {
	return os.WriteFile(filepath.Join(a.Dir, "signing.key"), []byte(key), 0o600)
}

// SigningKey returns "" when no signing key was exported.
func (a *Archive) SigningKey() (string, error) {
	raw, err := os.ReadFile(filepath.Join(a.Dir, "signing.key"))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return string(raw), err
}

func (a *Archive) WriteServerKeys(keys map[string][]json.RawMessage) error {
	return writeJSON(filepath.Join(a.Dir, "server_keys.json"), keys)
}

func (a *Archive) ServerKeys() (map[string][]json.RawMessage, error) {
	keys := map[string][]json.RawMessage{}
	return keys, readOptionalJSON(filepath.Join(a.Dir, "server_keys.json"), &keys)
}

func (a *Archive) ReadRoomState(roomID string) (*RoomImportState, error) {
	s := &RoomImportState{}
	err := readJSON(filepath.Join(a.RoomDir(roomID), "import.json"), s)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if s.Events == nil {
		s.Events = map[string]string{}
	}
	if s.Media == nil {
		s.Media = map[string]string{}
	}
	return s, nil
}

func (a *Archive) WriteRoomState(roomID string, s *RoomImportState) error {
	return writeJSON(filepath.Join(a.RoomDir(roomID), "import.json"), s)
}

func (a *Archive) WriteSecrets(userID string, s *Secrets) error {
	return writeJSON(filepath.Join(a.UserDir(userID), "secrets.json"), s)
}

// ReadSecrets returns nil when no secrets were exported.
func (a *Archive) ReadSecrets(userID string) (*Secrets, error) {
	s := &Secrets{}
	err := readJSON(filepath.Join(a.UserDir(userID), "secrets.json"), s)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return s, err
}

func (a *Archive) Sessions() (map[string]Session, error) {
	m := map[string]Session{}
	return m, readOptionalJSON(filepath.Join(a.Dir, "sessions.json"), &m)
}

func (a *Archive) WriteSessions(m map[string]Session) error {
	return writeJSON(filepath.Join(a.Dir, "sessions.json"), m)
}

// PendingPasswords is keyed by destination user ID.
func (a *Archive) PendingPasswords() (map[string]PendingPassword, error) {
	m := map[string]PendingPassword{}
	return m, readOptionalJSON(filepath.Join(a.Dir, "passwords.json"), &m)
}

func (a *Archive) WritePendingPasswords(m map[string]PendingPassword) error {
	return writeJSON(filepath.Join(a.Dir, "passwords.json"), m)
}

func readOptionalJSON(path string, v any) error {
	if err := readJSON(path, v); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

type Server struct {
	HistoryAtCheckpoint     bool     `json:"history_at_checkpoint,omitempty"`
	AppserviceRegistrations []string `json:"appservice_registrations,omitempty"`
	Media                   []Media  `json:"media,omitempty"`
	UnavailableMedia        []string `json:"unavailable_media,omitempty"`
	SkippedRemoteMedia      bool     `json:"skipped_remote_media,omitempty"`
	// Unsupported source data that blocks strict import.
	Limitations        []string            `json:"limitations,omitempty"`
	RegistrationTokens []RegistrationToken `json:"registration_tokens,omitempty"`
	BlockedRooms       []string            `json:"blocked_rooms,omitempty"`
	Aliases            map[string]string   `json:"aliases,omitempty"`
	Reports            []Report            `json:"reports,omitempty"`
	// Messages the source homeserver had not delivered yet.
	ToDevice []ToDevice `json:"to_device,omitempty"`
}

type ToDevice struct {
	// Key identifies the message in the import state.
	Key       string          `json:"key"`
	Sender    string          `json:"sender"`
	Type      string          `json:"type"`
	Recipient string          `json:"recipient"`
	DeviceID  string          `json:"device_id"`
	Content   json.RawMessage `json:"content"`
}

type Report struct {
	// Kind is "event", "room" or "user".
	Kind         string `json:"kind"`
	ID           int64  `json:"id"`
	Reporter     string `json:"reporter"`
	RoomID       string `json:"room_id,omitempty"`
	EventID      string `json:"event_id,omitempty"`
	TargetUserID string `json:"target_user_id,omitempty"`
	Reason       string `json:"reason,omitempty"`
	ReceivedTS   int64  `json:"received_ts"`
}

// Key identifies the report in the import state.
func (r Report) Key() string { return fmt.Sprintf("%s/%d", r.Kind, r.ID) }

type RegistrationToken struct {
	Token       string `json:"token"`
	UsesAllowed *int   `json:"uses_allowed"`
	Completed   int    `json:"completed"`
	ExpiryTime  *int64 `json:"expiry_time"`
}

func (a *Archive) WriteServer(s *Server) error {
	return writeJSON(filepath.Join(a.Dir, "server.json"), s)
}

// ReadServer returns nil when no server state was exported.
func (a *Archive) ReadServer() (*Server, error) {
	s := &Server{}
	err := readJSON(filepath.Join(a.Dir, "server.json"), s)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return s, err
}

type ServerImportState struct {
	// Source registration token to the token issued on import.
	Tokens map[string]string `json:"tokens"`
	// Report.Key of the reports filed again.
	Reports  map[string]bool `json:"reports,omitempty"`
	ToDevice map[string]bool `json:"to_device,omitempty"`
}

func (a *Archive) ReadServerState() (*ServerImportState, error) {
	s := &ServerImportState{}
	if err := readOptionalJSON(filepath.Join(a.Dir, "server-import.json"), s); err != nil {
		return nil, err
	}
	if s.Tokens == nil {
		s.Tokens = map[string]string{}
	}
	if s.Reports == nil {
		s.Reports = map[string]bool{}
	}
	if s.ToDevice == nil {
		s.ToDevice = map[string]bool{}
	}
	return s, nil
}

func (a *Archive) WriteServerState(s *ServerImportState) error {
	return writeJSON(filepath.Join(a.Dir, "server-import.json"), s)
}

func (a *Archive) CredentialsPath() string { return filepath.Join(a.Dir, "credentials.csv") }

func (a *Archive) Credentials() (map[string]Credential, error) {
	creds := map[string]Credential{}
	f, err := os.Open(a.CredentialsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return creds, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	for i, r := range records {
		if i == 0 || len(r) != 3 {
			continue
		}
		creds[r[0]] = Credential{SourceUserID: r[0], DestUserID: r[1], Password: r[2]}
	}
	return creds, nil
}

func (a *Archive) AddCredential(c Credential) error {
	path := a.CredentialsPath()
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if errors.Is(statErr, fs.ErrNotExist) {
		_ = w.Write([]string{"source_user_id", "dest_user_id", "password"})
	}
	_ = w.Write([]string{c.SourceUserID, c.DestUserID, c.Password})
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return jsonv2.UnmarshalRead(f, v, json.DefaultOptionsV1())
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = jsonv2.MarshalWrite(f, v, json.DefaultOptionsV1(), jsontext.WithIndent("  "))
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ExportReport records whether the last export finished successfully.
type ExportReport struct {
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}

func (a *Archive) BeginExport() error {
	return writeJSON(filepath.Join(a.Dir, "export-report.json"), ExportReport{})
}

func (a *Archive) FinishExport(err error) error {
	r := ExportReport{Complete: err == nil}
	if err != nil {
		r.Error = err.Error()
	}
	return writeJSON(filepath.Join(a.Dir, "export-report.json"), r)
}

func (a *Archive) CheckExport() error {
	var r ExportReport
	err := readJSON(filepath.Join(a.Dir, "export-report.json"), &r)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // Archives created before export reports were introduced.
	}
	if err != nil {
		return err
	}
	if !r.Complete {
		return fmt.Errorf("archive export is incomplete; rerun export before importing: %s", r.Error)
	}
	return nil
}

func (a *Archive) WriteImportReport(report any) error {
	return writeJSON(filepath.Join(a.Dir, "import-report.json"), report)
}
