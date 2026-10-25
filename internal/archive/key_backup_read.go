package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
)

type BackupSession struct {
	RoomID    string
	SessionID string
	Data      json.RawMessage
}

type KeyBackupReader struct {
	Algorithm string
	AuthData  json.RawMessage
	file      *os.File
}

// OpenKeyBackup validates the file without loading its room keys into memory.
// It returns nil when no key backup was exported.
func (a *Archive) OpenKeyBackup(ctx context.Context, userID string) (*KeyBackupReader, error) {
	f, err := os.Open(filepath.Join(a.UserDir(userID), "key_backup.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r := &KeyBackupReader{file: f}
	if err := r.readMetadata(ctx); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

func (r *KeyBackupReader) Close() error { return r.file.Close() }

func (r *KeyBackupReader) readMetadata(ctx context.Context) error {
	dec := jsontext.NewDecoder(keyBackupContextReader{ctx, r.file})
	if err := keyBackupToken(dec, '{'); err != nil {
		return err
	}
	for dec.PeekKind() != '}' {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := dec.ReadToken()
		if err != nil {
			return err
		}
		switch name.String() {
		case "algorithm":
			value, err := dec.ReadToken()
			if err != nil || value.Kind() != '"' {
				return errors.New("invalid key-backup algorithm")
			}
			r.Algorithm = value.String()
		case "auth_data":
			value, err := dec.ReadValue()
			if err != nil || value.Kind() != '{' {
				return errors.New("invalid key-backup auth data")
			}
			r.AuthData = bytes.Clone(value)
		default:
			if err := dec.SkipValue(); err != nil {
				return err
			}
		}
	}
	if err := keyBackupToken(dec, '}'); err != nil {
		return err
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data in key backup")
	}
	if r.Algorithm == "" || len(r.AuthData) == 0 {
		return errors.New("key-backup metadata missing")
	}
	return nil
}

// Sessions yields one encrypted room key at a time. Each Data value is owned
// by the caller and remains valid after the iterator advances.
func (r *KeyBackupReader) Sessions(ctx context.Context) iter.Seq2[BackupSession, error] {
	return func(yield func(BackupSession, error) bool) {
		if _, err := r.file.Seek(0, io.SeekStart); err != nil {
			yield(BackupSession{}, err)
			return
		}
		dec := jsontext.NewDecoder(keyBackupContextReader{ctx, r.file})
		err := func() error {
			if err := keyBackupToken(dec, '{'); err != nil {
				return err
			}
			for dec.PeekKind() != '}' {
				if err := ctx.Err(); err != nil {
					return err
				}
				name, err := dec.ReadToken()
				if err != nil {
					return err
				}
				if name.String() != "rooms" || dec.PeekKind() == 'n' {
					if err := dec.SkipValue(); err != nil {
						return err
					}
					continue
				}
				if err := keyBackupToken(dec, '{'); err != nil {
					return err
				}
				for dec.PeekKind() != '}' {
					room, err := dec.ReadToken()
					if err != nil {
						return err
					}
					roomID := room.String()
					if err := keyBackupToken(dec, '{'); err != nil {
						return err
					}
					for dec.PeekKind() != '}' {
						field, err := dec.ReadToken()
						if err != nil {
							return err
						}
						if field.String() != "sessions" {
							if err := dec.SkipValue(); err != nil {
								return err
							}
							continue
						}
						if err := keyBackupToken(dec, '{'); err != nil {
							return err
						}
						for dec.PeekKind() != '}' {
							if err := ctx.Err(); err != nil {
								return err
							}
							session, err := dec.ReadToken()
							if err != nil {
								return err
							}
							sessionID := session.String()
							raw, err := dec.ReadValue()
							if err != nil {
								return err
							}
							if !yield(BackupSession{RoomID: roomID, SessionID: sessionID, Data: bytes.Clone(raw)}, nil) {
								return nil
							}
						}
						if err := keyBackupToken(dec, '}'); err != nil {
							return err
						}
					}
					if err := keyBackupToken(dec, '}'); err != nil {
						return err
					}
				}
				if err := keyBackupToken(dec, '}'); err != nil {
					return err
				}
			}
			return keyBackupToken(dec, '}')
		}()
		if err != nil {
			yield(BackupSession{}, err)
		}
	}
}

type keyBackupContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r keyBackupContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func keyBackupToken(dec *jsontext.Decoder, kind jsontext.Kind) error {
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != kind {
		return fmt.Errorf("invalid key-backup JSON: expected %q", kind)
	}
	return nil
}
