package archive

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"iter"
	"os"
	"path/filepath"
)

func readRoomHeader(path string, room *ArchivedRoom) error {
	header := struct {
		*ArchivedRoom
		State skippedRoomState `json:"state"`
	}{ArchivedRoom: room}
	return readJSON(path, &header)
}

type skippedRoomState struct{}

func (*skippedRoomState) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return dec.SkipValue()
}

// RoomStateIter reads one state event at a time. Each value is valid until
// the iterator advances.
func (a *Archive) RoomStateIter(ctx context.Context, roomID string) iter.Seq2[json.RawMessage, error] {
	return func(yield func(json.RawMessage, error) bool) {
		f, err := os.Open(filepath.Join(a.RoomDir(roomID), "room.json"))
		if err != nil {
			yield(nil, err)
			return
		}
		defer f.Close()
		dec := jsontext.NewDecoder(f)
		token, err := dec.ReadToken()
		if err != nil || token.Kind() != '{' {
			yield(nil, errors.New("invalid archived room object"))
			return
		}
		for dec.PeekKind() != '}' {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			key, err := dec.ReadToken()
			if err != nil {
				yield(nil, err)
				return
			}
			if key.String() != "state" {
				if err := dec.SkipValue(); err != nil {
					yield(nil, err)
					return
				}
				continue
			}
			token, err := dec.ReadToken()
			if err == nil && token.Kind() == 'n' {
				continue
			}
			if err != nil || token.Kind() != '[' {
				yield(nil, errors.New("archived room state must be an array"))
				return
			}
			for dec.PeekKind() != ']' {
				if err := ctx.Err(); err != nil {
					yield(nil, err)
					return
				}
				value, err := dec.ReadValue()
				if err != nil {
					yield(nil, err)
					return
				}
				if !yield(value, nil) {
					return
				}
			}
			if _, err := dec.ReadToken(); err != nil {
				yield(nil, err)
				return
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			yield(nil, err)
			return
		}
		if _, err := dec.ReadToken(); err != io.EOF {
			yield(nil, errors.New("trailing archived room data"))
		}
	}
}
