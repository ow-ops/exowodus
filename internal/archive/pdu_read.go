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

// RoomPDUEvents reads one event envelope at a time and skips the state indexes.
// The returned bytes are valid until the next iteration.
func (a *Archive) RoomPDUEvents(ctx context.Context, roomID string) iter.Seq2[json.RawMessage, error] {
	return func(yield func(json.RawMessage, error) bool) {
		f, err := os.Open(filepath.Join(a.RoomDir(roomID), "pdus.json"))
		if err != nil {
			yield(nil, err)
			return
		}
		defer f.Close()
		if err := readPDUEvents(ctx, f, yield); err != nil {
			yield(nil, err)
		}
	}
}

func readPDUEvents(ctx context.Context, r io.Reader, yield func(json.RawMessage, error) bool) error {
	dec := jsontext.NewDecoder(pduContextReader{ctx, r})
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '{' {
		return errors.New("room PDUs must be a JSON object")
	}
	found := false
	for dec.PeekKind() != '}' {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := dec.ReadToken()
		if err != nil {
			return err
		}
		if name.String() != "events" {
			if err := dec.SkipValue(); err != nil {
				return err
			}
			continue
		}
		found = true
		if dec.PeekKind() != '[' {
			return errors.New("room PDUs events must be an array")
		}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		for dec.PeekKind() != ']' {
			if err := ctx.Err(); err != nil {
				return err
			}
			raw, err := dec.ReadValue()
			if err != nil {
				return err
			}
			if !yield(json.RawMessage(raw), nil) {
				return nil
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
	}
	if _, err := dec.ReadToken(); err != nil {
		return err
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("room PDUs contain multiple JSON values")
		}
		return err
	}
	if !found {
		return errors.New("room PDUs have no events array")
	}
	return ctx.Err()
}

type pduContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r pduContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
