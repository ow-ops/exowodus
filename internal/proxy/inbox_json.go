package proxy

import (
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
)

type inboxJSON struct {
	dec                      *jsontext.Decoder
	enc                      *jsontext.Encoder
	batch                    *inboxSync
	next, device, deviceNext bool
}

func rewriteInboxSync(out io.Writer, in io.Reader, batch *inboxSync) error {
	s := &inboxJSON{dec: jsontext.NewDecoder(in), enc: jsontext.NewEncoder(out), batch: batch}
	if err := s.object(0); err != nil {
		return err
	}
	if _, err := s.dec.ReadToken(); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("trailing sync data")
	}
	return nil
}

// level 0 is the response, 1 is sliding-sync extensions, 2 is to_device.
func (s *inboxJSON) object(level int) error {
	token, err := s.dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '{' {
		return errors.New("sync field must be an object")
	}
	if err := s.enc.WriteToken(token); err != nil {
		return err
	}
	hasEvents := false
	for s.dec.PeekKind() != '}' {
		key, err := s.dec.ReadToken()
		if err != nil {
			return err
		}
		if key.Kind() != '"' {
			return errors.New("invalid sync object key")
		}
		if err := s.enc.WriteToken(key); err != nil {
			return err
		}
		name := key.String()
		switch {
		case level == 0 && ((!s.batch.sliding && name == "next_batch") || (s.batch.sliding && name == "pos")):
			s.next = true
			kind := "since"
			if s.batch.sliding {
				kind = "pos"
			}
			if err := s.cursor(kind); err != nil {
				return err
			}
		case level == 0 && s.batch.sliding && name == "extensions":
			if err := s.object(1); err != nil {
				return err
			}
		case ((level == 0 && !s.batch.sliding) || level == 1) && name == "to_device":
			s.device = true
			if err := s.object(2); err != nil {
				return err
			}
		case level == 2 && s.batch.sliding && name == "next_batch":
			s.deviceNext = true
			if err := s.cursor("device"); err != nil {
				return err
			}
		case level == 2 && name == "events":
			hasEvents = true
			if err := s.events(); err != nil {
				return err
			}
		default:
			if err := copyJSONValue(s.enc, s.dec); err != nil {
				return err
			}
		}
	}
	if level == 0 && !s.batch.sliding && !s.device {
		s.device = true
		if err := s.enc.WriteToken(jsontext.String("to_device")); err != nil {
			return err
		}
		if err := s.enc.WriteToken(jsontext.BeginObject); err != nil {
			return err
		}
		if err := s.writeEvents(); err != nil {
			return err
		}
		if err := s.enc.WriteToken(jsontext.EndObject); err != nil {
			return err
		}
	}
	if level == 2 && !hasEvents {
		if err := s.writeEvents(); err != nil {
			return err
		}
	}
	// Leave the JSON incomplete if no device messages can be delivered.
	if level == 0 && (!s.next || !s.device || (s.batch.sliding && !s.deviceNext)) {
		return errors.New("upstream sync omitted its cursor or to-device extension")
	}
	token, err = s.dec.ReadToken()
	if err != nil {
		return err
	}
	return s.enc.WriteToken(token)
}

func (s *inboxJSON) cursor(kind string) error {
	token, err := s.dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '"' {
		return errors.New("sync cursor must be a string")
	}
	value := encodeInboxToken(s.batch.secret, kind, s.batch.end, token.String())
	return s.enc.WriteToken(jsontext.String(value))
}

func (s *inboxJSON) events() error {
	token, err := s.dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '[' {
		return errors.New("to-device events must be an array")
	}
	if err := s.enc.WriteToken(token); err != nil {
		return err
	}
	for s.dec.PeekKind() != ']' {
		if err := copyJSONValue(s.enc, s.dec); err != nil {
			return err
		}
	}
	if _, err := s.dec.ReadToken(); err != nil {
		return err
	}
	return s.appendEvents()
}

func (s *inboxJSON) writeEvents() error {
	if err := s.enc.WriteToken(jsontext.String("events")); err != nil {
		return err
	}
	if err := s.enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	return s.appendEvents()
}

func (s *inboxJSON) appendEvents() error {
	for _, m := range s.batch.messages {
		raw, err := json.Marshal(struct {
			Sender  string          `json:"sender"`
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		}{m.Sender, m.Type, m.Content})
		if err != nil {
			return err
		}
		if err := s.enc.WriteValue(raw); err != nil {
			return err
		}
	}
	return s.enc.WriteToken(jsontext.EndArray)
}

func copyJSONValue(enc *jsontext.Encoder, dec *jsontext.Decoder) error {
	depth := 0
	for {
		token, err := dec.ReadToken()
		if err != nil {
			return err
		}
		switch token.Kind() {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
		if err := enc.WriteToken(token); err != nil {
			return err
		}
		if depth == 0 {
			return nil
		}
	}
}
