package migrate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
)

type tuwunelValueRef struct {
	offset int64
	size   int
}
type tuwunelDiskTable struct {
	path   string
	values map[string]tuwunelValueRef
}

func indexTuwunelScan(ctx context.Context, path string) (*tuwunelDiskTable, error) {
	table := &tuwunelDiskTable{path: path, values: map[string]tuwunelValueRef{}}
	err := walkTuwunelScan(ctx, path, func(key string, _ []byte, ref tuwunelValueRef) error {
		if _, ok := table.values[key]; ok {
			return errors.New("duplicate key")
		}
		table.values[key] = ref
		return nil
	})
	if err != nil {
		return nil, err
	}
	return table, nil
}

// The value passed to visit is valid until the next call.
func walkTuwunelScan(ctx context.Context, path string, visit func(string, []byte, tuwunelValueRef) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)
	// Preserve CR bytes when calculating offsets for CRLF input.
	scanner.Split(func(data []byte, eof bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if eof && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	var offset int64
	var decoded []byte
	line := 0
	progress := time.Now()
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := scanner.Bytes()
		start := offset
		offset += int64(len(raw) + 1)
		line++
		text := bytes.TrimSpace(raw)
		if len(text) == 0 {
			continue
		}
		key, value, ok := bytes.Cut(text, []byte(" ==> "))
		if !ok || !bytes.HasPrefix(key, []byte("0x")) || !bytes.HasPrefix(value, []byte("0x")) {
			return fmt.Errorf("%s:%d: expected ldb scan --hex output", path, line)
		}
		k, err := hex.DecodeString(string(key[2:]))
		if err != nil {
			return fmt.Errorf("%s:%d: invalid hex row: %w", path, line, err)
		}
		decoded, err = hex.AppendDecode(decoded[:0], value[2:])
		if err != nil {
			return fmt.Errorf("%s:%d: invalid hex row: %w", path, line, err)
		}
		pos := bytes.Index(raw, []byte(" ==> ")) + len(" ==> ") + 2
		if err := visit(string(k), decoded, tuwunelValueRef{offset: start + int64(pos), size: len(value) - 2}); err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if time.Since(progress) >= 5*time.Second {
			slog.Info("reading Tuwunel dump", "path", path, "rows", line)
			progress = time.Now()
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return ctx.Err()
}

func (t *tuwunelDiskTable) read(f *os.File, key string) ([]byte, error) {
	ref, ok := t.values[key]
	if !ok {
		return nil, nil
	}
	return readTuwunelValue(f, ref)
}

func readTuwunelValue(f *os.File, ref tuwunelValueRef) ([]byte, error) {
	encoded := make([]byte, ref.size)
	if _, err := f.ReadAt(encoded, ref.offset); err != nil {
		return nil, err
	}
	decoded := make([]byte, hex.DecodedLen(len(encoded)))
	_, err := hex.Decode(decoded, encoded)
	return decoded, err
}

func (d *TuwunelDump) eachValue(ctx context.Context, name string, fn func(string, []byte) error) error {
	if table := d.disk[name]; table != nil {
		return walkTuwunelScan(ctx, table.path, func(key string, raw []byte, _ tuwunelValueRef) error { return fn(key, raw) })
	}
	for key, raw := range d.maps[name] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(key, raw); err != nil {
			return err
		}
	}
	return nil
}
