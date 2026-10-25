package archive

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoomPDUEvents(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        int
		fails       bool
	}{
		{"state first", `{"groups":{"1":{"state":{"member":"$member"}}},"events":[{"event_id":"$first","pdu":{}},{"event_id":"$second","pdu":{}}],"current_state":{"member":"$member"}}`, 2, false},
		{"events first", `{"events":[{"event_id":"$first","pdu":{}}],"groups":{}}`, 1, false},
		{"missing", `{"groups":{}}`, 0, true},
		{"null", `{"events":null}`, 0, true},
		{"object", `{"events":{}}`, 0, true},
		{"duplicate array", `{"events":[],"events":[]}`, 0, true},
		{"truncated event", `{"events":[{"event_id":"$first","pdu":{}`, 0, true},
		{"truncated state", `{"events":[],"groups":{`, 0, true},
		{"trailing data", `{"events":[]} {}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			err := readPDUEvents(t.Context(), strings.NewReader(tc.input), func(raw json.RawMessage, _ error) bool {
				if !json.Valid(raw) {
					t.Error("invalid event envelope")
				}
				count++
				return true
			})
			if (err != nil) != tc.fails || count != tc.want {
				t.Fatalf("events=%d, error=%v", count, err)
			}
		})
	}
	a, err := Create(t.TempDir(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range a.RoomPDUEvents(t.Context(), "!missing:example.org") {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func TestRoomPDUEventsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	input := `{"events":[{"event_id":"$first","pdu":{}},{"event_id":"$second","pdu":{}}]}`
	count := 0
	err := readPDUEvents(ctx, strings.NewReader(input), func(json.RawMessage, error) bool {
		count++
		cancel()
		return true
	})
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatalf("events=%d, error=%v", count, err)
	}
}

func TestRoomPDUEventsSkipsLargeState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pdus.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	if _, err := w.WriteString(`{"groups":{`); err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("e", 256)
	for group := range 256 {
		if group != 0 {
			_, _ = w.WriteString(",")
		}
		_, _ = fmt.Fprintf(w, `"%d":{"state":{`, group)
		for member := range 256 {
			if member != 0 {
				_, _ = w.WriteString(",")
			}
			_, _ = fmt.Fprintf(w, `"m.room.member\u0000@user%d:example.org":"$%s"`, member, value)
		}
		_, _ = w.WriteString(`}}`)
	}
	_, _ = w.WriteString(`},"events":[{"event_id":"$first","pdu":{}}]}`)
	if err := errors.Join(w.Flush(), f.Close()); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	count := 0
	reader := &pduHeapReader{r: f, next: 1 << 20}
	if err := readPDUEvents(t.Context(), reader, func(json.RawMessage, error) bool { count++; return true }); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if count != 1 {
		t.Fatal("original event was not read")
	}
	if growth := int64(reader.peak) - int64(before.HeapAlloc); growth > 4<<20 {
		t.Fatalf("reading one event retained %d bytes of ignored state", growth)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read one event past %d bytes of state; live heap growth %d bytes, total allocation %d bytes", info.Size(), int64(reader.peak)-int64(before.HeapAlloc), after.TotalAlloc-before.TotalAlloc)
}

type pduHeapReader struct {
	r           io.Reader
	total, next int
	peak        uint64
}

func (r *pduHeapReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.total += n
	if r.total >= r.next {
		runtime.GC()
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		r.peak = max(r.peak, memory.HeapAlloc)
		r.next = r.total + 1<<20
	}
	return n, err
}
