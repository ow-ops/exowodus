package migrate

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"exowodus/internal/relay"
)

func TestTuwunelDiskRelay(t *testing.T) {
	memory := tuwunelRoomsFixture(3, 20)
	dir := t.TempDir()
	tables := map[string]map[string][]byte{"userid_password": {}, "token_userdeviceid": {}}
	for name, rows := range memory.maps {
		tables[name] = rows
	}
	for name, rows := range tables {
		var text strings.Builder
		for k, v := range rows {
			fmt.Fprintf(&text, "  0x%x ==> 0x%x  \r\n", k, v)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(text.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	disk, err := OpenTuwunelDump(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pduid_pdu", "eventid_outlierpdu", "shortstatehash_statediff"} {
		if len(disk.maps[name]) != 0 || disk.disk[name] == nil {
			t.Fatalf("%s retained in memory", name)
		}
	}
	for _, name := range []string{"pduid_pdu", "eventid_outlierpdu"} {
		if len(disk.disk[name].values) != 0 {
			t.Fatal("retained duplicate event offset index")
		}
	}
	for room, index := range disk.relayRooms {
		if len(index.events) != 0 {
			t.Fatal("event bodies retained in index")
		}
		got, err := collectTuwunelRoom(t.Context(), disk, room)
		if err != nil {
			t.Fatal(err)
		}
		want, err := collectTuwunelRoom(t.Context(), memory, room)
		if err != nil {
			t.Fatal(err)
		}
		// The disk iterator follows file offsets, while memory uses event IDs.
		byID := func(a, b relay.EventJSON) int { return cmp.Compare(a.EventID, b.EventID) }
		slices.SortFunc(got.Events, byID)
		slices.SortFunc(want.Events, byID)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("room %s changed", room)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenTuwunelDump(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

type countingTuwunelReader struct {
	*bytes.Reader
	reads int
}

func (r *countingTuwunelReader) ReadAt(p []byte, offset int64) (int, error) {
	r.reads++
	return r.Reader.ReadAt(p, offset)
}

func TestTuwunelValueBufferedReads(t *testing.T) {
	want := bytes.Repeat([]byte("abcd"), 256*1024)
	encoded := []byte("prefix" + hex.EncodeToString(want) + "suffix")
	reader := &countingTuwunelReader{Reader: bytes.NewReader(encoded)}
	got, err := readTuwunelValue(reader, tuwunelValueRef{offset: 6, size: len(want) * 2})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("value changed: %v", err)
	}
	if reader.reads > 32 {
		t.Fatalf("2 MiB hex value took %d reads, want at most 32", reader.reads)
	}
}

func TestTuwunelRoomEventsFileOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pduid_pdu.txt")
	if err := os.WriteFile(path, []byte("7b7d7b7d7b7d"), 0600); err != nil {
		t.Fatal(err)
	}
	dump := &TuwunelDump{
		disk: map[string]*tuwunelDiskTable{"pduid_pdu": {path: path}},
		relayRooms: map[string]*tuwunelRoomIndex{"!room": {diskEvents: map[string]tuwunelEventRef{
			"$z": {table: "pduid_pdu", value: tuwunelValueRef{offset: 0, size: 4}},
			"$a": {table: "pduid_pdu", value: tuwunelValueRef{offset: 4, size: 4}},
			"$m": {table: "pduid_pdu", value: tuwunelValueRef{offset: 8, size: 4}},
		}}},
	}
	var ids []string
	for event, err := range dump.roomEvents(t.Context(), "!room") {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, event.EventID)
	}
	if !slices.Equal(ids, []string{"$z", "$a", "$m"}) {
		t.Fatalf("read events in %v order", ids)
	}
}

func TestTuwunelDiskValidation(t *testing.T) {
	for _, text := range []string{"0x61 ==> 0x0", "0x61 ==> 0xzz", "0x61 ==> 0x\n0x61 ==> 0x", "bad"} {
		p := filepath.Join(t.TempDir(), "scan.txt")
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := indexTuwunelScan(context.Background(), p); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}

func BenchmarkTuwunelScanMemory(b *testing.B) {
	p := filepath.Join(b.TempDir(), "scan.txt")
	f, err := os.Create(p)
	if err != nil {
		b.Fatal(err)
	}
	value := strings.Repeat("61", 64*1024)
	for i := 0; i < 256; i++ {
		if _, err := fmt.Fprintf(f, "0x%08x ==> 0x%s\n", i, value); err != nil {
			b.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	b.Run("memory", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rows, err := readTuwunelScan(context.Background(), p)
			if err != nil {
				b.Fatal(err)
			}
			if len(rows) != 256 {
				b.Fatal(len(rows))
			}
		}
	})
	b.Run("offsets", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			table, err := indexTuwunelScan(context.Background(), p)
			if err != nil {
				b.Fatal(err)
			}
			if len(table.values) != 256 {
				b.Fatal(len(table.values))
			}
		}
	})
}

func TestTuwunelDiskCancellationAndTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scan.txt")
	if err := os.WriteFile(p, []byte("0x61 ==> 0x6263\n0x64 ==> 0x65\n"), 0600); err != nil {
		t.Fatal(err)
	}
	table, err := indexTuwunelScan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &TuwunelDump{disk: map[string]*tuwunelDiskTable{"pduid_pdu": table}}
	calls := 0
	err = d.eachValue(ctx, "pduid_pdu", func(string, []byte) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := table.read(f, "a"); err == nil {
		t.Fatal("accepted truncated dump")
	}
}

func TestTuwunelMediaScanKeepsOnlyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mediaid_lazycontent.txt")
	value := strings.Repeat("61", 64*1024)
	if err := os.WriteFile(path, []byte("0x6d78633a2f2f6578616d706c652e6f72672f61 ==> 0x"+value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := readTuwunelKeys(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := rows["mxc://example.org/a"]
	if !ok || len(raw) != 0 {
		t.Fatal("media value retained or key lost")
	}
	d := &TuwunelDump{maps: map[string]map[string][]byte{"mediaid_lazycontent": rows}}
	ids, err := d.MediaIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "mxc://example.org/a" {
		t.Fatal(ids)
	}
}
