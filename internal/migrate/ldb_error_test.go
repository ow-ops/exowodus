package migrate

import (
	"errors"
	"strings"
	"testing"
)

func TestLDBDiagnosticRedactsKeyMaterial(t *testing.T) {
	failed := errors.New("exit status 1")
	key := strings.Repeat("abcd", 40)
	for _, output := range []string{
		"Failed: IO error: Permission denied\nRejected: 0x6b657970616972 ==> 0x" + key,
		"Failed: IO error: Permission denied\nValue: " + strings.ToUpper(key),
		"Failed: IO error: Permission denied\nBinary: \xff\x00secret",
	} {
		err := ldbCommandError(failed, []byte(output))
		if !errors.Is(err, failed) || !strings.Contains(err.Error(), "Permission denied") {
			t.Fatal("ldb failure detail was lost")
		}
		if strings.Contains(strings.ToLower(err.Error()), key) || strings.Contains(err.Error(), "secret") {
			t.Fatal("ldb error exposed key material")
		}
	}
}

func TestLDBDiagnosticBoundsOutputAndRedactsTruncatedHex(t *testing.T) {
	var output ldbOutput
	raw := []byte(strings.Repeat("x", maxLDBDiagnostic-10) + "0x0123456789abcdef" + strings.Repeat("z", 1<<20))
	if n, err := output.Write(raw); err != nil || n != len(raw) {
		t.Fatal("diagnostic writer did not consume output")
	}
	if len(output.data) != maxLDBDiagnostic {
		t.Fatal("diagnostic buffer is unbounded")
	}
	if err := ldbCommandError(errors.New("exit status 1"), output.data); strings.Contains(err.Error(), "012345") {
		t.Fatal("truncated hexadecimal key was exposed")
	}
}
