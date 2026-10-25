package migrate

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxLDBDiagnostic = 16 << 10

type ldbOutput struct{ data []byte }

func (b *ldbOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := maxLDBDiagnostic - len(b.data); remaining > 0 {
		b.data = append(b.data, p[:min(n, remaining)]...)
	}
	return n, nil
}

var ldbHex = regexp.MustCompile(`(?i)0x[0-9a-f]+|[0-9a-f]{32,}`)

// ldb can echo a rejected input row, which contains the private signing key.
func ldbCommandError(err error, output []byte) error {
	if len(output) > maxLDBDiagnostic {
		output = output[:maxLDBDiagnostic]
	}
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if !utf8.ValidString(line) || strings.ContainsFunc(line, func(r rune) bool { return unicode.IsControl(r) && r != '\t' && r != '\r' }) {
			lines[i] = "[binary output omitted]"
			continue
		}
		if key, _, ok := strings.Cut(line, " ==> "); ok {
			line = key + " ==> [key data omitted]"
		}
		lines[i] = ldbHex.ReplaceAllString(line, "[hex data omitted]")
	}
	diagnostic := strings.TrimSpace(strings.Join(lines, "\n"))
	if diagnostic == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, diagnostic)
}
