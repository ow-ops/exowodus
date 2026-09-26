package migrate

import (
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/event"
)

func TestOwnReceiptKeepsTypesApart(t *testing.T) {
	raw := json.RawMessage(`{
		"$pub": {"m.read": {"@me:x": {"ts": 1}, "@other:x": {"ts": 9}}},
		"$priv": {"m.read.private": {"@me:x": {"ts": 2}}},
		"$later": {"m.read": {"@me:x": {"ts": 3}}}
	}`)
	events := []*event.Event{{Type: event.EphemeralEventReceipt, Content: event.Content{VeryRaw: raw}}}
	if got := ownReceipt(events, "@me:x", "m.read"); got != "$later" {
		t.Fatalf("public receipt = %q", got)
	}
	if got := ownReceipt(events, "@me:x", "m.read.private"); got != "$priv" {
		t.Fatalf("private receipt = %q", got)
	}
}
