package migrate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"exowodus/internal/relay"
)

func TestStoredEventReferenceHashes(t *testing.T) {
	// Expected IDs are SHA-256 hashes of canonical redacted federation events.
	for _, tc := range []struct {
		name, version, eventID, raw string
	}{
		{"legacy redaction", "10", "$yrbPtTDlhezyUJaXj1l8u_7mxqAPBffgMgyCzlFV9pg", `{"auth_events":[],"content":{"reason":"spam"},"depth":1,"event_id":"$yrbPtTDlhezyUJaXj1l8u_7mxqAPBffgMgyCzlFV9pg","hashes":{"sha256":"rTr+mUQ1bZhnbjmQQqWRAu0BfxVu6Mf6aBmrhXepvSw"},"origin_server_ts":123456789,"prev_events":[],"redacts":"$target","room_id":"!room:example.org","sender":"@alice:example.org","type":"m.room.redaction"}`},
		{"v11 create", "11", "$IUTvDcRaFUGUkRNNtb02GQGqil6EAbMkddU8vySqVjo", `{"auth_events":[],"content":{"m.federate":true,"room_version":"11"},"depth":1,"event_id":"$IUTvDcRaFUGUkRNNtb02GQGqil6EAbMkddU8vySqVjo","hashes":{"sha256":"JYLrYfy8VR541s+42NEL89Xa3/C1Mfd2r8NX7SCTpCU"},"origin_server_ts":123456789,"prev_events":[],"room_id":"!room:example.org","sender":"@alice:example.org","state_key":"","type":"m.room.create"}`},
		{"v12 create", "12", "$hJdb7xlELIXY34O_6gH-b9gIlii5HxQqBA41NvZGHTE", `{"auth_events":[],"content":{"m.federate":true,"room_version":"12"},"depth":1,"event_id":"$hJdb7xlELIXY34O_6gH-b9gIlii5HxQqBA41NvZGHTE","hashes":{"sha256":"VrIta1jPWyyrhVnorYQ6cJTOHGegIoFJvhJNpOkS7Sg"},"origin_server_ts":123456789,"prev_events":[],"room_id":"!hJdb7xlELIXY34O_6gH-b9gIlii5HxQqBA41NvZGHTE","sender":"@alice:example.org","state_key":"","type":"m.room.create"}`},
		{"v12 message", "12", "$3eajWN6Kz4CKpnf6gp3a4MsuUpMShqh_5QcwW7HZsAg", `{"auth_events":[],"content":{"body":"hello","msgtype":"m.text"},"depth":1,"event_id":"$3eajWN6Kz4CKpnf6gp3a4MsuUpMShqh_5QcwW7HZsAg","hashes":{"sha256":"4U1qKjD+hkK7t3fcQnSrixaNtCrhdJTDvQoNoIGgVBY"},"origin_server_ts":123456789,"prev_events":[],"room_id":"!room:example.org","sender":"@alice:example.org","type":"m.room.message"}`},
		{"redacted v12 message", "12", "$3eajWN6Kz4CKpnf6gp3a4MsuUpMShqh_5QcwW7HZsAg", `{"auth_events":[],"content":{},"depth":1,"event_id":"$3eajWN6Kz4CKpnf6gp3a4MsuUpMShqh_5QcwW7HZsAg","hashes":{"sha256":"4U1qKjD+hkK7t3fcQnSrixaNtCrhdJTDvQoNoIGgVBY"},"origin_server_ts":123456789,"prev_events":[],"room_id":"!room:example.org","sender":"@alice:example.org","type":"m.room.message","unsigned":{"redacted_because":{"event_id":"$redaction"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(tc.raw)
			before := bytes.Clone(raw)
			if err := checkEventID(relay.EventJSON{EventID: tc.eventID, PDU: raw}, tc.version); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("verification changed the stored PDU")
			}
			changed := json.RawMessage(strings.Replace(tc.raw, "123456789", "123456790", 1))
			if failures := checkEventIDs([]relay.EventJSON{{EventID: tc.eventID, PDU: changed}}, tc.version); failures != 1 {
				t.Fatal("changed signed fields were accepted")
			}
		})
	}
}
