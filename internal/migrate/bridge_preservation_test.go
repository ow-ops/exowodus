package migrate

import (
	"database/sql"
	"strings"
	"testing"

	"exowodus/internal/archive"
)

func TestBridgePreservationRefusesReplayBeforeRequests(t *testing.T) {
	for _, mode := range []string{"missing queue check", "different registration", "no relay", "changed room", "changed event", "missing key", "missing PDUs"} {
		t.Run(mode, func(t *testing.T) {
			a, err := archive.Create(t.TempDir(), "example.org")
			if err != nil {
				t.Fatal(err)
			}
			b, err := parseBridge([]byte(testBridgeRegistration), nil)
			if err != nil {
				t.Fatal(err)
			}
			im := &Importer{Archive: a, Admin: &ContinuwuityAdmin{bot: "@conduit:example.org"}, Bridges: []*Bridge{b}}
			srv := &archive.Server{BridgeQueuesDrained: true, AppserviceRegistrations: []string{testBridgeRegistration}}
			room := &archive.ArchivedRoom{RoomID: "!portal:example.org", Version: "10"}
			state := &archive.RoomImportState{}
			hasRelay := true
			switch mode {
			case "missing queue check":
				srv.BridgeQueuesDrained = false
			case "different registration":
				srv.AppserviceRegistrations = nil
			case "no relay":
				hasRelay = false
			case "changed room":
				state.NewRoomID = "!replacement:example.org"
			case "changed event":
				state.Events = map[string]string{"$old": "$new"}
			case "missing PDUs":
				if err := a.WriteSigningKey("ed25519 test AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.WriteRoomState(room.RoomID, state); err != nil {
				t.Fatal(err)
			}
			if err := im.CheckBridgePreservation(t.Context(), []*archive.ArchivedRoom{room}, srv, hasRelay); err == nil {
				t.Fatal("unsafe bridge migration accepted")
			}
			reports := im.ReplayRooms(t.Context(), []*archive.ArchivedRoom{room})
			if len(reports) != 1 || len(reports[0].Failures) != 1 || reports[0].Failures[0].Step != "bridge_preservation" {
				t.Fatalf("replay was not blocked: %+v", reports)
			}
		})
	}
}

func TestSynapseBridgeSourceMustDrain(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`CREATE TABLE appservice_stream_position (stream_ordering BIGINT)`,
		`CREATE TABLE events (stream_ordering BIGINT)`,
		`CREATE TABLE application_services_txns (as_id TEXT, txn_id BIGINT)`,
		`INSERT INTO appservice_stream_position VALUES (4)`,
		`INSERT INTO events VALUES (5)`,
		`INSERT INTO application_services_txns VALUES ('bridge',1)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	source := &SynapseDB{db: db}
	bridges := []*Bridge{{ID: "bridge"}}
	if err := source.CheckAppserviceQueues(t.Context(), bridges); err == nil || !strings.Contains(err.Error(), "caught up") {
		t.Fatalf("dispatcher lag accepted: %v", err)
	}
	if _, err := db.Exec(`UPDATE appservice_stream_position SET stream_ordering=5`); err != nil {
		t.Fatal(err)
	}
	if err := source.CheckAppserviceQueues(t.Context(), bridges); err == nil || !strings.Contains(err.Error(), "undelivered") {
		t.Fatalf("unacknowledged source deliveries accepted: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM application_services_txns`); err != nil {
		t.Fatal(err)
	}
	if err := source.CheckAppserviceQueues(t.Context(), bridges); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE application_services_txns`); err != nil {
		t.Fatal(err)
	}
	if err := source.CheckAppserviceQueues(t.Context(), bridges); err == nil {
		t.Fatal("unknown queue state accepted")
	}
}
