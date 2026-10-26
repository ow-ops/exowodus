package relay

import (
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/id"
)

// Federated dummy events with non-object content, accepted by Tuwunel under these IDs.
var nonObjectContentEvents = []string{
	`{"auth_events":["$apdPG4TrN_i93pJi9sTdEV__6uXpvNyGgtiHxHfMI-8","$TvbjNX6tN_aV6vX_Ao11BTVbklkzE83TjmTQ8h3HXv4"],"content":"{}","depth":4115,"event_id":"$f9Z2_T5382grEmwuwQAEUmWiz6O8HBLvO2kXUq-e5l8","hashes":{"sha256":"sjJNl54UFL9xeL4wvHyBntKEC0keMC6TcdnmZd9K4hA"},"origin_server_ts":1781986684833,"prev_events":["$-00czuISL-2zwBIN34kA_tHZC2uZkh6xu8HkFgVaUUI","$-CYmw77MROJIysn0Wz48JXiH1eHLeQ-Jxir8ktOhjJw","$3mSbFMhk74opY7V7PDSaWmA1NTl_7GZqK_vmOp4T1nM","$4-EV2vq6ugKAQ8GlcYt40cl_Pi1GGGDVjGGdVPqDuZI","$4dzrz2D3u08kmPGANIVCrn3XzgQGksfI8V5i_THUYa0","$A7caEpW78kMUm8fQt8SuHLc6Ns1rIgJXkM4evW9EQNY","$ASLIinzCsEuxtvUlrNi7T-feQmf2b5y6XxfS9Mk9Xe4","$OdMlyd6gghFj7bJS__JxfT4dXBjrARIGmTOtbaI7BkU","$QGSy50mvlt43KcjLgWyNU23Ephaz_-nxnRvKh0czVfU","$XH18e4KwErSn0lMRJWMvVPo6FkFq9t0B3npDApYcyPQ","$_j8LxmRqmotN06dwm7P3DPmnP56e8Anpn2VlxA7kTlw","$aYBKCqnT5gKLrM8JZsZdw3BgL1hF_n3TMHhv4V46xfY","$puFoIqMmk-5pnZtk7icWdgk7R54rY2lvbkgqYJ3s_ws","$rZdjpZN1nlYtabFp1NRvZmUsoR52ERlSWOcA9riLuxk","$u0K843ZHvTORJxtya5Z_ZjihyN9PPUOziVMT0ORoo1U","$vB5MbiIRZGs3DJmOmH8qBU29Yofka6txo0LHkeY1ZR4"],"room_id":"!5sR_D-NrNrQWRbV4wrKysuRrbpBzn-fi7_Dga02FVvk","sender":"@gergo:c10y.dinnye.pitty.hu","signatures":{"c10y.dinnye.pitty.hu":{"ed25519:FsVF8WT7":"2tVRt4298gMWZgFuiXPGIImJD6o1AAwplmeyXhrj0+NDFaN/2nhe52/q5iu/pv1kkwWkzueW7izp28sSHx30CA"}},"type":"org.matrix.dummy_event"}`,
	`{"auth_events":["$1Ob4k-pQdMiOjqJ_GtKUjJYh4tHZ8GTmgMGPT5zOkX0","$lDB5kY9gHufzypzevyDxQu4VSaPUbqZCRHFiZd6eqZ0"],"content":null,"depth":7907,"event_id":"$hkRGJfk6HQAwdD1IkmYzHSXl4THzraL-0G6kTN4Ksfg","hashes":{"sha256":"66Z7S8cL1S6CEUhZLxtfIlib0GSs0RYKmWI500Vkz0Q"},"origin_server_ts":1781672417189,"prev_events":["$6kxFfLjv8gI4HuoP-8wDv4hfG53vPlpm9UNvpnRdPBk","$IVVieY6CUz79OpSY7ros7dxjFv9vb_V7cFUtSe96T2w","$ORv8lymmNDYI2V18izUvl0sn7oMRoZMn6a9BhRYEFbw","$PIKowSpO4-dkaUTJ51Ufo-y7FXVr_c8uFUAwktiPUTc","$P_kbs4EeeYzlgATFO1mEZBtF-mXV5olCegfAX9iUCQI","$Q2FZQBMzMwF0H8ynSXMQ1U9LFwOi-ZLFlWQxpd0PFPQ","$RLTiaMH_b_xEH25tyx-tM49QONSm-7zuRfl2kywMMH8","$SR5u9etLEO-tFB4RDPz4S-cc1nT-2kVfO-onF9O20eQ","$lTD9yoLPZyN8qddcI6086wNM5abZiOk8D9niBHT6j78","$oGteFW-Zw60SN3ihIGMJqeM5yohJlccm95OSesrz4hM","$uDg0SG8japbNVpGnDzRNtSByqHKE9uZc_T06F0Ih3es"],"room_id":"!maudcarBFGzzh29d4ILqt-brFj-g8YlYQ10LarmkK5c","sender":"@vestibule:explodie.org","signatures":{"explodie.org":{"ed25519:nTG1lEoB":"AhVrAHNtoUzXVFyll2u+n8IkXsdEw599NXNWPvh6LgiD0JhgA9Vg9woXTyjirsT1TVGaMTSgkWpEnnFtHAAuCw"}},"type":"org.matrix.dummy_event"}`,
}

func TestEventIDKeepsNonObjectContent(t *testing.T) {
	for _, raw := range nonObjectContentEvents {
		var stored struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			t.Fatal(err)
		}
		wire, err := federationPDU(json.RawMessage(raw), "12")
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePDU(wire)
		if err != nil {
			t.Fatal(err)
		}
		if mautrixID, _ := p.GetEventID("12"); string(mautrixID) == stored.EventID {
			t.Fatal("fixture no longer exercises non-object content")
		}
		got, err := EventID(p, id.RoomVersion("12"))
		if err != nil || string(got) != stored.EventID {
			t.Fatalf("EventID = %s, %v; want %s", got, err, stored.EventID)
		}
		if !p.VerifyContentHash() {
			t.Fatal("content hash of the original event did not verify")
		}
	}
}
