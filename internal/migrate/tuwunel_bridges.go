package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"exodus/internal/mx"
)

func (d *TuwunelDump) appservices() ([]*Bridge, error) {
	rows := d.maps["id_appserviceregistrations"]
	var bridges []*Bridge
	for _, id := range slices.Sorted(maps.Keys(rows)) {
		b, err := parseBridge(rows[id], nil)
		if err != nil {
			return nil, fmt.Errorf("id_appserviceregistrations %s: %w", id, err)
		}
		if b.ID != id {
			return nil, fmt.Errorf("id_appserviceregistrations %s: registration ID differs from database key", id)
		}
		if b.sender == "" {
			return nil, fmt.Errorf("id_appserviceregistrations %s: missing sender_localpart", id)
		}
		bridges = append(bridges, b)
	}
	return bridges, nil
}

// BridgeUsers selects exclusive appservice users without saved login or device data.
func (d *TuwunelDump) BridgeUsers(users map[string]bool, serverName string) (map[string]bool, error) {
	bridges, err := d.appservices()
	if err != nil {
		return nil, err
	}
	skipped := map[string]bool{}
	if len(bridges) == 0 {
		return skipped, nil
	}
	protected := map[string]bool{}
	for user, password := range d.passwords {
		if len(password) != 0 && string(password) != "*" {
			protected[user] = true
		}
	}
	for _, value := range d.tokens {
		user, _, ok := bytes.Cut(value, []byte{0xff})
		if !ok {
			return nil, errors.New("invalid Tuwunel token record")
		}
		protected[string(user)] = true
	}
	for _, name := range []string{"userdeviceid_metadata", "onetimekeyid4225_otk", "onetimekeyid_onetimekeys", "userdeviceidalgorithm_fallback", "senderkey_pusher"} {
		for key := range d.maps[name] {
			user, _, ok := strings.Cut(key, "\xff")
			if !ok {
				return nil, fmt.Errorf("%s: invalid Tuwunel device key", name)
			}
			protected[user] = true
		}
	}
	for key := range d.refresh {
		user, _, ok := strings.Cut(key, "\xff")
		if !ok {
			return nil, errors.New("invalid Tuwunel refresh-token key")
		}
		protected[user] = true
	}
	for _, b := range bridges {
		protected["@"+b.sender+":"+serverName] = true
	}
	consider := func(user string) {
		if protected[user] || mx.ServerName(user) != serverName {
			return
		}
		for _, b := range bridges {
			for _, re := range b.exclusive {
				if re.MatchString(user) {
					skipped[user] = true
					return
				}
			}
		}
	}
	for user := range users {
		consider(user)
	}
	for user := range d.passwords {
		consider(user)
	}
	return skipped, nil
}
