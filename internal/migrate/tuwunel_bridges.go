package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"exowodus/internal/mx"
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
	protected, err := d.protectedBridgeUsers(bridges, serverName)
	if err != nil {
		return nil, err
	}
	consider := func(user string) {
		if isBridgeGhost(user, bridges, protected, serverName) {
			skipped[user] = true
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

func isBridgeGhost(user string, bridges []*Bridge, protected map[string]bool, serverName string) bool {
	if protected[user] || mx.ServerName(user) != serverName {
		return false
	}
	for _, b := range bridges {
		for _, re := range b.exclusive {
			if re.MatchString(user) {
				return true
			}
		}
	}
	return false
}

func (d *TuwunelDump) protectedBridgeUsers(bridges []*Bridge, serverName string) (map[string]bool, error) {
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
	return protected, nil
}
