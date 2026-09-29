package migrate

import (
	"encoding/json"
	"maps"
	"net/url"
	"strconv"
	"strings"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

// Restored through dedicated endpoints.
var skipAccountData = map[string]bool{"m.push_rules": true, "m.fully_read": true}

// transformAccountData returns false when the type must not be copied.
// Cross-signing secrets need keepIdentity: they belong to the old user ID.
func transformAccountData(typ string, content json.RawMessage, mapID, mapRoom func(string) string, keepIdentity bool) (json.RawMessage, bool, error) {
	if skipAccountData[typ] || !keepIdentity && strings.HasPrefix(typ, "m.cross_signing.") {
		return nil, false, nil
	}
	switch typ {
	case "m.direct":
		var direct map[string][]string
		if err := json.Unmarshal(content, &direct); err != nil {
			return nil, false, err
		}
		out := make(map[string][]string, len(direct))
		for user, rooms := range direct {
			id := mapID(user)
			for _, r := range rooms {
				out[id] = append(out[id], mapRoom(r))
			}
		}
		data, err := json.Marshal(out)
		return data, true, err
	case "m.ignored_user_list":
		var list map[string]json.RawMessage
		if err := json.Unmarshal(content, &list); err != nil {
			return nil, false, err
		}
		var ignored map[string]json.RawMessage
		if raw, ok := list["ignored_users"]; ok {
			if err := json.Unmarshal(raw, &ignored); err != nil {
				return nil, false, err
			}
		}
		out := make(map[string]json.RawMessage, len(ignored))
		for user, v := range ignored {
			out[mapID(user)] = v
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return nil, false, err
		}
		list["ignored_users"] = raw
		data, err := json.Marshal(list)
		return data, true, err
	}
	return content, true, nil
}

type pushRule struct {
	RuleID     string            `json:"rule_id"`
	Default    bool              `json:"default"`
	Enabled    bool              `json:"enabled"`
	Actions    []json.RawMessage `json:"actions"`
	Conditions []json.RawMessage `json:"conditions,omitempty"`
	Pattern    string            `json:"pattern,omitempty"`
}

type putOp struct {
	Path  mautrix.ClientURLPath
	Query url.Values
	Body  any
	// Optional ops target server-default rules the destination may lack.
	Optional bool
}

var pushRuleKinds = []string{"override", "content", "room", "sender", "underride"}

// pushRuleOps preserves the order of user-defined rules within each kind.
func pushRuleOps(raw json.RawMessage, mapID, mapRoom func(string) string) ([]putOp, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var rules struct {
		Global map[string][]pushRule `json:"global"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	var ops []putOp
	for _, kind := range pushRuleKinds {
		prev := ""
		for _, r := range rules.Global[kind] {
			if r.Default {
				ops = append(ops,
					putOp{Path: pushRulePath(kind, r.RuleID, "enabled"), Body: map[string]bool{"enabled": r.Enabled}, Optional: true},
					putOp{Path: pushRulePath(kind, r.RuleID, "actions"), Body: map[string]any{"actions": r.Actions}, Optional: true},
				)
				continue
			}
			id := r.RuleID
			switch kind {
			case "sender":
				id = mapID(id)
			case "room":
				id = mapRoom(id)
			}
			body := map[string]any{"actions": r.Actions}
			switch kind {
			case "override", "underride":
				body["conditions"] = r.Conditions
			case "content":
				body["pattern"] = r.Pattern
			}
			var q url.Values
			if prev != "" {
				q = url.Values{"after": {prev}}
			}
			ops = append(ops, putOp{Path: pushRulePath(kind, id), Query: q, Body: body})
			if !r.Enabled {
				ops = append(ops, putOp{Path: pushRulePath(kind, id, "enabled"), Body: map[string]bool{"enabled": false}})
			}
			prev = id
		}
	}
	return ops, nil
}

func (op putOp) url(c *mautrix.Client) string {
	return c.BuildURLWithFullQuery(op.Path, func(q url.Values) { maps.Copy(q, op.Query) })
}

func pushRulePath(kind, ruleID string, attr ...any) mautrix.ClientURLPath {
	return append(mautrix.ClientURLPath{"v3", "pushrules", "global", kind, ruleID}, attr...)
}

// raisePower grants newID oldID's level; false when unchanged.
func raisePower(content map[string]any, oldID, newID string) bool {
	users, _ := content["users"].(map[string]any)
	def := powerValue(content["users_default"])
	old := def
	if v, ok := users[oldID]; ok {
		old = powerValue(v)
	}
	if old <= def {
		return false
	}
	return grantPower(content, newID, old)
}

func grantPower(content map[string]any, userID string, level int64) bool {
	users, _ := content["users"].(map[string]any)
	if users == nil {
		users = map[string]any{}
	}
	if v, ok := users[userID]; ok && powerValue(v) >= level {
		return false
	}
	users[userID] = level
	content["users"] = users
	return true
}

func isV12Creator(state []*event.Event, userID string) bool {
	for _, ev := range state {
		if ev.Type != event.StateCreate || string(ev.Sender) != userID {
			continue
		}
		var content struct {
			RoomVersion string `json:"room_version"`
		}
		return json.Unmarshal(ev.Content.VeryRaw, &content) == nil && content.RoomVersion == "12"
	}
	return false
}

func powerValue(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int64:
		return n
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}
