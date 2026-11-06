// Package protocol describes the fixed operations of the disposable three-host
// qualification image. It accepts no executable, URL, file path or shell input.
package protocol

import "encoding/json"

type Request struct {
	Operation   string          `json:"operation"`
	Target      int             `json:"target"`
	OperatorKey []byte          `json:"operator_key,omitempty"`
	Provision   json.RawMessage `json:"provision,omitempty"`
}

type Reply struct {
	Operation string         `json:"operation"`
	Passed    bool           `json:"passed"`
	Seconds   float64        `json:"seconds"`
	Checks    map[string]any `json:"checks,omitempty"`
}

func (q Request) Valid() bool {
	if q.Target < 0 || q.Target > 2 {
		return false
	}
	switch q.Operation {
	case "init":
		return len(q.OperatorKey) > 0 && len(q.OperatorKey) < 4096 && len(q.Provision) < 8192
	case "startup", "status", "provision", "seed", "attach", "burst", "prepare", "refuse", "survive", "heal", "revoke", "revoked", "overlap", "admit", "retire", "roll-safe":
		return len(q.OperatorKey) == 0 && len(q.Provision) == 0
	}
	return false
}
