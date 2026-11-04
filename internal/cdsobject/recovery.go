package cdsobject

import (
	"encoding/json"
	"net/http"
)

// ServeRecoveryRequest publishes only the process's ephemeral public key and
// measured identity. An authority must authenticate this response over pinned
// armTLS itself; a relay's copy of it is not evidence of an attested recipient.
func (n *Node) ServeRecoveryRequest(w http.ResponseWriter, r *http.Request) {
	if n.recovery == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(n.recovery.Request())
}
