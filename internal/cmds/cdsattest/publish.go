package cdsattest

import (
	"encoding/json"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

// handleRoutePublication serves the applied signed manifest in the CDS's
// GET /routes envelope, byte for byte, so a client can verify it under its
// pinned operator keys and compare its digest with the transcript's (V2). It
// answers 404 before the first apply. A stale manifest is still the applied
// one, so it is still served.
func (s *Server) handleRoutePublication(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var applied *routing.Applied
	if s.routes != nil {
		applied = s.routes.Current()
	}
	if applied == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, err := json.Marshal(applied.Signed.Envelope())
	if err != nil {
		s.log.Error("marshal route publication", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
