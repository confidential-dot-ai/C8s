package cds

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// wellKnown prefixes the public rollout-journal routes.
const wellKnown = "/.well-known/c8s"

var objectHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// authorityFingerprint is sha256:<hex> of the key's DER SubjectPublicKeyInfo.
func authorityFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// signedState is the wire form of a signed state: Signature is ASN.1 ECDSA
// over SHA-384 of the exact State bytes, by the key /ca certifies.
type signedState struct {
	State     json.RawMessage `json:"state"`
	Signature []byte          `json:"signature"`
}

func handleObject(store *allowlist.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := chi.URLParam(r, "hex")
		if !objectHex.MatchString(h) {
			http.Error(w, "object digest must be 64 lowercase hex", http.StatusBadRequest)
			return
		}
		body, ok, err := store.Object("sha256:" + h)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}

func handleLatest(store *allowlist.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		st, err := store.State()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"allowlist_version": st.Version, "policy": st.Policy})
	}
}

// handleState serves the signed state. With challenge set it reads
// {"nonce":"<hex>"} and binds the nonce into the signed state.
func handleState(store *allowlist.Store, key *ecdsa.PrivateKey, challenge bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := store.State()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if challenge {
			var req struct {
				Nonce string `json:"nonce"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Nonce) < 32 || len(req.Nonce) > 128 {
				http.Error(w, `body must be {"nonce":"<32 to 128 hex chars>"}`, http.StatusBadRequest)
				return
			}
			if _, err := hex.DecodeString(req.Nonce); err != nil {
				http.Error(w, "nonce must be hex", http.StatusBadRequest)
				return
			}
			st.Nonce = req.Nonce
		}
		body, err := json.Marshal(st)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		sum := sha512.Sum384(body)
		sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, signedState{State: body, Signature: sig})
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
