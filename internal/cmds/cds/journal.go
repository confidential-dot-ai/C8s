package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/rolloutstate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// wellKnown prefixes the public rollout-journal routes.
const wellKnown = "/.well-known/c8s"

var objectHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// authorityFingerprint is sha256:<hex> of the key's DER SubjectPublicKeyInfo.
func authorityFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])
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
		rolloutstate.Stamp(&st, time.Now())
		body, err := json.Marshal(st)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		sigContext := rolloutstate.ContextState
		if challenge {
			sigContext = rolloutstate.ContextChallenge
		}
		sig, err := rolloutstate.Sign(key, sigContext, body)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, types.SignedRolloutState{State: body, Signature: sig})
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// startJournal starts the allowlist journal with cfg's lease, and activates
// an update an earlier run staged once its lease has run.
func startJournal(store *allowlist.Store, authority string, cfg config) error {
	if err := store.StartJournal(authority, cfg.activationLease); err != nil {
		return fmt.Errorf("start allowlist journal: %w", err)
	}
	// Without a lease, an update staged by an earlier run activates now
	// rather than blocking writes forever.
	if _, err := store.Activate(time.Now()); err != nil {
		return fmt.Errorf("activate pending allowlist update: %w", err)
	}
	return nil
}

// policyAcker asks one node's inventory for its policy acknowledgement.
type policyAcker interface {
	PolicyAck(ctx context.Context, host string) (workloadclaims.PolicyAck, error)
}

// nodeAcks decides when the rollout bound may drain: every node that may run
// a workload must acknowledge the enforced policy clean. nodes lists those
// nodes, each as the addresses it may answer on; an empty list never drains,
// since nothing vouches that no node runs an earlier policy.
type nodeAcks struct {
	client policyAcker
	nodes  func() [][]string
	// every spaces the node polls; zero means drainCheckInterval.
	every time.Duration
}

func (a nodeAcks) interval() time.Duration {
	if a.every > 0 {
		return a.every
	}
	return drainCheckInterval
}

// acked reports whether every node acknowledges policy clean on one of its
// addresses. It returns the addresses that did, or else the addresses of the
// first node that did not and why.
func (a nodeAcks) acked(ctx context.Context, policy string) (bool, []string, string) {
	nodes := a.nodes()
	if len(nodes) == 0 {
		return false, nil, "no nodes known"
	}
	var acked []string
	for _, addrs := range nodes {
		why := "no address"
		for _, host := range addrs {
			ack, err := a.client.PolicyAck(ctx, host)
			switch {
			case err != nil:
				why = err.Error()
			case ack.Policy != policy:
				why = "acknowledges " + ack.Policy
			case !ack.Clean:
				why = "still runs a container the policy denies"
			default:
				why = ""
			}
			if why == "" {
				acked = append(acked, host)
				break
			}
		}
		if why != "" {
			return false, addrs, why
		}
	}
	return true, acked, ""
}

// drainCheckInterval spaces the node polls while the bound holds more than
// one policy, by default.
const drainCheckInterval = 10 * time.Second

// journalLoop enforces a pending allowlist update once its lease has run, and
// drains a widened bound once every node acknowledges the enforced policy.
// acks nil never drains.
func journalLoop(ctx context.Context, store *allowlist.Store, tick time.Duration, acks *nodeAcks) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	var lastCheck time.Time
	var lastWait string
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if ok, err := store.Activate(now); err != nil {
				slog.Error("allowlist activation failed", "error", err)
			} else if ok {
				slog.Info("allowlist update activated")
			}
			if acks == nil || now.Sub(lastCheck) < acks.interval() {
				continue
			}
			st, err := store.State()
			if err != nil || len(st.Bound) < 2 || st.Pending != "" {
				continue
			}
			lastCheck = now
			checkCtx, cancel := context.WithTimeout(ctx, acks.interval())
			ok, nodes, why := acks.acked(checkCtx, st.Policy)
			cancel()
			if !ok {
				// Logged once per change: a drain can wait for hours.
				if wait := fmt.Sprint(st.Policy, nodes, why); wait != lastWait {
					lastWait = wait
					slog.Info("allowlist bound not drained yet", "policy", st.Policy, "nodes", nodes, "reason", why)
				}
				continue
			}
			if ok, err := store.Drain(st.Policy, nodes); err != nil {
				slog.Error("allowlist drain failed", "error", err)
			} else if ok {
				slog.Info("allowlist bound drained: every node acknowledged the enforced policy", "policy", st.Policy)
			}
		}
	}
}
