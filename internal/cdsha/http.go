package cdsha

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The replica's HA API, served beside the CDS routes on the client port.
const (
	GenesisPath         = "/ha/genesis"
	EntriesPath         = "/ha/entries"
	ChainPath           = "/ha/chain"
	StatusPath          = "/ha/status"
	ResolvePath         = "/ha/resolve"
	StoreCredentialPath = "/ha/store-credential"
	GossipPath          = "/ha/gossip"
	HandoffPath         = "/ha/handoff"
	JoinPath            = "/ha/join"
)

// chainPage is the most entries one GET /ha/chain answers.
const chainPage = 32

// Chain is a page of the served chain and the served head.
type Chain struct {
	Entries []cdschain.Entry `json:"entries"`
	Head    cdschain.Head    `json:"head"`
}

// Status is a replica's view of itself, for operators and the CLI.
type Status struct {
	Slot         int             `json:"slot"`
	Member       string          `json:"member"`
	Pending      bool            `json:"genesisPending"`
	Held         *cdschain.Head  `json:"held,omitempty"`
	Floor        uint64          `json:"servedFloor"`
	Halted       string          `json:"halted,omitempty"`
	Fresh        bool            `json:"fresh"`
	IsMember     bool            `json:"isMember"`
	StoreError   string          `json:"storeError,omitempty"`
	Fork         *Fork           `json:"fork,omitempty"`
	Confirmed    []cdschain.Head `json:"confirmed,omitempty"`
	Evicted      string          `json:"evicted,omitempty"`
	ChainEntries int             `json:"chainEntries"`
	ChainBytes   int64           `json:"chainBytes"`
	Build        string          `json:"build,omitempty"`
	Serving      string          `json:"serving,omitempty"`
}

// Resolution is an operator's settlement of a fork at one replica.
type Resolution struct {
	Cluster string        `json:"cluster"`
	Slot    int           `json:"slot"`
	Seq     uint64        `json:"seq"`
	Keep    cdschain.Hash `json:"keep"`
	Drop    cdschain.Hash `json:"drop"`
	Nonce   string        `json:"nonce"`
}

// Authorizer checks an operator request's token for its exact body under keys.
type Authorizer func(r *http.Request, body []byte, keys []*ecdsa.PublicKey) error

// Status reports the replica; Serving is why it serves nothing, if so.
func (r *Replica) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{Slot: r.slot(), Member: r.memberPEM, Pending: r.state == nil && !r.joining, StoreError: r.storeErr, Fork: r.fork}
	if err := r.servingLocked(); err != nil {
		s.Serving = err.Error()
	}
	if r.state == nil {
		return s
	}
	held := r.state.Head
	s.Held, s.Floor, s.Fresh, s.Confirmed = &held, held.Seq, r.freshLocked() && r.fork == nil, r.done
	s.IsMember = r.state.Members[r.slot()] == r.memberPEM
	s.ChainEntries, s.ChainBytes, s.Build = r.state.Entries, r.state.Bytes, r.buildLocked()
	if r.fork != nil {
		s.Halted = s.Serving
	}
	if s.Build == "" {
		s.Evicted = "its build is not among the accepted builds"
	}
	return s
}

// Handler serves the HA API; authorize checks operator requests under the
// held chain's operator keys, the launch file's before a chain.
func (r *Replica) Handler(authorize Authorizer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+StatusPath, func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, r.Status()) })
	for path, genesis := range map[string]bool{GenesisPath: true, JoinPath: false} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
			p, err := r.Pending(genesis)
			if err == nil && p == nil {
				err = ErrNotPending
			}
			reply(w, p, err)
		})
	}
	mux.HandleFunc("POST "+GenesisPath, func(w http.ResponseWriter, req *http.Request) {
		var e cdschain.Entry
		if readJSON(w, req, cdschain.MaxEntryBytes, &e) {
			reply(w, nil, r.Start(Handoff{Entries: []cdschain.Entry{e}}))
		}
	})
	mux.HandleFunc("POST "+HandoffPath, func(w http.ResponseWriter, req *http.Request) {
		var h Handoff
		if readJSON(w, req, maxAnswer, &h) {
			reply(w, nil, r.Start(h))
		}
	})
	mux.HandleFunc("POST "+GossipPath, func(w http.ResponseWriter, req *http.Request) {
		var g Gossip
		if readJSON(w, req, 64<<10, &g) {
			pong, err := r.HandleGossip(req.Context(), g)
			reply(w, pong, err)
		}
	})
	mux.HandleFunc("POST "+EntriesPath, func(w http.ResponseWriter, req *http.Request) {
		var e cdschain.Entry
		if !readJSON(w, req, cdschain.MaxEntryBytes, &e) {
			return
		}
		head, confirmed, err := r.Submit(req.Context(), e)
		switch {
		case err == nil && !confirmed, errors.Is(err, ErrMayHaveCommitted):
			// The store took it (or may have), but no majority showed
			// that no other write took its seq.
			writeJSON(w, http.StatusAccepted, head)
		default:
			reply(w, head, err)
		}
	})
	mux.HandleFunc("GET "+ChainPath, func(w http.ResponseWriter, req *http.Request) {
		from, err := strconv.ParseUint(req.URL.Query().Get("from"), 10, 64)
		if err != nil {
			http.Error(w, "from must be a seq", http.StatusBadRequest)
			return
		}
		state, err := r.Current(req.Context())
		if err != nil {
			reply(w, nil, err)
			return
		}
		r.mu.Lock()
		page := Chain{Head: state.Head}
		// A resolve may have cut the chain since Current read it.
		if end := min(state.Head.Seq+1, from+chainPage, uint64(len(r.chain))); from < end {
			page.Entries = r.chain[from:end]
		}
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("POST "+ResolvePath, func(w http.ResponseWriter, req *http.Request) {
		var res Resolution
		if body, ok := r.operator(w, req, authorize, 4096); ok {
			if err := cdschain.DecodeStrict(body, &res); err != nil || res.Cluster != r.cfg.Cluster || res.Slot != r.slot() {
				http.Error(w, "the resolution is not for this replica", http.StatusUnprocessableEntity)
				return
			}
			reply(w, nil, r.Resolve(res.Seq, res.Keep, res.Drop))
		}
	})
	mux.HandleFunc("POST "+StoreCredentialPath, func(w http.ResponseWriter, req *http.Request) {
		if body, ok := r.operator(w, req, authorize, 64<<10); ok {
			reply(w, nil, r.SetCredential(body))
		}
	})
	return mux
}

func (r *Replica) operator(w http.ResponseWriter, req *http.Request, authorize Authorizer, limit int64) ([]byte, bool) {
	body, ok := httputil.ReadCappedBody(w, req, limit)
	if !ok {
		return nil, false
	}
	keys := r.cfg.OperatorKeys
	if state := r.State(); state != nil {
		keys = state.OperatorKeys
	}
	if err := authorize(req, body, keys); err != nil {
		slog.Warn("HA operator request refused", "path", req.URL.Path, "remote", req.RemoteAddr, "reason", err)
		// A token minted within the clock skew of this replica's start is
		// refused for now, not for good: a fresh one is taken later.
		if errors.Is(err, operatorauth.ErrTokenBeforeStart) {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return nil, false
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, req *http.Request, limit int64, v any) bool {
	body, ok := httputil.ReadCappedBody(w, req, limit)
	if ok {
		if err := cdschain.DecodeStrict(body, v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return false
		}
	}
	return ok
}

// reply answers v, or err's status: 409 a conflict, 422 an invalid entry,
// 503 anything that is not a definite answer.
func reply(w http.ResponseWriter, v any, err error) {
	switch {
	case err == nil && v == nil:
		w.WriteHeader(http.StatusNoContent)
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, ErrConflict), errors.Is(err, ErrNotPending):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrInvalid):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}
