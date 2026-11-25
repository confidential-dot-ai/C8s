package taha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
)

type prepareTransport func(*http.Request) (*http.Response, error)

func (f prepareTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func preparedPolicy(t *testing.T, label string) []byte {
	t.Helper()
	data, err := policyDocument(t, label).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func prepareFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]string{}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[file.Name()] = string(data)
	}
	return snapshot
}

func TestReadPreparedPolicyRefusesUncheckedBytes(t *testing.T) {
	canonical := preparedPolicy(t, "reviewed")
	matching := func(data []byte) string { return cdschain.Hash(sha256.Sum256(data)).String() }
	for name, tc := range map[string]struct {
		data   []byte
		digest func([]byte) string
	}{
		"invalid":        {data: []byte(`{}`), digest: matching},
		"malformed":      {data: []byte(`{"schema":`), digest: matching},
		"noncanonical":   {data: append(bytes.Clone(canonical), '\n'), digest: matching},
		"wrong digest":   {data: canonical, digest: func([]byte) string { return cdschain.Hash{}.String() }},
		"invalid digest": {data: canonical, digest: func(data []byte) string { return "sha256:" + matching(data) }},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readPreparedPolicy(path, tc.digest(tc.data)); err == nil {
				t.Fatal("unchecked policy accepted")
			}
		})
	}
}

func TestReadPreparedPolicySizeLimit(t *testing.T) {
	baseSize := len(preparedPolicy(t, "x"))
	for _, size := range []int{maxPolicyBytes, maxPolicyBytes + 1} {
		policy := preparedPolicy(t, strings.Repeat("x", size-baseSize+1))
		if len(policy) != size {
			t.Fatalf("fixture has %d bytes, want %d", len(policy), size)
		}
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, policy, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readPreparedPolicy(path, cdschain.Hash(sha256.Sum256(policy)).String())
		if size == maxPolicyBytes {
			if err != nil {
				t.Fatalf("canonical policy at the limit was rejected: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "policy exceeds ") {
			t.Fatalf("expected input-size refusal, got %v", err)
		}
	}
}

type policyHistoryTest struct {
	w       *writer
	target  policyTarget
	key     *ecdsa.PrivateKey
	entries []cdschain.Entry
	entry   cdschain.Entry
	reads   int
}

func newPolicyHistoryTest(t *testing.T) *policyHistoryTest {
	t.Helper()
	entries, key := testChain(t, 2)
	state, err := cdschain.Verify(entries)
	if err != nil {
		t.Fatal(err)
	}
	f := &policyHistoryTest{
		w: &writer{
			o:   &options{stateDir: t.TempDir()},
			url: "https://replica.invalid",
		},
		target: policyTarget{
			cluster: state.Cluster,
			genesis: state.Genesis,
			head:    state.Head,
		},
		key:     key,
		entries: entries,
	}
	payload, _ := json.Marshal(cdschain.Policy{Allowlist: preparedPolicy(t, "<reviewed>&")})
	f.entry, err = cdschain.Sign(key, cdschain.Body{
		Cluster: state.Cluster,
		Seq:     state.Head.Seq + 1,
		Prev:    state.Head.Hash,
		Type:    cdschain.TypePolicy,
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.w.client = &http.Client{Transport: prepareTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != haapi.ChainPath || r.URL.Query().Get("from") != "0" {
			t.Fatalf("validation sent unexpected request %s %s", r.Method, r.URL)
		}
		f.reads++
		response := httptest.NewRecorder()
		_ = json.NewEncoder(response).Encode(haapi.Chain{Entries: f.entries})
		return response.Result(), nil
	})}
	return f
}

func TestReadPolicyPreservesState(t *testing.T) {
	f := newPolicyHistoryTest(t)
	before := prepareFiles(t, f.w.o.stateDir)
	history, err := f.w.readPolicy(context.Background(), f.target, f.entry)
	if err != nil {
		t.Fatal(err)
	}
	if history.state.Head != f.target.head || len(history.entries) != len(f.entries) || history.entry.Hash != f.entry.Hash() || f.reads != 1 {
		t.Fatalf("incorrect checked history: %+v", history)
	}
	if !reflect.DeepEqual(before, prepareFiles(t, f.w.o.stateDir)) || f.w.chain != nil || f.w.key != nil {
		t.Fatal("validation changed local state or used an operator key")
	}
}

func TestReadPolicyRefusesInvalidHistory(t *testing.T) {
	for _, name := range []string{
		"cluster", "genesis", "predecessor seq", "predecessor hash", "record genesis",
		"rollback", "fork", "missing predecessor", "signature", "held signature", "held body", "corrupt tail", "invalid policy", "empty log",
	} {
		t.Run(name, func(t *testing.T) {
			f := newPolicyHistoryTest(t)
			genesis, floor := f.target.genesis, f.target.head
			switch name {
			case "cluster":
				f.target.cluster = "other"
			case "genesis":
				f.target.genesis = cdschain.Hash{9}
			case "predecessor seq":
				f.target.head.Seq++
			case "predecessor hash":
				f.target.head.Hash = cdschain.Hash{9}
			case "record genesis":
				genesis = cdschain.Hash{9}
			case "rollback":
				floor.Seq++
			case "fork":
				floor.Hash = cdschain.Hash{9}
			case "missing predecessor":
				f.entries = f.entries[:1]
			case "signature":
				f.entry.Sig = "invalid"
			case "held signature":
				f.entries = append(f.entries, f.entry)
				body, _ := f.entry.Decode()
				f.entry, _ = cdschain.Sign(f.key, body)
				if f.entry.Sig == f.entries[len(f.entries)-1].Sig {
					t.Fatal("fixture needs a different valid signature at the same hash")
				}
			case "held body", "invalid policy":
				body, _ := f.entry.Decode()
				body.Payload, _ = json.Marshal(cdschain.Policy{Allowlist: preparedPolicy(t, "other")})
				if name == "invalid policy" {
					body.Payload = json.RawMessage("{}")
					f.entry, _ = cdschain.Sign(f.key, body)
				} else {
					other, _ := cdschain.Sign(f.key, body)
					f.entries = append(f.entries, other)
				}
			case "corrupt tail":
				f.entries = append(f.entries, f.entry, cdschain.Entry{Body: []byte("{}")})
			case "empty log":
				f.entries = nil
			}
			if name == "record genesis" || name == "rollback" || name == "fork" {
				if err := f.w.o.acknowledge(genesis, floor); err != nil {
					t.Fatal(err)
				}
			}
			before := prepareFiles(t, f.w.o.stateDir)
			if _, err := f.w.readPolicy(context.Background(), f.target, f.entry); err == nil {
				t.Fatalf("invalid artifact, history or floor accepted: %v", err)
			}
			if !reflect.DeepEqual(before, prepareFiles(t, f.w.o.stateDir)) {
				t.Fatal("refusal changed local state")
			}
		})
	}
}

func TestReadSubmittedPolicyRefusesInvalidInput(t *testing.T) {
	for name, encoded := range map[string][]byte{
		"malformed":        []byte("{"),
		"duplicate":        []byte(`{"body":"","body":"","sig":""}`),
		"oversized":        bytes.Repeat([]byte(" "), cdschain.MaxEntryBytes+1),
		"nonpolicy":        nil,
		"zero seq":         nil,
		"cluster":          nil,
		"predecessor seq":  nil,
		"predecessor hash": nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newPolicyHistoryTest(t)
			if encoded == nil {
				body, _ := f.entry.Decode()
				switch name {
				case "nonpolicy":
					body.Type = cdschain.TypeRoutes
				case "zero seq":
					body.Seq = 0
					f.target.head.Seq = ^uint64(0)
				case "cluster":
					f.target.cluster = "other"
				case "predecessor seq":
					f.target.head.Seq++
				case "predecessor hash":
					f.target.head.Hash = cdschain.Hash{9}
				}
				f.entry, _ = cdschain.Sign(f.key, body)
			}
			if encoded == nil {
				encoded, _ = f.entry.Encode()
			}
			path := filepath.Join(t.TempDir(), "entry.json")
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readSubmittedPolicy(path, f.target); err == nil || f.reads != 0 {
				t.Fatalf("unchecked artifact reached the network: %v", err)
			}
		})
	}
}
