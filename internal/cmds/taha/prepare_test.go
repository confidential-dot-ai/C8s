package taha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
)

func prepareFixture(t *testing.T) (*writer, policyTarget) {
	t.Helper()
	entries, key := testChain(t, 3)
	state, err := cdschain.Verify(entries)
	if err != nil {
		t.Fatal(err)
	}
	replica := &racedReplica{entries: entries}
	w := &writer{
		o: &options{
			stateDir:   t.TempDir(),
			genesisPin: state.Genesis.String(),
		},
		url: "https://replica.invalid",
		key: key,
		client: &http.Client{Transport: prepareTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("preparation sent %s %s", r.Method, r.URL.Path)
			}
			response := httptest.NewRecorder()
			replica.ServeHTTP(response, r)
			return response.Result(), nil
		})},
	}
	return w, policyTarget{
		cluster: state.Cluster,
		genesis: state.Genesis,
		head:    state.Head,
	}
}

func TestPreparePolicyPreservesBytesAndAcceptedState(t *testing.T) {
	w, target := prepareFixture(t)
	policy := preparedPolicy(t, "<reviewed>&")
	input := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(input, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	checked, err := readPreparedPolicy(input, cdschain.Hash(sha256.Sum256(policy)).String())
	if err != nil || !bytes.Equal(checked, policy) {
		t.Fatalf("reading exact policy bytes: %v", err)
	}
	output := filepath.Join(t.TempDir(), "entry.json")
	var message bytes.Buffer
	if err := w.preparePolicy(context.Background(), &message, target, checked, output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := cdschain.ParseEntry(data)
	if err != nil {
		t.Fatal(err)
	}
	body, err := entry.Decode()
	if err != nil || body.Cluster != target.cluster || body.Seq != target.head.Seq+1 || body.Prev != target.head.Hash || body.Type != cdschain.TypePolicy {
		t.Fatalf("incorrect prepared body: %+v %v", body, err)
	}
	var payload cdschain.Policy
	if err := json.Unmarshal(body.Payload, &payload); err != nil || !bytes.Equal(payload.Allowlist, policy) {
		t.Fatal("prepared payload changed the reviewed bytes")
	}
	if _, err := w.chain.state.Apply(entry); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("artifact permissions are not 0600")
	}
	rec, err := w.o.record(target.cluster)
	if err != nil || rec == nil || rec.Genesis != target.genesis || rec.Acknowledged.Seq != 0 || rec.Acknowledged.Hash != target.genesis {
		t.Fatal("preparation acknowledged more than the explicitly trusted genesis")
	}
	cache, err := os.ReadFile(filepath.Join(w.o.stateDir, target.cluster+".chain"))
	var accepted verifiedChain
	if err != nil || json.Unmarshal(cache, &accepted) != nil || accepted.restore() != nil || accepted.state.Head != target.head || accepted.state.Policy != nil || w.chain.state.Head != target.head {
		t.Fatal("preparation advanced accepted state or cached its candidate")
	}
	if !strings.Contains(message.String(), "prepared head") || !strings.Contains(message.String(), "not submitted") {
		t.Fatalf("misleading result: %s", message.String())
	}
}

func TestPreparePolicyChecksBeforeLocalSideEffects(t *testing.T) {
	for _, name := range []string{"cluster", "genesis", "head seq", "head hash", "existing pin conflict", "record genesis", "rollback", "fork"} {
		t.Run(name, func(t *testing.T) {
			w, target := prepareFixture(t)
			genesis, head := target.genesis, target.head
			recorded := false
			switch name {
			case "cluster":
				target.cluster = "other"
			case "genesis":
				target.genesis = cdschain.Hash{9}
			case "head seq":
				target.head.Seq++
			case "head hash":
				target.head.Hash = cdschain.Hash{9}
			case "existing pin conflict":
				// An explicit --genesis binds even where a record already agrees with the chain.
				w.o.genesisPin, recorded = cdschain.Hash{9}.String(), true
			case "record genesis":
				genesis, recorded = cdschain.Hash{9}, true
			case "rollback":
				head.Seq, recorded = head.Seq+1, true
			case "fork":
				head.Hash, recorded = cdschain.Hash{9}, true
			}
			if recorded {
				if err := w.o.acknowledge(genesis, head); err != nil {
					t.Fatal(err)
				}
			}
			before := prepareFiles(t, w.o.stateDir)
			output := filepath.Join(t.TempDir(), "entry.json")
			err := w.preparePolicy(context.Background(), io.Discard, target, preparedPolicy(t, "reviewed"), output)
			if err == nil {
				t.Fatal("invalid target or floor accepted")
			}
			if !reflect.DeepEqual(before, prepareFiles(t, w.o.stateDir)) || w.chain != nil {
				t.Fatal("failed target or floor check changed records or cache")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failed target or floor check created an artifact")
			}
		})
	}
}

func TestPreparePolicyRefusesSignerAndOutputFailures(t *testing.T) {
	for _, name := range []string{"unauthorized", "existing", "missing directory", "encoded size"} {
		t.Run(name, func(t *testing.T) {
			w, target := prepareFixture(t)
			output := filepath.Join(t.TempDir(), "entry.json")
			policy := preparedPolicy(t, "reviewed")
			switch name {
			case "unauthorized":
				w.key = testKey(t)
			case "existing":
				if err := os.WriteFile(output, []byte("retained"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing directory":
				output = filepath.Join(output, "entry.json")
			case "encoded size":
				policy = preparedPolicy(t, strings.Repeat("x", cdschain.MaxEntryBytes*7/8))
			}
			if err := w.preparePolicy(context.Background(), io.Discard, target, policy, output); err == nil {
				t.Fatal("expected preparation failure")
			}
			if name == "existing" {
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "retained" {
					t.Fatal("existing output was replaced")
				}
			} else if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failed preparation left an artifact")
			}
			rec, err := w.o.record(target.cluster)
			if err != nil || rec == nil || rec.Acknowledged.Seq != 0 || w.chain.state.Head != target.head || w.chain.state.Policy != nil {
				t.Fatal("failed preparation advanced its acknowledged or accepted state")
			}
		})
	}
}

func TestPreparePolicyCommandRequiresTrustAndInputs(t *testing.T) {
	base := map[string]string{
		"url":               "http://127.0.0.1:1",
		"image-policy-file": "pins.json",
		"cluster":           "lane",
		"genesis":           strings.Repeat("1", 64),
		"expect-head":       "0:" + strings.Repeat("1", 64),
		"file":              "policy.json",
		"policy-sha256":     strings.Repeat("1", 64),
		"out":               "entry.json",
	}
	// Each refusal is matched by its own text: a flag's name alone also
	// appears in refusals of other checks.
	for name, want := range map[string]string{
		"insecure":                  "prepare-policy requires attested HTTPS; --insecure is not allowed",
		"missing-image-policy-file": "prepare-policy requires independent Trust Authority pins: pass --image-policy-file",
		"cluster":                   "--cluster must not be empty",
		"genesis":                   "--genesis is required",
		"expect-head":               "--expect-head: ",
		"policy-sha256":             "--policy-sha256: ",
		"missing-cluster":           `required flag(s) "cluster" not set`,
		"missing-expect-head":       `required flag(s) "expect-head" not set`,
		"missing-file":              `required flag(s) "file" not set`,
		"missing-policy-sha256":     `required flag(s) "policy-sha256" not set`,
		"missing-out":               `required flag(s) "out" not set`,
	} {
		t.Run(name, func(t *testing.T) {
			flags := maps.Clone(base)
			flag := strings.TrimPrefix(name, "missing-")
			switch {
			case name == "insecure":
				flags[flag] = "true"
			case strings.HasPrefix(name, "missing-"):
				delete(flags, flag)
			default:
				flags[flag] = ""
			}
			args := []string{"prepare-policy"}
			for key, value := range flags {
				args = append(args, "--"+key+"="+value)
			}
			cmd := NewCmd()
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("expected %q, got %v", want, err)
			}
		})
	}
}

func TestNewOutputRefusesBeforeAnythingIsSigned(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "entry.json")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newOutput(existing); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("existing output: %v", err)
	}
	if err := newOutput(filepath.Join(dir, "missing", "entry.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing output directory: %v", err)
	}
	if err := newOutput(filepath.Join(dir, "new.json")); err != nil {
		t.Fatal(err)
	}
}
