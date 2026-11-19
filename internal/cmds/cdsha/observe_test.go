package cdsha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

type observationTest struct {
	*submissionTest
	status haapi.Status
	output bytes.Buffer
	onRead func()
}

func newObservationTest(t *testing.T) *observationTest {
	t.Helper()
	f := &observationTest{submissionTest: newSubmissionTest(t)}
	f.entries = append(f.entries, f.entry)
	f.held(t)
	f.status.Confirmed = []cdschain.Head{f.head()}
	transport := f.w.client.Transport
	f.w.client.Transport = prepareTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("observation sent %s %s", r.Method, r.URL)
		}
		if f.onRead != nil {
			f.onRead()
		}
		if r.URL.Path != haapi.StatusPath {
			return transport.RoundTrip(r)
		}
		response := httptest.NewRecorder()
		_ = json.NewEncoder(response).Encode(f.status)
		return response.Result(), nil
	})
	return f
}

func (f *observationTest) held(t *testing.T) {
	t.Helper()
	s, err := cdschain.Verify(f.entries)
	if err != nil {
		t.Fatal(err)
	}
	f.status = haapi.Status{
		Held:     &s.Head,
		Fresh:    true,
		IsMember: true,
	}
}

func (f *observationTest) observe(t *testing.T) error {
	t.Helper()
	encoded, err := f.entry.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.encoded = append(append([]byte(" \n"), encoded...), '\n')
	if err := os.WriteFile(f.path, f.encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	data, entry, err := readSubmittedPolicy(f.path, f.target)
	if err == nil {
		var observed observedPolicy
		observed, err = f.w.readObservedPolicy(context.Background(), f.target, data, entry)
		if err == nil {
			err = f.w.o.reportObservedPolicy(&f.output, f.target.genesis, observed)
		}
	}
	after, readErr := os.ReadFile(f.path)
	if readErr != nil || !bytes.Equal(after, f.encoded) || f.posts != 0 || f.w.key != nil || f.w.chain != nil {
		t.Fatal("observation changed the artifact, submitted it, or used signing/cache state")
	}
	return err
}

func TestObservePolicyConfirmationAndCurrentPolicy(t *testing.T) {
	for _, kind := range []string{"exact", "rotation", "new policy", "unconfirmed newer policy", "concurrent higher floor"} {
		t.Run(kind, func(t *testing.T) {
			f := newObservationTest(t)
			if kind != "exact" {
				typ := cdschain.TypePolicy
				payload, _ := json.Marshal(cdschain.Policy{Allowlist: preparedPolicy(t, "new policy")})
				if kind == "rotation" || kind == "concurrent higher floor" {
					typ = cdschain.TypeOperatorKeys
					pub, _ := cdschain.PublicKeyPEM(&testKey(t).PublicKey)
					payload, _ = json.Marshal(cdschain.OperatorKeys{Keys: pub})
				}
				next, err := cdschain.Sign(f.key, cdschain.Body{
					Cluster: f.target.cluster,
					Seq:     f.head().Seq + 1,
					Prev:    f.entry.Hash(),
					Type:    typ,
					Payload: payload,
				})
				if err != nil {
					t.Fatal(err)
				}
				f.entries = append(f.entries, next)
				f.held(t)
				f.status.Confirmed = []cdschain.Head{*f.status.Held}
				if kind == "unconfirmed newer policy" || kind == "concurrent higher floor" {
					f.status.Confirmed = []cdschain.Head{f.head()}
				}
				if kind == "concurrent higher floor" {
					f.onRead = func() {
						if f.reads > 0 {
							if err := f.w.o.acknowledge(f.target.genesis, *f.status.Held); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
			if err := f.observe(t); err != nil {
				t.Fatal(err)
			}
			var result observedPolicy
			if err := json.Unmarshal(f.output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			state, _ := cdschain.Verify(f.entries)
			rec, err := f.w.o.record(f.target.cluster)
			wantCurrent := kind == "exact" || kind == "rotation" || kind == "concurrent higher floor"
			wantFloor := result.Confirmed
			if kind == "concurrent higher floor" {
				wantFloor = *f.status.Held
			}
			if err != nil || rec == nil || rec.Acknowledged != wantFloor || result.Confirmed != f.status.Confirmed[0] || result.Entry != f.head() || result.Held != *f.status.Held || result.Current != wantCurrent {
				t.Fatalf("observation or saved floor: %+v, %+v, %v", result, rec, err)
			}
			if result.Policy.Seq != state.PolicySeq || result.Policy.Hash != f.entries[state.PolicySeq].Hash() || result.PolicySHA256 != cdschain.Hash(sha256.Sum256(state.Policy)) || result.ArtifactSHA256 != cdschain.Hash(sha256.Sum256(f.encoded)) {
				t.Fatalf("wrong policy or artifact identity: %+v", result)
			}
		})
	}
}

func TestObservePolicyRefusesWithoutChangingLocalState(t *testing.T) {
	for _, kind := range []string{
		"not held", "same body different signature", "wrong genesis", "wrong cluster", "wrong predecessor", "corrupt tail",
		"no confirmation", "older confirmation", "foreign confirmation", "wrong confirmed hash", "confirmed past head",
		"not serving", "not fresh", "not member", "fork", "missing held", "changed head", "held hash", "held cluster",
		"saved genesis", "rollback", "saved fork", "corrupt record", "saved floor removed during read",
	} {
		t.Run(kind, func(t *testing.T) {
			f := newObservationTest(t)
			switch kind {
			case "not held":
				f.entries = f.entries[:len(f.entries)-1]
			case "same body different signature":
				body, _ := f.entry.Decode()
				f.entry, _ = cdschain.Sign(f.key, body)
			case "wrong genesis":
				f.target.genesis = cdschain.Hash{9}
			case "wrong cluster":
				f.target.cluster = "other"
			case "wrong predecessor":
				f.target.head.Hash = cdschain.Hash{9}
			case "corrupt tail":
				f.entries[len(f.entries)-1].Sig = "invalid"
			case "no confirmation":
				f.status.Confirmed = nil
			case "older confirmation":
				f.status.Confirmed[0] = f.target.head
			case "foreign confirmation":
				f.status.Confirmed[0].Cluster = "other"
			case "wrong confirmed hash":
				f.status.Confirmed[0].Hash = cdschain.Hash{9}
			case "confirmed past head":
				f.status.Confirmed[0].Seq++
			case "not serving":
				f.status.Serving = "unavailable"
			case "not fresh":
				f.status.Fresh = false
			case "not member":
				f.status.IsMember = false
			case "fork":
				f.status.Fork = &haapi.Fork{Seq: 1}
			case "missing held":
				f.status.Held = nil
			case "changed head":
				f.status.Held.Seq++
			case "held hash":
				f.status.Held.Hash = cdschain.Hash{9}
			case "held cluster":
				f.status.Held.Cluster = "other"
			case "saved genesis", "rollback", "saved fork", "saved floor removed during read":
				genesis, head := f.target.genesis, f.head()
				if kind == "saved genesis" {
					genesis = cdschain.Hash{9}
				}
				if kind == "rollback" || kind == "saved floor removed during read" {
					head.Seq++
				}
				if kind == "saved fork" {
					head.Hash = cdschain.Hash{9}
				}
				if err := f.w.o.acknowledge(genesis, head); err != nil {
					t.Fatal(err)
				}
				if kind == "saved floor removed during read" {
					f.onRead = func() { f.onRead = nil; path, _ := f.w.o.recordPath(f.target.cluster); _ = os.Remove(path) }
				}
			case "corrupt record":
				path, _ := f.w.o.recordPath(f.target.cluster)
				if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := prepareFiles(t, f.w.o.stateDir)
			err := f.observe(t)
			if err == nil || f.output.Len() != 0 {
				t.Fatalf("unverified observation succeeded: %v, %s", err, f.output.String())
			}
			switch kind {
			case "not held", "no confirmation", "older confirmation", "not serving", "not fresh", "not member", "fork", "missing held", "changed head", "held hash", "held cluster":
				if cmdsutil.ExitStatus(err) != cmdsutil.ExitNotConfirmed {
					t.Fatalf("expected unconfirmed exit status: %v", err)
				}
			}
			if kind != "saved floor removed during read" && !reflect.DeepEqual(before, prepareFiles(t, f.w.o.stateDir)) {
				t.Fatal("failed observation changed local state")
			}
		})
	}
}

func TestObservePolicyPersistenceFailureWithholdsOutput(t *testing.T) {
	f := newObservationTest(t)
	f.w.o.persist = func(string, []byte, os.FileMode) error { return errors.New("sync failed") }
	err := f.observe(t)
	if cmdsutil.ExitStatus(err) != cmdsutil.ExitNotConfirmed || f.output.Len() != 0 {
		t.Fatalf("persistence failure reported success: %v, %s", err, f.output.String())
	}
}

func TestObservePolicyConcurrentRecordConflict(t *testing.T) {
	f := newObservationTest(t)
	f.onRead = func() {
		if f.reads > 0 {
			head := f.head()
			head.Hash = cdschain.Hash{9}
			if err := f.w.o.acknowledge(f.target.genesis, head); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.observe(t); !errors.Is(err, ErrRecordConflict) || f.output.Len() != 0 {
		t.Fatalf("concurrent conflicting record was accepted: %v", err)
	}
}

func TestObservePolicyRequiresPins(t *testing.T) {
	f := newObservationTest(t)
	base := map[string]string{
		"image-policy-file": "independent.json",
		"cluster":           f.target.cluster,
		"genesis":           f.target.genesis.String(),
		"expect-head":       fmt.Sprintf("%d:%s", f.target.head.Seq, f.target.head.Hash),
		"file":              f.path,
	}
	for _, name := range []string{"insecure", "image-policy-file", "cluster", "genesis", "expect-head", "file"} {
		flags := maps.Clone(base)
		delete(flags, name)
		if name == "insecure" {
			flags[name] = "true"
		}
		args := []string{"observe-policy"}
		for key, value := range flags {
			args = append(args, "--"+key+"="+value)
		}
		cmd := NewCmd()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("expected %s refusal: %v", name, err)
		}
	}
}

func TestObservePolicyChecksReplicaEndpoints(t *testing.T) {
	for _, kind := range []string{"second confirms", "neither confirms", "invalid first chain", "invalid confirmation", "record failure", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := newObservationTest(t)
			o := f.w.o
			o.URL, o.endpoints = "", nil
			o.genesisPin = f.target.genesis.String()
			o.MeasurementsConfig = testutil.CDSPinFile(t)
			o.Verifier, o.Timeout, o.DirectCDS = testutil.ApproveAll(), time.Second, true
			var reads [2]atomic.Int32
			for slot := range 2 {
				status := f.status
				entries := append([]cdschain.Entry(nil), f.entries...)
				if slot == 0 || kind == "neither confirms" {
					status.Confirmed = nil
				}
				if slot == 0 && kind == "invalid first chain" {
					entries[0].Sig = "invalid"
				}
				if slot == 1 && kind == "invalid confirmation" {
					head := f.head()
					head.Hash = cdschain.Hash{9}
					status.Confirmed = []cdschain.Head{head}
				}
				if kind == "record failure" {
					status.Confirmed = []cdschain.Head{f.head()}
					o.persist = failedPersist
				}
				mux := http.NewServeMux()
				mux.HandleFunc(haapi.ChainPath, func(w http.ResponseWriter, r *http.Request) {
					reads[slot].Add(1)
					if r.Method != http.MethodGet {
						t.Error("observation sent a mutation")
					}
					_ = json.NewEncoder(w).Encode(haapi.Chain{Entries: entries})
				})
				mux.HandleFunc(haapi.StatusPath, func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Error("observation sent a mutation")
					}
					_ = json.NewEncoder(w).Encode(status)
				})
				server := testutil.NewARMTLSServer(t, mux)
				o.endpoints = append(o.endpoints, strings.TrimPrefix(server.URL, "https://"))
			}
			encoded, err := f.entry.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := newObservePolicyCmd(o)
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"--cluster", f.target.cluster, "--expect-head", fmt.Sprintf("%d:%s", f.target.head.Seq, f.target.head.Hash), "--file", f.path})
			cmd.SetOut(&f.output)
			cmd.SetErr(io.Discard)
			if kind == "cancelled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				cmd.SetContext(ctx)
			}
			err = cmd.Execute()
			success := kind == "second confirms" || kind == "invalid first chain"
			if (err == nil) != success || (f.output.Len() > 0) != success {
				t.Fatalf("observation: %v, output %q", err, &f.output)
			}
			if kind == "neither confirms" && cmdsutil.ExitStatus(err) != cmdsutil.ExitNotConfirmed {
				t.Fatalf("missing confirmation lost uncertainty: %v", err)
			}
			if kind == "invalid confirmation" && cmdsutil.ExitStatus(err) != 1 {
				t.Fatalf("invalid confirmation was reported as uncertainty: %v", err)
			}
			if (kind == "record failure" || kind == "cancelled") && reads[1].Load() != 0 {
				t.Fatal("local failure or cancellation tried another endpoint")
			}
			record, readErr := o.record(f.target.cluster)
			if readErr != nil || (record != nil) != success || (success && record.Acknowledged != f.head()) {
				t.Fatalf("saved floor: %+v, %v", record, readErr)
			}
		})
	}
}
