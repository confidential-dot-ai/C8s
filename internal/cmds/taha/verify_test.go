package taha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
)

func verificationFixture(t *testing.T) *observationTest {
	t.Helper()
	f := newObservationTest(t)
	f.entries = f.entries[:len(f.entries)-1]
	f.held(t)
	return f
}

func verifyArtifact(t *testing.T, f *observationTest, digest string) error {
	t.Helper()
	encoded, err := f.entry.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if f.encoded == nil {
		f.encoded = encoded
	}
	if err := os.WriteFile(f.path, f.encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	names, dirErr := os.ReadDir(f.w.o.stateDir)
	var before map[string]string
	if dirErr == nil {
		before = prepareFiles(t, f.w.o.stateDir)
	}
	data, entry, err := readSubmittedPolicy(f.path, f.target)
	if err == nil {
		var approved cdschain.Hash
		approved, err = reviewedPolicyDigest(entry, digest)
		if err == nil {
			err = f.w.verifyPolicy(context.Background(), &f.output, f.target, data, entry, approved)
		}
	}
	if dirErr == nil {
		after, readErr := os.ReadDir(f.w.o.stateDir)
		if readErr != nil || len(after) != len(names) || !reflect.DeepEqual(before, prepareFiles(t, f.w.o.stateDir)) {
			t.Fatal("verification changed local records or cache")
		}
	} else if _, afterErr := os.Stat(f.w.o.stateDir); !errors.Is(afterErr, os.ErrNotExist) {
		t.Fatal("verification created the state directory")
	}
	data, readErr := os.ReadFile(f.path)
	if readErr != nil || !bytes.Equal(data, f.encoded) || f.posts != 0 || f.w.key != nil || f.w.chain != nil {
		t.Fatal("verification changed or submitted the artifact, or used signing/cache state")
	}
	return err
}

func candidateDigest(t *testing.T, f *observationTest) string {
	t.Helper()
	body, err := f.entry.Decode()
	if err != nil {
		t.Fatal(err)
	}
	var policy cdschain.Policy
	if err := json.Unmarshal(body.Payload, &policy); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(policy.Allowlist))
}

func TestVerifyPolicySuccessorWithoutConfirmation(t *testing.T) {
	for _, kind := range []string{"ordinary", "genesis", "outer whitespace", "existing state", "absent directory", "rotated key", "held policy and routes"} {
		t.Run(kind, func(t *testing.T) {
			f := verificationFixture(t)
			body, _ := f.entry.Decode()
			current := make(map[cdschain.Type]cdschain.Entry)
			switch kind {
			case "held policy and routes":
				for _, typ := range []cdschain.Type{cdschain.TypePolicy, cdschain.TypeRoutes, cdschain.TypePolicy} {
					held := body
					held.Type, held.Seq, held.Prev = typ, uint64(len(f.entries)), f.entries[len(f.entries)-1].Hash()
					if typ == cdschain.TypeRoutes {
						held.Payload, _ = json.Marshal(cdschain.Routes{Manifest: []byte(`{"revision":1}`), Token: "router-token"})
					}
					entry, err := cdschain.Sign(f.key, held)
					if err != nil {
						t.Fatal(err)
					}
					f.entries = append(f.entries, entry)
					current[typ] = entry
				}
			case "genesis":
				f.entries = f.entries[:1]
			case "rotated key":
				key := testKey(t)
				pub, _ := cdschain.PublicKeyPEM(&key.PublicKey)
				payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: pub})
				rotation := body
				rotation.Type, rotation.Payload = cdschain.TypeOperatorKeys, payload
				entry, err := cdschain.Sign(f.key, rotation)
				if err != nil {
					t.Fatal(err)
				}
				f.entries = append(f.entries, entry)
				f.key = key
			case "existing state":
				if err := f.w.o.acknowledge(f.target.genesis, f.target.head); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.w.o.stateDir, "lane.chain"), []byte("retained cache"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "absent directory":
				f.w.o.stateDir = filepath.Join(f.w.o.stateDir, "absent")
			}
			f.held(t)
			f.target.head = *f.status.Held
			body.Seq, body.Prev = f.target.head.Seq+1, f.target.head.Hash
			var err error
			f.entry, err = cdschain.Sign(f.key, body)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "outer whitespace" {
				data, _ := f.entry.Encode()
				f.encoded = append(append([]byte(" \n"), data...), '\n')
			}
			digest := candidateDigest(t, f)
			if len(f.status.Confirmed) != 0 {
				t.Fatal("fixture unexpectedly requires confirmation")
			}
			if err := verifyArtifact(t, f, digest); err != nil {
				t.Fatal(err)
			}
			var result verifiedPolicy
			if err := json.Unmarshal(f.output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Entry != f.head() || result.Predecessor != f.target.head || result.PolicySHA256.String() != digest || result.ArtifactSHA256 != cdschain.Hash(sha256.Sum256(f.encoded)) {
				t.Fatalf("incorrect validated identities: %+v", result)
			}
			if !reflect.DeepEqual(result.CurrentEntries, current) {
				t.Fatalf("current entries must identify the latest held body and signature per type: %+v", result.CurrentEntries)
			}
		})
	}
}

func TestVerifyPolicyRejectsWithoutSuccess(t *testing.T) {
	for _, kind := range []string{
		"digest", "malformed digest", "noncanonical", "signature", "retired signer", "already held", "competing entry",
		"wrong genesis", "saved genesis", "saved fork", "rollback", "corrupt record", "not serving", "not fresh",
		"not member", "fork", "missing held", "changed head", "held hash", "held cluster",
	} {
		t.Run(kind, func(t *testing.T) {
			f := verificationFixture(t)
			digest := candidateDigest(t, f)
			switch kind {
			case "digest":
				digest = cdschain.Hash{9}.String()
			case "malformed digest":
				digest = "invalid"
			case "noncanonical":
				policy := []byte(`{"workloads":{},"schema":"c8s.allowlist/v1"}`)
				digest = fmt.Sprintf("%x", sha256.Sum256(policy))
				body, _ := f.entry.Decode()
				body.Payload, _ = json.Marshal(cdschain.Policy{Allowlist: policy})
				f.entry, _ = cdschain.Sign(f.key, body)
			case "signature":
				f.entry.Sig = "invalid"
			case "retired signer":
				pub, _ := cdschain.PublicKeyPEM(&testKey(t).PublicKey)
				payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: pub})
				body, _ := f.entry.Decode()
				rotation := body
				rotation.Type, rotation.Payload = cdschain.TypeOperatorKeys, payload
				entry, _ := cdschain.Sign(f.key, rotation)
				f.entries = append(f.entries, entry)
				f.held(t)
				f.target.head = *f.status.Held
				body.Seq, body.Prev = f.target.head.Seq+1, f.target.head.Hash
				f.entry, _ = cdschain.Sign(f.key, body)
			case "already held", "competing entry":
				f.entries = append(f.entries, f.entry)
				if kind == "competing entry" {
					body, _ := f.entry.Decode()
					f.entry, _ = cdschain.Sign(f.key, body)
				}
				f.held(t)
			case "wrong genesis":
				f.target.genesis = cdschain.Hash{9}
			case "saved genesis", "saved fork", "rollback":
				genesis, head := f.target.genesis, f.target.head
				if kind == "saved genesis" {
					genesis = cdschain.Hash{9}
				}
				if kind == "saved fork" {
					head.Hash = cdschain.Hash{9}
				}
				if kind == "rollback" {
					head.Seq++
				}
				if err := f.w.o.acknowledge(genesis, head); err != nil {
					t.Fatal(err)
				}
			case "corrupt record":
				path, _ := f.w.o.recordPath(f.target.cluster)
				if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
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
			}
			err := verifyArtifact(t, f, digest)
			if err == nil || f.output.Len() != 0 || cmdsutil.ExitStatus(err) != 1 {
				t.Fatalf("invalid successor must fail with exit 1 and no JSON: %v", err)
			}
			if kind == "noncanonical" && (!strings.Contains(err.Error(), "canonical") || f.reads == 0) {
				t.Fatalf("fixture failed before native canonical validation: %v", err)
			}
			if (kind == "digest" || kind == "malformed digest") && f.reads != 0 {
				t.Fatal("digest mismatch read the network")
			}
		})
	}
}

func TestVerifyPolicyRequiresIndependentInputs(t *testing.T) {
	f := verificationFixture(t)
	base := map[string]string{
		"image-policy-file": "independent.json",
		"cluster":           f.target.cluster,
		"genesis":           f.target.genesis.String(),
		"expect-head":       fmt.Sprintf("%d:%s", f.target.head.Seq, f.target.head.Hash),
		"file":              f.path,
		"policy-sha256":     candidateDigest(t, f),
	}
	for _, name := range []string{"insecure", "image-policy-file", "cluster", "genesis", "expect-head", "file", "policy-sha256"} {
		flags := maps.Clone(base)
		delete(flags, name)
		if name == "insecure" {
			flags[name] = "true"
		}
		args := []string{"verify-policy"}
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
