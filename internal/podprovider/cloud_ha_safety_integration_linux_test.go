//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
)

func cloudHAProofFixture() cloudHAProof {
	ca := strings.Repeat("a", 64)
	before := cloudHAState{Instance: "cds-vm", Boot: 1, Status: cdsha.Status{ClusterID: "run", ID: "member", GenesisCA: ca}}
	genesis := cdsdecree.Signed{Decree: cdsdecree.Decree{Kind: cdsdecree.Genesis, ClusterID: "run", TargetMember: "member", GenesisCA: ca, Alone: true}}
	pins := cdsdecree.Signed{Decree: cdsdecree.Decree{Kind: cdsdecree.UpdateMeasurements, ClusterID: "run", BaseVersion: 1}}
	joined := before
	joined.CA, joined.Status.CAFingerprint, joined.Status.GenesisCA = ca, ca, ""
	joined.Status.Joined, joined.Status.Serving.OK, joined.Status.Version, joined.Status.NodeImagesVersion = true, true, 1, 1
	joined.Status.Voters = []string{"member"}
	joined.Pins = genesis
	joined.Decrees = []cdsha.DecreeRecord{{Version: 1, AtMS: 1, Decree: genesis}}
	applied := joined
	applied.Status.Version, applied.Pins = 2, pins
	applied.Decrees = append([]cdsha.DecreeRecord{joined.Decrees[0]}, cdsha.DecreeRecord{Version: 2, AtMS: 2, Decree: pins})
	start := time.Unix(1700000000, 0).UTC()
	p := cloudHAProof{Passed: true, Run: "run", Before: before, Unjoined: map[string]int{"/ca": 503, "/readyz": 503}, Genesis: joined, Applied: applied, UID: "pod-uid", PodInstance: "pod-vm", PodBoot: 1, StaticFloor: 1, LocalGenericTrust: true,
		Tasks: cloudCDSState{Ready: true, Running: true, MeshReady: true, AppStart: start, MeshStart: start.Add(-time.Second)},
		Leaf:  &podcvmtest.Leaf{SandboxID: "sandbox", Workload: "cloud-a", Serial: "serial", SPKI: "key", Denied: true}}
	for _, name := range []string{"provider", "server", "cluster", "binding", "stale"} {
		r := cloudHARefusal{Name: name, Intent: "intent-" + name, Code: 400, Body: "decree signature: unauthorized", State: applied, Tasks: p.Tasks, Leaf: p.Leaf}
		switch name {
		case "cluster":
			r.Body = `decree for cluster "other", not "run"`
		case "binding", "stale":
			r.Code = 200
			reason := "the decree pins launch file bad, and this one is good"
			if name == "stale" {
				reason = "the decree applies on version 1, and the cluster is at version 2"
			}
			body, _ := json.Marshal(cdsha.Delivered{Intent: r.Intent, Refused: reason})
			r.Body = string(body)
		}
		p.Refusals = append(p.Refusals, r)
	}
	return p
}

func TestCloudAcceptanceHAProof(t *testing.T) {
	if err := cloudHAProofFixture().validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*cloudHAProof){
		"not-passed":              func(p *cloudHAProof) { p.Passed = false },
		"another-cluster":         func(p *cloudHAProof) { p.Before.Status.ClusterID = "other" },
		"already-joined":          func(p *cloudHAProof) { p.Before.Status.Joined = true },
		"missing-prejoin-refusal": func(p *cloudHAProof) { delete(p.Unjoined, "/ca") },
		"wrong-prejoin-status":    func(p *cloudHAProof) { p.Unjoined["/readyz"] = 502 },
		"missing-genesis":         func(p *cloudHAProof) { p.Genesis.Decrees = nil },
		"held-not-applied":        func(p *cloudHAProof) { p.Applied.Status.Version = 1 },
		"another-member":          func(p *cloudHAProof) { p.Applied.Status.ID = "other" },
		"another-ca":              func(p *cloudHAProof) { p.Applied.CA = strings.Repeat("b", 64) },
		"another-boot":            func(p *cloudHAProof) { p.Applied.Boot++ },
		"another-cds":             func(p *cloudHAProof) { p.Applied.Instance = "other" },
		"multiple-replicas":       func(p *cloudHAProof) { p.Applied.Status.Voters = []string{"member", "other"} },
		"unavailable-cds":         func(p *cloudHAProof) { p.Applied.Status.Serving.OK = false },
		"missing-floor":           func(p *cloudHAProof) { p.StaticFloor = 0 },
		"wrong-floor":             func(p *cloudHAProof) { p.StaticFloor = 2 },
		"generic-trust-unchecked": func(p *cloudHAProof) { p.LocalGenericTrust = false },
		"missing-refusal":         func(p *cloudHAProof) { p.Refusals = p.Refusals[:4] },
		"duplicate-refusal":       func(p *cloudHAProof) { p.Refusals[1] = p.Refusals[0] },
		"unexpected-application":  func(p *cloudHAProof) { p.Refusals[0].State.Status.Version++ },
		"changed-pins":            func(p *cloudHAProof) { p.Refusals[0].State.Pins.Signature = "changed" },
		"changed-history":         func(p *cloudHAProof) { p.Refusals[0].State.Decrees[0].AtMS++ },
		"changed-tasks":           func(p *cloudHAProof) { p.Refusals[0].Tasks.AppStart = time.Time{} },
		"app-restarted":           func(p *cloudHAProof) { p.Refusals[0].Tasks.Restarts++ },
		"readiness-lost":          func(p *cloudHAProof) { p.Refusals[0].Tasks.Ready = false },
		"changed-leaf":            func(p *cloudHAProof) { p.Refusals[0].Leaf.Serial = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(cloudHAProofFixture())
			var proof cloudHAProof
			if err := json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			change(&proof)
			if err := proof.validate(); err == nil {
				t.Fatal("incomplete HA evidence accepted")
			}
		})
	}
}

func TestCloudAcceptanceHARequiresExactAuthenticatedRefusals(t *testing.T) {
	for _, original := range cloudHAProofFixture().Refusals {
		for _, damage := range []string{"transport", "unavailable", "other-error", "wrong-intent", "held", "applied"} {
			t.Run(original.Name+"/"+damage, func(t *testing.T) {
				p := original
				switch damage {
				case "transport":
					p.Code = 0
				case "unavailable":
					p.Code = http.StatusServiceUnavailable
				case "other-error":
					p.Body = "unrelated error"
				case "wrong-intent", "held", "applied":
					r := cdsha.Delivered{Intent: p.Intent, Refused: "the decree applies on version 1, and the cluster is at version 2"}
					switch damage {
					case "wrong-intent":
						r.Intent = "other"
					case "held":
						r.Held = true
					case "applied":
						r.Version = 3
					}
					raw, _ := json.Marshal(r)
					p.Code, p.Body = 200, string(raw)
				}
				if err := cloudHARefused(p); err == nil {
					t.Fatal("unrelated or successful response accepted as refusal")
				}
			})
		}
	}
}
