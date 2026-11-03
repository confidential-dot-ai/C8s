//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

func cloudRenewalProofFixture() cloudCDSRenewalProof {
	start := time.Unix(1700000000, 0).UTC()
	state := cloudCDSState{Ready: true, Running: true, MeshReady: true, AppStart: start.Add(-time.Minute), MeshStart: start.Add(-2 * time.Minute)}
	leaf := &podcvmtest.Leaf{SandboxID: "pod-identity", Serial: "original", SPKI: "original-key", Workload: "cloud-a", Denied: true, NotBefore: start.Add(-time.Minute).Format(time.RFC3339), NotAfter: start.Add(6 * time.Hour).Format(time.RFC3339)}
	proof := cloudCDSRenewalProof{Passed: true, Run: "owned-run", UID: "owned-uid", CDSInstance: "i-cds", PodInstance: "i-pod", CDSBoot: 1, PodBoot: 1, FinalCDSBoot: 1, FinalPodBoot: 1, CABeforeSHA256: strings.Repeat("a", 64), CAAfterSHA256: strings.Repeat("a", 64), Initial: cloudCDSRenewalSample{At: start, State: state, Leaf: leaf}}
	proof.DisconnectedAt = start.Add(time.Second)
	proof.Retained = proof.Initial
	proof.Retained.At = proof.DisconnectedAt.Add(cloudCDSRenewalHold + time.Second)
	proof.Retained.State.Ready = false
	proof.RestoredAt = proof.Retained.At.Add(time.Second)
	proof.Renewed = proof.Initial
	proof.Renewed.At = proof.RestoredAt.Add(time.Minute)
	fresh := *leaf
	fresh.Serial, fresh.SPKI = "renewed", "renewed-key"
	fresh.NotBefore = proof.Renewed.At.Add(-time.Second).Format(time.RFC3339)
	fresh.NotAfter = proof.Renewed.At.Add(6 * time.Hour).Format(time.RFC3339)
	proof.Renewed.Leaf = &fresh
	proof.RevokedAt = proof.Renewed.At.Add(time.Second)
	proof.MeshWithdrawnAt = proof.RevokedAt.Add(time.Second)
	proof.RefusedUntil = proof.MeshWithdrawnAt.Add(cloudCDSRetention + time.Second)
	return proof
}

func TestCloudAcceptanceCDSRenewalProof(t *testing.T) {
	if err := cloudRenewalProofFixture().validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*cloudCDSRenewalProof){
		"missing-pass":               func(p *cloudCDSRenewalProof) { p.Passed = false },
		"missing-run":                func(p *cloudCDSRenewalProof) { p.Run = "" },
		"same-vm":                    func(p *cloudCDSRenewalProof) { p.CDSInstance = p.PodInstance },
		"changed-pod-boot":           func(p *cloudCDSRenewalProof) { p.FinalPodBoot++ },
		"changed-cds-boot":           func(p *cloudCDSRenewalProof) { p.FinalCDSBoot++ },
		"changed-ca":                 func(p *cloudCDSRenewalProof) { p.CAAfterSHA256 = strings.Repeat("b", 64) },
		"missing-ca":                 func(p *cloudCDSRenewalProof) { p.CABeforeSHA256, p.CAAfterSHA256 = "", "" },
		"app-restart":                func(p *cloudCDSRenewalProof) { p.Retained.State.Restarts++ },
		"changed-app-task":           func(p *cloudCDSRenewalProof) { p.Renewed.State.AppStart = p.Renewed.At },
		"changed-mesh-task":          func(p *cloudCDSRenewalProof) { p.Retained.State.MeshStart = p.Retained.At },
		"missing-task-start":         func(p *cloudCDSRenewalProof) { p.Initial.State.AppStart = time.Time{} },
		"guest-outage-not-confirmed": func(p *cloudCDSRenewalProof) { p.Retained.State.Ready = true },
		"guest-never-ready":          func(p *cloudCDSRenewalProof) { p.Initial.State.Ready = false },
		"guest-not-recovered":        func(p *cloudCDSRenewalProof) { p.Renewed.State.Ready = false },
		"premature-outage":           func(p *cloudCDSRenewalProof) { p.Retained.At = p.DisconnectedAt.Add(time.Minute) },
		"premature-restoration":      func(p *cloudCDSRenewalProof) { p.RestoredAt = p.Retained.At.Add(-time.Second) },
		"renewal-before-restoration": func(p *cloudCDSRenewalProof) { p.Renewed.At = p.RestoredAt.Add(-time.Second) },
		"renewal-too-late":           func(p *cloudCDSRenewalProof) { p.Renewed.At = p.RestoredAt.Add(cloudCDSRenewalRecovery + time.Second) },
		"no-sustained-revocation":    func(p *cloudCDSRenewalProof) { p.RefusedUntil = p.MeshWithdrawnAt },
		"revoked-before-renewal":     func(p *cloudCDSRenewalProof) { p.RevokedAt = p.Renewed.At.Add(-time.Second) },
		"expired-in-outage": func(p *cloudCDSRenewalProof) {
			p.Initial.Leaf.NotAfter = p.Retained.At.Format(time.RFC3339)
			p.Retained.Leaf.NotAfter = p.Initial.Leaf.NotAfter
		},
		"retained-leaf-changed":     func(p *cloudCDSRenewalProof) { p.Retained.Leaf.Serial = "unexpected" },
		"retained-validity-changed": func(p *cloudCDSRenewalProof) { p.Retained.Leaf.NotAfter = p.Renewed.Leaf.NotAfter },
		"retained-leaf-missing":     func(p *cloudCDSRenewalProof) { p.Retained.Leaf = nil },
		"renewed-leaf-missing":      func(p *cloudCDSRenewalProof) { p.Renewed.Leaf = nil },
		"renewed-serial-missing":    func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.Serial = "" },
		"renewed-key-missing":       func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.SPKI = "" },
		"renewed-key-reused":        func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.SPKI = p.Initial.Leaf.SPKI },
		"renewed-serial-reused":     func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.Serial = p.Initial.Leaf.Serial },
		"wrong-workload":            func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.Workload = "other" },
		"wrong-sandbox":             func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.SandboxID = "other" },
		"certless-access":           func(p *cloudCDSRenewalProof) { p.Renewed.Leaf.Denied = false },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(cloudRenewalProofFixture())
			var proof cloudCDSRenewalProof
			if err := json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			change(&proof)
			if err := proof.validate(); err == nil {
				t.Fatal("incomplete renewal outage evidence accepted")
			}
		})
	}
}

func TestCloudAcceptanceCDSRenewalRequiresOwnedCleanup(t *testing.T) {
	for _, damage := range []string{"none", "missing-complete", "pod-running", "cds-running", "wrong-run", "wrong-uid", "wrong-pod", "wrong-cds", "missing-receipt"} {
		t.Run(damage, func(t *testing.T) {
			r, _, _ := cloudOwnershipFixture(t)
			proof := cloudRenewalProofFixture()
			r.ledger.Run, r.ledger.Complete = proof.Run, true
			r.ledger.Owned = map[string]*cloudOwned{
				"a":   {UID: proof.UID, Receipt: &cloudReceipt{ID: proof.PodInstance}, Terminated: true},
				"cds": {Receipt: &cloudReceipt{ID: proof.CDSInstance}, Terminated: true},
			}
			switch damage {
			case "missing-complete":
				r.ledger.Complete = false
			case "pod-running":
				r.ledger.Owned["a"].Terminated = false
			case "cds-running":
				r.ledger.Owned["cds"].Terminated = false
			case "wrong-run":
				proof.Run = "other"
			case "wrong-uid":
				proof.UID = "other"
			case "wrong-pod":
				proof.PodInstance = "i-other"
			case "wrong-cds":
				proof.CDSInstance = "i-other"
			case "missing-receipt":
				r.ledger.Owned["a"].Receipt = nil
			}
			if err := cloudWrite(filepath.Join(r.dir, "cds-renewal-outage.json"), proof); err != nil {
				t.Fatal(err)
			}
			err := r.cdsRenewalProofComplete()
			if (damage == "none") != (err == nil) {
				t.Fatalf("proof result = %v", err)
			}
		})
	}
}

func TestCloudAcceptanceCDSRenewalWorkload(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.Scenario = "cds-renewal-outage"
	pod, wire, err := r.cdsWorkload(endpoint{Name: "cds", Host: "203.0.113.5", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.instanceCount() != 2 || len(pod.Spec.Containers) != 1 || pod.Spec.NodeName != "" {
		t.Fatal("renewal workload lost its normally scheduled single app")
	}
	app := pod.Spec.Containers[0]
	if !slices.Equal(app.Args, podfixture.CDSProbeArgs("203.0.113.5", cloudCDSRenewalHold)) || app.Args[2] != "3900" {
		t.Fatal("guest outage duration or owned endpoint differs")
	}
	raw, _ := json.Marshal(wire)
	policy, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.Workloads["cloud-a"].Containers[0].Args.Argv, app.Args) {
		t.Fatal("served policy does not bind the actual renewal probe")
	}
	start := metav1.NewTime(time.Unix(1700000000, 0))
	finish := metav1.NewTime(start.Add(time.Minute))
	before := cloudCDSState{Running: true, Ready: true, MeshReady: true, AppStart: start.Time, MeshStart: start.Time}
	stopped := cloudCDSState{Restarts: 1, MeshStart: start.Time, Exit: &podstatus.ContainerTerminated{StartedAt: &start, FinishedAt: &finish, ExitCode: 143}}
	if done, err := cloudCDSRevoked(before, stopped); err != nil || !done {
		t.Fatalf("zero-restart revocation failed: %v", err)
	}
	stopped.Running, stopped.AppStart = true, finish.Time
	if _, err := cloudCDSRevoked(before, stopped); err == nil {
		t.Fatal("a new task passed as revocation")
	}
}
