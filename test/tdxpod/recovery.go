package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	fixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-recovery"
)

const baselineDisk = "eb2dffb9712048ad23a2a62c04441c85f708cad60a846ce8cf4c5d7f4b610bb6"
const baselineMesh = "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:e05ccc28f168972c86ccc1bdb899a371264a38a0ef69a2f0eece6d9813baee27"

func validateRecoveryPins(p pins) error {
	if err := validatePinStructure(p); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, k := range []string{"schema", "source", "profileSource", "buildRun", "image", "artifact", "manifestSHA256", "diskSHA256", "meshImage", "recoveryFixture", "overlaySource", "controllerSHA256", "baselineDiskSHA256", "runtimeComponentsSHA256"} {
		allowed[k] = true
	}
	if len(p) != len(allowed) {
		return errors.New("incomplete recovery build receipt")
	}
	for k := range p {
		if !allowed[k] {
			return errors.New("unexpected recovery build field")
		}
	}
	marked, _ := p.flag("recoveryFixture")
	if !marked || p.str("source") != fixture.Baseline || p.str("profileSource") != fixture.Baseline || p.str("baselineDiskSHA256") != baselineDisk || p.str("meshImage") != baselineMesh || p.str("diskSHA256") == baselineDisk {
		return errors.New("recovery fixture must retain the fixed production baseline under a distinct measured image")
	}
	if !hexCommit.MatchString(p.str("overlaySource")) || p.str("overlaySource") != os.Getenv("GITHUB_SHA") {
		return errors.New("fixture overlay differs from the dispatched harness")
	}
	for _, key := range []string{"controllerSHA256", "runtimeComponentsSHA256"} {
		if !hexSHA256.MatchString(p.str(key)) {
			return errors.New("missing verified fixture build hashes")
		}
	}
	return nil
}

func recoveryPins() ([]byte, error) {
	path, expected := os.Getenv("POD_RECOVERY_RECEIPT"), os.Getenv("POD_RECOVERY_RECEIPT_SHA256")
	if !filepath.IsAbs(path) || !hexSHA256.MatchString(expected) {
		return nil, errors.New("explicit pinned recovery build receipt required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		return nil, errors.New("bounded regular recovery receipt required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if sha256Hex(raw) != expected {
		return nil, errors.New("recovery receipt digest differs")
	}
	p, err := loadPins(raw)
	if err != nil {
		return nil, err
	}
	if err := validateRecoveryPins(p); err != nil {
		return nil, err
	}
	return raw, nil
}

type recoveryAcceptance struct {
	*acceptance
	requests map[string]string
}

func newRecovery(root, run, attempt, repo string, raw []byte) (*recoveryAcceptance, error) {
	a, err := newAcceptanceWith(root, run, attempt, repo, "c8s-podrecover", "pod-service-recovery", raw, 65*time.Minute)
	if err != nil {
		return nil, err
	}
	r := &recoveryAcceptance{acceptance: a, requests: map[string]string{}}
	a.recovery = true
	a.validateImage = func(raw []byte) error {
		if err := validateRecoveryPins(a.pins); err != nil {
			return err
		}
		if raw == nil {
			return nil
		}
		_, err := validateManifestStructure(raw, a.pins)
		return err
	}
	a.vmFn = func(side string) map[string]any {
		spec := a.vm(side)
		domain := spec["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["domain"].(map[string]any)
		domain["resources"].(map[string]any)["requests"].(map[string]string)["cpu"] = fmt.Sprint(domain["cpu"].(map[string]any)["cores"])
		return spec
	}
	return r, nil
}

func (r *recoveryAcceptance) attestConfig(side string, port int) podstatus.AttestConfig {
	return podstatus.AttestConfig{Node: r.connections[key(side, port)], LaunchKeyPubPath: filepath.Join(r.bundle, side+".pub"), ImageManifestPath: filepath.Join(r.private, "manifest.json"), Timeout: 15 * time.Second, ExpectDigests: r.identity.ExpectedDigests}
}

func (r *recoveryAcceptance) assign(side string, deadline time.Time) error {
	var target *podstatus.AssignmentTarget
	for now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		var err error
		target, err = podstatus.VerifyAssignmentTarget(ctx, r.attestConfig(side, 8443))
		cancel()
		if err == nil {
			break
		}
		pause(deadline, 5*time.Second)
	}
	if target == nil {
		return errors.New("generic guest did not freshly attest before assignment")
	}
	defer target.Close()
	private, err := os.ReadFile(filepath.Join(r.bundle, side+".key"))
	if err != nil {
		return err
	}
	launchKey, err := certutil.ParseECPrivateKey(private)
	clear(private)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(filepath.Join(r.bundle, "pod.json"))
	if err != nil {
		return err
	}
	entries, err := os.ReadFile(filepath.Join(r.bundle, "pod-workloads.json"))
	if err != nil {
		return err
	}
	peers, err := json.Marshal([]string{r.identity.Services["a"].IP + ":8080", r.identity.Services["b"].IP + ":8080"})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	request, err := target.Prepare(ctx, launchKey, manifest, entries, peers)
	if err != nil {
		return err
	}
	// Freeze authority and bytes before the first possibly ambiguous POST.
	if err := writeNew(filepath.Join(r.private, side+"-assignment.json"), request); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(r.private, side+"-assignment-key.der"), target.ServingKey()); err != nil {
		return err
	}
	r.requests[side] = sha256Hex(request)
	uid, err := target.Send(ctx, request)
	if err != nil || uid != r.name {
		return errors.New("assignment outcome is uncertain or names another Pod")
	}
	return nil
}

func (r *recoveryAcceptance) receipt(side string, deadline time.Time) (*fixture.Receipt, *podstatus.Report, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	proof, client, err := podstatus.Attest(ctx, r.attestConfig(side, fixture.Port))
	if err != nil {
		return nil, nil, err
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+r.connections[key(side, fixture.Port)]+fixture.ReceiptPath, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("fixture receipt unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, fixture.MaxReceipt+1))
	if err != nil {
		return nil, nil, err
	}
	receipt, err := fixture.Decode(raw)
	return receipt, proof, err
}

func (r *recoveryAcceptance) observeRecovery() error {
	for _, side := range sides {
		ports := []int{8443, 8080, fixture.Port}
		if side == "server" {
			ports = []int{30808}
		}
		for _, port := range ports {
			if err := r.connectFn(side, port); err != nil {
				return err
			}
		}
	}
	deadline := r.deadline(20 * time.Minute)
	caReady := false
	for now().Before(deadline) {
		if err := r.caFn(filepath.Join(r.evidence, "mesh-ca.pem"), deadline); err == nil {
			caReady = true
			break
		}
		pause(deadline, 5*time.Second)
	}
	if !caReady {
		return errors.New("CDS did not authenticate")
	}
	for _, side := range []string{"a", "b"} {
		if err := r.assign(side, deadline); err != nil {
			return err
		}
	}
	before := map[string]fixture.Snapshot{}
	starts := map[string]map[string]string{}
	leaves := map[string]*leaf{}
	done := map[string]bool{}
	deadline = r.deadline(35 * time.Minute)
	for now().Before(deadline) {
		for _, side := range []string{"a", "b"} {
			if done[side] {
				continue
			}
			if _, err := r.instanceFn(side, deadline); err != nil {
				return err
			}
			receipt, proof, err := r.receipt(side, deadline)
			if err != nil {
				continue
			} // An unattested response is never evidence.
			if receipt.State == "failed" {
				if err := write(filepath.Join(r.evidence, side+"-recovery-failure.json"), map[string]any{"receipt": receipt, "attestation": proof}); err != nil {
					return err
				}
				return errors.New("measured guest recovery fixture failed")
			}
			if _, seen := before[side]; !seen {
				if receipt.State == "waiting" {
					continue
				}
				if receipt.State != "baseline" || receipt.Baseline == nil || len(receipt.Phases) != 0 {
					return errors.New("external baseline missed the fixed pre-fault interval")
				}
				b := *receipt.Baseline
				if b.Validate() != nil || b.AssignedUID != r.name || b.RequestSHA256 != r.requests[side] {
					return errors.New("fixture baseline differs from signed assignment")
				}
				status, err := r.cliReadFn(side, []string{"pod-status", "get"}, deadline, true)
				if err != nil {
					continue
				}
				state, err := podStateOf(status, r.name)
				if err != nil || !state.Complete || !state.Ready {
					continue
				}
				l, err := r.leafFn(side, "certless")
				if err != nil {
					continue
				}
				if l.SandboxID != b.CredentialID || l.Workload != "connected" || !l.Denied {
					return errors.New("fixture credential identity differs")
				}
				before[side], starts[side], leaves[side] = b, state.Starts, l
				if err := write(filepath.Join(r.evidence, side+"-recovery-baseline.json"), map[string]any{"receipt": receipt, "attestation": proof, "status": status, "leaf": l.Raw}); err != nil {
					return err
				}
			}
			if receipt.State != "complete" {
				continue
			}
			if err := receipt.ValidateComplete(before[side]); err != nil {
				return err
			}
			status, err := r.cliReadFn(side, []string{"pod-status", "get"}, deadline, true)
			if err != nil {
				return err
			}
			state, err := podStateOf(status, r.name)
			if err != nil || !state.Complete || !state.Ready || !sameStarts(starts[side], state.Starts) {
				return errors.New("external workload identity or health changed after recovery")
			}
			l, err := r.leafFn(side, "certless")
			if err != nil {
				return err
			}
			if l.SandboxID != leaves[side].SandboxID || l.Workload != leaves[side].Workload || !l.Denied {
				return errors.New("workload credential identity changed after recovery")
			}
			if err := write(filepath.Join(r.evidence, side+"-recovery-complete.json"), map[string]any{"receipt": receipt, "attestation": proof, "status": status, "leaf": l.Raw}); err != nil {
				return err
			}
			done[side] = true
		}
		if done["a"] && done["b"] {
			break
		}
		pause(deadline, 3*time.Second)
	}
	if !done["a"] || !done["b"] {
		return errors.New("bounded guest recovery acceptance did not complete")
	}
	if reflect.DeepEqual(before["a"].KernelBootID, before["b"].KernelBootID) || before["a"].CredentialID == before["b"].CredentialID {
		return errors.New("distinct guests share recovery identity")
	}
	caBefore, err := os.ReadFile(filepath.Join(r.evidence, "mesh-ca.pem"))
	if err != nil {
		return err
	}
	if err := r.caFn(filepath.Join(r.private, "recovery-final-ca.pem"), deadline); err != nil {
		return err
	}
	caAfter, err := os.ReadFile(filepath.Join(r.private, "recovery-final-ca.pem"))
	if err != nil || string(caBefore) != string(caAfter) {
		return errors.New("CDS CA changed")
	}
	return write(filepath.Join(r.evidence, "result.json"), map[string]any{"schema": 1, "passed": true, "scope": fixture.Scope, "phases": fixture.Phases, "vmiUIDs": r.vmiUIDs, "genericAssignment": true})
}

func runRecovery(mode string) error {
	root := filepath.Join(os.Getenv("RUNNER_TEMP"), "pod-service-recovery")
	if mode == "cleanup" {
		// Cleanup authority is the original ledger, independent of build inputs.
		o, err := newOwned(root, os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_REPOSITORY"), "c8s-podrecover", "pod-service-recovery")
		if err != nil {
			return err
		}
		return o.cleanup()
	}
	raw, err := recoveryPins()
	if err != nil {
		return err
	}
	r, err := newRecovery(root, os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_REPOSITORY"), raw)
	if err != nil {
		return err
	}
	entries, err := r.resources()
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("recovery lane already owns resources")
	}
	return runPhases(r.acceptance, [][2]any{{"prepare", r.prepareFn}, {"provision", r.provisionFn}, {"recover", r.observeRecovery}}, r.recordFailure)
}
