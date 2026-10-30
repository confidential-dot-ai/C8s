//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
)

const cloudCDSRetention = 70 * time.Second

type cloudCDSProof struct {
	Passed         bool             `json:"passed"`
	CABeforeSHA256 string           `json:"caBeforeSHA256"`
	CAAfterSHA256  string           `json:"caAfterSHA256"`
	Run            string           `json:"run"`
	UID            string           `json:"uid"`
	CDSInstance    string           `json:"cdsInstance"`
	PodInstance    string           `json:"podInstance"`
	DisconnectedAt time.Time        `json:"disconnectedAt"`
	RetainedAt     time.Time        `json:"retainedAt"`
	RestartedAt    time.Time        `json:"restartedAt"`
	RestoredAt     time.Time        `json:"restoredAt"`
	RevokedAt      time.Time        `json:"revokedAt"`
	RefusedUntil   time.Time        `json:"refusedUntil"`
	InitialLeaf    *podcvmtest.Leaf `json:"initialLeaf"`
	RetainedLeaf   *podcvmtest.Leaf `json:"retainedLeaf"`
}

func (r *cloudRun) cdsObserve(ctx context.Context, h *providerControlPlane, cfg *Config, guest *cloudGuest, sequence int) (cloudCDSState, error) {
	var out cloudCDSState
	select {
	case <-h.manager.done:
		return out, errors.New("provider stopped during CDS outage acceptance")
	default:
	}
	rec, err := r.snapshot(ctx, h, cfg, "a")
	if err != nil {
		return out, err
	}
	if rec.InstanceID != guest.rec.InstanceID || rec.UID != guest.rec.UID || rec.DeleteRequested || rec.Deleted || rec.TerminalStatus != nil || !reflect.DeepEqual(rec.Request, guest.rec.Request) {
		return out, errors.New("CDS outage replaced or ended the original Pod intent")
	}
	in, err := r.getOwned(ctx, "a")
	if err != nil {
		return out, err
	}
	if in == nil || in.ID != rec.InstanceID || in.Status != "running" || in.Boot.Count != guest.boot {
		return out, errors.New("Pod guest stopped or rebooted during CDS outage")
	}
	status, statusErr := cloudEndpoint(in, "pod-status")
	app, appErr := cloudEndpoint(in, "app-8080")
	if statusErr != nil || appErr != nil || status != guest.status || app != guest.app {
		return out, errors.New("Pod endpoints changed during CDS outage")
	}
	if _, err = r.bootPod(ctx, h, cfg, "a"); err != nil {
		return out, err
	}
	projection, err := readGuest(ctx, rec, net.JoinHostPort(status.Host, strconv.Itoa(status.Port)))
	if err != nil {
		return out, err
	}
	out, err = cloudCDSStatus(projection, rec)
	if err != nil {
		return out, err
	}
	if err = r.exactAttestation(ctx, guest); err != nil {
		return out, err
	}
	attestation, err := cloudPrivateRead(filepath.Join(r.dir, "attestation-"+string(rec.UID)+".json"), 1<<20)
	if err != nil {
		return out, err
	}
	err = cloudWrite(filepath.Join(r.dir, fmt.Sprintf("cds-observation-%04d.json", sequence)), map[string]any{"at": time.Now().UTC(), "status": projection, "attestation": json.RawMessage(attestation), "bootCount": in.Boot.Count, "instanceID": in.ID})
	return out, err
}

func (r *cloudRun) cdsOutage(ctx context.Context, h *providerControlPlane, cfg *Config, guest *cloudGuest, cds endpoint) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	base, added, err := r.cdsPolicies(cfg)
	if err != nil {
		return err
	}
	doc, err := guest.rec.document()
	if err != nil {
		return err
	}
	if !json.Valid([]byte(doc.Workloads)) {
		return errors.New("Pod has no valid immutable base")
	}
	var actualBase, expectedBase any
	if json.Unmarshal([]byte(doc.Workloads), &actualBase) != nil || json.Unmarshal(base, &expectedBase) != nil || !reflect.DeepEqual(actualBase, expectedBase) {
		return errors.New("signed Pod launch includes an application admission source")
	}
	baseline, err := cloudPrivateRead(filepath.Join(r.dir, "cds-policy-baseline.json"), 2<<20)
	if err != nil {
		return err
	}
	_, added, err = cloudCDSServedPolicies(base, added, baseline)
	if err != nil {
		return err
	}
	ca, err := r.ca(ctx, cds)
	if err != nil {
		return err
	}
	_, actual, err := r.policy(ctx, cds)
	if err != nil {
		return err
	}
	if err = r.cdsPolicyRequire("outage-before", added, actual); err != nil {
		return err
	}
	sequence := 0
	observe := func() (cloudCDSState, error) {
		sequence++
		return r.cdsObserve(ctx, h, cfg, guest, sequence)
	}
	var first cloudCDSState
	readyUntil := time.Now().Add(time.Minute)
	for {
		first, err = observe()
		if err != nil {
			return err
		}
		if first.Restarts != 0 || first.Exit != nil {
			return errors.New("application restarted before CDS fault injection")
		}
		if first.Ready && first.Running {
			break
		}
		if time.Now().After(readyUntil) {
			return errors.New("application did not become ready before CDS fault injection")
		}
		if err = cloudPause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	leaf, err := r.leaf(ctx, guest, "certless")
	if err != nil {
		return err
	}
	if leaf.Workload != "cloud-a" || !leaf.Denied || leaf.SandboxID == "" || leaf.SPKI == "" {
		return errors.New("CDS scenario has no authenticated application identity")
	}
	before, err := r.getOwned(ctx, "cds")
	if err != nil {
		return err
	}
	matched, err := cloudCDSIngressState(before, before, true)
	if err != nil || !matched {
		return errors.New("CDS ingress was not stable before its owned fault")
	}
	original, err := cloudEndpoint(before, "cds")
	if err != nil || original != cds {
		return errors.New("CDS endpoint changed before its fault")
	}
	proof := cloudCDSProof{Run: r.ledger.Run, UID: string(guest.rec.UID), CDSInstance: before.ID, PodInstance: guest.rec.InstanceID, InitialLeaf: leaf, CABeforeSHA256: cloudHash(ca)}
	restored := false
	defer func() {
		if !restored {
			recovery, stop := context.WithTimeout(context.Background(), 2*time.Minute)
			defer stop()
			result = errors.Join(result, r.cdsIngress(recovery, before, true))
		}
	}()
	if err = r.cdsIngress(ctx, before, false); err != nil {
		return err
	}
	if err = cloudCDSPortClosed(ctx, cds); err != nil {
		return err
	}
	disconnected := time.Now()
	proof.DisconnectedAt = disconnected.UTC()
	var restarted cloudCDSState
	for {
		in, err := r.getOwned(ctx, "cds")
		if err != nil {
			return err
		}
		matched, err := cloudCDSIngressState(in, before, false)
		if err != nil || !matched {
			return errors.New("owned CDS outage did not remain applied")
		}
		if err = cloudCDSPortClosed(ctx, cds); err != nil {
			return err
		}
		if err = cloudWrite(filepath.Join(r.dir, fmt.Sprintf("cds-network-%04d.json", sequence+1)), map[string]any{"at": time.Now().UTC(), "instance": in, "transportFailure": true}); err != nil {
			return err
		}
		state, err := observe()
		if err != nil {
			return err
		}
		done, err := cloudCDSRestart(first, state, !proof.RetainedAt.IsZero())
		if err != nil {
			return err
		}
		if state.Running && state.Restarts == 0 && time.Since(disconnected) >= cloudCDSRetention {
			proof.RetainedAt = time.Now().UTC()
		}
		if done {
			if err = cloudCDSPortClosed(ctx, cds); err != nil {
				return err
			}
			restarted, proof.RestartedAt = state, time.Now().UTC()
			break
		}
		if err = cloudPause(ctx, 3*time.Second); err != nil {
			return err
		}
	}
	proof.RetainedLeaf, err = r.leaf(ctx, guest, "certless")
	if err != nil {
		return err
	}
	retained := proof.RetainedLeaf
	if retained.SandboxID != leaf.SandboxID || retained.SPKI != leaf.SPKI || retained.Workload != "cloud-a" || !retained.Denied {
		return errors.New("Pod credential identity changed during CDS outage")
	}
	if err = cloudWrite(filepath.Join(r.dir, "cds-retained.json"), proof); err != nil {
		return err
	}
	if err = r.cdsIngress(ctx, before, true); err != nil {
		return err
	}
	restored = true
	proof.RestoredAt = time.Now().UTC()
	afterCA, err := r.ca(ctx, cds)
	if err != nil {
		return err
	}
	if !bytes.Equal(ca, afterCA) {
		return errors.New("restored CDS changed its authenticated CA")
	}
	proof.CAAfterSHA256 = cloudHash(afterCA)
	afterRestore, err := observe()
	if err != nil {
		return err
	}
	if !afterRestore.Ready || !afterRestore.Running || afterRestore.Restarts != 1 || !afterRestore.AppStart.Equal(restarted.AppStart) || !afterRestore.MeshStart.Equal(restarted.MeshStart) {
		return errors.New("application did not remain in its retained start before signed revocation")
	}
	if err = r.cdsPolicyUpdate(ctx, cfg, cds, false); err != nil {
		return err
	}
	proof.RevokedAt = time.Now().UTC()
	var refusedAt time.Time
	var stopped *podstatus.ContainerTerminated
	until := time.Now().Add(3 * time.Minute)
	for {
		state, err := observe()
		if err != nil {
			return err
		}
		refused, err := cloudCDSRevoked(restarted, state)
		if err != nil {
			return err
		}
		if !refusedAt.IsZero() && (!refused || !reflect.DeepEqual(stopped, state.Exit)) {
			return errors.New("revoked application resumed or changed its stopped process")
		}
		if refused {
			if refusedAt.IsZero() {
				refusedAt, stopped = time.Now(), state.Exit
			}
			if time.Since(refusedAt) >= cloudCDSRetention {
				pod, err := r.bootPod(ctx, h, cfg, "a")
				if err != nil {
					return err
				}
				if controlPlanePodReady(pod) {
					return errors.New("provider still reports the revoked application ready")
				}
				proof.RefusedUntil = time.Now().UTC()
				break
			}
		}
		if time.Now().After(until) {
			return errors.New("signed policy deletion did not cause sustained application revocation")
		}
		if err = cloudPause(ctx, 3*time.Second); err != nil {
			return err
		}
	}
	finalCDS, err := r.getOwned(ctx, "cds")
	if err != nil {
		return err
	}
	matched, err = cloudCDSIngressState(finalCDS, before, true)
	if err != nil || !matched {
		return errors.New("restored CDS changed before acceptance completed")
	}
	proof.Passed = true
	return cloudWrite(filepath.Join(r.dir, "cds-outage.json"), proof)
}

func (r *cloudRun) cdsProofComplete() bool {
	raw, err := os.ReadFile(filepath.Join(r.dir, "cds-outage.json"))
	var proof cloudCDSProof
	return err == nil && json.Unmarshal(raw, &proof) == nil && proof.Passed && proof.Run == r.ledger.Run && proof.InitialLeaf != nil && proof.RetainedLeaf != nil && proof.InitialLeaf.Workload == "cloud-a" && proof.RetainedLeaf.Workload == "cloud-a" && proof.InitialLeaf.Denied && proof.RetainedLeaf.Denied && proof.InitialLeaf.SandboxID != "" && proof.InitialLeaf.SandboxID == proof.RetainedLeaf.SandboxID && proof.InitialLeaf.SPKI != "" && proof.InitialLeaf.SPKI == proof.RetainedLeaf.SPKI && cloudHex.MatchString(proof.CABeforeSHA256) && proof.CAAfterSHA256 == proof.CABeforeSHA256 && proof.UID != "" && proof.CDSInstance != "" && proof.PodInstance != "" && proof.RetainedAt.Sub(proof.DisconnectedAt) >= cloudCDSRetention && proof.RestartedAt.After(proof.RetainedAt) && proof.RestoredAt.After(proof.RestartedAt) && proof.RevokedAt.After(proof.RestoredAt) && proof.RefusedUntil.Sub(proof.RevokedAt) >= cloudCDSRetention
}
