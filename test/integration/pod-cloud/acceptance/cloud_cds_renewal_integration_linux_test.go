//go:build linux && pod_cloud_integration

package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// RunGuest (internal/cmds/getcert/guest.go) schedules at most one hour;
// renewalInterval only shortens it. This covers that ceiling plus observation
// slack, not certificate expiry. The authenticated leaf must outlive recovery.
const cloudCDSRenewalHold = 65 * time.Minute

// Transport retries back off exponentially; allow the missed attempt to retry.
const cloudCDSRenewalRecovery = 25 * time.Minute

type cloudCDSRenewalSample struct {
	At    time.Time     `json:"at"`
	State cloudCDSState `json:"state"`
	Leaf  *Leaf         `json:"leaf"`
}

type cloudCDSRenewalProof struct {
	Passed         bool                  `json:"passed"`
	Run            string                `json:"run"`
	UID            string                `json:"uid"`
	CDSInstance    string                `json:"cdsInstance"`
	PodInstance    string                `json:"podInstance"`
	CDSBoot        int64                 `json:"cdsBoot"`
	PodBoot        int64                 `json:"podBoot"`
	FinalCDSBoot   int64                 `json:"finalCDSBoot"`
	FinalPodBoot   int64                 `json:"finalPodBoot"`
	CABeforeSHA256 string                `json:"caBeforeSHA256"`
	CAAfterSHA256  string                `json:"caAfterSHA256"`
	DisconnectedAt time.Time             `json:"disconnectedAt"`
	RestoredAt     time.Time             `json:"restoredAt"`
	Initial        cloudCDSRenewalSample `json:"initial"`
	Retained       cloudCDSRenewalSample `json:"retained"`
	Renewed        cloudCDSRenewalSample `json:"renewed"`
	cloudCDSRevocationProof
}

func cloudCDSUnchangedTasks(before, current cloudCDSState) error {
	if before.AppStart.IsZero() || before.MeshStart.IsZero() || !current.Running || !current.MeshReady || current.Restarts != 0 || current.Exit != nil || !current.AppStart.Equal(before.AppStart) || !current.MeshStart.Equal(before.MeshStart) {
		return errors.New("renewal outage changed application or mesh task identity")
	}
	return nil
}

func cloudCDSSameLeaf(before, current *Leaf) bool {
	return before.Accepted("cloud-a", acceptanceTenant) == nil && current.Accepted("cloud-a", acceptanceTenant) == nil && before.SandboxID == current.SandboxID && current.Serial == before.Serial && current.SPKI == before.SPKI && current.NotBefore == before.NotBefore && current.NotAfter == before.NotAfter
}

func (p cloudCDSRenewalProof) validate() error {
	if !p.Passed || p.Run == "" || p.UID == "" || p.CDSInstance == "" || p.PodInstance == "" || p.CDSInstance == p.PodInstance || p.CDSBoot != 1 || p.PodBoot != 1 || p.FinalCDSBoot != p.CDSBoot || p.FinalPodBoot != p.PodBoot || !cloudHex.MatchString(p.CABeforeSHA256) || p.CAAfterSHA256 != p.CABeforeSHA256 {
		return errors.New("renewal outage has incomplete identity, boot or CA proof")
	}
	if err := cloudCDSUnchangedTasks(p.Initial.State, p.Initial.State); err != nil {
		return err
	}
	for _, sample := range []cloudCDSRenewalSample{p.Retained, p.Renewed} {
		if err := cloudCDSUnchangedTasks(p.Initial.State, sample.State); err != nil {
			return err
		}
	}
	if p.Initial.At.IsZero() || !p.Initial.State.Ready || p.Retained.State.Ready || !p.Renewed.State.Ready || !p.DisconnectedAt.After(p.Initial.At) || p.Retained.At.Sub(p.DisconnectedAt) < cloudCDSRenewalHold || !p.RestoredAt.After(p.Retained.At) || !p.Renewed.At.After(p.RestoredAt) || p.Renewed.At.Sub(p.RestoredAt) > cloudCDSRenewalRecovery || !p.RevokedAt.After(p.Renewed.At) || !p.MeshWithdrawnAt.After(p.RevokedAt) || p.RefusedUntil.Sub(p.MeshWithdrawnAt) < cloudCDSRetention {
		return errors.New("renewal outage lacks guest-confirmed duration, restoration, renewal or sustained revocation")
	}
	if !cloudCDSSameLeaf(p.Initial.Leaf, p.Retained.Leaf) || p.Renewed.Leaf.Accepted("cloud-a", acceptanceTenant) != nil {
		return errors.New("renewal outage replaced its retained certificate")
	}
	expiry, err := time.Parse(time.RFC3339, p.Initial.Leaf.NotAfter)
	if err != nil || !expiry.After(p.RestoredAt.Add(cloudCDSRenewalRecovery)) {
		return errors.New("renewal outage crossed leaf expiry instead of testing retained valid credentials")
	}
	renewed, err := RenewalEventNamed(p.Initial.Leaf, p.Renewed.Leaf, p.Renewed.At.Sub(p.Initial.At), "cloud-a")
	if err != nil || !renewed {
		return errors.New("renewal outage did not produce a fresh authenticated certificate")
	}
	return nil
}

func (r *cloudRun) cdsRenewalProofComplete() error {
	raw, err := cloudPrivateRead(filepath.Join(r.dir, "cds-renewal-outage.json"), 64<<10)
	if err != nil {
		return err
	}
	var proof cloudCDSRenewalProof
	if err = json.Unmarshal(raw, &proof); err != nil {
		return err
	}
	if err = proof.validate(); err != nil {
		return err
	}
	pod, cds := r.ledger.Owned["a"], r.ledger.Owned["cds"]
	if proof.Run != r.ledger.Run || pod == nil || cds == nil || !r.ledger.Complete || !pod.Terminated || !cds.Terminated || pod.Receipt == nil || cds.Receipt == nil || proof.UID != pod.UID || proof.PodInstance != pod.Receipt.ID || proof.CDSInstance != cds.Receipt.ID {
		return errors.New("renewal outage proof lacks its matching completed Cloud cleanup")
	}
	return nil
}

func (r *cloudRun) cdsRenewalOutage(ctx context.Context, cfg *Config, guest *cloudGuest, cds endpoint) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 110*time.Minute)
	defer cancel()
	if err := r.cdsRequireInitialAppPolicy(ctx, cfg, guest, cds, "renewal-before"); err != nil {
		return err
	}
	ca, err := r.ca(ctx, cds)
	if err != nil {
		return err
	}
	before, err := r.getOwned(ctx, "cds")
	if err != nil {
		return err
	}
	if ok, err := cloudCDSIngressState(before, before, true); err != nil || !ok {
		return errors.New("CDS renewal outage requires stable owned ingress")
	}
	proof := cloudCDSRenewalProof{Run: r.ledger.Run, UID: string(guest.rec.UID), CDSInstance: before.ID, PodInstance: guest.rec.InstanceID, CDSBoot: before.Boot.Count, PodBoot: guest.boot, CABeforeSHA256: cloudHash(ca)}
	sequence := 0
	observe := func(phase cloudCDSPhase) (cloudCDSState, error) {
		sequence++
		return r.cdsObserve(ctx, guest, sequence, phase)
	}
	sample := func() (cloudCDSRenewalSample, error) {
		state, err := observe(cloudCDSActive)
		if err != nil {
			return cloudCDSRenewalSample{}, err
		}
		leaf, err := r.leaf(ctx, guest, "certless")
		if err != nil {
			return cloudCDSRenewalSample{}, err
		}
		out := cloudCDSRenewalSample{At: time.Now().UTC(), State: state, Leaf: leaf}
		return out, cloudWrite(filepath.Join(r.dir, fmt.Sprintf("cds-renewal-%04d.json", sequence)), out)
	}
	readyUntil := time.Now().Add(time.Minute)
	for {
		proof.Initial, err = sample()
		if err != nil {
			return err
		}
		if !cloudCDSSameLeaf(proof.Initial.Leaf, proof.Initial.Leaf) {
			return errors.New("renewal outage needs a named initial leaf")
		}
		if err = cloudCDSUnchangedTasks(proof.Initial.State, proof.Initial.State); err != nil {
			return err
		}
		if proof.Initial.State.Ready {
			break
		}
		if time.Now().After(readyUntil) {
			return errors.New("application did not become ready before the renewal outage")
		}
		if err = cloudPause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	expiry, err := time.Parse(time.RFC3339, proof.Initial.Leaf.NotAfter)
	if err != nil || time.Until(expiry) < cloudCDSRenewalHold+2*cloudCDSRenewalRecovery {
		return errors.New("initial leaf cannot outlive the bounded renewal outage and restoration")
	}
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
	for {
		in, err := r.getOwned(ctx, "cds")
		if err != nil {
			return err
		}
		if ok, err := cloudCDSIngressState(in, before, false); err != nil || !ok {
			return errors.New("CDS renewal outage ended or changed boot before restoration")
		}
		if err = cloudCDSPortClosed(ctx, cds); err != nil {
			return err
		}
		if err = cloudWrite(filepath.Join(r.dir, fmt.Sprintf("cds-renewal-network-%04d.json", sequence+1)), map[string]any{"at": time.Now().UTC(), "instance": in, "transportFailure": true}); err != nil {
			return err
		}
		current, err := sample()
		if err != nil {
			return err
		}
		if err = cloudCDSUnchangedTasks(proof.Initial.State, current.State); err != nil {
			return err
		}
		if !cloudCDSSameLeaf(proof.Initial.Leaf, current.Leaf) {
			return errors.New("certificate changed while CDS was unavailable")
		}
		// Guest and external observations begin independently. Keep ingress
		// closed until both have covered the full interval.
		if !current.State.Ready && time.Since(disconnected) >= cloudCDSRenewalHold {
			proof.Retained = current
			break
		}
		if time.Since(disconnected) > cloudCDSRenewalHold+5*time.Minute {
			return errors.New("guest did not confirm continuous outage across renewal")
		}
		if err = cloudPause(ctx, 15*time.Second); err != nil {
			return err
		}
	}
	if err = cloudWrite(filepath.Join(r.dir, "cds-renewal-retained.json"), proof); err != nil {
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
	proof.CAAfterSHA256 = cloudHash(afterCA)
	if !bytes.Equal(ca, afterCA) {
		return errors.New("renewal recovery changed the authenticated CDS CA")
	}
	for {
		current, err := sample()
		if err != nil {
			return err
		}
		if err = cloudCDSUnchangedTasks(proof.Initial.State, current.State); err != nil {
			return err
		}
		renewed, err := RenewalEventNamed(proof.Initial.Leaf, current.Leaf, current.At.Sub(proof.Initial.At), "cloud-a")
		if err != nil {
			return err
		}
		if current.State.Ready && renewed {
			proof.Renewed = current
			break
		}
		if time.Since(proof.RestoredAt) > cloudCDSRenewalRecovery {
			return errors.New("CDS restoration did not renew the retained Pod credential")
		}
		if err = cloudPause(ctx, 10*time.Second); err != nil {
			return err
		}
	}
	proof.cloudCDSRevocationProof, err = r.cdsRevoke(ctx, cfg, cds, proof.Renewed.State, observe)
	if err != nil {
		return err
	}
	finalCDS, err := r.getOwned(ctx, "cds")
	if err != nil {
		return err
	}
	if ok, err := cloudCDSIngressState(finalCDS, before, true); err != nil || !ok {
		return errors.New("restored CDS changed before renewal acceptance completed")
	}
	finalPod, err := r.getOwned(ctx, "a")
	if err != nil || finalPod == nil || finalPod.ID != proof.PodInstance || finalPod.Status != "running" {
		return errors.New("renewal acceptance lost the original running Pod VM")
	}
	proof.FinalCDSBoot, proof.FinalPodBoot = finalCDS.Boot.Count, finalPod.Boot.Count
	proof.Passed = true
	if err = proof.validate(); err != nil {
		return err
	}
	return cloudWrite(filepath.Join(r.dir, "cds-renewal-outage.json"), proof)
}
