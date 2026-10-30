//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// writeResult keeps the scenario proof separate from cleanup and from the
// caller-supplied guest/CLI publication source. The runner independently checks
// the executed provider binary against its local build receipt.
func (r *cloudRun) writeResult(h *providerControlPlane) error {
	if !r.cdsAccessProofComplete() {
		return errors.New("complete authenticated CDS access-control proof required")
	}
	path, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.Open(path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	if err = errors.Join(err, binary.Close()); err != nil {
		return err
	}
	assertions := map[string]bool{"cdsAccessControl": true, "normalScheduler": true, "restartRecovery": true, "attestedReadiness": true, "exactDigests": true, "meshDNSInternet": true, "readinessCycle": true, "timedRenewal": true, "negativeProbes": true, "providerDeletion": true, "cleanup": true}
	scope := "normal Kubernetes scheduling, production provider, real Cloud TDX, authenticated connected acceptance"
	if r.cfg.scenario() == "verification-timeout" {
		assertions = map[string]bool{"cdsAccessControl": true, "normalScheduler": true, "attestedReadiness": true, "exactDigests": true, "persistedVerificationDeadline": true, "restartRecovery": true, "lateVerifiedResultRejected": true, "readinessWithdrawn": true, "timeoutTermination": true, "providerDeletion": true, "cleanup": true}
		scope = "real Cloud TDX boot and production verification; injected result unavailability and latency across provider restart; confirmed timeout termination before Pod deletion"
	}
	if r.cfg.scenario() == "warm-assignment" {
		assertions = map[string]bool{"cdsAccessControl": true, "assignmentBeforePOST": true, "attestedReadiness": true, "certificateIdentity": true, "cleanup": true, "conflictingAssignmentRejected": true, "exactDigests": true, "genericIdle": true, "normalScheduler": true, "poolDrain": true, "providerDeletion": true, "restartRecovery": true, "uidFencedClaim": true}
		scope = "real Kubernetes scheduling and production provider components with durable observation wrappers; real Cloud TDX generic boot, authenticated one-time assignment, provider restart, refill and drain"
	}
	if r.cfg.scenario() == "cds-outage" {
		if !r.cdsProofComplete() {
			return errors.New("complete CDS outage proof required before acceptance receipt")
		}
		assertions = map[string]bool{"cdsAccessControl": true, "attestedReadiness": true, "authenticatedPolicyUpdate": true, "cdsIngressRestored": true, "certificateIdentity": true, "cleanup": true, "exactDigests": true, "guestObservedOutage": true, "normalScheduler": true, "providerDeletion": true, "revocationEnforced": true, "servedPolicyRetained": true}
		scope = "real Cloud TDX and normal Kubernetes scheduling; authenticated served-only application admission, owned CDS network outage observed from guest and runner, retained admission across one app restart, restored same-CA CDS and enforced signed revocation"
	}
	return cloudWrite(filepath.Join(r.dir, "result.json"), map[string]any{
		"version": 2, "podLaunchFormat": "c8s-launch/v2", "cdsLaunchFormat": "c8s-cds/v1",
		"cdsConfigSHA256": r.ledger.Owned["cds"].LaunchFileSHA256,
		"passed":          true, "run": r.ledger.Run, "scenario": r.cfg.scenario(),
		"source": r.cfg.Source, "sourceProvenance": "caller-supplied guest/CLI release provenance; local artifact hashes and remote measured image are enforced",
		"providerBinarySHA256": hex.EncodeToString(hash.Sum(nil)),
		"cliSHA256":            r.cfg.CLISHA256, "manifestDigest": r.cfg.ManifestDigest, "diskDigest": r.cfg.DiskDigest,
		"cdsManifestDigest": r.cfg.CDSManifestDigest, "cdsDiskDigest": r.cfg.CDSDiskDigest,
		"meshImage": r.cfg.MeshImage, "image": r.cfg.Image, "cdsImage": r.cfg.CDSImage,
		"infrastructurePlacement": h.infrastructure, "scope": scope, "assertions": assertions,
	})
}
