//go:build linux && pod_cloud_integration

package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// writeResult keeps the scenario proof separate from cleanup and from the
// caller-supplied guest/CLI publication source. The runner independently
// checks the executed acceptance binary against its local build receipt.
func (r *cloudRun) writeResult() error {
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
	assertions := map[string]bool{"cdsAccessControl": true, "attestedReadiness": true, "exactDigests": true, "meshDNSInternet": true, "readinessCycle": true, "timedRenewal": true, "negativeProbes": true, "ownedDeletion": true, "cleanup": true}
	scope := "signed Cloud launches, real Cloud TDX, authenticated connected acceptance between two Pod guests"
	if r.cfg.scenario() == "warm-assignment" {
		assertions = map[string]bool{"cdsAccessControl": true, "assignmentBeforePOST": true, "attestedReadiness": true, "certificateIdentity": true, "cleanup": true, "conflictingAssignmentRejected": true, "exactDigests": true, "genericIdle": true, "ownedDeletion": true}
		scope = "real Cloud TDX generic boot, verified empty attestation, authenticated one-time assignment through the guest status service, refused conflicting assignment, workload ingress and readiness after assignment"
	}
	if r.cfg.scenario() == "cds-outage" {
		if !r.cdsProofComplete() {
			return errors.New("complete CDS outage proof required before acceptance receipt")
		}
		assertions = map[string]bool{"cdsAccessControl": true, "attestedReadiness": true, "authenticatedPolicyUpdate": true, "cdsIngressRestored": true, "certificateIdentity": true, "cleanup": true, "exactDigests": true, "guestObservedOutage": true, "ownedDeletion": true, "revocationEnforced": true, "servedPolicyRetained": true}
		scope = "real Cloud TDX; authenticated served-only application admission, owned CDS network outage observed from guest and runner, retained admission across one app restart, restored same-CA CDS and enforced signed revocation"
	}
	if r.cfg.scenario() == "cds-renewal-outage" {
		if err := r.cdsRenewalProofComplete(); err != nil {
			return err
		}
		assertions = map[string]bool{"cdsAccessControl": true, "attestedReadiness": true, "authenticatedPolicyUpdate": true, "cdsIngressRestored": true, "certificateIdentity": true, "cleanup": true, "exactDigests": true, "guestObservedOutage": true, "ownedDeletion": true, "revocationEnforced": true, "servedPolicyRetained": true, "renewalAfterOutage": true, "taskContinuity": true}
		scope = "real Cloud TDX; 65-minute owned CDS network outage spanning the production renewal schedule, unchanged tasks and leaf during outage, same-CA restoration and renewed serial/SPKI, signed revocation and cleanup; not leaf expiry or CDS process restart"
	}
	return cloudWrite(filepath.Join(r.dir, "result.json"), map[string]any{
		"version": 2, "podLaunchFormat": "c8s-launch/v2", "cdsLaunchFormat": "c8s-cds/v1",
		"cdsConfigSHA256": r.ledger.Owned["cds"].LaunchFileSHA256,
		"passed":          true, "run": r.ledger.Run, "scenario": r.cfg.scenario(),
		"source": r.cfg.Source, "sourceProvenance": "caller-supplied guest/CLI release provenance; local artifact hashes and remote measured image are enforced",
		"acceptanceBinarySHA256": hex.EncodeToString(hash.Sum(nil)),
		"cliSHA256":              r.cfg.CLISHA256, "manifestDigest": r.cfg.ManifestDigest, "diskDigest": r.cfg.DiskDigest,
		"cdsManifestDigest": r.cfg.CDSManifestDigest, "cdsDiskDigest": r.cfg.CDSDiskDigest,
		"meshImage": r.cfg.MeshImage, "image": r.cfg.Image, "cdsImage": r.cfg.CDSImage,
		"scope": scope, "assertions": assertions,
	})
}
