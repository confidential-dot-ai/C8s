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
	assertions := map[string]bool{"normalScheduler": true, "restartRecovery": true, "attestedReadiness": true, "exactDigests": true, "meshDNSInternet": true, "readinessCycle": true, "timedRenewal": true, "negativeProbes": true, "providerDeletion": true, "cleanup": true}
	scope := "normal Kubernetes scheduling, production provider, real Cloud TDX, authenticated connected acceptance"
	if r.cfg.scenario() == "verification-timeout" {
		assertions = map[string]bool{"normalScheduler": true, "attestedReadiness": true, "exactDigests": true, "persistedVerificationDeadline": true, "restartRecovery": true, "lateVerifiedResultRejected": true, "readinessWithdrawn": true, "timeoutTermination": true, "providerDeletion": true, "cleanup": true}
		scope = "real Cloud TDX boot and production verification; injected result unavailability and latency across provider restart; confirmed timeout termination before Pod deletion"
	}
	return cloudWrite(filepath.Join(r.dir, "result.json"), map[string]any{
		"passed": true, "run": r.ledger.Run, "scenario": r.cfg.scenario(),
		"source": r.cfg.Source, "sourceProvenance": "caller-supplied guest/CLI release provenance; local artifact hashes and remote measured image are enforced",
		"providerBinarySHA256": hex.EncodeToString(hash.Sum(nil)),
		"cliSHA256":            r.cfg.CLISHA256, "manifestDigest": r.cfg.ManifestDigest,
		"meshImage": r.cfg.MeshImage, "image": r.cfg.Image, "cdsImage": r.cfg.CDSImage,
		"infrastructurePlacement": h.infrastructure, "scope": scope, "assertions": assertions,
	})
}
