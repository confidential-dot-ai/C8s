package nriimagepolicy

import (
	"fmt"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// renderedCDSPinsName is where the plugin keeps the document it renders for a
// node configured with independent pins. It sits in the plugin's own runtime
// directory, which no pod can write.
const renderedCDSPinsName = "cds-pins.json"

// prepareCDSPins resolves the CDS attestation policy this node hands its
// injected credential clients, before any container can be created. A node
// whose policy is a document hands that document over as it is — measured, on a
// baked node — after loading it, so a document no client could use fails here
// instead of in every pod. A node configured with independent pins gets the
// same document rendered from them, so one format reaches every client.
func (p *plugin) prepareCDSPins() error {
	if p.cfg.WorkloadClaims.SocketDir == "" {
		// No inventory directory, so no pod of this node is injected and
		// nothing would read a policy.
		return nil
	}
	if path, err := configuredPolicyDocument(p.cfg); err != nil || path != "" {
		p.cdsPins = path
		return err
	}
	path, err := renderNodePins(p.cfg)
	if err != nil {
		return err
	}
	p.cdsPins = path
	return nil
}

// configuredPolicyDocument is the policy document the node's config names,
// loaded so that an unreadable one, or one for another platform, fails at
// startup. "" means the node names no document.
func configuredPolicyDocument(cfg *config) (string, error) {
	path := cfg.Allowlist.Pull.CDSMeasurementsConfig
	if path == "" {
		return "", nil
	}
	if _, err := cmdsutil.LoadImagePolicyValues(cmdsutil.ImagePolicyValuesConfig{
		Source:       cmdsutil.ImagePolicySource{File: path},
		Platform:     cfg.NormalizedPlatform(),
		PlatformFlag: "platform",
	}); err != nil {
		return "", fmt.Errorf("allowlist.pull.cds_measurements_config: %w", err)
	}
	return path, nil
}

// renderNodePins writes the node's independent pins as a policy document in the
// plugin's runtime directory, and returns its path. "" means the node pins
// nothing, which leaves its clients to report themselves unpinned.
func renderNodePins(cfg *config) (string, error) {
	pull := cfg.Allowlist.Pull
	if len(pull.CDSMeasurements) == 0 {
		return "", nil
	}
	document, err := renderCDSPins(cfg.NormalizedPlatform(), pull.CDSMeasurements, pull.CDSRTMRs)
	if err != nil {
		return "", fmt.Errorf("allowlist.pull: %w", err)
	}
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, renderedCDSPinsName)
	if err := fileutil.WriteAtomic(path, document, 0o644); err != nil {
		return "", fmt.Errorf("write the rendered CDS pins: %w", err)
	}
	return path, nil
}

// renderCDSPins is the independent pins as one policy document: each launch
// digest is an accepted CDS image, named by that digest, and on TDX each
// carries the node's register pins.
func renderCDSPins(platform string, measurements, registers []string) ([]byte, error) {
	family, err := teetypes.ParseFamily(platform)
	if err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}
	digests, err := refvalues.ParseHexMeasurementsList(measurements)
	if err != nil {
		return nil, fmt.Errorf("cds_measurements: %w", err)
	}
	pins, err := refvalues.ParseRegisterPins(registers)
	if err != nil {
		return nil, fmt.Errorf("cds_rtmrs: %w", err)
	}
	set := refvalues.ReferenceValues{Family: family}
	for i, digest := range digests {
		image := remote.ImagePin{Name: measurements[i], Digest: digest}
		if family == teetypes.FamilyTDX {
			image.Registers = pins
		}
		set.Images = append(set.Images, image)
	}
	document, err := refvalues.Format(set)
	if err != nil {
		return nil, fmt.Errorf("render the pins as a policy document: %w", err)
	}
	return document, nil
}
