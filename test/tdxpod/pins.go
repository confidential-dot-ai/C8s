package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

//go:embed fixtures/pod-connected/production-image.json
var productionPins []byte

//go:embed fixtures/pod-connected/development-image.json
var developmentPins []byte

var (
	imageRef = regexp.MustCompile(`^ghcr\.io/confidential-dot-ai/node-guest-base@sha256:[0-9a-f]{64}$`)
	meshRef  = regexp.MustCompile(`^ghcr\.io/confidential-dot-ai/armtls-mesh@sha256:[0-9a-f]{64}$`)
)

// pins is a pinned image fixture: the exact image, its artifact, manifest and
// disk digests, the mesh image, and the commit both were built from.
type pins map[string]any

func loadPins(data []byte) (pins, error) {
	var p pins
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, errors.New("unreadable image pins")
	}
	return p, nil
}

func (p pins) str(key string) string {
	s, _ := p[key].(string)
	return s
}

func (p pins) flag(key string) (value, present bool) {
	v, ok := p[key]
	if !ok {
		return false, false
	}
	value, _ = v.(bool)
	return value, true
}

func (p pins) with(key string, value any) pins {
	copy := pins{}
	for k, v := range p {
		copy[k] = v
	}
	copy[key] = value
	return copy
}

func validatePinStructure(p pins) error {
	if schema, _ := p["schema"].(float64); schema != 1 || !hexCommit.MatchString(p.str("source")) {
		return errors.New("invalid production source pin")
	}
	if p.str("profileSource") != p.str("source") {
		return errors.New("image profile and components must match")
	}
	if !decimal.MatchString(p.str("buildRun")) {
		return errors.New("invalid image build run")
	}
	for _, key := range []string{"image", "artifact"} {
		if !imageRef.MatchString(p.str(key)) {
			return errors.New("unbound image reference")
		}
	}
	for _, key := range []string{"manifestSHA256", "diskSHA256"} {
		if !hexSHA256.MatchString(p.str(key)) {
			return errors.New("invalid image digest")
		}
	}
	if !meshRef.MatchString(p.str("meshImage")) {
		return errors.New("unbound mesh image")
	}
	return nil
}

// validatePins admits only production pins: development markers, even false,
// never enter acceptance.
func validatePins(p pins) error {
	if err := validatePinStructure(p); err != nil {
		return err
	}
	for _, key := range []string{"diagnosticOnly", "developmentProfile", "runtimeWrapper"} {
		if _, present := p[key]; present {
			return errors.New("development image pins cannot enter production acceptance")
		}
	}
	return nil
}

// imageManifest is the subset of the image build manifest the lanes check.
type imageManifest struct {
	Build struct {
		Platform string `json:"platform"`
	} `json:"build"`
	Inputs struct {
		BaseImage struct {
			SHA256 string `json:"sha256"`
		} `json:"base_image"`
	} `json:"inputs"`
	Outputs struct {
		DiskImage struct {
			SHA256 string `json:"sha256"`
		} `json:"disk_image"`
	} `json:"outputs"`
	TDX map[string]string `json:"tdx"`
}

func validateManifest(raw []byte, p pins) (*imageManifest, error) {
	if err := validatePins(p); err != nil {
		return nil, err
	}
	return validateManifestStructure(raw, p)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validateManifestStructure(raw []byte, p pins) (*imageManifest, error) {
	if err := validatePinStructure(p); err != nil {
		return nil, err
	}
	if len(raw) > 65536 || sha256Hex(raw) != p.str("manifestSHA256") {
		return nil, errors.New("production manifest digest differs")
	}
	var m imageManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("unreadable production manifest")
	}
	if m.Build.Platform != "tdx" {
		return nil, errors.New("production manifest is not TDX")
	}
	if m.Inputs.BaseImage.SHA256 != p.str("diskSHA256") {
		return nil, errors.New("production disk differs")
	}
	if m.Outputs.DiskImage.SHA256 != p.str("diskSHA256") {
		return nil, errors.New("published disk differs")
	}
	for _, key := range []string{"mrtd", "rtmr1", "rtmr2"} {
		if !hexRTMR.MatchString(m.TDX[key]) {
			return nil, errors.New("incomplete TDX identity")
		}
	}
	return &m, nil
}
