package webhook

import (
	"os"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestEveryInjectedFetcherRetainsCompleteCDSPolicy(t *testing.T) {
	doc, err := os.ReadFile("../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := secretsConfig()
	cfg.CDSMeasurementsConfigJSON = string(doc)
	cfg.WorkloadClaimsHostDir = "/run/nri-image-policy"
	cfg.AttestationApiURL = "unix:///run/nri-image-policy/attestation-api.sock"
	// Derived scalar diagnostics must not become conflicting CLI inputs
	// or replace the complete policy sent to a helper.
	cfg.CDSMeasurements = []string{strings.Repeat("ab", 48)}
	cfg.CDSRTMRs = []string{"1=" + strings.Repeat("cd", 48)}
	inj := &injection{}
	for name, container := range map[string]corev1.Container{
		"certificate": certContainer(inj, cfg),
		"secret":      secretContainer(inj, cfg),
		"volume":      volumeContainer(inj, cfg),
	} {
		t.Run(name, func(t *testing.T) {
			if !slices.Contains(container.Args, "--attestation-api-url=unix://"+workloadclaims.SidecarSocketDir+"/attestation-api.sock") {
				t.Fatalf("sidecar did not use the local attestation socket: %v", container.Args)
			}
			if slices.ContainsFunc(container.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.MountPath == workloadclaims.SidecarSocketDir
			}) {
				t.Fatal("sidecar socket must arrive through NRI; a pod-spec hostPath would fail restricted PSA")
			}
			if !slices.Contains(container.Args, "--image-policy-json="+string(doc)) {
				t.Fatal("injected fetcher lost the complete policy")
			}
			for _, arg := range container.Args {
				for _, prefix := range []string{"--measurements=", "--rtmrs=", "--cds-measurements=", "--cds-rtmrs="} {
					if strings.HasPrefix(arg, prefix) {
						t.Fatalf("flat fallback flag: %s", arg)
					}
				}
			}
		})
	}
}

// On an HA cluster every injected CDS client also gets what it needs to
// follow the operator's signed CDS pin decrees.
func TestInjectedFetchersFollowCDSPinDecrees(t *testing.T) {
	doc, err := os.ReadFile("../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := secretsConfig()
	cfg.CDSMeasurementsConfigJSON = string(doc)
	cfg.CDSPinsArgs = []string{"--cds-cluster-id=c1", "--cds-decree-key=KEY"}
	inj := &injection{}
	for name, container := range map[string]corev1.Container{
		"certificate": certContainer(inj, cfg),
		"secret":      secretContainer(inj, cfg),
		"volume":      volumeContainer(inj, cfg),
	} {
		if !slices.Contains(container.Args, "--cds-cluster-id=c1") || !slices.Contains(container.Args, "--cds-decree-key=KEY") {
			t.Fatalf("%s: %v", name, container.Args)
		}
	}
}
