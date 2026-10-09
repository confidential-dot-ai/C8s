// The mesh endpoint's seeded launch. CDS serves the chart's seed and the node
// image bakes it, and the enforcer admits a container that either the measured
// base or the served document admits — so a seed entry wider than the measured
// base (node-guest-image/c8s/image-policy.yaml.in) is what the mesh image may
// actually run as, in any pod.
package helmchart

import (
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const (
	meshSeedDigest         = "sha256:00000000000000000000000000000000000000000000000000000000000000f1"
	meshSeedOperatorDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000f2"
	meshSeedNginxDigest    = "sha256:00000000000000000000000000000000000000000000000000000000000000f3"
)

// meshCertMount is the injected credential volume as the node classifies it: a
// memory-backed emptyDir the pod's fsGroup owns.
func meshCertMount(destination string) pkgallowlist.ObservedMount {
	return pkgallowlist.ObservedMount{
		Destination: destination,
		Class:       pkgallowlist.MountEmptyDir,
		Storage:     pkgallowlist.MountMemory,
	}
}

// injectedMeshLaunch is the endpoint the injector builds, as the enforcer
// observes it: the image's entrypoint, the three credential paths and the one
// credential volume (internal/webhook/pod_mutator.go, meshContainer).
func injectedMeshLaunch() pkgallowlist.RunningContainer {
	return pkgallowlist.RunningContainer{
		Digest: meshSeedDigest,
		Argv: []string{
			"/app/c8s",
			"armtls-mesh",
			"--cert-path=/etc/c8s/certs/tls.crt",
			"--key-path=/etc/c8s/certs/tls.key",
			"--ca-path=/etc/c8s/certs/ca.crt",
		},
		Mounts: []pkgallowlist.ObservedMount{meshCertMount("/etc/c8s/certs")},
	}
}

// meshLaunchWith is the injected endpoint with its argv or its mounts replaced.
func meshLaunchWith(argv []string, mounts []pkgallowlist.ObservedMount) pkgallowlist.RunningContainer {
	launch := injectedMeshLaunch()
	if argv != nil {
		launch.Argv = argv
	}
	launch.Mounts = mounts
	return launch
}

// TestChartSeedPinsTheMeshEndpointLaunch proves the rendered seed admits the
// mesh image for the injected launch alone, and that it reaches the same
// verdict as the measured base on every launch tried: a seed that admits more
// hands the mesh digest a command line and a mount set the measured base
// refuses.
func TestChartSeedPinsTheMeshEndpointLaunch(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "armtlsMesh.image.digest="+meshSeedDigest,
		"--set-string", "image.digest="+meshSeedOperatorDigest,
		"--set-string", "router.nginx.image.digest="+meshSeedNginxDigest,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out).BuildIndex()
	measured := measuredBaseAllowlist(t, map[string]string{
		"@MESH_DIGEST@":     meshSeedDigest,
		"@OPERATOR_DIGEST@": meshSeedOperatorDigest,
		"@ROUTER_DIGEST@":   meshSeedNginxDigest,
	}).BuildIndex()

	// CDS refuses to issue a certificate to a pod running a digest its
	// allowlist does not list, so the entry stays, pinned rather than absent.
	if !seed.AdmitsDigest(meshSeedDigest) {
		t.Fatal("the seed lists no mesh digest, so no member pod is issued a certificate")
	}

	for _, tc := range []struct {
		name     string
		launch   pkgallowlist.RunningContainer
		admitted bool
	}{
		{
			name:     "the injected endpoint",
			launch:   injectedMeshLaunch(),
			admitted: true,
		},
		{
			name:     "another command line",
			launch:   meshLaunchWith([]string{"/bin/sh", "-c", "cat /etc/c8s/certs/tls.key"}, []pkgallowlist.ObservedMount{meshCertMount("/etc/c8s/certs")}),
			admitted: false,
		},
		{
			name:     "another credential path",
			launch:   meshLaunchWith([]string{"/app/c8s", "armtls-mesh", "--cert-path=/etc/c8s/certs/tls.crt"}, []pkgallowlist.ObservedMount{meshCertMount("/etc/c8s/certs")}),
			admitted: false,
		},
		{
			name:     "an extra mount",
			launch:   meshLaunchWith(nil, []pkgallowlist.ObservedMount{meshCertMount("/etc/c8s/certs"), meshCertMount("/etc/c8s/elsewhere")}),
			admitted: false,
		},
		{
			name:     "no credential mount",
			launch:   meshLaunchWith(nil, []pkgallowlist.ObservedMount{}),
			admitted: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := seed.AdmitsContainer(tc.launch); got != tc.admitted {
				t.Errorf("the seed admits the mesh image for %s: %t, want %t", tc.name, got, tc.admitted)
			}
			if got := measured.AdmitsContainer(tc.launch); got != tc.admitted {
				t.Errorf("the measured base admits the mesh image for %s: %t, want %t", tc.name, got, tc.admitted)
			}
		})
	}
}
