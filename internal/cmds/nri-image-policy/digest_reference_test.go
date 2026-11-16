package nriimagepolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A served entry admits only a digest reference: a tag is resolved at hook
// time, not bound to the image the runtime created the container from. The
// base keeps its tags, which the node's own manifests use.
func TestCheckImage_ServedAdmitsOnlyDigestReferences(t *testing.T) {
	served := anyAllowlist(map[string]string{pushDigestA: "image-a"})
	base := anyAllowlist(map[string]string{pushDigestB: "image-b"})
	resolveTo := map[string]string{"registry/app:v1": pushDigestA, "registry/base:v1": pushDigestB}

	for _, tt := range []struct {
		name, ref string
		want      imageVerdict
	}{
		{"served tag refused", "registry/app:v1", verdictDeny},
		{"served digest admitted", "registry/app@" + pushDigestA, verdictAllow},
		{"served tag and digest admitted", "registry/app:v1@" + pushDigestA, verdictAllow},
		{"base tag admitted", "registry/base:v1", verdictAllow},
	} {
		for _, phase := range []launchPhase{launchPreliminary, launchFinal} {
			p, _ := newCachedPlugin(&config{
				Allowlist: allowlistConfig{Base: base},
				Policy:    policyConfig{Mode: ModeFailClosed},
			}, served)
			p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
				return resolveTo[ref], nil
			}}
			verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
				Namespace: "default", PodName: "pod", Container: "ctr",
				ImageRef: tt.ref, Mounts: []allowlist.ObservedMount{},
			}, phase)
			if verdict != tt.want {
				t.Fatalf("%s (phase %d): verdict %d, want %d (reason %q)", tt.name, phase, verdict, tt.want, reason)
			}
			if verdict == verdictDeny && !strings.Contains(reason, "image must be referenced by digest") {
				t.Fatalf("%s: reason %q does not name the digest rule", tt.name, reason)
			}
		}
	}
}
