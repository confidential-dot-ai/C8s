package nriimagepolicy

import (
	"context"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

func TestBaseAllowlistEnforcesFinalEnvAndMounts(t *testing.T) {
	base, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"base":{"containers":[{
		"digest":"` + pushDigestA + `",
		"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
		"env":{"policy":"exact","values":{"MODE":"production"}},
		"mounts":{"policy":"exact","rules":[{"destination":"/cache","kind":"emptyDir"}]}
	}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	goodEnv, err := allowlist.ObserveEnv([]string{"MODE=production"})
	if err != nil {
		t.Fatal(err)
	}
	wrongEnv, err := allowlist.ObserveEnv([]string{"MODE=development"})
	if err != nil {
		t.Fatal(err)
	}
	goodMounts := []allowlist.ObservedMount{{Destination: "/cache", Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory}}
	for _, tc := range []struct {
		name   string
		env    *allowlist.EnvObservation
		mounts []allowlist.ObservedMount
		want   imageVerdict
	}{
		{"matching", goodEnv, goodMounts, verdictAllow},
		{"wrong environment", wrongEnv, goodMounts, verdictDeny},
		{"missing environment", nil, goodMounts, verdictDeny},
		{"missing mounts", goodEnv, nil, verdictDeny},
		{"empty mounts", goodEnv, []allowlist.ObservedMount{}, verdictDeny},
		{"foreign mounts", goodEnv, []allowlist.ObservedMount{{Destination: "/cache", Class: allowlist.MountHost, Storage: allowlist.MountUnknown}}, verdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newCachedPlugin(&config{Allowlist: allowlistConfig{Base: base}, Policy: policyConfig{Mode: ModeFailClosed}}, &allowlist.Allowlist{})
			for _, phase := range []launchPhase{launchPreliminary, launchFinal} {
				want := tc.want
				if phase == launchPreliminary {
					want = verdictAllow
				}
				got, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
					Namespace: "default",
					PodName:   "pod",
					Container: "ctr",
					ImageRef:  "registry/app@" + pushDigestA,
					Argv:      []string{"/app"},
					Env:       tc.env,
					Mounts:    tc.mounts,
				}, phase)
				if got != want {
					t.Fatalf("phase %d: verdict=%d want=%d reason=%q", phase, got, want, reason)
				}
			}
		})
	}
}
