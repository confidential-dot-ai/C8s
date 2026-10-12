package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func newTestPlugin(cfg *config) *plugin {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	return &plugin{
		cfg:        cfg,
		audit:      audit.NewLogger(),
		logger:     slog.Default(),
		containerd: &fakeContainerd{},
	}
}

// fakeContainerd is the containerdOps a test drives. An unset hook panics, so a
// test that reaches containerd without arranging for it names the call it made.
type fakeContainerd struct {
	resolve func(ctx context.Context, imageRef string) (string, error)
	stop    func(ctx context.Context, containerID string) error
}

func (f *fakeContainerd) Resolve(ctx context.Context, imageRef string) (string, error) {
	if f.resolve == nil {
		panic("unexpected containerd resolve")
	}
	return f.resolve(ctx, imageRef)
}

func (f *fakeContainerd) StopContainer(ctx context.Context, containerID string) error {
	if f.stop == nil {
		panic("unexpected container kill")
	}
	return f.stop(ctx, containerID)
}

func TestCheckImage_MissingAnnotation_DenyEnabled(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
		},
	})

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "",
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != "container has no image annotation" {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckImage_MissingAnnotation_DenyDisabled(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: false,
		},
	})

	verdict, _ := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "",
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip, got %d", verdict)
	}
}

func TestCheckContainer_MissingAnnotation_SystemNamespaceDenied(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			DenyMissingAnnotation: true,
		},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))

	pod := makePod("kube-system", "pod")
	verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, makeCtr(pod.Id, "ctr"), "")
	if verdict != verdictDeny {
		t.Fatalf("a system namespace buys nothing without an image annotation, got %d", verdict)
	}
}

// --- Startup security gap tests ---

func makePod(namespace, name string) *api.PodSandbox {
	return &api.PodSandbox{
		Id:        name + "-id",
		Name:      name,
		Namespace: namespace,
	}
}

func makeCtr(podSandboxID, name string) *api.Container {
	return &api.Container{
		Id:           name + "-id",
		PodSandboxId: podSandboxID,
		Name:         name,
	}
}

// The pod-sandbox lifecycle feeds the inventory's sandbox set: Synchronize seeds
// it even while the container check is deferred, RunPodSandbox adds,
// RemovePodSandbox evicts.
func TestPodSandboxEventsFeedInventory(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{EnforceExisting: true}})
	p.inventory = newAdmissionInventory(t.TempDir())

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, known, _ := p.inventory.DigestsForSandbox("pod1-id"); !known {
		t.Fatal("Synchronize did not seed the inventory sandbox set while deferring")
	}

	if err := p.RunPodSandbox(context.Background(), makePod("default", "pod2")); err != nil {
		t.Fatal(err)
	}
	if _, _, known, _ := p.inventory.DigestsForSandbox("pod2-id"); !known {
		t.Fatal("RunPodSandbox did not record the sandbox")
	}

	if err := p.RemovePodSandbox(context.Background(), makePod("default", "pod2")); err != nil {
		t.Fatal(err)
	}
	if _, _, known, _ := p.inventory.DigestsForSandbox("pod2-id"); known {
		t.Fatal("RemovePodSandbox did not evict the sandbox")
	}
}

// Pod-sandbox events are subscribed exactly when the inventory is enabled.
func TestConfigureSubscribesPodSandboxEventsWithInventory(t *testing.T) {
	p := newTestPlugin(&config{})
	mask, err := p.Configure(context.Background(), "", "containerd", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	if mask.IsSet(api.Event_RUN_POD_SANDBOX) || mask.IsSet(api.Event_REMOVE_POD_SANDBOX) {
		t.Fatal("pod-sandbox events subscribed without an inventory")
	}

	p.inventory = newAdmissionInventory(t.TempDir())
	mask, err = p.Configure(context.Background(), "", "containerd", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	if !mask.IsSet(api.Event_RUN_POD_SANDBOX) || !mask.IsSet(api.Event_REMOVE_POD_SANDBOX) {
		t.Fatal("pod-sandbox events not subscribed with the inventory enabled")
	}
}

func TestCreateContainer_NotReady_DeniesNonBaseImage(t *testing.T) {
	p := basePlugin(t)
	// plugin is NOT ready (default zero value of atomic.Bool is false)

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error when plugin not ready and the image is not in the base allowlist")
	}
	if !strings.HasPrefix(err.Error(), "image policy plugin initializing: ") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_NotReady_AdmitsBaseDigest(t *testing.T) {
	p := basePlugin(t)

	// The digest rides the reference, so admission needs no containerd call
	// (fakeContainerd panics if one happens).
	pod := makePod("kube-system", "coredns")
	ctr := makeCtrWithImage(pod.Id, "coredns", "registry/repo@"+pushDigestA)

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("a base digest should be admitted while initializing, got: %v", err)
	}
}

func TestCreateContainer_NotReady_AuditModeAllows(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "audit",
		},
	})

	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected audit mode to allow during init, got error: %v", err)
	}
}

func TestSynchronize_NotReady_Defers(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}

	updates, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}

	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredPods) != 1 {
		t.Fatalf("expected 1 deferred pod, got %d", len(p.deferredPods))
	}
	if len(p.deferredCtrs) != 1 {
		t.Fatalf("expected 1 deferred container, got %d", len(p.deferredCtrs))
	}
}

func TestSynchronize_NotReady_EnforceExistingDisabled_NoDeferral(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: false,
		},
	})

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}

	_, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredPods) != 0 {
		t.Fatalf("expected no deferred pods, got %d", len(p.deferredPods))
	}
}

func TestRunDeferredCheck_NothingDeferred(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})
	p.SetReady()

	// Should be a no-op without panic
	p.RunDeferredCheck(context.Background())
}

func TestCreateContainer_Ready_PassesThrough(t *testing.T) {
	p := &plugin{
		cfg: &config{
			Allowlist: allowlistConfig{Pull: pullConfig{URL: "http://wl.local:8080", Timeout: 30}},
			Policy: policyConfig{
				Mode:                  "fail-closed",
				DenyMissingAnnotation: true,
			},
		},
		audit:      audit.NewLogger(),
		logger:     slog.Default(),
		policy:     newPolicyStore(nil),
		containerd: &fakeContainerd{},
	}
	p.SetReady()

	// Container with no image annotation and deny_missing_annotation=true
	// should go through the normal path and be denied (not the init guard).
	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from normal allowlist check path")
	}
	// Should be the "no image annotation" denial, not the "initializing" denial
	if err.Error() == "image policy plugin initializing, container creation denied" {
		t.Fatal("got init guard denial but plugin is ready — should use normal path")
	}
	expected := "container has no image annotation"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

// The claims socket directory reaches injected sidecars as an NRI mount — a
// pod-spec hostPath would fail PodSecurity restricted — so CreateContainer
// must adjust exactly the webhook-injected sidecars of an injected pod, on the
// ready and initializing paths alike.
//
// The pods here carry only the annotation, never a real injection, so this
// also pins the forged-trigger posture: any pod that fakes the annotation and
// a sidecar name gets the RO mount, by design — the sockets behind it bind
// callers by kernel peer credentials, not by who holds the mount.
func TestCreateContainer_MountsSocketDirIntoInjectedSidecars(t *testing.T) {
	const socketDir = "/var/run/nri-image-policy"
	for name, ready := range map[string]bool{"ready": true, "initializing": false} {
		t.Run(name, func(t *testing.T) {
			p := newTestPlugin(&config{
				Policy:         policyConfig{Mode: ModeAudit},
				WorkloadClaims: workloadClaimsConfig{SocketDir: socketDir},
			})
			p.inventory = newAdmissionInventory(t.TempDir())
			if ready {
				p.SetReady()
				p.policy = newPolicyStore(nil)
			}
			pod := makePod("default", "pod1")
			pod.Annotations = map[string]string{workloadclaims.AnnotationInjected: "true"}

			for _, ctrName := range []string{
				workloadclaims.CertContainerName,
				workloadclaims.SecretContainerName,
				workloadclaims.VolumeContainerName,
				workloadclaims.AttestContainerName,
			} {
				adjust, _, err := createAndStart(p, context.Background(), pod, makeCtr(pod.Id, ctrName))
				if err != nil {
					t.Fatalf("%s: %v", ctrName, err)
				}
				if adjust == nil || len(adjust.Mounts) != 1 {
					t.Fatalf("%s: adjustment = %+v, want exactly the socket-dir mount", ctrName, adjust)
				}
				m := adjust.Mounts[0]
				if m.Source != socketDir || m.Destination != workloadclaims.SidecarSocketDir {
					t.Fatalf("%s: mount %s -> %s, want %s -> %s", ctrName, m.Source, m.Destination, socketDir, workloadclaims.SidecarSocketDir)
				}
				if !slices.Contains(m.Options, "ro") {
					t.Fatalf("%s: socket-dir mount not read-only: %v", ctrName, m.Options)
				}
			}
		})
	}
}

// Everything else gets no mount: a workload container in an injected pod, a
// sidecar-named container in a pod the webhook never touched, and any
// container when the inventory is disabled.
func TestCreateContainer_NoSocketDirMountOutsideInjectedSidecars(t *testing.T) {
	injected := makePod("default", "pod1")
	injected.Annotations = map[string]string{workloadclaims.AnnotationInjected: "true"}
	plain := makePod("default", "pod2")
	halfway := makePod("default", "pod3")
	halfway.Annotations = map[string]string{workloadclaims.AnnotationInjected: "false"}

	for name, tc := range map[string]struct {
		inventory bool
		pod       *api.PodSandbox
		ctr       string
	}{
		"workload container":     {true, injected, "app"},
		"cert-wait is no dialer": {true, injected, "c8s-cert-wait"},
		"uninjected pod":         {true, plain, workloadclaims.CertContainerName},
		"annotation not true":    {true, halfway, workloadclaims.CertContainerName},
		"inventory disabled":     {false, injected, workloadclaims.CertContainerName},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config{Policy: policyConfig{Mode: ModeAudit}}
			if tc.inventory {
				cfg.WorkloadClaims = workloadClaimsConfig{SocketDir: "/var/run/nri-image-policy"}
			}
			p := newTestPlugin(cfg)
			if tc.inventory {
				p.inventory = newAdmissionInventory(t.TempDir())
			}
			p.SetReady()
			p.policy = newPolicyStore(nil)

			adjust, _, err := createAndStart(p, context.Background(), tc.pod, makeCtr(tc.pod.Id, tc.ctr))
			if err != nil {
				t.Fatal(err)
			}
			if adjust != nil {
				t.Fatalf("adjustment = %+v, want none", adjust)
			}
		})
	}
}

// A denied container gets no adjustment alongside its error, on the ready and
// initializing paths alike.
func TestCreateContainer_DeniedContainerGetsNoAdjustment(t *testing.T) {
	for name, ready := range map[string]bool{"ready": true, "initializing": false} {
		t.Run(name, func(t *testing.T) {
			p := newTestPlugin(&config{
				Allowlist:      allowlistConfig{Pull: pullConfig{URL: "http://wl.local:8080", Timeout: 30}},
				Policy:         policyConfig{Mode: ModeFailClosed, DenyMissingAnnotation: true},
				WorkloadClaims: workloadClaimsConfig{SocketDir: "/var/run/nri-image-policy"},
			})
			p.inventory = newAdmissionInventory(t.TempDir())
			if ready {
				p.SetReady()
				p.policy = newPolicyStore(nil)
			}
			pod := makePod("default", "pod1")
			pod.Annotations = map[string]string{workloadclaims.AnnotationInjected: "true"}

			adjust, _, err := createAndStart(p, context.Background(), pod, makeCtr(pod.Id, workloadclaims.CertContainerName))
			if err == nil {
				t.Fatal("denied container admitted")
			}
			if adjust != nil {
				t.Fatalf("denied container got adjustment %+v", adjust)
			}
		})
	}
}

// --- Label selector evaluation tests ---

func makePodWithLabels(namespace, name string, labels map[string]string) *api.PodSandbox {
	return &api.PodSandbox{
		Id:        name + "-id",
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

func mustCompileRule(t *testing.T, rule labelRule) labelRule {
	t.Helper()
	rules := []labelRule{rule}
	if err := validateLabelRules(rules); err != nil {
		t.Fatalf("compile label rule: %v", err)
	}
	return rules[0]
}

// --- evaluateRule tests ---

func TestEvaluateRule_AllExpressionsMustMatch(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"acme"}},
			{Key: "team", Operator: "Exists"},
		},
	})
	// Both match
	if !evaluateRule(rule, map[string]string{"tenant": "acme", "team": "backend"}) {
		t.Fatal("expected rule to pass when all expressions match")
	}
	// Only first matches
	if evaluateRule(rule, map[string]string{"tenant": "acme"}) {
		t.Fatal("expected rule to fail when not all expressions match")
	}
}

func TestEvaluateRule_NilLabels(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "Exists"},
		},
	})
	if evaluateRule(rule, nil) {
		t.Fatal("expected rule to fail with nil labels")
	}
}

func TestEvaluateRule_DoesNotExist_NilLabels(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "privileged", Operator: "DoesNotExist"},
		},
	})
	if !evaluateRule(rule, nil) {
		t.Fatal("expected DoesNotExist to pass with nil labels")
	}
}

func TestEvaluateRule_UncompiledRuleFailsClosed(t *testing.T) {
	rule := labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "Exists"},
		},
	}
	if evaluateRule(rule, map[string]string{"tenant": "acme"}) {
		t.Fatal("uncompiled label rule should fail closed")
	}
}

// --- checkLabels tests ---

func TestCheckContainer_SystemNamespace_LabelDenialStands(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})

	pod := makePod("kube-system", "pod")
	verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, makeCtr(pod.Id, "ctr"), "")
	if verdict != verdictDeny {
		t.Fatalf("a label denial in a system namespace must stand, got %d", verdict)
	}
}

func TestCheckLabels_RuleViolation(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme", "beta"}},
				}},
			},
		},
	})

	// Pod with wrong tenant value
	verdict, reason := p.checkLabels(p.cfg, "default", "pod", "ctr",
		map[string]string{"tenant": "gamma"})
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != `label rule "allowed-tenants" denied workload` {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckLabels_AllRulesPass(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme", "beta"}},
				}},
				{Name: "no-privileged", MatchExpressions: []labelExpression{
					{Key: "privileged", Operator: "DoesNotExist"},
				}},
			},
		},
	})

	verdict, _ := p.checkLabels(p.cfg, "default", "pod", "ctr",
		map[string]string{"tenant": "acme"})
	if verdict != verdictAllow {
		t.Fatalf("expected verdictAllow, got %d", verdict)
	}
}

func TestCheckLabels_FirstViolationWins(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "first-rule", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
				{Name: "second-rule", MatchExpressions: []labelExpression{
					{Key: "team", Operator: "Exists"},
				}},
			},
		},
	})

	// Both rules violated — first should be reported
	verdict, reason := p.checkLabels(p.cfg, "default", "pod", "ctr", map[string]string{})
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != `label rule "first-rule" denied workload` {
		t.Fatalf("expected first rule to be reported, got: %s", reason)
	}
}

// --- CreateContainer with label rules ---

func TestCreateContainer_LabelRuleDeny_FailClosed(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "fail-closed",
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme"}},
				}},
			},
		},
	})
	p.SetReady()

	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "evil"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from label rule denial")
	}
	if err.Error() != `label rule "allowed-tenants" denied workload` {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_LabelRuleDeny_AuditMode(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "audit",
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme"}},
				}},
			},
		},
	})
	p.SetReady()

	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "evil"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected audit mode to allow, got error: %v", err)
	}
}

func TestCreateContainer_AllowlistDisabled_SkipsImageCheck(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:                  "fail-closed",
			DenyMissingAnnotation: true,
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})
	p.SetReady()

	// Pod has tenant label, no image annotation — should pass because
	// allowlist is disabled (no URL), image check is skipped.
	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "acme"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected no error with allowlist disabled, got: %v", err)
	}
}

// mustDigest parses a digest string or fails the test.
func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

// newCachedPlugin builds a plugin whose policy store admits wl (applied as a
// version-1 pull) plus the config's base allowlist.
func newCachedPlugin(cfg *config, wl *allowlist.Allowlist) (*plugin, *policyStore) {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	store := newPolicyStore(cfg.Allowlist.Base)
	store.apply(wl, 1)
	p := &plugin{
		cfg:        cfg,
		policy:     store,
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
	}
	return p, store
}

// --- checkImage: digest-bearing references (no resolver needed) ---

func TestCheckImage_DigestInAllowlist_Allows(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		anyAllowlist(map[string]string{pushDigestA: "image-a"}))

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  imageRef,
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictAllow {
		t.Fatalf("expected verdictAllow, got %d (reason=%q)", verdict, reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason on allow, got %q", reason)
	}
}

func TestCheckImage_DigestNotInAllowlist_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		anyAllowlist(map[string]string{pushDigestA: "image-a"}))

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  imageRef,
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason on deny")
	}
}

func TestCheckImage_NoPolicyLoaded_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, s := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	s.snap.Store(nil) // no admission snapshot loaded

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  imageRef,
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when no policy is loaded, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason when no allowlist is available")
	}
}

// --- workload argv policy: an any-argv entry admits any argv, an exact entry gates on argv ---

// workloadAllowlist builds an allowlist with one entry pinning wlDigest to an
// exact entrypoint and one entry admitting anyDigest under any argv.
func workloadAllowlist(t *testing.T, anyDigest, wlDigest string, entrypoint []string) *allowlist.Allowlist {
	t.Helper()
	al := anyAllowlist(map[string]string{anyDigest: "any-image"})
	al.Workloads["w"] = allowlist.Workload{Containers: []allowlist.Container{{
		Digest:  mustDigest(t, wlDigest),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: entrypoint},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
	}}}
	return al
}

func TestCheckImage_AnyArgvEntry_AdmitsAnyArgv(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestA,
		Argv:      []string{"/anything", "--wild"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictAllow {
		t.Fatalf("an any-argv entry should admit any argv, got %d (reason=%q)", verdict, reason)
	}
}

// An any-argv base entry admits by digest ahead of the served index, whatever
// the argv, and it is not consulted for a digest it does not name.
func TestCheckImage_BaseAdmitsByDigestAlone(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "installer"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Schema: allowlist.Schema})

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestA,
		Argv:      []string{"/anything"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictAllow {
		t.Fatalf("a base digest should be admitted, got %d (reason=%q)", verdict, reason)
	}
	if verdict, _ := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestB,
		Argv:      []string{"/anything"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal); verdict != verdictDeny {
		t.Fatalf("a digest outside the base allowlist and the served index must be denied, got %d", verdict)
	}
}

func TestCheckImage_WorkloadDigest_ArgvMatchAdmits(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestB,
		Argv:      []string{"/bin/app", "--serve"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictAllow {
		t.Fatalf("matching argv should admit workload digest, got %d (reason=%q)", verdict, reason)
	}
}

func TestCheckImage_WorkloadDigest_ArgvMismatchDenies(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, _ := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestB,
		Argv:      []string{"/bin/evil"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictDeny {
		t.Fatalf("non-matching argv should deny workload digest, got %d", verdict)
	}
}

// The two denials need different fixes — allowlist the image, versus correct the
// entry's argv policy — so the reason has to tell them apart.
func TestCheckImage_DenialSeparatesUnlistedFromArgvMismatch(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	_, argvMismatch := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestB,
		Argv:      []string{"/bin/evil"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if !strings.Contains(argvMismatch, "satisfies no workload entry's command, args, env or mounts policy") {
		t.Fatalf("a listed digest denied on argv should say so, got %q", argvMismatch)
	}

	_, unlisted := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestC,
		Argv:      []string{"/bin/app"},
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if !strings.Contains(unlisted, "image not in allowlist") {
		t.Fatalf("an unlisted digest should keep the not-in-allowlist denial, got %q", unlisted)
	}
}

func TestCreateContainer_WorkloadArgv_MatchAndMismatch(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base-image"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))
	p.SetReady()

	pod := makePod("default", "mypod")

	match := makeCtrWithImageArgs(pod.Id, "match", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
	if _, _, err := createAndStart(p, context.Background(), pod, match); err != nil {
		t.Fatalf("matching argv should be admitted, got: %v", err)
	}

	mismatch := makeCtrWithImageArgs(pod.Id, "mismatch", "registry/repo@"+pushDigestB, []string{"/bin/evil"})
	if _, _, err := createAndStart(p, context.Background(), pod, mismatch); err == nil {
		t.Fatal("non-matching argv should be denied")
	}
}

// --- CreateContainer end-to-end through the image allowlist path ---

func makeCtrWithImage(podSandboxID, name, image string) *api.Container {
	return &api.Container{
		Id:           name + "-id",
		PodSandboxId: podSandboxID,
		Name:         name,
		Annotations:  map[string]string{annotationImageName: image},
	}
}

// makeCtrWithImageArgs is makeCtrWithImage plus the container's effective argv
// (NRI folds the OCI process.args into api.Container.Args).
func makeCtrWithImageArgs(podSandboxID, name, image string, args []string) *api.Container {
	ctr := makeCtrWithImage(podSandboxID, name, image)
	ctr.Args = args
	return ctr
}

func TestCreateContainer_DigestNotInAllowlist_FailClosed(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected denial for image not in allowlist")
	}
}

func TestCreateContainer_DigestNotInAllowlist_AuditAllows(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeAudit},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("audit mode should allow despite deny verdict, got: %v", err)
	}
}

func TestCreateContainer_DigestInAllowlist_Allows(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestA)

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected allow for allowlisted digest, got: %v", err)
	}
}

// The pod annotation names the sandbox image, not this container's, so a
// container without its own annotation has no reference to check.
func TestCreateContainer_PodAnnotationDoesNotSupplyImage(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, DenyMissingAnnotation: true},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	pod := makePod("default", "mypod")
	pod.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestA}
	ctr := makeCtr(pod.Id, "myctr") // no annotations

	_, _, err := createAndStart(p, context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected denial: the container carries no image annotation")
	}
}

// --- checkExisting via deferred check (audit mode → no container kill attempted) ---

// assertDeferredCleared checks that RunDeferredCheck consumed the deferred state.
func assertDeferredCleared(t *testing.T, p *plugin) {
	t.Helper()
	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if p.deferredPods != nil || p.deferredCtrs != nil {
		t.Fatal("deferred state not cleared after RunDeferredCheck")
	}
}

func TestRunDeferredCheck_AuditMode_NoKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy: policyConfig{
			Mode:            ModeAudit, // audit → never calls resolver.StopContainer
			EnforceExisting: true,
		},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	pod := makePod("default", "pod1")
	// Container image is NOT in the allowlist → would be denied, but audit
	// mode means checkExisting continues without attempting a kill.
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// Should run the check without reaching containerd (fakeContainerd panics).
	p.RunDeferredCheck(context.Background())
	assertDeferredCleared(t, p)
}

func TestRunDeferredCheck_OrphanContainer_Skipped(t *testing.T) {
	// A container whose pod sandbox is absent is skipped (podByID miss).
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	ctr := makeCtrWithImage("missing-pod-id", "orphan", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = nil
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	p.RunDeferredCheck(context.Background())
	assertDeferredCleared(t, p)
}

func TestRunDeferredCheck_EnforceExistingDisabled_NoOp(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// EnforceExisting=false → early return before clearing deferred state.
	p.RunDeferredCheck(context.Background())
	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredCtrs) != 1 || len(p.deferredPods) != 1 {
		t.Fatal("disabled check must leave deferred state untouched")
	}
}

// --- enforce_existing=false still rebuilds broker state across a restart ---

func TestSynchronize_EnforceExistingDisabled_BrokerRecordsWithoutKilling(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	allowed := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)
	denied := makeCtrWithImage(pod.Id, "ctr2", "registry/repo@"+pushDigestB)

	// Fail-closed, but enforce_existing off: the denied container must not reach
	// StopContainer (fakeContainerd panics).
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{allowed, denied}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec, ok := p.inventory.containers[allowed.Id]
	if !ok {
		t.Fatalf("allowlisted container not recorded in the inventory: %v", p.inventory.containers)
	}
	if rec.digest != pushDigestA {
		t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestA)
	}
	// The denial did not stop it, so /digests must report it: a sandbox whose
	// answer omits a running container reads as a workload it is not.
	if _, ok := p.inventory.containers[denied.Id]; !ok {
		t.Fatalf("a denied container left running is invisible to the inventory: %v", p.inventory.containers)
	}
	digests, _, _, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil {
		t.Fatalf("DigestsForSandbox: %v", err)
	}
	if !slices.Contains(digests, pushDigestB) {
		t.Fatalf("/digests omits the denied container: %v", digests)
	}
}

// The restart sequence in full: NRI replays Synchronize before the initial CDS
// pull completes, so recovery runs through the deferred path.
func TestSynchronize_EnforceExistingDisabled_NotReady_DefersThenRecords(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)

	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.inventory.containers) != 0 {
		t.Fatal("nothing should be recorded before the plugin is ready")
	}

	p.SetReady()
	p.RunDeferredCheck(context.Background())

	if _, ok := p.inventory.containers[ctr.Id]; !ok {
		t.Fatalf("deferred check did not record the container: %v", p.inventory.containers)
	}
}

func TestSynchronize_Ready_AuditMode_ChecksWithoutEnforcing(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	allowed := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)
	denied := makeCtrWithImage(pod.Id, "ctr2", "registry/repo@"+pushDigestB)

	// Audit mode must run the check without enforcement: a denied container
	// reaching StopContainer would panic (fakeContainerd).
	updates, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{allowed, denied})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}
	if _, ok := p.inventory.containers[allowed.Id]; !ok {
		t.Fatalf("check did not record the allowed container in the inventory: %v", p.inventory.containers)
	}
	// Audit mode leaves the denied container running, so it belongs in /digests.
	if _, ok := p.inventory.containers[denied.Id]; !ok {
		t.Fatalf("audit mode left a container running and unrecorded: %v", p.inventory.containers)
	}
}

// --- System-component admission: digest-keyed, recorded everywhere ---

// captureAudit collects the audit events fn emits on the default slog logger.
// Swaps a process-global: not safe under t.Parallel.
func captureAudit(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	fn()

	var events []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if rec["msg"] == "audit" {
			events = append(events, rec)
		}
	}
	return events
}

// basePlugin admits pushDigestA from its base allowlist, and carries an inventory.
// No pull has been applied, the state a plugin is in before its first CDS
// fetch.
func basePlugin(t *testing.T) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
		},
	}
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(cfg.Allowlist.Base),
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
	}
	p.inventory = newAdmissionInventory("/proc")
	return p
}

// Admission keys on the image digest alone: a non-base image is denied in
// every namespace, kube-system included.
func TestCheckContainer_SystemNamespace_NonBaseImage_Denied(t *testing.T) {
	p := basePlugin(t)
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestB // not in the base allowlist
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictDeny {
		t.Fatalf("a non-base image in kube-system must be denied, got verdict %d", verdict)
	}
	if len(events) != 1 || events[0]["action"] != "deny" || events[0]["reason"] != "not_in_allowlist" {
		t.Fatalf("want exactly the digest denial, got %v", events)
	}
}

func TestBaseContainerIsRecordedOnEveryPath(t *testing.T) {
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestA // in the base allowlist
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	paths := []struct {
		name string
		run  func(*testing.T, *plugin)
	}{
		{"create hook", func(t *testing.T, p *plugin) {
			p.SetReady()
			if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
				t.Fatalf("base digest should be admitted: %v", err)
			}
		}},
		{"create hook while initializing", func(t *testing.T, p *plugin) {
			if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
				t.Fatalf("base digest should be admitted: %v", err)
			}
		}},
		{"startup check", func(t *testing.T, p *plugin) {
			p.SetReady()
			if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatal(err)
			}
		}},
		{"deferred check", func(t *testing.T, p *plugin) {
			if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatal(err)
			}
			p.SetReady()
			p.RunDeferredCheck(context.Background())
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			p := basePlugin(t)
			path.run(t, p)

			rec, ok := p.inventory.containers[ctr.Id]
			if !ok {
				t.Fatalf("base container is invisible to the inventory: %v", p.inventory.containers)
			}
			if rec.digest != pushDigestA {
				t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestA)
			}
			digests, _, known, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || !known {
				t.Fatalf("DigestsForSandbox(%s) = known %v, err %v", pod.Id, known, err)
			}
			if !slices.Contains(digests, pushDigestA) {
				t.Fatalf("/digests omits the base container: %v", digests)
			}
		})
	}
}

// A platform component takes the ordinary allow: one verified event, nothing
// else.
func TestCheckContainer_SystemNamespace_BaseImageIsPlainAllow(t *testing.T) {
	p := basePlugin(t)
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestA // in the base allowlist
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictAllow {
		t.Fatalf("a base image should be a plain allow, got verdict %d", verdict)
	}
	if len(events) != 1 || events[0]["reason"] != "verified" {
		t.Fatalf("want exactly the verified allow, got %v", events)
	}
}

// No namespace rescues a non-base image — exact or near-miss.
func TestCheckContainer_NamespaceNeverRescues(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB // not in the base allowlist
	for _, namespace := range []string{
		"kube-system",
		"local-path-storage",
		"",
		"kube-system ",
		" kube-system",
		"KUBE-SYSTEM",
		"Kube-System",
		"kube-system.",
		"kube-system\x00",
		"kube-system\n",
		"kube-systems",
		"kube_system",
	} {
		t.Run(fmt.Sprintf("%q", namespace), func(t *testing.T) {
			p := basePlugin(t)
			pod := makePod(namespace, "pod1")
			ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

			verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
			if verdict != verdictDeny {
				t.Fatalf("namespace %q: verdict %d, want verdictDeny", namespace, verdict)
			}
		})
	}
}

// Pre-Ready the admission decision resolves a tag against the base allowlist, but the
// inventory record keeps the inline-only contract: no digest is committed
// without one riding the reference, and the sandbox answer stays closed.
func TestCreateContainer_NotReady_ResolvesForAdmission_RecordsInlineOnly(t *testing.T) {
	p := basePlugin(t) // not ready
	var resolved []string
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
		resolved = append(resolved, ref)
		return pushDigestA, nil
	}}

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest") // no inline digest

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("a tag resolving to the base allowlist should be admitted: %v", err)
	}
	if len(resolved) != 3 {
		t.Fatalf("admission did not resolve the tag: %v", resolved)
	}
	rec, ok := p.inventory.containers[ctr.Id]
	if !ok {
		t.Fatalf("bootstrap container not recorded: %v", p.inventory.containers)
	}
	if rec.digest != "" {
		t.Fatalf("the bootstrap path resolved a digest, got %q", rec.digest)
	}
	if _, _, _, err := p.inventory.DigestsForSandbox(pod.Id); err == nil {
		t.Fatal("an unresolved digest must fail the sandbox answer closed")
	}
}

// The denial twin: a tag resolving outside the base allowlist is refused while
// initializing, in any namespace.
func TestCreateContainer_NotReady_TagOutsideBase_Denied(t *testing.T) {
	p := basePlugin(t) // not ready
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
		return pushDigestB, nil
	}}

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest")

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("a tag resolving outside the base allowlist must be denied while initializing")
	}
}

// A tag that fails to resolve during init is denied, not admitted: the
// bootstrap window enforces the base allowlist even when containerd cannot answer
// inside NRI's timeout.
func TestCreateContainer_NotReady_ResolveFails_Denied(t *testing.T) {
	p := basePlugin(t) // not ready
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, _ string) (string, error) {
		return "", errors.New("resolve timed out")
	}}

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest")

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("a tag that fails to resolve while initializing must be denied")
	}
}

// Audit mode admits what it denies, so what it admits it must record.
func TestCreateContainer_AuditModeDenial_IsRecorded(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeAudit},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("audit mode should admit: %v", err)
	}
	rec, ok := p.inventory.containers[ctr.Id]
	if !ok {
		t.Fatalf("audit mode admitted a container it did not record: %v", p.inventory.containers)
	}
	if rec.digest != pushDigestB {
		t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestB)
	}
}

func TestCheckExisting_RecordsBeforeAttemptingTheKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	var killed []string
	var recordedAtKill bool
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		_, recordedAtKill = p.inventory.containers[denied.Id]
		return errors.New("kill not delivered")
	}}

	p.checkExisting(context.Background(), p.cfg, []*api.PodSandbox{pod}, []*api.Container{denied})

	if len(killed) != 1 || killed[0] != denied.Id {
		t.Fatalf("the kill was not attempted: %v", killed)
	}
	if !recordedAtKill {
		t.Fatal("the container was recorded only after the kill was attempted")
	}
	if _, ok := p.inventory.containers[denied.Id]; !ok {
		t.Fatal("an undeliverable kill left the container unrecorded")
	}
}

// enforce_existing stops a foreign container in kube-system: the kill path
// never reads the namespace, so an exempt name does not spare a non-base
// image (issue #96's enforce case).
func TestCheckExisting_KubeSystemForeignContainerIsStopped(t *testing.T) {
	p := basePlugin(t)
	p.SetReady()

	pod := makePod("kube-system", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB) // not in the base allowlist

	var killed []string
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		return nil
	}}

	p.checkExisting(context.Background(), p.cfg, []*api.PodSandbox{pod}, []*api.Container{denied})

	if len(killed) != 1 || killed[0] != denied.Id {
		t.Fatalf("a non-base container in kube-system must be stopped, got %v", killed)
	}
}

// A container whose sandbox is absent from the Synchronize list runs like any
// other, so the sandbox's answer must carry it.
func TestCheckExisting_OrphanContainerIsStillRecorded(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	orphan := makeCtrWithImage("missing-pod-id", "orphan", "registry/repo@"+pushDigestB)
	if _, err := p.Synchronize(context.Background(), nil, []*api.Container{orphan}); err != nil {
		t.Fatal(err)
	}

	if _, ok := p.inventory.containers[orphan.Id]; !ok {
		t.Fatalf("a container with no pod in the list went unrecorded: %v", p.inventory.containers)
	}
	digests, _, known, err := p.inventory.DigestsForSandbox("missing-pod-id")
	if err != nil || !known {
		t.Fatalf("DigestsForSandbox = known %v, err %v", known, err)
	}
	if !slices.Contains(digests, pushDigestB) {
		t.Fatalf("the sandbox answer launders the orphan: %v", digests)
	}
}

// Only the pre-allowlist hook skips containerd; the startup path resolves.
func TestCheckExisting_ResolvesTagOnlyReference(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	var resolved []string
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
		resolved = append(resolved, ref)
		return pushDigestA, nil
	}}
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest")
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatal(err)
	}

	if len(resolved) == 0 {
		t.Fatal("the startup path recorded a tag-only reference without resolving it")
	}
	if rec := p.inventory.containers[ctr.Id]; rec.digest != pushDigestA {
		t.Fatalf("recorded digest = %q, want the resolved %q", rec.digest, pushDigestA)
	}
}

// argv reaches MatchWorkload, so the recorded value must be the container's.
func TestCreateContainer_RecordsTheContainerArgv(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	argv := []string{"/bin/app", "--serve"}
	ctr := makeCtrWithImageArgs(pod.Id, "ctr1", "registry/repo@"+pushDigestA, argv)

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
		t.Fatalf("allowlisted digest should be admitted: %v", err)
	}
	if rec := p.inventory.containers[ctr.Id]; !slices.Equal(rec.argv, argv) {
		t.Fatalf("recorded argv = %v, want %v", rec.argv, argv)
	}
	_, containers, _, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil {
		t.Fatalf("DigestsForSandbox: %v", err)
	}
	if len(containers) != 1 || !slices.Equal(containers[0].Argv, argv) {
		t.Fatalf("the sandbox answer reports argv %v, want %v", containers, argv)
	}
}

// A container the create hook rejected never ran.
func TestCreateContainer_DeniedContainerIsNotRecorded(t *testing.T) {
	p := basePlugin(t)
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	if _, _, err := createAndStart(p, context.Background(), pod, ctr); err == nil {
		t.Fatal("expected denial for an image not in the base allowlist")
	}
	if _, ok := p.inventory.containers[ctr.Id]; ok {
		t.Fatal("a denied container must not be recorded in the inventory")
	}
}

// --- Configure ---

func TestConfigure_SetsCreateContainerMask(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	mask, err := p.Configure(context.Background(), "", "containerd", "1.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want api.EventMask
	want.Set(api.Event_CREATE_CONTAINER)
	want.Set(api.Event_START_CONTAINER)
	want.Set(api.Event_VALIDATE_CONTAINER_ADJUSTMENT)
	if mask != want {
		t.Fatalf("mask = %v, want %v", mask, want)
	}
}

func TestCheckImage_ExactMountPolicyRequiresFinalObservation(t *testing.T) {
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	c := al.Workloads["w"].Containers[0]
	c.Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/expected", Kind: allowlist.MountEmptyDir}}}
	c.Env = allowlist.EnvPolicy{Policy: allowlist.PolicyAny}
	al.Workloads["w"].Containers[0] = c

	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, al)

	verdict, reason := p.checkImagePhase(context.Background(), p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo@" + pushDigestB,
		Argv:      []string{"/bin/app", "--serve"},
	}, launchFinal)
	if verdict != verdictDeny {
		t.Fatalf("unobserved exact mounts: verdict %d, want deny (reason=%q)", verdict, reason)
	}

	// Non-vacuity: the same entry refuses a container that does report one, so
	// the admit above is this plugin's silence rather than a dead policy.
	if p.policy.current().index.AdmitsContainer(allowlist.RunningContainer{
		Digest: pushDigestB,
		Argv:   []string{"/bin/app", "--serve"},
		Mounts: []allowlist.ObservedMount{{Destination: "/injected", Class: allowlist.MountHost, Storage: allowlist.MountUnknown}},
	}) {
		t.Error("the entry admitted a reported bind mount; the exact-empty policy is not live")
	}
}
