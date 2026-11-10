package nriimagepolicy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// auditedCheck is one container's identity: the fields every audit event of a
// check carries.
func auditedCheck(ref string, argv ...string) imageCheck {
	return imageCheck{
		Namespace: "tenant",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  ref,
		Argv:      argv,
		Mounts:    []allowlist.ObservedMount{},
	}
}

// Every gate of checkImagePhase records what the node let run: one audit event
// naming the container, the action and the rule, plus the denial the pod's
// namespace reads.
func TestCheckImagePhaseAuditsEveryGate(t *testing.T) {
	unlisted := "registry/repo@" + pushDigestC
	listed := "registry/repo@" + pushDigestB
	for _, tc := range []struct {
		name        string
		build       func(t *testing.T) *plugin
		check       imageCheck
		wantVerdict imageVerdict
		wantAction  string
		wantReason  string
		wantMessage string
		wantError   string
	}{
		{
			name: "no image annotation, denied",
			build: func(t *testing.T) *plugin {
				return newTestPlugin(&config{Policy: policyConfig{DenyMissingAnnotation: true}})
			},
			check:       auditedCheck(""),
			wantVerdict: verdictDeny,
			wantAction:  "deny",
			wantReason:  "no_image_annotation",
			wantMessage: "container has no image annotation",
		},
		{
			name: "no image annotation, no check applied",
			build: func(t *testing.T) *plugin {
				return newTestPlugin(&config{Policy: policyConfig{DenyMissingAnnotation: false}})
			},
			check:       auditedCheck(""),
			wantVerdict: verdictSkip,
			wantAction:  "allow",
			wantReason:  "no_image_annotation",
		},
		{
			name: "containerd cannot resolve the tag",
			build: func(t *testing.T) *plugin {
				p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
					anyAllowlist(map[string]string{pushDigestA: "image-a"}))
				p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
					return "", errors.New("containerd is unreachable")
				}}
				return p
			},
			check:       auditedCheck("registry/repo:latest"),
			wantVerdict: verdictDeny,
			wantAction:  "deny",
			wantReason:  "resolve_failed",
			wantMessage: "cannot resolve digest for registry/repo:latest: containerd is unreachable",
			wantError:   "containerd is unreachable",
		},
		{
			name: "no allowlist snapshot loaded",
			build: func(t *testing.T) *plugin {
				p, store := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
					anyAllowlist(map[string]string{pushDigestA: "image-a"}))
				store.snap.Store(nil)
				return p
			},
			check:       auditedCheck("registry/repo@" + pushDigestA),
			wantVerdict: verdictDeny,
			wantAction:  "deny",
			wantReason:  "no_allowlist_available",
			wantMessage: "no allowlist available for registry/repo@" + pushDigestA,
		},
		{
			name: "a worker keeps no tag",
			build: func(t *testing.T) *plugin {
				p, _ := newCachedPlugin(&config{
					Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
					Policy:    policyConfig{Mode: ModeFailClosed},
					Worker:    true,
				}, anyAllowlist(map[string]string{}))
				p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
					return pushDigestA, nil
				}}
				return p
			},
			check:       auditedCheck("registry/repo:v1"),
			wantVerdict: verdictDeny,
			wantAction:  "deny",
			wantReason:  "not_digest_pinned",
			wantMessage: "image must be referenced by digest (name@sha256:...): registry/repo:v1",
		},
		{
			name: "digest in no allowlist",
			build: func(t *testing.T) *plugin {
				p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
					workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))
				return p
			},
			check:       auditedCheck(unlisted, "/bin/app"),
			wantVerdict: verdictDeny,
			wantAction:  "deny",
			wantReason:  "not_in_allowlist",
			wantMessage: "image not in allowlist: " + unlisted,
		},
		{
			name: "allowlisted digest, launch satisfies no entry",
			build: func(t *testing.T) *plugin {
				p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
					workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))
				return p
			},
			check:       auditedCheck(listed, "/bin/evil"),
			wantVerdict: verdictDeny,
			wantAction:  "deny",
			wantReason:  "launch_not_admitted",
			wantMessage: "image " + listed + " is allowlisted, but its launch specification satisfies no workload entry's" +
				" command, args, env or mounts policy; the closest entry differs in command",
		},
		{
			name: "admitted launch",
			build: func(t *testing.T) *plugin {
				p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
					anyAllowlist(map[string]string{pushDigestA: "image-a"}))
				return p
			},
			check:       auditedCheck("registry/repo@"+pushDigestA, "/bin/app"),
			wantVerdict: verdictAllow,
			wantAction:  "allow",
			wantReason:  "verified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.build(t)
			var verdict imageVerdict
			var message string
			events := captureAudit(t, func() {
				verdict, message = p.checkImagePhase(context.Background(), p.cfg, tc.check, launchFinal)
			})
			if verdict != tc.wantVerdict {
				t.Fatalf("verdict = %d, want %d (message %q)", verdict, tc.wantVerdict, message)
			}
			if message != tc.wantMessage {
				t.Errorf("message = %q, want %q", message, tc.wantMessage)
			}
			if len(events) != 1 {
				t.Fatalf("audit events = %v, want exactly one", events)
			}
			event := events[0]
			for field, want := range map[string]string{
				"action":    tc.wantAction,
				"reason":    tc.wantReason,
				"namespace": "tenant",
				"pod":       "pod",
				"container": "ctr",
				"image":     tc.check.ImageRef,
			} {
				if event[field] != want {
					t.Errorf("audit %s = %v, want %q", field, event[field], want)
				}
			}
			got, logged := event["error"]
			if tc.wantError == "" && logged {
				t.Errorf("audit error = %v, want no error field", got)
			}
			if tc.wantError != "" && got != tc.wantError {
				t.Errorf("audit error = %v, want %q", got, tc.wantError)
			}
		})
	}
}

// pinnedMountEntry lists digest under an exact command and an exact mount rule,
// so a matching argv passes the preliminary check and the mounts decide the
// final one.
func pinnedMountEntry(t *testing.T, digest string) *allowlist.Allowlist {
	t.Helper()
	al := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
	al.Workloads["w"] = allowlist.Workload{Containers: []allowlist.Container{{
		Digest:  mustDigest(t, digest),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/bin/app"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{
			{Destination: "/cache", Kind: allowlist.MountEmptyDir},
		}},
	}}}
	return al
}

// The preliminary check judges the process, the final one the whole container:
// a served entry whose mount rule the launch misses admits it before the
// runtime has built the spec, and refuses it once it has.
func TestCheckImagePhaseServedEntryJudgesTheProcessBeforeTheContainer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		phase       launchPhase
		wantVerdict imageVerdict
		wantReason  string
	}{
		{"preliminary", launchPreliminary, verdictAllow, "verified"},
		{"final", launchFinal, verdictDeny, "launch_not_admitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
				pinnedMountEntry(t, pushDigestB))
			check := auditedCheck("registry/repo@"+pushDigestB, "/bin/app")
			var verdict imageVerdict
			events := captureAudit(t, func() {
				verdict, _ = p.checkImagePhase(context.Background(), p.cfg, check, tc.phase)
			})
			if verdict != tc.wantVerdict {
				t.Fatalf("verdict = %d, want %d", verdict, tc.wantVerdict)
			}
			if len(events) != 1 || events[0]["reason"] != tc.wantReason {
				t.Fatalf("audit events = %v, want one with reason %q", events, tc.wantReason)
			}
		})
	}
}

// A preliminary denial names the fields the phase actually checked, so a
// workload author is not sent after mounts and env the runtime had not built
// yet.
func TestCheckImagePhasePreliminaryDenialNamesTheProcessFieldsOnly(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		pinnedMountEntry(t, pushDigestB))
	check := auditedCheck("registry/repo@"+pushDigestB, "/bin/evil")

	_, preliminary := p.checkImagePhase(context.Background(), p.cfg, check, launchPreliminary)
	if !strings.HasSuffix(preliminary, "the closest entry differs in command") {
		t.Fatalf("preliminary denial = %q, want it to end at the command mismatch", preliminary)
	}
	_, final := p.checkImagePhase(context.Background(), p.cfg, check, launchFinal)
	if !strings.HasSuffix(final, "the closest entry differs in command, mounts") {
		t.Fatalf("final denial = %q, want the mount mismatch too", final)
	}
}

// The journal line of a refused launch carries the digest the node judged and
// a hash of the argv, never the argv itself: its values can carry credentials.
func TestCheckImagePhaseDenialLogsTheArgvHashNotTheArgv(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))
	var journal bytes.Buffer
	p.logger = slog.New(slog.NewTextHandler(&journal, nil))

	argv := []string{"/bin/evil", "--token=hunter2"}
	p.checkImagePhase(context.Background(), p.cfg, auditedCheck("registry/repo@"+pushDigestB, argv...), launchFinal)

	line := journal.String()
	for _, want := range []string{
		"digest=" + pushDigestB,
		"argv_sha256=" + argvDigest(argv),
		"reason=launch_not_admitted",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("journal line %q does not carry %q", line, want)
		}
	}
	if strings.Contains(line, "hunter2") {
		t.Errorf("journal line %q carries an argv value", line)
	}
}
