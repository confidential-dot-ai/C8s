package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/launchbinding"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlistclient"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
)

const (
	pushDigestA = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	pushDigestB = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
	pushDigestC = "sha256:0000000000000000000000000000000000000000000000000000000000000003"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// anyAllowlist builds an allowlist with one any-argv entry per digest, named
// "w-" plus the first 12 hex digits of the digest.
func anyAllowlist(digests map[string]string) *allowlist.Allowlist {
	al := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
	for d, image := range digests {
		al.Workloads["w-"+d[len("sha256:"):][:12]] = allowlist.Workload{Label: image, Containers: []allowlist.Container{{
			Digest:  mustDigestOrPanic(d),
			Image:   image,
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		}}}
	}
	return al
}

func mustDigestOrPanic(s string) types.Digest {
	d, err := types.ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

// canonicalBody renders an allowlist as the Trust Authority /allowlist wire body.
func canonicalBody(t *testing.T, al *allowlist.Allowlist) []byte {
	t.Helper()
	b, err := al.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return b
}

// admitsDigest mirrors the plugin's admission order: the base allowlist
// first, then the served index.
func admitsDigest(store *policyStore, digest string) bool {
	snap := store.current()
	return store.baseAdmits(allowlist.RunningContainer{Digest: digest}, launchPreliminary) || (snap != nil && snap.index.AdmitsDigest(digest))
}

func TestStartupSourceMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config
		want string
	}{
		{
			name: "pull",
			cfg: &config{Allowlist: allowlistConfig{
				Pull: pullConfig{URL: "https://cds.example"},
			}},
			want: "pull",
		},
		{
			name: "base only",
			cfg: &config{Allowlist: allowlistConfig{
				Base: anyAllowlist(map[string]string{pushDigestA: "image-a"}),
			}},
			want: "base",
		},
		{
			name: "label rules only",
			cfg: &config{Policy: policyConfig{
				LabelRules: []labelRule{{Name: "require-tenant"}},
			}},
			want: "label_rules",
		},
		{
			name: "base and label rules",
			cfg: &config{
				Allowlist: allowlistConfig{
					Base: anyAllowlist(map[string]string{pushDigestA: "image-a"}),
				},
				Policy: policyConfig{
					LabelRules: []labelRule{{Name: "require-tenant"}},
				},
			},
			want: "base+label_rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startupSourceMode(tt.cfg); got != tt.want {
				t.Fatalf("startupSourceMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- policyStore epoch anti-rollback ---

func TestPolicyStoreEpochAntiRollback(t *testing.T) {
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())

	if !store.apply(anyAllowlist(map[string]string{pushDigestB: "v5"}), 5) {
		t.Fatal("apply of version 5 rejected")
	}
	if store.current().version != 5 {
		t.Fatalf("version = %d, want 5", store.current().version)
	}

	// A lower version (rolled-back / withheld Trust Authority) must be ignored.
	if store.apply(anyAllowlist(map[string]string{pushDigestC: "v3"}), 3) {
		t.Fatal("rolled-back version 3 was applied")
	}
	if store.current().version != 5 {
		t.Fatalf("version after rollback = %d, want 5 (unchanged)", store.current().version)
	}
	if admitsDigest(store, pushDigestC) {
		t.Fatal("rolled-back digest admitted")
	}
	if !admitsDigest(store, pushDigestB) {
		t.Fatal("version-5 digest dropped by rollback attempt")
	}

	// A forward version applies.
	if !store.apply(anyAllowlist(map[string]string{pushDigestC: "v6"}), 6) {
		t.Fatal("forward version 6 rejected")
	}
	if !admitsDigest(store, pushDigestC) {
		t.Fatal("forward digest not admitted")
	}
}

// After a restart the store is fresh (version 0), so it trusts the first pull it
// sees whatever its version — even one below what a prior process had applied.
// Rollback protection is per-process-lifetime; state re-syncs from the Trust Authority.
func TestPolicyStoreTrustsFirstVersionAfterRestart(t *testing.T) {
	// A prior process reached version 9.
	prior := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	prior.apply(anyAllowlist(map[string]string{pushDigestB: "v9"}), 9)

	// A restart is a brand-new store; its first apply is trusted regardless of value.
	fresh := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	if !fresh.apply(anyAllowlist(map[string]string{pushDigestC: "v3"}), 3) {
		t.Fatal("fresh store must trust the first version seen after a restart")
	}
	if fresh.current().version != 3 {
		t.Fatalf("version = %d, want 3", fresh.current().version)
	}
}

// componentContainer declares one c8s component container as a set entry
// must: a pinned command and mount set, and no capability.
func componentContainer(t *testing.T, digest, role string, argv []string) allowlist.Container {
	t.Helper()
	return allowlist.Container{
		Digest:  mustDigest(t, digest),
		Role:    role,
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: argv},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{
			Destination: "/run/c8s",
			Kind:        allowlist.MountEmptyDir,
			Source:      "c8s-run",
		}}},
	}
}

// componentDocument is a document whose one component set, version 0.43.0,
// declares containers and retires at retire when that is not nil. It is
// round-tripped through the wire form, so a test judges what a node is served.
func componentDocument(t *testing.T, retire *allowlist.Retirement, containers ...allowlist.Container) *allowlist.Allowlist {
	t.Helper()
	document := anyAllowlist(map[string]string{})
	document.Components = map[string]allowlist.ComponentSet{"0.43.0": {
		Retire:  retire,
		Entries: map[string]allowlist.Workload{"c8s-component": {Containers: containers}},
	}}
	parsed, err := allowlist.ParseJSON(canonicalBody(t, document))
	if err != nil {
		t.Fatalf("component document: %v", err)
	}
	return parsed
}

// componentLaunch is the running container componentContainer declares, with
// the mount evidence its exact policy requires.
func componentLaunch(digest string, argv []string) allowlist.RunningContainer {
	return allowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: []allowlist.ObservedMount{{
		Destination: "/run/c8s",
		Volume:      "c8s-run",
		Class:       allowlist.MountEmptyDir,
		Storage:     allowlist.MountMemory,
	}}}
}

// A role is bound by the measured base or by a component set in force, and two
// indexes binding different roles to one launch bind none of them.
func TestPolicyStoreRoleFromBaseOrSetInForce(t *testing.T) {
	argv := []string{"/usr/local/bin/c8s", "armtls-mesh"}
	launch := componentLaunch(pushDigestB, argv)
	for _, tc := range []struct {
		name string
		base string
		set  string
		want string
	}{
		{name: "set alone", set: allowlist.RoleMesh, want: allowlist.RoleMesh},
		{name: "base alone", base: allowlist.RoleMesh, want: allowlist.RoleMesh},
		{name: "both the same", base: allowlist.RoleMesh, set: allowlist.RoleMesh, want: allowlist.RoleMesh},
		{name: "disagreeing", base: allowlist.RoleCredentials, set: allowlist.RoleMesh},
		{name: "neither"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := anyAllowlist(map[string]string{})
			if tc.base != "" {
				base = roleBase(t, pushDigestB, tc.base, argv)
			}
			store := newPolicyStore(base, localClock())
			var declared []allowlist.Container
			if tc.set != "" {
				declared = append(declared, componentContainer(t, pushDigestB, tc.set, argv))
			}
			store.apply(componentDocument(t, nil, declared...), 1)
			if got := store.roleOf(launch); got != tc.want {
				t.Fatalf("role = %q, want %q", got, tc.want)
			}
		})
	}
}

// A set entry pins its mount set, so the role it binds runs where only a
// mount-pinning declaration carries one, whatever the base entry says.
func TestPolicyStoreBindsRoleMountsFromASetInForce(t *testing.T) {
	argv := []string{"/usr/local/bin/c8s", "router"}
	launch := componentLaunch(pushDigestB, argv)
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	if store.bindsRoleMounts(launch, allowlist.RoleRouter) {
		t.Fatal("a launch no index declares binds pinned mounts")
	}
	store.apply(componentDocument(t, nil, componentContainer(t, pushDigestB, allowlist.RoleRouter, argv)), 1)
	if !store.bindsRoleMounts(launch, allowlist.RoleRouter) {
		t.Fatal("the set entry pins its mounts, but the role is bound without them")
	}
}

// A set ends when Trust Authority time reaches its deadline: the kept document
// is rebuilt without it, at the same version, and what it alone admitted is
// refused.
func TestPolicyStoreEndsASetAtItsDeadline(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	store := newPolicyStore(anyAllowlist(map[string]string{}), newTAClock(func() time.Time { return taTime }))
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	argv := []string{"/usr/local/bin/c8s", "armtls-mesh"}
	store.apply(componentDocument(t, retiring, componentContainer(t, pushDigestB, allowlist.RoleMesh, argv)), 4)

	if !admitsDigest(store, pushDigestB) {
		t.Fatal("the set in force does not admit its own entry")
	}
	if store.rebuildEndedSets() {
		t.Fatal("a set in force was ended before its deadline")
	}

	taTime = deadline
	if !store.rebuildEndedSets() {
		t.Fatal("the retired set was kept in force past its deadline")
	}
	if admitsDigest(store, pushDigestB) {
		t.Fatal("the retired set still admits its entry")
	}
	if got := store.roleOf(componentLaunch(pushDigestB, argv)); got != "" {
		t.Fatalf("the retired set still binds the role %q", got)
	}
	if version := store.current().version; version != 4 {
		t.Fatalf("version = %d, want 4: ending a set rewrites no policy", version)
	}
	if store.rebuildEndedSets() {
		t.Fatal("the rebuilt snapshot reports an ended set again")
	}
}

// --- pull loop ---

// flippingHandler serves a canonical allowlist body per version as Trust Authority does,
// tagged with its digest, honoring If-None-Match with a 304. idx advances
// after each 200 so a test can script a version sequence.
type flippingHandler struct {
	mu         sync.Mutex
	versions   []string          // sequence of versions to serve
	idx        int               // current position in versions
	hits       atomic.Int32      // total requests seen
	bodyByV    map[string][]byte // canonical allowlist body per version
	statusCode int               // overrides normal logic when non-zero
}

func (f *flippingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.statusCode != 0 {
		w.WriteHeader(f.statusCode)
		return
	}

	version := f.versions[f.idx]
	etag := servedTag(f.bodyByV[version])
	w.Header().Set("ETag", etag)
	w.Header().Set(allowlist.VersionHeader, version)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(f.bodyByV[version])
	if f.idx < len(f.versions)-1 {
		f.idx++
	}
}

func TestPullLoopOnly200UpdatesIndexAndETag(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1", "2"},
		bodyByV: map[string][]byte{
			"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"})),
			"2": canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"})),
		},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var sweeps int
	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     quietPull(),
			client:   client,
			interval: 20 * time.Millisecond,
			timeout:  time.Second,
			etag:     "",
			logger:   discardLogger(),

			target: nodeTarget{
				store:       store,
				killRevoked: func(context.Context) { sweeps++ },
			},
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !admitsDigest(store, pushDigestB) {
		if time.Now().After(deadline) {
			t.Fatalf("pull loop did not pick up the second update; version=%d", store.current().version)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if store.current().version != 2 {
		t.Fatalf("applied version = %d, want 2", store.current().version)
	}

	cancel()
	<-done
	if sweeps != 2 {
		t.Fatalf("running containers rechecked %d times, want 2 (once per applied version)", sweeps)
	}
}

// datedHandler serves one document, answers 304 for it afterwards, and dates
// every reply from a clock the test moves, so the node's Trust Authority time
// follows it.
type datedHandler struct {
	body []byte

	mu   sync.Mutex
	date time.Time
}

func (h *datedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	etag := servedTag(h.body)
	w.Header().Set("ETag", etag)
	w.Header().Set(allowlist.VersionHeader, "3")
	w.Header().Set("Date", h.servedAt().UTC().Format(http.TimeFormat))
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(h.body)
}

func (h *datedHandler) servedAt() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.date
}

func (h *datedHandler) dateRepliesFrom(date time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.date = date
}

// waitFor polls until condition holds, and fails with what it was waiting for.
func waitFor(t *testing.T, condition func() bool, waited string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", waited)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A container a component set alone admits is refused within one poll of the
// set's deadline, with no new document to apply: the 304 dating the reply past
// the deadline is enough, and the running containers are rechecked.
func TestPullLoopEndsARetiredSetOnA304(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	argv := []string{"/usr/local/bin/c8s", "armtls-mesh"}
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	document := componentDocument(t, retiring, componentContainer(t, pushDigestB, allowlist.RoleMesh, argv))
	handler := &datedHandler{body: canonicalBody(t, document), date: taTime}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	var rechecks atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runPullLoop(ctx, pullLoopArgs{
		pull:     quietPull(),
		client:   allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: time.Second}),
		interval: 5 * time.Millisecond,
		timeout:  time.Second,
		logger:   discardLogger(),

		target: nodeTarget{
			store:       store,
			killRevoked: func(context.Context) { rechecks.Add(1) },
		},
	})

	waitFor(t, func() bool { return admitsDigest(store, pushDigestB) }, "the set in force to be applied")
	handler.dateRepliesFrom(deadline)
	waitFor(t, func() bool { return !admitsDigest(store, pushDigestB) }, "the retired set to end on the node")

	if version := store.current().version; version != 3 {
		t.Fatalf("version = %d, want 3: the set ended with no new document", version)
	}
	if got := rechecks.Load(); got < 2 {
		t.Fatalf("running containers rechecked %d times, want the applied pull and the ended set", got)
	}
}

// The node installs a pulled policy before it rechecks running containers.
func TestPullLoopInstallsBeforeRecheckingContainers(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"}))
	srv := httptest.NewServer(&flippingHandler{versions: []string{"7"}, bodyByV: map[string][]byte{"7": body}})
	defer srv.Close()
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "image-1"}), localClock())
	ctx, cancel := context.WithCancel(t.Context())
	rechecks := 0
	runPullLoop(ctx, pullLoopArgs{
		pull:     quietPull(),
		client:   allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
		interval: time.Millisecond,
		timeout:  time.Second,
		logger:   discardLogger(),

		target: nodeTarget{
			store: store,
			killRevoked: func(context.Context) {
				rechecks++
				if version := store.current().version; version != 7 || !admitsDigest(store, pushDigestB) {
					t.Errorf("recheck ran at version %d, want the pulled version 7 installed", version)
				}
				cancel()
			},
		},
	})

	if rechecks != 1 {
		t.Fatalf("running containers rechecked %d times, want 1", rechecks)
	}
}

// A Pod guest's pull is installed only once its runtime registered.
func TestPullLoopInstallsPodPolicyOnARegisteredRuntime(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"}))
	for _, tc := range []struct {
		name        string
		registered  bool
		wantVersion uint64
	}{
		{name: "registered runtime", registered: true, wantVersion: 2},
		{name: "unregistered runtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &flippingHandler{versions: []string{"2"}, bodyByV: map[string][]byte{"2": body}}
			ctx, cancel := context.WithCancel(t.Context())
			var bodies, conditional atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") == "" {
					bodies.Add(1)
				} else {
					conditional.Add(1)
				}
				handler.ServeHTTP(w, r)
				if handler.hits.Load() >= 3 {
					cancel()
				}
			}))
			defer srv.Close()
			p := newPodPolicyPlugin(t, tc.registered)
			runPullLoop(ctx, pullLoopArgs{
				pull:     quietPull(),
				client:   allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
				interval: time.Millisecond,
				timeout:  time.Second,
				logger:   discardLogger(),
				target:   podTarget{plugin: p},
			})

			applied := p.policy.current().pulled != nil && admitsDigest(p.policy, pushDigestB)
			if version := p.policy.current().version; applied != tc.registered || version != tc.wantVersion {
				t.Fatalf("installed %v at version %d, want %v at version %d", applied, version, tc.registered, tc.wantVersion)
			}
			if tc.registered && (bodies.Load() != 1 || conditional.Load() == 0) {
				t.Fatalf("fetched %d bodies and %d conditional polls, want one body then 304s", bodies.Load(), conditional.Load())
			}
			if !tc.registered && (bodies.Load() < 2 || conditional.Load() != 0) {
				t.Fatalf("fetched %d bodies and %d conditional polls, want the document re-fetched under no ETag", bodies.Load(), conditional.Load())
			}
		})
	}
}

func TestPullLoop304LeavesIndexUntouched(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1"},
		bodyByV:  map[string][]byte{"1": body},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	store.apply(anyAllowlist(map[string]string{pushDigestA: "image-1"}), 1)
	before := store.current()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pre-seed the loop with the matching ETag so the first tick should 304.
	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     quietPull(),
			client:   client,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     servedTag(body),
			logger:   discardLogger(),

			target: nodeTarget{
				store:       store,
				killRevoked: func(context.Context) {},
			},
		})
		close(done)
	}()

	// A few 304 ticks must not swap the snapshot.
	time.Sleep(100 * time.Millisecond)
	if store.current() != before {
		t.Fatal("304 ticks should leave the snapshot pointer unchanged")
	}

	cancel()
	<-done
}

// A 304 at a higher version keeps the index and raises the applied version,
// so a write that moved the version without changing the bytes still raises
// the version a rollback is judged against.
func TestPullLoop304RaisesAppliedVersion(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"5"},
		bodyByV:  map[string][]byte{"5": body},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	store.apply(anyAllowlist(map[string]string{pushDigestA: "image-1"}), 1)
	index := store.current().index

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     quietPull(),
			client:   client,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     servedTag(body),
			logger:   discardLogger(),

			target: nodeTarget{
				store:       store,
				killRevoked: func(context.Context) { t.Error("a 304 rechecked the running containers") },
			},
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for store.current().version != 5 {
		if time.Now().After(deadline) {
			t.Fatalf("applied version = %d after 304s at version 5, want 5", store.current().version)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if store.current().index != index {
		t.Fatal("a 304 rebuilt the index")
	}
	if !store.rolledBack(4) {
		t.Fatal("version 4 is not a rollback after the 304 at version 5")
	}

	cancel()
	<-done
}

// A 304 reaches Trust Authority, so a failure right after it is not yet a stall.
func TestPullLoop304CountsAsReachingTA(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1"},
		bodyByV:  map[string][]byte{"1": body},
	})
	defer srv.Close()

	pull, advance := testPull(discardLogger())
	advance(pullStallAfter)
	pull.failed(errors.New("lookup cds.private: no such host"))
	if pull.stall() == "" {
		t.Fatal("no stall reported for a Trust Authority the node reached nothing from")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     pull,
			client:   allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     servedTag(body),
			logger:   discardLogger(),

			target: nodeTarget{
				store:       newPolicyStore(anyAllowlist(map[string]string{}), localClock()),
				killRevoked: func(context.Context) { t.Error("a 304 rechecked the running containers") },
			},
		})
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for pull.stall() != "" {
		if time.Now().After(deadline) {
			t.Fatal("a 304 poll did not clear the stall")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done
	pull.failed(errors.New("read: connection reset by peer"))
	if stall := pull.stall(); stall != "" {
		t.Fatalf("stall = %q after a 304 reached Trust Authority, want none", stall)
	}
}

func TestPullLoop5xxLeavesIndexUntouched(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{statusCode: http.StatusInternalServerError})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	store.apply(anyAllowlist(map[string]string{pushDigestA: "image-1"}), 5)
	before := store.current()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     quietPull(),
			client:   client,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     servedTag(canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))),
			logger:   discardLogger(),

			target: nodeTarget{
				store:       store,
				killRevoked: func(context.Context) {},
			},
		})
		close(done)
	}()

	time.Sleep(80 * time.Millisecond)
	if store.current() != before {
		t.Fatal("5xx ticks should leave the snapshot pointer unchanged")
	}

	cancel()
	<-done
}

func TestPullLoopKeepsTheBaseBesidePulled(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1"},
		bodyByV:  map[string][]byte{"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "pulled-image"}))},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}), localClock())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     quietPull(),
			client:   client,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     "",
			logger:   discardLogger(),

			target: nodeTarget{
				store:       store,
				killRevoked: func(context.Context) {},
			},
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !admitsDigest(store, pushDigestB) {
		if time.Now().After(deadline) {
			t.Fatal("pull loop never delivered the pulled entry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("base entry lost after pull")
	}

	cancel()
	<-done
}

// TestPullLoopIgnoresRolledBackFetch drives the anti-rollback guard through the
// fetch path: Trust Authority serves version 5, then a withheld/rolled-back version 3. The
// loop must keep version 5 and never admit the rolled-back digest.
func TestPullLoopIgnoresRolledBackFetch(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"5", "3"},
		bodyByV: map[string][]byte{
			"5": canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "v5"})),
			"3": canonicalBody(t, anyAllowlist(map[string]string{pushDigestC: "v3"})),
		},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var sweeps int
	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:     quietPull(),
			client:   client,
			interval: 15 * time.Millisecond,
			timeout:  time.Second,
			etag:     "",
			logger:   discardLogger(),

			target: nodeTarget{
				store:       store,
				killRevoked: func(context.Context) { sweeps++ },
			},
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !admitsDigest(store, pushDigestB) {
		if time.Now().After(deadline) {
			t.Fatal("pull loop never applied version 5")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Let the loop fetch the rolled-back version 3 several times.
	time.Sleep(150 * time.Millisecond)
	if admitsDigest(store, pushDigestC) {
		t.Fatal("rolled-back version 3 digest was admitted")
	}
	if store.current().version != 5 {
		t.Fatalf("version = %d, want 5 (rollback ignored)", store.current().version)
	}

	cancel()
	<-done
	if sweeps != 1 {
		t.Fatalf("running containers rechecked %d times, want 1 (only for version 5)", sweeps)
	}
}

func TestPullInitialSucceedsAfterTransientFailures(t *testing.T) {
	orig := allowlistApiInitialDelay
	allowlistApiInitialDelay = time.Millisecond
	defer func() { allowlistApiInitialDelay = orig }()

	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "pulled-image"}))
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", servedTag(body))
		w.Header().Set(allowlist.VersionHeader, "1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}), localClock())

	pluginErrCh := make(chan error, 1)
	ctx := t.Context()

	etag, err := pullInitial(ctx, pullArgs{
		pull:        quietPull(),
		client:      client,
		target:      nodeTarget{store: store},
		timeout:     time.Second,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if etag != servedTag(body) {
		t.Fatalf("etag = %q, want %s", etag, servedTag(body))
	}
	if !admitsDigest(store, pushDigestB) {
		t.Fatal("store missing pulled entry")
	}
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("store missing base entry")
	}
}

func TestPullInitialFailsAfterMaxRetries(t *testing.T) {
	orig := allowlistApiInitialDelay
	allowlistApiInitialDelay = time.Millisecond
	defer func() { allowlistApiInitialDelay = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}), localClock())
	pluginErrCh := make(chan error, 1)
	ctx := t.Context()

	_, err := pullInitial(ctx, pullArgs{
		pull:        quietPull(),
		client:      client,
		target:      nodeTarget{store: store},
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected error after max retries against a 5xx server")
	}
	// A fetch failure must NOT look like a dead plugin: run() degrades to
	// the base allowlist on a fetch failure but stays fatal on errPluginDied.
	if errors.Is(err, errPluginDied) {
		t.Fatalf("fetch failure misclassified as errPluginDied: %v", err)
	}
	// The base allowlist still enforces after the failure.
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("base allowlist lost after failed initial pull")
	}
}

// A plugin-half death during init wraps errPluginDied so run() can treat it as
// fatal, unlike a recoverable fetch failure.
func TestPullInitialPluginDeathWrapsErrPluginDied(t *testing.T) {
	pluginErrCh := make(chan error, 1)
	pluginErrCh <- errors.New("nri socket closed")
	_, err := pullInitial(context.Background(), pullArgs{
		pull:        quietPull(),
		client:      allowlistclient.NewClientWithHTTP("https://unused", &http.Client{}),
		target:      nodeTarget{store: newPolicyStore(anyAllowlist(map[string]string{}), localClock())},
		timeout:     time.Second,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if !errors.Is(err, errPluginDied) {
		t.Fatalf("plugin death not classified as errPluginDied: %v", err)
	}
}

func TestPullInitialNotModifiedDoesNotDereferenceNilAllowlist(t *testing.T) {
	origDelay := allowlistApiInitialDelay
	origRetries := allowlistApiMaxRetries
	allowlistApiInitialDelay = time.Millisecond
	allowlistApiMaxRetries = 1
	defer func() {
		allowlistApiInitialDelay = origDelay
		allowlistApiMaxRetries = origRetries
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}), localClock())
	before := store.current()
	pluginErrCh := make(chan error, 1)
	ctx := t.Context()

	_, err := pullInitial(ctx, pullArgs{
		pull:        quietPull(),
		client:      client,
		target:      nodeTarget{store: store},
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected error for initial 304 without a pulled allowlist")
	}
	if !errors.Is(err, errInitialAllowlistNotModified) {
		t.Fatalf("expected errInitialAllowlistNotModified, got %v", err)
	}
	if store.current() != before {
		t.Fatal("initial 304 should leave the snapshot pointer unchanged")
	}
}

func TestPullInitialCancelledMidRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
	pluginErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay so we land inside the backoff sleep.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	etag, err := pullInitial(ctx, pullArgs{
		pull:        quietPull(),
		client:      client,
		target:      nodeTarget{store: store},
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation should surface context.Canceled, got err=%v", err)
	}
	if etag != "" {
		t.Fatalf("cancellation should return empty etag, got %q", etag)
	}
}

// TestParseVersion covers the counter extraction used for anti-rollback.
func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    uint64
	}{
		{"5", 5},
		{"", 0},
		{`W/"5"`, 0},
		{"not-a-number", 0},
	} {
		if got := parseVersion(tc.version); got != tc.want {
			t.Errorf("parseVersion(%q) = %d, want %d", tc.version, got, tc.want)
		}
	}
}

func servedDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// servedTag is the ETag Trust Authority serves body under.
func servedTag(body []byte) string {
	return allowlist.EntityTag(servedDigest(body))
}

// The initial pull measures the served digest before applying it, and does
// not apply a policy it could not measure.
func TestPullInitialMeasuresBeforeApplying(t *testing.T) {
	origRetries := allowlistApiMaxRetries
	allowlistApiMaxRetries = 1
	defer func() { allowlistApiMaxRetries = origRetries }()

	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
	for _, tc := range []struct {
		name        string
		measureErr  error
		measureOff  bool
		wantApplied bool
	}{
		{name: "measured", wantApplied: true},
		{name: "measure fails", measureErr: errors.New("register write failed")},
		{name: "measuring off", measureOff: true, wantApplied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(&flippingHandler{versions: []string{"1"}, bodyByV: map[string][]byte{"1": body}})
			defer srv.Close()
			store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())
			var measured []string
			measure := func(d string) error {
				if admitsDigest(store, pushDigestA) {
					t.Error("policy applied before it was measured")
				}
				measured = append(measured, d)
				return tc.measureErr
			}
			if tc.measureOff {
				measure = nil
			}
			_, err := pullInitial(t.Context(), pullArgs{
				pull:        quietPull(),
				client:      allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
				target:      nodeTarget{store: store},
				measure:     measure,
				timeout:     time.Second,
				pluginErrCh: make(chan error),
				logger:      discardLogger(),
			})
			if (err == nil) != tc.wantApplied || admitsDigest(store, pushDigestA) != tc.wantApplied {
				t.Fatalf("pullInitial = %v, applied %v, want applied %v", err, admitsDigest(store, pushDigestA), tc.wantApplied)
			}
			if !tc.measureOff && (len(measured) != 1 || measured[0] != servedDigest(body)) {
				t.Fatalf("measured %v, want the served digest %s", measured, servedDigest(body))
			}
		})
	}
}

// The pull loop skips a policy it could not measure and applies the next
// one only after measuring it.
func TestPullLoopAppliesOnlyMeasuredPolicies(t *testing.T) {
	bodyA := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
	bodyB := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"}))
	srv := httptest.NewServer(&flippingHandler{versions: []string{"1", "2"}, bodyByV: map[string][]byte{"1": bodyA, "2": bodyB}})
	defer srv.Close()
	store := newPolicyStore(anyAllowlist(map[string]string{}), localClock())

	ctx, cancel := context.WithCancel(t.Context())
	var measured []string
	measure := func(d string) error {
		measured = append(measured, d)
		if d == servedDigest(bodyA) {
			return errors.New("register write failed")
		}
		if admitsDigest(store, pushDigestA) || admitsDigest(store, pushDigestB) {
			t.Error("a policy was applied before it was measured")
		}
		cancel()
		return nil
	}
	runPullLoop(ctx, pullLoopArgs{
		pull:     quietPull(),
		client:   allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
		measure:  measure,
		interval: time.Millisecond,
		timeout:  time.Second,
		logger:   discardLogger(),

		target: nodeTarget{
			store:       store,
			killRevoked: func(context.Context) {},
		},
	})

	if want := []string{servedDigest(bodyA), servedDigest(bodyB)}; !slices.Equal(measured, want) {
		t.Fatalf("measured %v, want %v", measured, want)
	}
	if admitsDigest(store, pushDigestA) || !admitsDigest(store, pushDigestB) {
		t.Fatalf("applied A=%v B=%v, want only the measured B", admitsDigest(store, pushDigestA), admitsDigest(store, pushDigestB))
	}
}

// Measuring is off unless configured and on a platform with a runtime
// register; when it is on but cannot work, every measure fails so nothing
// unmeasured is applied.
func TestPolicyMeasurer(t *testing.T) {
	orig := readOperatorKey
	t.Cleanup(func() { readOperatorKey = orig })
	readOperatorKey = func() ([]byte, error) { return nil, fmt.Errorf("%w: test", launchbinding.ErrNoOperatorKey) }

	for _, tc := range []struct {
		name     string
		platform string
		measure  bool
		wantHook bool
	}{
		{name: "off by default", platform: "tdx"},
		{name: "no runtime register", platform: "snp", measure: true},
		{name: "on without an operator key", platform: "tdx", measure: true, wantHook: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config{
				Platform:       tc.platform,
				WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
				Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: tc.measure}},
			}
			hook := policyMeasurer(cfg, discardLogger())
			if (hook != nil) != tc.wantHook {
				t.Fatalf("policyMeasurer returned a hook: %v, want %v", hook != nil, tc.wantHook)
			}
			if hook != nil {
				if err := hook("sha256:" + strings.Repeat("1", 64)); !errors.Is(err, errPolicyRefused) {
					t.Fatalf("hook = %v, want errPolicyRefused, which keeps the policy unapplied", err)
				}
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("runtime directory holds %v, want no journal", entries)
			}
		})
	}
}

// memRegister is an in-memory RTMR[3] seeded by the launch anchor.
type memRegister struct {
	val      [runtimemeasure.Size]byte
	extends  int
	fail     error
	readFail error
}

func (r *memRegister) Extend(event []byte) error {
	if r.fail != nil {
		return r.fail
	}
	r.val = runtimemeasure.Extend(r.val, [runtimemeasure.Size]byte(event))
	r.extends++
	return nil
}

func (r *memRegister) Extension() ([]byte, error) {
	if r.readFail != nil {
		return nil, r.readFail
	}
	return slices.Clone(r.val[:]), nil
}

// The hook extends each digest once and leaves the journal readable by the
// router's non-root cds-attest, also after a failed extend rewrote it 0600.
func TestPolicyMeasurerMeasures(t *testing.T) {
	anchor := []byte("operator key")
	origKey := readOperatorKey
	origOpen := openPolicyJournal
	t.Cleanup(func() { readOperatorKey, openPolicyJournal = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return anchor, nil }

	digest := "sha256:" + strings.Repeat("1", 64)
	for _, tc := range []struct {
		name        string
		fail        error
		wantErr     bool
		wantExtends int
		wantJournal string
	}{
		{name: "extends once", wantExtends: 1, wantJournal: digest + "\n"},
		{name: "extend fails", fail: errors.New("tsm write failed"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			reg := &memRegister{val: runtimemeasure.Seed(anchor), fail: tc.fail}
			openPolicyJournal = func(runtimeDir string, _ teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
				return runtimemeasure.OpenJournalSeeded(filepath.Join(runtimeDir, armtls.MeasuredPoliciesJournal), reg, runtimemeasure.Seed(anchor))
			}
			cfg := &config{
				Platform:       "tdx",
				WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
				Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: true}},
			}
			hook := policyMeasurer(cfg, discardLogger())
			for range 2 {
				if err := hook(digest); (err != nil) != tc.wantErr {
					t.Fatalf("hook(%s) = %v, want error %v", digest, err, tc.wantErr)
				}
			}
			if reg.extends != tc.wantExtends {
				t.Errorf("register extended %d times, want %d", reg.extends, tc.wantExtends)
			}
			path := filepath.Join(dir, armtls.MeasuredPoliciesJournal)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o644 {
				t.Errorf("journal mode = %v, want 0644", perm)
			}
			if b, _ := os.ReadFile(path); string(b) != tc.wantJournal {
				t.Errorf("journal = %q, want %q", b, tc.wantJournal)
			}
		})
	}
}

// Past armtls.MaxRuntimeExtensions the hook refuses a new policy without
// extending, so the node keeps a certificate-sized history, and still accepts
// one it already measured.
func TestPolicyMeasurerStopsAtTheCap(t *testing.T) {
	anchor := []byte("operator key")
	origKey := readOperatorKey
	origOpen := openPolicyJournal
	t.Cleanup(func() { readOperatorKey, openPolicyJournal = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return anchor, nil }
	reg := &memRegister{val: runtimemeasure.Seed(anchor)}
	openPolicyJournal = func(runtimeDir string, _ teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
		return runtimemeasure.OpenJournalSeeded(filepath.Join(runtimeDir, armtls.MeasuredPoliciesJournal), reg, runtimemeasure.Seed(anchor))
	}
	cfg := &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: true}},
	}
	hook := policyMeasurer(cfg, discardLogger())
	digest := func(i int) string { return fmt.Sprintf("sha256:%064x", i) }
	for i := range armtls.MaxRuntimeExtensions {
		if err := hook(digest(i)); err != nil {
			t.Fatalf("hook(policy %d) = %v", i, err)
		}
	}
	if err := hook(digest(armtls.MaxRuntimeExtensions)); !errors.Is(err, errPolicyRefused) {
		t.Errorf("hook(policy %d) = %v, want errPolicyRefused past the cap", armtls.MaxRuntimeExtensions, err)
	}
	if err := hook(digest(0)); err != nil {
		t.Errorf("hook(measured policy 0) = %v, want nil", err)
	}
	if reg.extends != armtls.MaxRuntimeExtensions {
		t.Errorf("register extended %d times, want %d", reg.extends, armtls.MaxRuntimeExtensions)
	}
}

func TestValidateMeasurePoliciesNeedsSocketDir(t *testing.T) {
	for _, tc := range []struct {
		socketDir string
		noPull    bool
		wantErr   bool
	}{
		{socketDir: "", wantErr: true},
		{socketDir: "/run/custom-nri", wantErr: true},
		{socketDir: filepath.Dir(armtls.NodeJournal)},
		{socketDir: filepath.Dir(armtls.NodeJournal) + "/"},
		{socketDir: filepath.Dir(armtls.NodeJournal), noPull: true, wantErr: true},
	} {
		cfg := validConfig()
		cfg.Allowlist.Pull.MeasurePolicies = true
		cfg.WorkloadClaims.SocketDir = tc.socketDir
		if tc.noPull {
			cfg.Allowlist.Pull.URL = ""
		}
		if err := cfg.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("Validate() with socket_dir %q, pull %v = %v, want error %v", tc.socketDir, !tc.noPull, err, tc.wantErr)
		}
	}
}

// A version the measurer refuses for good is fetched, measured and logged
// once; later ticks get 304 and the current policy stays applied.
func TestPullLoopRefusedVersionNotRefetched(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"}))
	ctx, cancel := context.WithCancel(t.Context())
	handler := &flippingHandler{versions: []string{"2"}, bodyByV: map[string][]byte{"2": body}}
	var bodies atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == "" {
			bodies.Add(1)
		}
		handler.ServeHTTP(w, r)
		if handler.hits.Load() >= 5 {
			cancel()
		}
	}))
	defer srv.Close()
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "image-1"}), localClock())
	measures := 0
	var logs bytes.Buffer
	runPullLoop(ctx, pullLoopArgs{
		pull:   quietPull(),
		client: allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
		measure: func(string) error {
			measures++
			return fmt.Errorf("%w: cap reached", errPolicyRefused)
		},
		interval: time.Millisecond,
		timeout:  time.Second,
		logger:   slog.New(slog.NewTextHandler(&logs, nil)),

		target: nodeTarget{
			store:       store,
			killRevoked: func(context.Context) {},
		},
	})

	if measures != 1 || bodies.Load() != 1 {
		t.Errorf("measured %d times, fetched the body %d times; want 1 and 1", measures, bodies.Load())
	}
	if n := strings.Count(logs.String(), "allowlist refused"); n != 1 {
		t.Errorf("refusal logged %d times, want 1:\n%s", n, logs.String())
	}
	if !admitsDigest(store, pushDigestA) || admitsDigest(store, pushDigestB) {
		t.Errorf("applied A=%v B=%v, want the current policy A only", admitsDigest(store, pushDigestA), admitsDigest(store, pushDigestB))
	}
}

// A version the node fails to measure is retried every tick, but the failure
// is logged at Error once.
func TestPullLoopLogsMeasureFailureOnce(t *testing.T) {
	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"}))
	srv := httptest.NewServer(&flippingHandler{versions: []string{"2"}, bodyByV: map[string][]byte{"2": body}})
	defer srv.Close()
	ctx, cancel := context.WithCancel(t.Context())
	measures := 0
	var logs bytes.Buffer
	runPullLoop(ctx, pullLoopArgs{
		pull:   quietPull(),
		client: allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
		measure: func(string) error {
			if measures++; measures == 3 {
				cancel()
			}
			return errors.New("register write failed")
		},
		interval: time.Millisecond,
		timeout:  time.Second,
		logger:   slog.New(slog.NewTextHandler(&logs, nil)),

		target: nodeTarget{
			store:       newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "image-1"}), localClock()),
			killRevoked: func(context.Context) {},
		},
	})

	if measures != 3 {
		t.Errorf("measured %d times, want 3", measures)
	}
	if n := strings.Count(logs.String(), "could not measure"); n != 1 {
		t.Errorf("measure failure logged %d times at Error, want 1:\n%s", n, logs.String())
	}
}

// A transient open failure is not a refusal: the next call opens the
// journal again and measures.
func TestPolicyMeasurerRetriesOpen(t *testing.T) {
	anchor := []byte("operator key")
	origKey := readOperatorKey
	origOpen := openPolicyJournal
	t.Cleanup(func() { readOperatorKey, openPolicyJournal = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return anchor, nil }
	reg := &memRegister{val: runtimemeasure.Seed(anchor)}
	opens := 0
	openPolicyJournal = func(runtimeDir string, _ teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
		if opens++; opens <= 2 {
			return nil, errors.New("register not ready")
		}
		return runtimemeasure.OpenJournalSeeded(filepath.Join(runtimeDir, armtls.MeasuredPoliciesJournal), reg, runtimemeasure.Seed(anchor))
	}
	cfg := &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: true}},
	}
	hook := policyMeasurer(cfg, discardLogger())
	digest := "sha256:" + strings.Repeat("1", 64)
	if err := hook(digest); err == nil || errors.Is(err, errPolicyRefused) {
		t.Fatalf("hook(%s) = %v, want a retryable error", digest, err)
	}
	if err := hook(digest); err != nil {
		t.Fatalf("hook(%s) after the register came up = %v, want nil", digest, err)
	}
	if reg.extends != 1 {
		t.Errorf("register extended %d times, want 1", reg.extends)
	}
}

// A journal opened over an unreadable register is not reconciled with it, so
// the hook extends nothing and reopens it on the next call.
func TestPolicyMeasurerRetriesUnreadableRegister(t *testing.T) {
	anchor := []byte("operator key")
	origKey := readOperatorKey
	origOpen := openPolicyJournal
	t.Cleanup(func() { readOperatorKey, openPolicyJournal = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return anchor, nil }
	reg := &memRegister{val: runtimemeasure.Seed(anchor), readFail: errors.New("register unreadable")}
	openPolicyJournal = func(runtimeDir string, _ teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
		return runtimemeasure.OpenJournalSeeded(filepath.Join(runtimeDir, armtls.MeasuredPoliciesJournal), reg, runtimemeasure.Seed(anchor))
	}
	cfg := &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: true}},
	}
	hook := policyMeasurer(cfg, discardLogger())
	digest := "sha256:" + strings.Repeat("1", 64)
	if err := hook(digest); err == nil || errors.Is(err, errPolicyRefused) {
		t.Fatalf("hook(%s) over an unreadable register = %v, want a retryable error", digest, err)
	}
	if reg.extends != 0 {
		t.Fatalf("register extended %d times over an unreadable register, want 0", reg.extends)
	}
	reg.readFail = nil
	if err := hook(digest); err != nil {
		t.Fatalf("hook(%s) after the register became readable = %v, want nil", digest, err)
	}
	if reg.extends != 1 {
		t.Errorf("register extended %d times, want 1", reg.extends)
	}
}

// A platform without a runtime register is a refusal that names the cause.
func TestPolicyMeasurerNoRegister(t *testing.T) {
	origKey := readOperatorKey
	origOpen := openPolicyJournal
	t.Cleanup(func() { readOperatorKey, openPolicyJournal = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return []byte("operator key"), nil }
	openPolicyJournal = func(runtimeDir string, _ teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
		return openJournal(runtimeDir, teetypes.PlatformType("snp"), anchor)
	}
	cfg := &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: true}},
	}
	err := policyMeasurer(cfg, discardLogger())("sha256:" + strings.Repeat("1", 64))
	if !errors.Is(err, errPolicyRefused) || !errors.Is(err, runtimemeasure.ErrNoRegister) {
		t.Errorf("hook = %v, want errPolicyRefused wrapping ErrNoRegister", err)
	}
}

// A measure failure after a refusal of another digest is logged at Error
// again, even for the digest that failed before.
func TestPullLoopLogsMeasureFailureAfterRefusal(t *testing.T) {
	bodyA := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
	bodyB := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"}))
	srv := httptest.NewServer(&flippingHandler{versions: []string{"1", "2", "3"}, bodyByV: map[string][]byte{"1": bodyA, "2": bodyB, "3": bodyA}})
	defer srv.Close()
	ctx, cancel := context.WithCancel(t.Context())
	measures := 0
	var logs bytes.Buffer
	runPullLoop(ctx, pullLoopArgs{
		pull:   quietPull(),
		client: allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
		measure: func(digest string) error {
			if measures++; measures == 3 {
				cancel()
			}
			if digest == servedDigest(bodyB) {
				return fmt.Errorf("%w: cap reached", errPolicyRefused)
			}
			return errors.New("register write failed")
		},
		interval: time.Millisecond,
		timeout:  time.Second,
		logger:   slog.New(slog.NewTextHandler(&logs, nil)),

		target: nodeTarget{
			store:       newPolicyStore(anyAllowlist(map[string]string{pushDigestC: "image-3"}), localClock()),
			killRevoked: func(context.Context) {},
		},
	})

	if n := strings.Count(logs.String(), "could not measure"); n != 2 {
		t.Errorf("measure failure logged %d times at Error, want 2:\n%s", n, logs.String())
	}
}

// A register that diverged from the journal refuses every policy for good.
func TestPolicyMeasurerRefusesOnDivergedRegister(t *testing.T) {
	anchor := []byte("operator key")
	origKey := readOperatorKey
	origOpen := openPolicyJournal
	t.Cleanup(func() { readOperatorKey, openPolicyJournal = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return anchor, nil }
	reg := &memRegister{val: runtimemeasure.Seed([]byte("another key"))}
	openPolicyJournal = func(runtimeDir string, _ teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
		return runtimemeasure.OpenJournalSeeded(filepath.Join(runtimeDir, armtls.MeasuredPoliciesJournal), reg, runtimemeasure.Seed(anchor))
	}
	cfg := &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{MeasurePolicies: true}},
	}
	hook := policyMeasurer(cfg, discardLogger())
	if err := hook("sha256:" + strings.Repeat("1", 64)); !errors.Is(err, errPolicyRefused) {
		t.Errorf("hook = %v, want errPolicyRefused on a diverged register", err)
	}
	if reg.extends != 0 {
		t.Errorf("register extended %d times, want 0", reg.extends)
	}
}

// A refused initial policy ends the initial pull at once instead of retrying.
func TestPullInitialStopsOnRefusal(t *testing.T) {
	handler := &flippingHandler{versions: []string{"1"}, bodyByV: map[string][]byte{"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))}}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	_, err := pullInitial(t.Context(), pullArgs{
		pull:        quietPull(),
		client:      allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second}),
		target:      nodeTarget{store: newPolicyStore(anyAllowlist(map[string]string{}), localClock())},
		measure:     func(string) error { return fmt.Errorf("%w: cap reached", errPolicyRefused) },
		timeout:     time.Second,
		pluginErrCh: make(chan error),
		logger:      discardLogger(),
	})
	if !errors.Is(err, errPolicyRefused) || handler.hits.Load() != 1 {
		t.Fatalf("pullInitial = %v after %d fetches, want errPolicyRefused after 1", err, handler.hits.Load())
	}
}
