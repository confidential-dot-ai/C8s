//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

// TestPodProviderCloudLocalCleanup proves only that the live process stopped
// before it persisted any Cloud authority. It never reads credentials or calls
// Cloud, and cannot turn an acceptance run into a passing result.
func TestPodProviderCloudLocalCleanup(t *testing.T) {
	if os.Getenv("C8S_PODCLOUD_LIVE") != "1" {
		t.Skip("local cleanup proof requires explicit opt-in")
	}
	if err := closeCloudLocalState(os.Getenv("C8S_PODCLOUD_STATE")); err != nil {
		t.Fatal(err)
	}
}

func closeCloudLocalState(dir string) error {
	info, err := os.Lstat(dir)
	if !filepath.IsAbs(dir) || err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private state directory required")
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("live Go process still owns this state; refusing local cleanup")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, err = os.Lstat(filepath.Join(dir, "ledger.json")); !os.IsNotExist(err) {
		return errors.New("Cloud ledger exists or cannot be checked; normal cleanup required")
	}
	if _, err = os.Lstat(filepath.Join(dir, "cloud-authority-issued.json")); !os.IsNotExist(err) {
		return errors.New("Cloud authority was issued but its ledger is missing; refusing local-only cleanup")
	}
	// A delayed original process may not have reached its lock yet. This durable
	// fence makes its eventual run admission fail even after this proof exits.
	return cloudWrite(filepath.Join(dir, "closed-before-ledger.json"), map[string]bool{"localCleanup": true})
}

// TestPodProviderCloud is a separate, explicit live lane. Unlike the scheduler
// CI test, its production Setup owns real Cloud requests and TDX verification.
func TestPodProviderCloud(t *testing.T) {
	if os.Getenv("C8S_PODCLOUD_LIVE") != "1" {
		t.Skip("live Cloud lane requires explicit opt-in")
	}
	mode := os.Getenv("C8S_PODCLOUD_MODE")
	r, err := openCloudRun(os.Getenv("C8S_PODCLOUD_CONFIG"), os.Getenv("C8S_PODCLOUD_STATE"), mode)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if mode == "cleanup" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err = r.recoverUnattempted(ctx, nil); err != nil {
			t.Log("local interruption proof unavailable; cleanup will require Cloud receipts")
		}
		if err = r.cleanup(ctx); err != nil {
			t.Fatal(err)
		}
		t.Log("confirmed owned Cloud cleanup and preserved pre-existing identities")
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 140*time.Minute)
	defer cancel()
	if err = r.preflight(ctx); err != nil {
		t.Fatal(err)
	}
	var h *providerControlPlane
	accepted := false
	// Direct cleanup is the failure/resume fallback. Successful acceptance first
	// requires production finalizers and records to confirm both Pod deletions.
	defer func() {
		if h != nil && h.manager != nil {
			h.manager.stop(t)
			select {
			case <-h.manager.done:
			default:
				t.Error("provider has not stopped; retain state before cleanup")
				return
			}
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if h != nil {
			if err := r.recoverUnattempted(cleanup, h); err != nil {
				t.Log("local interruption proof unavailable; cleanup will require Cloud receipts")
			}
		}
		if err := r.cleanup(cleanup); err != nil {
			t.Errorf("owned Cloud cleanup incomplete; retain private state and rerun cleanup: %v", err)
			return
		}
		if accepted && !t.Failed() {
			if err := r.writeResult(h); err != nil {
				t.Error(err)
			}
		}
	}()
	cfg, podA, cds, err := r.bootstrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("exact paired CDS booted and its CA was attested")
	h = newProviderControlPlaneWithTimeout(t, cfg, 135*time.Minute)
	if r.cfg.scenario() == "warm-assignment" {
		if err = r.warmAssignment(ctx, t, h, cfg, podA); err != nil {
			t.Fatal(err)
		}
		accepted = true
		return
	}
	start := func() {
		h.cfg = cfg
		h.startManager(t, func(mgr ctrl.Manager, _ string) error { return Setup(mgr, cfg) })
	}
	start()
	h.installWebhooks(t)
	h.waitForVirtualNode(t)
	if err = r.submit(ctx, h, podA, cfg, "a"); err != nil {
		t.Fatal(err)
	}
	a, err := r.waitBoot(ctx, h, cfg, "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("normal scheduler bound PodA; real guest status and exact measured digests verified")
	if r.cfg.scenario() == "cds-outage" {
		if err = r.cdsOutage(ctx, h, cfg, a, cds); err != nil {
			t.Fatal(err)
		}
		h.assertKindInfrastructure(t)
		if err = r.deleteThroughProvider(ctx, h, cfg); err != nil {
			t.Fatal(err)
		}
		accepted = true
		return
	}
	if r.cfg.scenario() == "verification-timeout" {
		if err = r.verificationTimeout(ctx, t, h, cfg, a); err != nil {
			t.Fatal(err)
		}
		h.assertKindInfrastructure(t)
		if err = r.deleteThroughProvider(ctx, h, cfg); err != nil {
			t.Fatal(err)
		}
		accepted = true
		return
	}
	frozen, err := json.Marshal(a.rec.Request)
	if err != nil {
		t.Fatal(err)
	}
	podB, next, expectedPolicy, err := r.addB(ctx, cds, a.app, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.manager.stop(t)
	cfg = next
	start()
	h.waitForVirtualNode(t)
	recovered, err := r.snapshot(ctx, h, cfg, "a")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(recovered.Request)
	if !bytes.Equal(frozen, after) || recovered.InstanceID != a.rec.InstanceID {
		t.Fatal("provider restart changed A's frozen intent or Cloud identity")
	}
	if err = r.submit(ctx, h, podB, cfg, "b"); err != nil {
		t.Fatal(err)
	}
	b, err := r.waitBoot(ctx, h, cfg, "b")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("provider restart recovered A; scheduler bound B with the configured A mesh peer")
	if a.rec.InstanceID == b.rec.InstanceID || a.app == b.app {
		t.Fatal("Pod guests alias the same Cloud identity or endpoint")
	}
	if err = r.observe(ctx, h, cfg, cds, map[string]*cloudGuest{"a": a, "b": b}, expectedPolicy, t.Log); err != nil {
		t.Fatal(err)
	}
	h.assertKindInfrastructure(t)
	if err = r.deleteThroughProvider(ctx, h, cfg); err != nil {
		t.Fatal(err)
	}
	accepted = true
	t.Log("Cloud acceptance passed; production provider confirmed both Pod deletions")
}

// recoverUnattempted is read-only on Kubernetes. With the test process stopped
// and its filesystem lock held, a frozen CreateAttempted=false record (or the
// exact still-gated Pod) proves that no provider POST could have happened.
func (r *cloudRun) recoverUnattempted(ctx context.Context, h *providerControlPlane) error {
	if r.ledger.Owned["a"] == nil && r.ledger.Owned["b"] == nil {
		return nil
	}
	if h == nil {
		kubeconfig := os.Getenv("C8S_PODPROVIDER_KUBECONFIG")
		if kubeconfig == "" {
			return nil
		}
		cfg, err := LoadConfig(filepath.Join(r.dir, "provider.json"))
		if err != nil {
			return err
		}
		if cfg.ProviderID != r.ledger.Run || cfg.CloudURL != r.cfg.CloudURL || credentialHash(cfg.token) != r.ledger.CredentialHash {
			return errors.New("local provider configuration differs from cleanup authority")
		}
		rest, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return err
		}
		rest.Timeout = 5 * time.Second
		direct, err := client.New(rest, client.Options{Scheme: clientgoscheme.Scheme})
		if err != nil {
			return err
		}
		h = &providerControlPlane{cfg: cfg, client: direct}
	}
	for _, side := range []string{"a", "b"} {
		o := r.ledger.Owned[side]
		if o == nil || o.Receipt != nil || o.Terminated {
			continue
		}
		rec, err := r.snapshot(ctx, h, h.cfg, side)
		if err == nil {
			if !rec.CreateAttempted {
				o.Attempted = false
			}
			continue
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		pod := &corev1.Pod{}
		err = h.client.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "cloud-" + side}, pod)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
		if string(pod.UID) == o.UID && pod.Spec.NodeName == "" && len(pod.Spec.SchedulingGates) == 1 && pod.Spec.SchedulingGates[0].Name == "acceptance.confidential.ai/durable-intent" {
			o.Attempted = false
		}
	}
	return r.save()
}

func (r *cloudRun) submit(ctx context.Context, h *providerControlPlane, pod *corev1.Pod, cfg *Config, side string) error {
	if pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 {
		return errors.New("live Pod must enter the normal scheduler behind its intent gate")
	}
	if err := h.client.Create(ctx, pod); err != nil {
		return err
	}
	if pod.UID == "" || pod.Spec.NodeName != "" {
		return errors.New("new gated Pod identity was not assigned safely")
	}
	// Persist the exact assigned UID before allowing any Cloud side effect.
	if err := r.recordPod(pod, cfg, side); err != nil {
		return err
	}
	before := pod.DeepCopy()
	pod.Spec.SchedulingGates = nil
	return h.client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}

func (r *cloudRun) snapshot(ctx context.Context, h *providerControlPlane, cfg *Config, side string) (*record, error) {
	owned, ok := r.submittedPod(side)
	if !ok {
		return nil, errors.New("missing Pod ownership intent")
	}
	verifier := &Reconciler{client: h.client, cfg: cfg}
	rec, secret, err := verifier.loadRecord(ctx, owned.Key)
	if err != nil {
		return nil, err
	}
	if string(rec.UID) != owned.UID {
		return nil, errors.New("record UID differs from durable run intent")
	}
	if rec.Pool != nil && rec.PoolCommitted {
		p, slot, err := r.cloudPool(ctx, verifier, rec, secret)
		if err != nil {
			return nil, err
		}
		if err = r.bindCloudPod(side, owned, p, slot); err != nil {
			return nil, err
		}
		// This returned copy projects the allocation identity for observers only.
		rec.InstanceID = p.InstanceID
	}
	// Contains signed launch material. The whole run directory is private and is
	// never an upload artifact; this export survives control-plane/process loss.
	if err = cloudWrite(filepath.Join(r.dir, "record-"+side+".json"), secret); err != nil {
		return nil, err
	}
	return rec, nil
}

type cloudGuest struct {
	rec         *record
	status, app endpoint
	boot        int64
}

func (r *cloudRun) waitBoot(ctx context.Context, h *providerControlPlane, cfg *Config, side string) (*cloudGuest, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	for {
		pod, err := r.bootPod(ctx, h, cfg, side)
		if err != nil {
			return nil, err
		}
		rec, err := r.snapshot(ctx, h, cfg, side)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		}
		if rec != nil && (rec.DeleteRequested || rec.Deleted || rec.TerminalStatus != nil) {
			return nil, r.bootFailure(side, "provider record became terminal or entered deletion", pod, rec)
		}
		if err == nil && rec.InstanceID != "" {
			in, err := r.getOwned(ctx, side)
			if err != nil {
				return nil, err
			}
			if in != nil && (in.Status == "failed" || in.Status == "terminated" || in.Status == "terminating" || in.Status == "stopped" || in.Boot.Count > 1) {
				return nil, r.bootFailure(side, "Cloud guest stopped or restarted before boot acceptance", pod, rec)
			}
			if in != nil && in.Status == "running" && in.Boot.Count == 1 {
				status, e1 := cloudEndpoint(in, "pod-status")
				app, e2 := cloudEndpoint(in, "app-8080")
				if e1 == nil && e2 == nil {
					guest := &cloudGuest{rec: rec, status: status, app: app, boot: in.Boot.Count}
					raw, state, readErr := r.readStatus(ctx, guest)
					if err := r.observation("warmup-"+side, raw, nil, readErr == nil); err != nil {
						return nil, err
					}
					if readErr == nil && state.Running {
						if err = r.exactAttestation(ctx, guest); err == nil {
							pod, err := r.bootPod(ctx, h, cfg, side)
							if err != nil {
								return nil, err
							}
							if pod.Spec.NodeName != cfg.NodeName || pod.UID != rec.UID {
								return nil, errors.New("normal scheduler binding differs from provider intent")
							}
							if err = cloudWriteBytes(filepath.Join(r.dir, "boot-"+side+".json"), raw); err != nil {
								return nil, err
							}
							return guest, nil
						}
					}
				}
			}
		}
		if err := cloudPause(ctx, 10*time.Second); err != nil {
			return nil, errors.New("real Pod guest did not boot and attest before deadline")
		}
	}
}

// A submitted Pod can be preempted while Cloud is still booting. Waiting for a
// now-deleted guest to attest hides the scheduler cause and wastes the deadline.
func (r *cloudRun) bootPod(ctx context.Context, h *providerControlPlane, cfg *Config, side string) (*corev1.Pod, error) {
	owned, ok := r.submittedPod(side)
	if !ok || owned.UID == "" {
		return nil, errors.New("missing submitted Pod identity")
	}
	pod := &corev1.Pod{}
	if err := h.client.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "cloud-" + side}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, r.bootFailure(side, "submitted Pod disappeared", nil, nil)
		}
		return nil, err
	}
	reason := ""
	switch {
	case string(pod.UID) != owned.UID:
		reason = "submitted Pod UID was replaced"
	case !pod.DeletionTimestamp.IsZero():
		reason = "submitted Pod is deleting"
	case pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded:
		reason = "submitted Pod reached a terminal phase"
	case pod.Spec.NodeName != "" && pod.Spec.NodeName != cfg.NodeName:
		reason = "submitted Pod was bound to another node"
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.DisruptionTarget && condition.Status == corev1.ConditionTrue {
			reason = "submitted Pod is a disruption target"
		}
	}
	if reason != "" {
		return nil, r.bootFailure(side, reason, pod, nil)
	}
	return pod, nil
}

func (r *cloudRun) bootFailure(side, reason string, pod *corev1.Pod, rec *record) error {
	evidence := map[string]any{"side": side, "failure": reason}
	if owned, ok := r.submittedPod(side); ok {
		evidence["expectedPodUID"] = owned.UID
	}
	if pod != nil {
		evidence["podUID"], evidence["node"], evidence["phase"] = pod.UID, pod.Spec.NodeName, pod.Status.Phase
		evidence["deleting"], evidence["reason"] = !pod.DeletionTimestamp.IsZero(), truncateBootReason(pod.Status.Reason)
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.DisruptionTarget {
				evidence["disruption"] = map[string]any{"status": condition.Status, "reason": truncateBootReason(condition.Reason)}
			}
		}
	}
	if rec != nil {
		evidence["record"] = map[string]any{"uid": rec.UID, "instanceID": rec.InstanceID, "deleteRequested": rec.DeleteRequested, "deleted": rec.Deleted, "terminal": rec.TerminalStatus != nil}
	}
	return errors.Join(fmt.Errorf("Pod %s boot stopped: %s", side, reason), cloudWrite(filepath.Join(r.dir, "boot-failed-"+side+".json"), evidence))
}

func truncateBootReason(reason string) string {
	if len(reason) > 128 {
		return reason[:128]
	}
	return reason
}

func (r *cloudRun) readStatus(ctx context.Context, g *cloudGuest) ([]byte, podcvmtest.PodState, error) {
	projection, err := readGuest(ctx, g.rec, net.JoinHostPort(g.status.Host, strconv.Itoa(g.status.Port)))
	if err != nil {
		return nil, podcvmtest.PodState{}, err
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return nil, podcvmtest.PodState{}, err
	}
	if r.cfg.scenario() != "connected" {
		state, err := standaloneCloudState(projection, string(g.rec.UID))
		return raw, state, err
	}
	state, err := podcvmtest.PodStateFrom(raw, string(g.rec.UID))
	return raw, state, err
}

func (r *cloudRun) observation(name string, raw []byte, verdict any, accepted bool) error {
	return cloudWrite(filepath.Join(r.dir, name+".json"), map[string]any{"status": json.RawMessage(raw), "readiness": verdict, "authenticatedReadAccepted": accepted})
}

func (r *cloudRun) exactAttestation(ctx context.Context, g *cloudGuest) error {
	report, hc, err := podstatus.Attest(ctx, podstatus.AttestConfig{Node: net.JoinHostPort(g.status.Host, strconv.Itoa(g.status.Port)), LaunchKeyPubPath: filepath.Join(r.dir, "provider.pub"), ImageManifestPath: r.cfg.ManifestFile, ExpectDigests: []string{strings.Split(podfixture.PythonImage, "@")[1], strings.Split(r.cfg.MeshImage, "@")[1]}, Timeout: 45 * time.Second})
	if err != nil {
		return errors.New("fresh exact workload attestation failed")
	}
	hc.CloseIdleConnections()
	return cloudWrite(filepath.Join(r.dir, "attestation-"+string(g.rec.UID)+".json"), report)
}

func (r *cloudRun) leaf(ctx context.Context, g *cloudGuest, mode string) (*podcvmtest.Leaf, error) {
	raw, err := r.runTool(ctx, r.cfg.ProbeFile, "--address", net.JoinHostPort(g.app.Host, strconv.Itoa(g.app.Port)), "--ca", filepath.Join(r.dir, "mesh-ca.pem"), "--mode", mode)
	if err != nil {
		return nil, err
	}
	return podcvmtest.ParseLeaf(raw)
}

func (r *cloudRun) observe(ctx context.Context, h *providerControlPlane, cfg *Config, cds endpoint, guests map[string]*cloudGuest, expectedPolicy []byte, log func(...any)) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	ca, err := r.ca(ctx, cds)
	if err != nil {
		return err
	}
	previous := map[string]*podcvmtest.Leaf{}
	trackers := map[string]*podcvmtest.ReadinessTracker{}
	traces, kubeTraces := map[string][]bool{}, map[string][]bool{}
	rotated := map[string]bool{}
	starts := map[string]map[string]string{}
	started := time.Now()
	sample := 0
	for {
		complete := true
		evidence := map[string]any{"elapsed": time.Since(started).Seconds(), "pods": map[string]any{}}
		for _, side := range []string{"a", "b"} {
			g := guests[side]
			rec, err := r.snapshot(ctx, h, cfg, side)
			if err != nil {
				return err
			}
			if rec.InstanceID != g.rec.InstanceID {
				return errors.New("provider recovery replaced a guest")
			}
			in, err := r.getOwned(ctx, side)
			if err != nil {
				return err
			}
			if in == nil || in.Status != "running" || in.Boot.Count != g.boot {
				return errors.New("Cloud guest restarted or stopped during acceptance")
			}
			status, err := cloudEndpoint(in, "pod-status")
			if err != nil {
				return err
			}
			app, err := cloudEndpoint(in, "app-8080")
			if err != nil {
				return err
			}
			if status != g.status || app != g.app {
				return errors.New("owned Cloud endpoints changed")
			}
			raw, state, err := r.readStatus(ctx, g)
			name := fmt.Sprintf("readiness-%04d-%s", sample, side)
			if err != nil {
				return errors.Join(err, r.observation(name, raw, nil, false))
			}
			if trackers[side] == nil {
				starts[side] = state.Starts
				trackers[side] = podcvmtest.NewReadinessTracker(string(g.rec.UID), state.Starts)
			}
			traces[side] = append(traces[side], state.Ready)
			observation := trackers[side].Observe(raw, state, podcvmtest.ReadinessCycle(traces[side]))
			if err = r.observation(name, raw, observation, true); err != nil {
				return err
			}
			if !observation.Accepted {
				return errors.New(observation.Failure)
			}
			pod := &corev1.Pod{}
			if err = h.client.Get(ctx, client.ObjectKey{Namespace: g.rec.Namespace, Name: g.rec.Name}, pod); err != nil {
				return err
			}
			if !state.Complete {
				kubeTraces[side] = append(kubeTraces[side], controlPlanePodReady(pod))
			}
			leaf, err := r.leaf(ctx, g, "certless")
			if err != nil {
				return err
			}
			if leaf.Workload != "cloud-"+side || !leaf.Denied || leaf.Serial == "" || leaf.SPKI == "" {
				return errors.New("named mesh identity or certless denial missing")
			}
			if p := previous[side]; p != nil {
				renewed, err := podcvmtest.RenewalEventNamed(p, leaf, time.Since(started), "cloud-"+side)
				if err != nil {
					return err
				}
				rotated[side] = rotated[side] || renewed
			}
			previous[side] = leaf
			evidence["pods"].(map[string]any)[side] = map[string]any{"status": json.RawMessage(raw), "readiness": observation, "leaf": json.RawMessage(leaf.Raw), "kubernetesReady": controlPlanePodReady(pod)}
			complete = complete && state.Complete && state.Ready && rotated[side] && podcvmtest.ReadinessCycle(traces[side]) && podcvmtest.ReadinessCycle(kubeTraces[side])
		}
		if previous["a"].SandboxID == previous["b"].SandboxID {
			return errors.New("mesh identities alias across Pods")
		}
		if err = cloudWrite(filepath.Join(r.dir, fmt.Sprintf("sample-%04d.json", sample)), evidence); err != nil {
			return err
		}
		sample++
		if sample%10 == 0 {
			log("Cloud connected soak progressing; authenticated sample", sample)
		}
		if complete && time.Since(started) >= 65*time.Minute {
			break
		}
		if err = cloudPause(ctx, 15*time.Second); err != nil {
			return errors.New("connected checks, readiness cycle or timed renewal did not complete")
		}
	}
	for _, side := range []string{"a", "b"} {
		for _, mode := range []string{"plaintext", "certless", "wrong-ca"} {
			leaf, err := r.leaf(ctx, guests[side], mode)
			if err != nil || !leaf.Denied {
				return errors.New("negative mesh probe did not demonstrate rejection")
			}
			if err = cloudWriteBytes(filepath.Join(r.dir, side+"-negative-"+mode+".json"), leaf.Raw); err != nil {
				return err
			}
		}
	}
	// Confirm the negative probes did not perturb application health or identity.
	if err = cloudPause(ctx, 95*time.Second); err != nil {
		return err
	}
	for _, side := range []string{"a", "b"} {
		raw, state, err := r.readStatus(ctx, guests[side])
		if err != nil {
			return errors.Join(err, r.observation("final-"+side, raw, nil, false))
		}
		observation := trackers[side].Observe(raw, state, true)
		if err = r.observation("final-"+side, raw, observation, true); err != nil {
			return err
		}
		if !observation.Accepted || !state.Ready || !state.Complete || !podcvmtest.SameStarts(starts[side], state.Starts) {
			return errors.New("post-negative authenticated workload health changed")
		}
		if err = r.exactAttestation(ctx, guests[side]); err != nil {
			return err
		}
	}
	finalCA, err := r.ca(ctx, cds)
	if err != nil {
		return err
	}
	if !bytes.Equal(ca, finalCA) {
		return errors.New("CDS CA changed during acceptance")
	}
	_, policy, err := r.policy(ctx, cds)
	if err != nil {
		return err
	}
	if !bytes.Equal(policy, expectedPolicy) {
		return errors.New("CDS workload policy changed during acceptance")
	}
	return nil
}

func (r *cloudRun) deleteThroughProvider(ctx context.Context, h *providerControlPlane, cfg *Config) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	for _, side := range []string{"b", "a"} {
		o, ok := r.submittedPod(side)
		if !ok {
			continue // Single-Pod scenarios never submit the other side.
		}
		pod := &corev1.Pod{}
		if err := h.client.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "cloud-" + side}, pod); err != nil {
			return err
		}
		if string(pod.UID) != o.UID {
			return errors.New("refusing to delete a replacement Kubernetes Pod")
		}
		if err := h.client.Delete(ctx, pod, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &pod.UID}, GracePeriodSeconds: new(int64(0))}); err != nil {
			return err
		}
		for {
			rec, err := r.snapshot(ctx, h, cfg, side)
			if err != nil && !apierrors.IsNotFound(err) {
				return err
			}
			missing := apierrors.IsNotFound(err)
			p := &corev1.Pod{}
			podErr := h.client.Get(ctx, client.ObjectKey{Namespace: "tenant", Name: "cloud-" + side}, p)
			in, err := r.getOwned(ctx, side)
			if err != nil {
				return err
			}
			if missing && apierrors.IsNotFound(podErr) && in != nil && in.Status == "terminated" {
				if err = r.markTerminated(side); err != nil {
					return err
				}
				break
			}
			if rec != nil && rec.UID != types.UID(o.UID) {
				return errors.New("cleanup record UID changed")
			}
			if err = cloudPause(ctx, 5*time.Second); err != nil {
				return errors.New("provider did not confirm Cloud deletion and release its record/finalizer")
			}
		}
	}
	return nil
}
