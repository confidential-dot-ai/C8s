//go:build linux && pod_cloud_integration

package acceptance

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

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

// TestPodCloudLocalCleanup proves only that the live process stopped before
// it persisted any Cloud authority. It never reads credentials or calls Cloud,
// and cannot turn an acceptance run into a passing result.
func TestPodCloudLocalCleanup(t *testing.T) {
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

// TestPodCloud is the explicit live lane: it owns real Cloud requests, signed
// launches, guest assignment and TDX verification against production images.
func TestPodCloud(t *testing.T) {
	if os.Getenv("C8S_PODCLOUD_LIVE") != "1" {
		t.Skip("live Cloud lane requires explicit opt-in")
	}
	mode := os.Getenv("C8S_PODCLOUD_MODE")
	if err := cloudLaunchCompatibility(mode, launchconfig.SchemaVersion); err != nil {
		t.Fatal(err)
	}
	r, err := openCloudRun(os.Getenv("C8S_PODCLOUD_CONFIG"), os.Getenv("C8S_PODCLOUD_STATE"), mode)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if mode == "cleanup" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
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
	accepted := false
	// Direct cleanup is the failure/resume fallback. Successful acceptance first
	// requires the scenario's own observed deletions.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := r.cleanup(cleanup); err != nil {
			t.Errorf("owned Cloud cleanup incomplete; retain private state and rerun cleanup: %v", err)
			return
		}
		if accepted && !t.Failed() {
			if err := r.writeResult(); err != nil {
				t.Error(err)
			}
		}
	}()
	cfg, podA, cds, err := r.bootstrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("exact paired CDS booted and its CA was attested")
	if r.cfg.scenario() == "warm-assignment" {
		if err = r.warmAssignment(ctx, t, cfg, podA); err != nil {
			t.Fatal(err)
		}
		accepted = true
		return
	}
	if _, err = r.launch(ctx, cfg, podA, "a"); err != nil {
		t.Fatal(err)
	}
	a, err := r.waitBoot(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("launched PodA through Cloud; real guest status and exact measured digests verified")
	if r.cfg.cdsOutageScenario() {
		if r.cfg.scenario() == "cds-renewal-outage" {
			err = r.cdsRenewalOutage(ctx, cfg, a, cds)
		} else {
			err = r.cdsOutage(ctx, cfg, a, cds)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = r.deleteOwned(ctx); err != nil {
			t.Fatal(err)
		}
		accepted = true
		return
	}
	podB, next, expectedPolicy, err := r.addB(ctx, cds, a.app, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.launch(ctx, next, podB, "b"); err != nil {
		t.Fatal(err)
	}
	b, err := r.waitBoot(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("launched PodB with the A mesh peer in its signed document")
	if a.rec.InstanceID == b.rec.InstanceID || a.app == b.app {
		t.Fatal("Pod guests alias the same Cloud identity or endpoint")
	}
	if err = r.observe(ctx, cds, map[string]*cloudGuest{"a": a, "b": b}, expectedPolicy, t.Log); err != nil {
		t.Fatal(err)
	}
	if err = r.deleteOwned(ctx); err != nil {
		t.Fatal(err)
	}
	accepted = true
	t.Log("Cloud acceptance passed; both Pod guests were deleted through Cloud and confirmed terminated")
}

func (r *cloudRun) exactAttestation(ctx context.Context, g *cloudGuest) error {
	report, hc, err := podstatus.Attest(ctx, podstatus.AttestConfig{Node: net.JoinHostPort(g.status.Host, strconv.Itoa(g.status.Port)), LaunchKeyPubPath: filepath.Join(r.dir, "provider.pub"), ImageManifestPath: r.cfg.ManifestFile, ExpectDigests: []string{strings.Split(podfixture.Image, "@")[1], strings.Split(r.cfg.MeshImage, "@")[1]}, Timeout: 45 * time.Second})
	if err != nil {
		return errors.New("fresh exact workload attestation failed")
	}
	hc.CloseIdleConnections()
	return cloudWrite(filepath.Join(r.dir, "attestation-"+string(g.rec.UID)+".json"), report)
}

func (r *cloudRun) leaf(ctx context.Context, g *cloudGuest, mode string) (*Leaf, error) {
	raw, err := r.runTool(ctx, r.cfg.ProbeFile, "--address", net.JoinHostPort(g.app.Host, strconv.Itoa(g.app.Port)), "--ca", filepath.Join(r.dir, "mesh-ca.pem"), "--mode", mode)
	if err != nil {
		return nil, err
	}
	return ParseLeaf(raw)
}

func (r *cloudRun) observe(ctx context.Context, cds endpoint, guests map[string]*cloudGuest, expectedPolicy []byte, log func(...any)) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	ca, err := r.ca(ctx, cds)
	if err != nil {
		return err
	}
	previous := map[string]*Leaf{}
	trackers := map[string]*ReadinessTracker{}
	traces := map[string][]bool{}
	rotated := map[string]bool{}
	starts := map[string]map[string]string{}
	started := time.Now()
	sample := 0
	for {
		complete := true
		evidence := map[string]any{"elapsed": time.Since(started).Seconds(), "pods": map[string]any{}}
		for _, side := range []string{"a", "b"} {
			g := guests[side]
			rec, err := r.snapshot(side)
			if err != nil {
				return err
			}
			if rec.InstanceID != g.rec.InstanceID || rec.UID != g.rec.UID {
				return errors.New("launch record changed during acceptance")
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
				trackers[side] = NewReadinessTracker(string(g.rec.UID), state.Starts)
			}
			traces[side] = append(traces[side], state.Ready)
			observation := trackers[side].Observe(raw, state, ReadinessCycle(traces[side]))
			if err = r.observation(name, raw, observation, true); err != nil {
				return err
			}
			if !observation.Accepted {
				return errors.New(observation.Failure)
			}
			leaf, err := r.leaf(ctx, g, "certless")
			if err != nil {
				return err
			}
			if err = leaf.Accepted("cloud-"+side, acceptanceTenant); err != nil {
				return err
			}
			if p := previous[side]; p != nil {
				renewed, err := RenewalEventNamed(p, leaf, time.Since(started), "cloud-"+side)
				if err != nil {
					return err
				}
				rotated[side] = rotated[side] || renewed
			}
			previous[side] = leaf
			evidence["pods"].(map[string]any)[side] = map[string]any{"status": json.RawMessage(raw), "readiness": observation, "leaf": json.RawMessage(leaf.Raw)}
			complete = complete && state.Complete && state.Ready && rotated[side] && ReadinessCycle(traces[side])
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
			// The TLS probes observe the server leaf; plaintext sees no certificate.
			if mode != "plaintext" {
				if err = leaf.Accepted("cloud-"+side, acceptanceTenant); err != nil {
					return err
				}
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
		if !observation.Accepted || !state.Ready || !state.Complete || !SameStarts(starts[side], state.Starts) {
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
