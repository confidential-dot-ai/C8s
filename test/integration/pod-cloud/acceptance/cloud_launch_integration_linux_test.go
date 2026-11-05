//go:build linux && pod_cloud_integration

package acceptance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// newPodUID mints the Pod UID the launcher binds the guest to. No Kubernetes
// control plane assigns one here; the UID is the acceptance run's own.
func newPodUID() (types.UID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6], b[8] = (b[6]&0x0f)|0x40, (b[8]&0x3f)|0x80
	h := hex.EncodeToString(b[:])
	return types.UID(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]), nil
}

// cloudDefiniteRefusal reports a Cloud response that cannot have created
// anything. Transport errors, conflicts and server errors stay uncertain and
// keep their create attempt on the ledger for lookup recovery.
func cloudDefiniteRefusal(err error) bool {
	for _, status := range []string{"400", "401", "403", "404", "422"} {
		if strings.HasPrefix(err.Error(), "cloud returned HTTP "+status+" (") {
			return true
		}
	}
	return false
}

// preparePod freezes one side's signed launch intent under a fresh UID and
// records the ownership it implies. Nothing has reached Cloud yet.
func (r *cloudRun) preparePod(cfg *Config, pod *corev1.Pod, side string) (*record, error) {
	uid, err := newPodUID()
	if err != nil {
		return nil, err
	}
	pod.UID = uid
	req, err := cfg.launch(pod)
	if err != nil {
		return nil, err
	}
	rec := &record{Version: 1, ProviderID: cfg.ProviderID, CloudURL: cfg.CloudURL, CredentialHash: credentialHash(cfg.token), UID: pod.UID, Namespace: pod.Namespace, Name: pod.Name, Key: req.Name, Request: req, Manifest: cfg.manifest, VCPUs: cfg.VCPUs, MemoryMiB: cfg.MemoryMiB, CreatedAt: time.Now().UTC()}
	if r.cfg.scenario() == "warm-assignment" {
		rec.Allocation = "generic"
	}
	if _, err = rec.document(); err != nil {
		return nil, err
	}
	if err = r.recordPod(pod, cfg, side); err != nil {
		return nil, err
	}
	return rec, r.saveRecord(rec, side)
}

// launch creates one side's guest from its prepared record. The ledger holds
// the create attempt before the POST; a definite refusal withdraws it again.
func (r *cloudRun) launch(ctx context.Context, cfg *Config, pod *corev1.Pod, side string) (*record, error) {
	rec, err := r.preparePod(cfg, pod, side)
	if err != nil {
		return nil, err
	}
	return rec, r.create(ctx, rec, side)
}

// prepareGeneric freezes an unassigned launch and records its ownership under
// the generic handle; the warm scenario assigns a Pod to it after boot.
func (r *cloudRun) prepareGeneric(cfg *Config) (*record, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	key := identityKey(cfg.ProviderID, "generic-"+hex.EncodeToString(nonce[:]))
	req, err := cfg.genericLaunch(key)
	if err != nil {
		return nil, err
	}
	rec := &record{Version: 1, ProviderID: cfg.ProviderID, CloudURL: cfg.CloudURL, CredentialHash: credentialHash(cfg.token), Key: key, Request: req, Manifest: cfg.manifest, VCPUs: cfg.VCPUs, MemoryMiB: cfg.MemoryMiB, CreatedAt: time.Now().UTC(), Generic: true}
	if _, err = rec.document(); err != nil {
		return nil, err
	}
	if err = r.updateLedger(func(ledger *cloudLedger) error {
		if ledger.Owned["generic"] != nil {
			return errors.New("generic launch intent already exists")
		}
		ledger.Owned["generic"] = &cloudOwned{Key: key, Image: cfg.Image, LaunchKey: cfg.pub, Labels: map[string]string{"podcvm-provider": cfg.ProviderID, "podcvm-uid": strings.TrimPrefix(key, "podcvm-")}, IntentAt: rec.CreatedAt, Attempted: true}
		return nil
	}); err != nil {
		return nil, err
	}
	return rec, r.saveRecord(rec, "generic")
}

func (r *cloudRun) launchGeneric(ctx context.Context, cfg *Config) (*record, error) {
	rec, err := r.prepareGeneric(cfg)
	if err != nil {
		return nil, err
	}
	return rec, r.create(ctx, rec, "generic")
}

func (r *cloudRun) create(ctx context.Context, rec *record, handle string) error {
	owned, _, err := r.ownedSnapshot(handle)
	if err != nil {
		return err
	}
	if !owned.Attempted || owned.Key != rec.Key || owned.LaunchKey != rec.Request.Trust.LaunchKey {
		return errors.New("Cloud POST lacks its exact durable create intent")
	}
	rec.CreateAttempted = true
	if err = r.saveRecord(rec, handle); err != nil {
		return err
	}
	in, err := r.api.Create(ctx, rec.Key, rec.Request)
	if err != nil {
		if cloudDefiniteRefusal(err) {
			if saveErr := r.updateLedger(func(ledger *cloudLedger) error { ledger.Owned[handle].Attempted = false; return nil }); saveErr != nil {
				return errors.Join(err, saveErr)
			}
		}
		return err
	}
	if err = validateInstance(rec, in); err != nil {
		return err
	}
	rec.InstanceID = in.ID
	return r.saveRecord(rec, handle)
}

// Records contain signed launch material. The run directory is private and is
// never an upload artifact.
func (r *cloudRun) saveRecord(rec *record, handle string) error {
	return cloudWrite(filepath.Join(r.dir, "launch-"+handle+".json"), rec)
}

// snapshot re-reads one handle's record and checks it against the ledger's
// run authority and signed launch before any field of it is used.
func (r *cloudRun) snapshot(handle string) (*record, error) {
	raw, err := cloudPrivateRead(filepath.Join(r.dir, "launch-"+handle+".json"), 2<<20)
	if err != nil {
		return nil, err
	}
	var rec record
	if err = decode(raw, &rec); err != nil {
		return nil, errors.New("launch record is invalid")
	}
	if rec.Version != 1 || rec.ProviderID != r.ledger.Run || rec.CloudURL != r.cfg.CloudURL || rec.CredentialHash != r.ledger.CredentialHash || rec.CreatedAt.IsZero() || len(rec.Manifest) == 0 || rec.Request.Image != r.cfg.Image {
		return nil, errors.New("launch record identity or origin differs from this run")
	}
	if _, err = rec.document(); err != nil {
		return nil, err
	}
	if rec.Generic {
		if handle != "generic" || rec.Allocation != "" {
			return nil, errors.New("generic record is filed under a Pod side")
		}
		owned, _, err := r.ownedSnapshot(handle)
		if err != nil || owned.Key != rec.Key {
			return nil, errors.New("generic record differs from owned Cloud intent")
		}
		return &rec, nil
	}
	owned, ok := r.submittedPod(handle)
	if !ok || owned.UID != string(rec.UID) || owned.Key != rec.Key || identityKey(rec.ProviderID, string(rec.UID)) != rec.Key || owned.Allocation != rec.Allocation {
		return nil, errors.New("launch record differs from the durable Pod intent")
	}
	if rec.Allocation != "" {
		if rec.CreateAttempted || rec.InstanceID != "" {
			return nil, errors.New("assigned Pod record carries its own create authority")
		}
		generic, err := r.snapshot(rec.Allocation)
		if err != nil {
			return nil, err
		}
		// Observers see the assigned guest's Cloud identity through the Pod record.
		rec.InstanceID = generic.InstanceID
	}
	return &rec, nil
}

type cloudGuest struct {
	rec         *record
	status, app endpoint
	boot        int64
}

// waitBoot waits for one side's guest to run, attest and present its
// endpoints. A stopped, failed or rebooted guest ends the wait with evidence.
func (r *cloudRun) waitBoot(ctx context.Context, side string) (*cloudGuest, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	for {
		rec, err := r.snapshot(side)
		if err != nil {
			return nil, err
		}
		if !rec.CreateAttempted || rec.InstanceID == "" {
			return nil, r.bootFailure(side, "launch record holds no Cloud instance", nil, rec)
		}
		in, err := r.getOwned(ctx, side)
		if err != nil {
			return nil, err
		}
		if in != nil {
			if err = validateInstance(rec, in); err != nil {
				return nil, err
			}
			if in.Status == "failed" || in.Status == "terminated" || in.Status == "terminating" || in.Status == "stopped" || in.Boot.Count > 1 {
				return nil, r.bootFailure(side, "Cloud guest stopped or restarted before boot acceptance", in, rec)
			}
			if in.Status == "running" && in.Boot.Count == 1 {
				status, e1 := cloudEndpoint(in, "pod-status")
				app, e2 := cloudEndpoint(in, "app-8080")
				if e1 == nil && e2 == nil {
					guest := &cloudGuest{rec: rec, status: status, app: app, boot: in.Boot.Count}
					raw, state, readErr := r.readStatus(ctx, guest)
					if err := r.observation("warmup-"+side, raw, nil, readErr == nil); err != nil {
						return nil, err
					}
					if errors.Is(readErr, errGuestHistoryDoesNotReplay) {
						return nil, r.bootFailure(side, readErr.Error(), in, rec)
					}
					if readErr == nil && state.Running {
						if err = r.exactAttestation(ctx, guest); err == nil {
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

func (r *cloudRun) bootFailure(side, reason string, in *instance, rec *record) error {
	evidence := map[string]any{"side": side, "failure": reason}
	if owned, ok := r.submittedPod(side); ok {
		evidence["expectedPodUID"] = owned.UID
	}
	if in != nil {
		evidence["instance"] = map[string]any{"id": in.ID, "status": in.Status, "bootCount": in.Boot.Count}
	}
	if rec != nil {
		evidence["record"] = map[string]any{"uid": rec.UID, "key": rec.Key, "instanceID": rec.InstanceID, "createAttempted": rec.CreateAttempted}
	}
	return errors.Join(fmt.Errorf("Pod %s boot stopped: %s", side, reason), cloudWrite(filepath.Join(r.dir, "boot-failed-"+side+".json"), evidence))
}

func (r *cloudRun) readStatus(ctx context.Context, g *cloudGuest) ([]byte, PodState, error) {
	projection, err := readGuest(ctx, g.rec, net.JoinHostPort(g.status.Host, strconv.Itoa(g.status.Port)))
	if err != nil {
		return nil, PodState{}, err
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return nil, PodState{}, err
	}
	if r.cfg.scenario() != "connected" {
		state, err := standaloneCloudState(projection, string(g.rec.UID))
		return raw, state, err
	}
	state, err := PodStateFrom(raw, string(g.rec.UID))
	return raw, state, err
}

func (r *cloudRun) observation(name string, raw []byte, verdict any, accepted bool) error {
	return cloudWrite(filepath.Join(r.dir, name+".json"), map[string]any{"status": json.RawMessage(raw), "readiness": verdict, "authenticatedReadAccepted": accepted})
}

// deleteOwned ends the scenario's guests through the Cloud API, newest first,
// and records each confirmed termination before the final cleanup pass.
func (r *cloudRun) deleteOwned(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	for _, side := range []string{"b", "a"} {
		if _, ok := r.submittedPod(side); !ok {
			continue // Single-Pod scenarios never submit the other side.
		}
		if err := r.cleanupOwned(ctx, side); err != nil {
			return fmt.Errorf("owned %s deletion: %w", side, err)
		}
	}
	return nil
}
