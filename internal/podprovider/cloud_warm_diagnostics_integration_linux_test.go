//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

// This test-only reader uses the same verifier, frozen trust, strict projection
// and budgets as readGuest. Detailed errors go only to private evidence; the
// provider receives the same redacted errors. It performs no diagnostic retry.
func cloudReadGuest(ctx context.Context, rec *record, address string, get func(context.Context, podstatus.AttestConfig) ([]byte, error)) (podstatus.PodProjection, error, error) {
	var projection podstatus.PodProjection
	dir, err := os.MkdirTemp("", "c8s-pod-status-")
	if err != nil {
		return projection, err, err
	}
	defer os.RemoveAll(dir)
	key, manifest := filepath.Join(dir, "pubkey"), filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(key, []byte(rec.Request.Trust.LaunchKey), 0600); err != nil {
		return projection, err, err
	}
	if err := os.WriteFile(manifest, rec.Manifest, 0600); err != nil {
		return projection, err, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	data, err := get(ctx, podstatus.AttestConfig{Node: address, LaunchKeyPubPath: key, ImageManifestPath: manifest, Timeout: 15 * time.Second})
	if err != nil {
		return projection, errors.New("guest status attestation unavailable"), err
	}
	if err := decode(data, &projection); err != nil {
		return projection, errors.New("guest status projection is invalid"), err
	}
	return projection, nil, nil
}

type cloudWarmCloudObservation struct {
	StartedAt       time.Time  `json:"startedAt"`
	FinishedAt      time.Time  `json:"finishedAt"`
	InstanceID      string     `json:"instanceID"`
	Status          string     `json:"status"`
	BootCount       int64      `json:"bootCount"`
	IngressUpdating bool       `json:"ingressUpdating"`
	Ingress         []ingress  `json:"ingress"`
	Endpoints       []endpoint `json:"endpoints"`
}

type cloudWarmReadObservation struct {
	Sequence       int                        `json:"sequence"`
	StartedAt      time.Time                  `json:"startedAt"`
	FinishedAt     time.Time                  `json:"finishedAt"`
	Deadline       *time.Time                 `json:"verificationDeadline,omitempty"`
	BeforeDeadline bool                       `json:"completedBeforeDeadline"`
	PodUID         string                     `json:"podUID"`
	Allocation     string                     `json:"allocation"`
	InstanceID     string                     `json:"instanceID"`
	Address        string                     `json:"address"`
	Accepted       bool                       `json:"authenticatedReadAccepted"`
	Detail         string                     `json:"detail,omitempty"`
	Cloud          *cloudWarmCloudObservation `json:"cloudObservation,omitempty"`
}

type cloudWarmDiagnostics struct {
	mu       sync.Mutex
	cloud    map[string]cloudWarmCloudObservation
	sequence int
	last     time.Time
	err      error
}

// Observe only the exact-owned GET the provider already made. Its independent
// times prevent a cached Cloud observation being mistaken for a simultaneous one.
func (d *cloudWarmDiagnostics) observeCloud(start, end time.Time, in *instance) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cloud == nil {
		d.cloud = make(map[string]cloudWarmCloudObservation)
	}
	if _, exists := d.cloud[in.ID]; !exists && len(d.cloud) >= 3 {
		d.err = errors.New("warm diagnostic Cloud identity budget exceeded")
		return
	}
	if len(in.Network.Ingress) > 16 || len(in.Endpoints) > 16 || len(in.Status) > 64 {
		d.err = errors.New("warm diagnostic Cloud observation exceeds bounds")
		return
	}
	for _, rule := range in.Network.Ingress {
		if len(rule.Name) > 64 {
			d.err = errors.New("warm diagnostic ingress exceeds bounds")
			return
		}
	}
	for _, endpoint := range in.Endpoints {
		if len(endpoint.Name) > 64 || len(endpoint.Host) > 256 {
			d.err = errors.New("warm diagnostic endpoint exceeds bounds")
			return
		}
	}
	d.cloud[in.ID] = cloudWarmCloudObservation{StartedAt: start.UTC(), FinishedAt: end.UTC(), InstanceID: in.ID, Status: in.Status, BootCount: in.Boot.Count,
		IngressUpdating: in.Network.IngressUpdating, Ingress: slices.Clone(in.Network.Ingress), Endpoints: slices.Clone(in.Endpoints)}
}

var cloudDiagnosticPEM = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?(-----END [^-]+-----|$)`)
var cloudDiagnosticBearer = regexp.MustCompile(`(?i)bearer\s+[^\s"']+`)

func cloudDiagnosticDetail(err error, token string) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if token != "" {
		message = strings.ReplaceAll(message, token, "[credential redacted]")
	}
	message = cloudDiagnosticPEM.ReplaceAllString(message, "[PEM redacted]")
	message = cloudDiagnosticBearer.ReplaceAllString(message, "[credential redacted]")
	if len(message) > 2048 {
		message = message[:2048]
	}
	return strings.ToValidUTF8(message, "?")
}

func (o *cloudAssignmentObserver) observeRead(rec *record, address string, start, end time.Time, accepted bool, detail error) {
	if rec.Pool == nil || o.posts.Load() == 0 {
		return
	}
	d := &o.diagnostics
	d.mu.Lock()
	defer d.mu.Unlock()
	// Retain the first three observations and a ring of the latest 21 sampled
	// observations. Long stalls cannot erase initial evidence or exhaust a cap.
	if d.sequence >= 3 && end.Sub(d.last) < 20*time.Second {
		return
	}
	pod, ok := o.run.submittedPod("a")
	owned, _, err := o.run.ownedSnapshot("a")
	if !ok || pod.UID != string(rec.UID) || err != nil || owned.Receipt == nil || owned.SlotUID != string(rec.Pool.UID) {
		d.err = errors.New("warm diagnostic lost exact submitted Pod ownership")
		return
	}
	d.sequence++
	d.last = end
	name := fmt.Sprintf("warm-read-first-%02d.json", d.sequence)
	if d.sequence > 3 {
		name = fmt.Sprintf("warm-read-latest-%02d.json", (d.sequence-4)%21)
	}
	observation := cloudWarmReadObservation{Sequence: d.sequence, StartedAt: start.UTC(), FinishedAt: end.UTC(), Deadline: rec.VerificationDeadline,
		BeforeDeadline: rec.VerificationDeadline == nil || end.Before(*rec.VerificationDeadline), PodUID: string(rec.UID), Allocation: pod.Allocation,
		InstanceID: owned.Receipt.ID, Address: address, Accepted: accepted, Detail: cloudDiagnosticDetail(detail, o.reader.cfg.token)}
	if cached, exists := d.cloud[owned.Receipt.ID]; exists {
		observation.Cloud = &cached
	}
	if err := cloudWrite(filepath.Join(o.run.dir, name), observation); err != nil {
		d.err = errors.New("write private warm status diagnostic failed")
	}
}

func (d *cloudWarmDiagnostics) failure() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}
