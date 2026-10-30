// Command pod-recovery-fixture is installed only by the measured test profile.
// It owns one fixed sequence; HTTP requests can observe but never control it.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	fixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-recovery"
)

const attester = "http://127.0.0.1:8400"
const assignment = "/run/c8s-pod/assignment/accepted.json"
const history = "/run/nri-image-policy/pod-recovery/state.json"
const manifest = "/run/c8s-pod/manifests/pod.yaml"
const policy = "/etc/nri/conf.d/image-policy.yaml"

const baselineTimeout = 25 * time.Minute
const baselineGrace = 2 * time.Minute
const phaseTimeout = 7 * time.Minute
const snapshotTimeout = 4 * time.Minute
const phaseInterval = 20 * time.Second

type controller struct {
	mu      sync.RWMutex
	receipt fixture.Receipt
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, fixture.ControllerTimeout)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "recovery fixture failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	doc, err := launchconfig.LoadStaged(launchconfig.DefaultStagedPath)
	if err != nil || doc.Role != launchconfig.Pod || doc.Pod != nil {
		return errors.New("generic Pod launch required")
	}
	if _, err := credrelease.LoadMeasuredOperatorKey(ctx, attester, armtls.NodeJournal); err != nil {
		return err
	}
	// This file survives a controller process restart within this boot. A crash
	// never repeats faults or resumes a partially completed sequence.
	f, err := os.OpenFile("/run/pod-recovery-fixture/started", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	c := &controller{receipt: fixture.Receipt{Schema: 1, Scope: fixture.Scope, State: "waiting", Phases: []fixture.Phase{}}}
	api := attestclient.NewClient("")
	evidence := podstatus.Handler{Journal: armtls.NodeJournal, Evidence: func(ctx context.Context, data []byte) ([]byte, error) {
		r, err := api.GenerateEvidenceContext(ctx, attester, data)
		if err != nil {
			return nil, err
		}
		return json.Marshal(r.Envelope())
	}}
	h := c.handler(evidence)
	go c.exercise(ctx)
	return armtls.Serve(ctx, ":8444", h, &armtls.ServerConfig{Platform: "tdx", AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(api, attester), MeasuredPoliciesFile: armtls.NodeJournal})
}

func (c *controller) handler(evidence http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case podstatus.MeasurementsPath, podstatus.EvidencePath:
			evidence.ServeHTTP(w, r)
		case fixture.ReceiptPath:
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			c.mu.RLock()
			defer c.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(c.receipt)
		default:
			http.NotFound(w, r)
		}
	})
}

func (c *controller) fail(stage, reason string, before, after fixture.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.receipt.State, c.receipt.Failure = "failed", reason
	c.receipt.FailedPhase = &fixture.Phase{Name: stage, Before: before, After: after}
}
func (c *controller) exercise(ctx context.Context) {
	before, err := waitSnapshot(ctx, baselineTimeout)
	if err != nil {
		c.fail("baseline", "healthy baseline unavailable", before, fixture.Snapshot{})
		return
	}
	initial := before
	c.mu.Lock()
	c.receipt.Baseline, c.receipt.State = &initial, "baseline"
	c.mu.Unlock()
	// The runner must independently attest this baseline before any fault.
	if !wait(ctx, baselineGrace) {
		c.fail("baseline", "baseline deadline", before, fixture.Snapshot{})
		return
	}
	for _, name := range fixture.Phases {
		phase, reason := c.recoverPhase(ctx, name, before)
		if reason != "" {
			c.fail(name, reason, phase.Before, phase.After)
			return
		}
		c.mu.Lock()
		c.receipt.Phases = append(c.receipt.Phases, phase)
		c.mu.Unlock()
		before = phase.After
		if !wait(ctx, phaseInterval) {
			c.fail(name, "post-restart deadline", phase.Before, phase.After)
			return
		}
	}
	c.mu.Lock()
	c.receipt.State = "complete"
	c.mu.Unlock()
}

func (c *controller) recoverPhase(ctx context.Context, name string, before fixture.Snapshot) (fixture.Phase, string) {
	ctx, cancel := context.WithTimeout(ctx, phaseTimeout)
	defer cancel()
	phase := fixture.Phase{Name: name, Before: before}
	// The connected workload intentionally withdraws readiness for 180 seconds.
	// Wait for recovery before each fault while preserving the complete identity.
	current, err := waitSnapshot(ctx, snapshotTimeout)
	if err != nil || !reflect.DeepEqual(before, current) {
		phase.After = current
		return phase, "pre-restart snapshot changed or unavailable"
	}
	c.mu.Lock()
	c.receipt.State = "restarting"
	c.mu.Unlock()
	if err := restart(ctx, name); err != nil {
		return phase, "fixed systemd restart failed"
	}
	phase.After, err = waitSnapshot(ctx, snapshotTimeout)
	if err != nil {
		return phase, "healthy post-restart snapshot unavailable"
	}
	if fixture.ValidatePhase(phase) != nil {
		return phase, "post-restart identity or generation changed"
	}
	return phase, ""
}

func wait(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
func restart(ctx context.Context, phase string) error {
	var units []string
	switch phase {
	case "status":
		units = []string{fixture.Units[0]}
	case "kubelet":
		units = []string{fixture.Units[1]}
	case "runtime":
		units = []string{fixture.Units[2], fixture.Units[1]}
	default:
		return errors.New("unknown fixed phase")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/systemctl", append([]string{"restart"}, units...)...).Run()
}

func read(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("bounded fixture input unavailable")
	}
	return b, nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func fileHash(path string) (string, error) {
	b, err := read(path, 16<<20)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

func process(pid uint32) (fixture.Process, error) {
	raw, err := read(fmt.Sprintf("/proc/%d/stat", pid), 8192)
	if err != nil {
		return fixture.Process{}, err
	}
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 {
		return fixture.Process{}, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[i+1:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return fixture.Process{}, errors.New("process is not live")
	}
	birth, err := strconv.ParseUint(fields[19], 10, 64)
	return fixture.Process{PID: pid, Birth: birth}, err
}

func services(ctx context.Context) (map[string]fixture.Process, fixture.Process, error) {
	result := map[string]fixture.Process{}
	for _, unit := range fixture.Units {
		child, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, err := exec.CommandContext(child, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", unit).Output()
		cancel()
		if err != nil {
			return nil, fixture.Process{}, err
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
		if err != nil || pid == 0 {
			return nil, fixture.Process{}, errors.New("service has no main process")
		}
		p, err := process(uint32(pid))
		if err != nil {
			return nil, fixture.Process{}, err
		}
		result[unit] = p
	}
	raw, err := read("/sys/fs/cgroup/system.slice/podcvm-containerd.service/cgroup.procs", 8192)
	if err != nil {
		return nil, fixture.Process{}, err
	}
	var found []fixture.Process
	for _, item := range strings.Fields(string(raw)) {
		pid, err := strconv.ParseUint(item, 10, 32)
		if err != nil {
			return nil, fixture.Process{}, err
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || exe != "/opt/nri/plugins/10-nri-image-policy" {
			continue
		}
		p, err := process(uint32(pid))
		if err != nil {
			return nil, fixture.Process{}, err
		}
		found = append(found, p)
	}
	if len(found) != 1 {
		return nil, fixture.Process{}, errors.New("expected one actual NRI process")
	}
	return result, found[0], nil
}

// Trust only the bounded root-owned kubelet leaf. Its SAN may name the node
// instead of loopback, so verify that trusted identity while dialing 127.0.0.1.
func kubeletTLSConfig(raw []byte) (*tls.Config, error) {
	if len(raw) > 64<<10 {
		return nil, errors.New("kubelet certificate exceeds limit")
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("kubelet certificate unavailable")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	names := append([]string{"127.0.0.1"}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	serverName := ""
	for _, name := range names {
		if name != "" && !strings.Contains(name, "*") && cert.VerifyHostname(name) == nil {
			serverName = name
			break
		}
	}
	if serverName == "" {
		return nil, errors.New("kubelet certificate has no usable identity")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, cert.Raw) {
				return errors.New("kubelet certificate differs")
			}
			return nil
		},
	}, nil
}

func pod(ctx context.Context, uid string) (*corev1.Pod, error) {
	raw, err := read(podstatus.KubeletCertPath, 64<<10)
	if err != nil {
		return nil, err
	}
	config, err := kubeletTLSConfig(raw)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:10250/pods", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("kubelet unavailable")
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var list corev1.PodList
	if json.Unmarshal(raw, &list) != nil || len(list.Items) != 1 {
		return nil, errors.New("expected one runtime Pod")
	}
	p := &list.Items[0]
	projection, err := json.Marshal(podstatus.ProjectPod(p))
	if err != nil {
		return nil, err
	}
	state, err := podcvmtest.PodStateFrom(projection, uid)
	if err != nil || !fixture.LiveWorkload(state) {
		return nil, errors.New("assigned workload is not healthy and running")
	}
	return p, nil
}

func snapshot(ctx context.Context) (fixture.Snapshot, error) {
	s := fixture.Snapshot{}
	raw, err := read(assignment, 4<<20)
	if err != nil {
		return s, err
	}
	var accepted struct {
		Request json.RawMessage `json:"request"`
	}
	if json.Unmarshal(raw, &accepted) != nil {
		return s, errors.New("invalid accepted assignment")
	}
	req, err := podassign.Decode(accepted.Request)
	if err != nil {
		return s, err
	}
	assigned, err := launchconfig.ParsePodManifest(req.Manifest)
	if err != nil {
		return s, err
	}
	s.AssignedUID, s.AssignmentSHA256, s.RequestSHA256 = string(assigned.UID), digest(raw), digest(accepted.Request)
	p, err := pod(ctx, s.AssignedUID)
	if err != nil {
		return s, err
	}
	s.RuntimeUID = string(p.UID)
	boot, err := read("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return s, err
	}
	s.KernelBootID = strings.TrimSpace(string(boot))
	for _, pair := range []struct {
		path string
		out  *string
	}{{policy, &s.ConfigSHA256}, {manifest, &s.ManifestSHA256}, {armtls.NodeJournal, &s.JournalSHA256}} {
		*pair.out, err = fileHash(pair.path)
		if err != nil {
			return s, err
		}
	}
	raw, err = read(history, 16<<20)
	if err != nil {
		return s, err
	}
	var state struct {
		KernelBootID string                   `json:"kernelBootID"`
		BootID       string                   `json:"bootID"`
		Terminal     string                   `json:"terminal"`
		Sandbox      struct{ ID, UID string } `json:"sandbox"`
		Processes    map[string]struct {
			PID     uint32 `json:"pid"`
			Birth   uint64 `json:"birth"`
			Name    string `json:"name"`
			Removed bool   `json:"removed"`
		} `json:"processes"`
	}
	if json.Unmarshal(raw, &state) != nil || state.Terminal != "" || state.KernelBootID != s.KernelBootID || state.Sandbox.UID != s.RuntimeUID {
		return s, errors.New("retained history does not identify this live boot")
	}
	s.CredentialID = (workloadclaims.PodClaims{BootID: state.BootID, RuntimePodUID: state.Sandbox.UID, SandboxID: state.Sandbox.ID}).InstanceID()
	s.Tasks = map[string]fixture.Process{}
	names := map[string]bool{}
	for id, known := range state.Processes {
		if known.Removed || (known.Name != "app" && known.Name != "checker" && known.Name != workloadclaims.MeshContainerName) {
			continue
		}
		if names[known.Name] {
			return s, errors.New("duplicate retained workload task")
		}
		names[known.Name] = true
		current, err := process(known.PID)
		if err != nil || current.Birth != known.Birth {
			return s, errors.New("retained task process changed")
		}
		ids, err := workloadclaims.ContainerIDCandidatesForPID("/proc", int(known.PID))
		if err != nil || !slices.Contains(ids, id) {
			return s, errors.New("task cgroup differs from retained container")
		}
		s.Tasks[id] = current
	}
	s.HistorySHA256, err = stableHistory(raw)
	if err != nil {
		return s, err
	}
	s.Services, s.NRI, err = services(ctx)
	if err != nil {
		return s, err
	}
	return s, s.Validate()
}

func waitSnapshot(ctx context.Context, limit time.Duration) (fixture.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		s, err := snapshot(ctx)
		if err == nil {
			return s, nil
		}
		if !wait(ctx, 2*time.Second) {
			return s, err
		}
	}
}

func stableHistory(raw []byte) (string, error) {
	var stable map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stable); err != nil {
		return "", err
	}
	// Only the admission revision may advance. Retain the authenticated policy.
	delete(stable, "revision")
	canonical, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	return digest(canonical), nil
}
