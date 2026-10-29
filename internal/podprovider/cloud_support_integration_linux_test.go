//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// The live lane deliberately accepts only a trusted local input file. Credentials
// never enter argv, evidence, test logs, Kubernetes tenant objects or CI artifacts.
type cloudRunConfig struct {
	Scenario       string `json:"scenario,omitempty"`
	Source         string `json:"source"`
	CloudURL       string `json:"cloudURL"`
	TokenFile      string `json:"tokenFile"`
	Image          string `json:"image"`
	CDSImage       string `json:"cdsImage"`
	ManifestFile   string `json:"manifestFile"`
	ManifestDigest string `json:"manifestDigest"`
	DiskDigest     string `json:"diskDigest"`
	CLIFile        string `json:"cliFile"`
	CLISHA256      string `json:"cliSHA256"`
	ProbeFile      string `json:"probeFile"`
	ProbeSHA256    string `json:"probeSHA256"`
	MeshImage      string `json:"meshImage"`
	Size           string `json:"size"`
	Location       string `json:"location"`
	VCPUs          int64  `json:"vCPUs"`
	MemoryMiB      int64  `json:"memoryMiB"`
}

type cloudReceipt struct {
	ID          string                                           `json:"id"`
	Name        string                                           `json:"name"`
	CreatedAt   time.Time                                        `json:"createdAt"`
	Tee         string                                           `json:"tee"`
	Size        string                                           `json:"size"`
	Location    string                                           `json:"location"`
	Labels      map[string]string                                `json:"labels"`
	Image       struct{ Family, Version, Digest, Launch string } `json:"image"`
	Attestation struct {
		ReferenceManifest struct {
			Digest string `json:"digest"`
		} `json:"referenceManifest"`
		LaunchBinding struct {
			SHA256 string `json:"sha256"`
		} `json:"launchBinding"`
	} `json:"attestation"`
}

type cloudPodIntent struct {
	UID        string `json:"uid"`
	Key        string `json:"key"`
	Allocation string `json:"allocation,omitempty"`
}

type cloudOwned struct {
	Key         string            `json:"key"`
	UID         string            `json:"uid,omitempty"`
	Image       string            `json:"image"`
	LaunchKey   string            `json:"launchKey"`
	Labels      map[string]string `json:"labels"`
	IntentAt    time.Time         `json:"intentAt"`
	Attempted   bool              `json:"attempted"`
	Receipt     *cloudReceipt     `json:"receipt,omitempty"`
	Terminated  bool              `json:"terminated,omitempty"`
	SlotName    string            `json:"slotName,omitempty"`
	SlotUID     string            `json:"slotUID,omitempty"`
	RequestHash string            `json:"requestHash,omitempty"`
}

type cloudLedger struct {
	Version        int                       `json:"version"`
	Run            string                    `json:"run"`
	Config         cloudRunConfig            `json:"config"`
	CredentialHash string                    `json:"credentialHash"`
	Before         map[string]cloudReceipt   `json:"before"`
	Owned          map[string]*cloudOwned    `json:"owned"`
	Pods           map[string]cloudPodIntent `json:"pods,omitempty"`
	Complete       bool                      `json:"complete"`
}

type cloudRun struct {
	dir           string
	cfg           cloudRunConfig
	api           *cloudClient
	ledgerMu      sync.Mutex
	ledger        cloudLedger
	lock          *os.File
	cleanupBudget time.Duration // Test-only shortening of the per-instance wait; never a live input.
	toolFailures  int
}

var cloudHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var cloudVersion = regexp.MustCompile(`^c8s-pod@[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[1-9][0-9]*$`)

func cloudHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func cloudPrivateRead(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("private regular input file required")
	}
	return os.ReadFile(path)
}

func cloudWrite(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return cloudWriteBytes(path, data)
}

func cloudWriteBytes(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func (r *cloudRun) save() error {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	return r.saveLocked(r.ledger)
}

func (r *cloudRun) saveLocked(ledger cloudLedger) error {
	marker := filepath.Join(r.dir, "cloud-authority-issued.json")
	if _, err := os.Lstat(marker); os.IsNotExist(err) {
		if err = cloudWrite(marker, map[string]string{"run": ledger.Run}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return cloudWrite(filepath.Join(r.dir, "ledger.json"), ledger)
}

func openCloudRun(config, dir, mode string) (*cloudRun, error) {
	if os.Getenv("C8S_PODCLOUD_LIVE") != "1" || !filepath.IsAbs(dir) || !filepath.IsAbs(config) || (mode != "run" && mode != "cleanup") {
		return nil, errors.New("explicit live opt-in, absolute config/state paths and run|cleanup mode required")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("existing private state directory required")
	}
	raw, err := cloudPrivateRead(config, 1<<20)
	if err != nil {
		return nil, err
	}
	r := &cloudRun{dir: dir}
	if err = decode(raw, &r.cfg); err != nil {
		return nil, errors.New("invalid live input configuration")
	}
	if err = r.cfg.validate(mode == "run"); err != nil {
		return nil, err
	}
	token, err := cloudPrivateRead(r.cfg.TokenFile, 16<<10)
	if err != nil {
		return nil, err
	}
	token = bytes.TrimSpace(token)
	if len(token) == 0 || bytes.ContainsAny(token, "\r\n\t ") {
		return nil, errors.New("invalid Cloud credential file")
	}
	r.api = newCloudClient(&Config{CloudURL: r.cfg.CloudURL, token: string(token)})
	r.lock, err = os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(r.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		r.lock.Close()
		return nil, errors.New("another live run or cleanup holds this state directory")
	}
	if mode == "run" {
		if _, closed := os.Lstat(filepath.Join(dir, "closed-before-ledger.json")); !os.IsNotExist(closed) {
			r.close()
			return nil, errors.New("local cleanup permanently closed this run before Cloud admission")
		}
	}
	path := filepath.Join(dir, "ledger.json")
	if mode == "cleanup" {
		raw, err = cloudPrivateRead(path, 8<<20)
		if err == nil {
			err = decode(raw, &r.ledger)
		}
		if err == nil && (r.ledger.Version != 1 || r.ledger.Config != r.cfg || r.ledger.CredentialHash != credentialHash(string(token)) || r.ledger.Before == nil || r.ledger.Owned == nil || !regexp.MustCompile(`^pcvm-[0-9a-f]{24}$`).MatchString(r.ledger.Run)) {
			err = errors.New("cleanup ledger/config/credential binding differs")
		}
	} else {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			err = errors.New("run requires fresh state; use cleanup for an existing ledger")
		} else {
			var nonce [12]byte
			_, err = rand.Read(nonce[:])
			r.ledger = cloudLedger{Version: 1, Run: "pcvm-" + hex.EncodeToString(nonce[:]), Config: r.cfg, CredentialHash: credentialHash(string(token)), Before: map[string]cloudReceipt{}, Owned: map[string]*cloudOwned{}}
		}
	}
	if err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

func (r *cloudRun) close() {
	if r.lock != nil {
		_ = syscall.Flock(int(r.lock.Fd()), syscall.LOCK_UN)
		_ = r.lock.Close()
	}
}

// Keep the stored zero value unchanged so historical cleanup ledgers still match.
func (c cloudRunConfig) scenario() string {
	if c.Scenario == "" {
		return "connected"
	}
	return c.Scenario
}

func (c cloudRunConfig) instanceCount() int64 {
	if c.scenario() == "verification-timeout" {
		return 2 // CDS and one Pod guest.
	}
	return 3
}

func (c cloudRunConfig) validate(artifacts bool) error {
	if c.scenario() != "connected" && c.scenario() != "verification-timeout" && c.scenario() != "warm-assignment" {
		return errors.New("unknown live Cloud acceptance scenario")
	}
	if c.CloudURL != "https://api.cloud.confidential.ai" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(c.Source) || !cloudVersion.MatchString(c.Image) || c.CDSImage != strings.Replace(c.Image, "c8s-pod@", "c8s-pod-cds@", 1) {
		return errors.New("exact source and paired production catalog versions required")
	}
	if !cloudHex.MatchString(strings.TrimPrefix(c.ManifestDigest, "sha256:")) || !strings.HasPrefix(c.ManifestDigest, "sha256:") || !cloudHex.MatchString(strings.TrimPrefix(c.DiskDigest, "sha256:")) || !strings.HasPrefix(c.DiskDigest, "sha256:") || !regexp.MustCompile(`^ghcr\.io/confidential-dot-ai/armtls-mesh@sha256:[0-9a-f]{64}$`).MatchString(c.MeshImage) {
		return errors.New("exact production image digests required")
	}
	if c.VCPUs < 2 || c.VCPUs > 16 || c.MemoryMiB < 8192 || c.MemoryMiB > 65536 || c.Size == "" || c.Location == "" {
		return errors.New("bounded explicit Cloud shape required")
	}
	if !filepath.IsAbs(c.TokenFile) {
		return errors.New("absolute credential file required")
	}
	// Resuming deletion does not depend on the availability of the old CLI or
	// guest manifest; its authority is the immutable ledger plus original key.
	if !artifacts {
		return nil
	}
	for _, pin := range []struct {
		path, hash string
		limit      int64
	}{{c.ManifestFile, strings.TrimPrefix(c.ManifestDigest, "sha256:"), 1 << 20}, {c.CLIFile, c.CLISHA256, 512 << 20}, {c.ProbeFile, c.ProbeSHA256, 128 << 20}} {
		if !filepath.IsAbs(pin.path) || !cloudHex.MatchString(pin.hash) {
			return errors.New("absolute pinned executable/manifest required")
		}
		data, err := cloudPrivateRead(pin.path, pin.limit)
		if err != nil {
			return err
		}
		if cloudHash(data) != pin.hash {
			return errors.New("local artifact does not match its trusted digest")
		}
	}
	image, err := launchconfig.ImageFromManifest(c.ManifestFile, 0)
	if err != nil || image.Platform != "tdx" {
		return errors.New("valid TDX production manifest required")
	}
	var manifest struct {
		Outputs struct {
			Disk struct {
				SHA256 string `json:"sha256"`
			} `json:"disk_image"`
		} `json:"outputs"`
	}
	raw, err := os.ReadFile(c.ManifestFile)
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &manifest) != nil || "sha256:"+manifest.Outputs.Disk.SHA256 != c.DiskDigest {
		return errors.New("manifest disk digest differs from catalog input")
	}
	return nil
}

// runTool drops inherited credentials and never prints subprocess output or argv.
func (r *cloudRun) runTool(ctx context.Context, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TMPDIR=" + r.dir}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var out, diagnostic cloudOutput
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		operation := "command"
		if len(args) > 0 && regexp.MustCompile(`^[a-z-]{1,32}$`).MatchString(args[0]) {
			operation = args[0]
		}
		failure := fmt.Errorf("paired %s %s command failed", filepath.Base(executable), operation)
		if r.toolFailures < 100 {
			r.toolFailures++
			stderr := diagnostic.Bytes()
			if len(stderr) > 16<<10 {
				stderr = stderr[len(stderr)-(16<<10):]
			}
			// Private diagnostics never enter test output or uploaded artifacts. No argv,
			// environment or stdout is retained; stderr is bounded even for a bad CLI.
			path := filepath.Join(r.dir, fmt.Sprintf("cli-failure-%03d.json", r.toolFailures))
			err = cloudWrite(path, map[string]any{"executable": filepath.Base(executable), "operation": operation, "stderr": string(stderr), "timedOut": ctx.Err() != nil})
			return nil, errors.Join(failure, err)
		}
		return nil, failure
	}
	return out.Bytes(), nil
}

type cloudOutput struct{ bytes.Buffer }

func (b *cloudOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2<<20 {
		return 0, errors.New("command output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func (r *cloudRun) items(ctx context.Context, resource string) ([]json.RawMessage, error) {
	var result []json.RawMessage
	next := ""
	seen := map[string]bool{}
	for range 20 {
		path := "/v1/" + resource + "?pageSize=100"
		if next != "" {
			path += "&pageToken=" + url.QueryEscape(next)
		}
		var page struct {
			Items []json.RawMessage `json:"items"`
			Next  string            `json:"nextPageToken"`
		}
		if err := r.api.do(ctx, http.MethodGet, path, "", nil, &page); err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if page.Next == "" {
			return result, nil
		}
		if seen[page.Next] {
			return nil, errors.New("Cloud pagination loop")
		}
		seen[page.Next] = true
		next = page.Next
	}
	return nil, errors.New("Cloud inventory exceeds bounded pagination")
}

func (r *cloudRun) preflight(ctx context.Context) error {
	images, err := r.items(ctx, "images")
	if err != nil {
		return err
	}
	for _, want := range []string{r.cfg.Image, r.cfg.CDSImage} {
		matches := 0
		for _, raw := range images {
			var item struct {
				Family, Version, Status string
				Launch                  struct {
					Access                                  string
					InitDataFormats                         []string
					UserData, Containers, AttestationPublic bool
					AttestationPort, MinMemoryGiB           int
					Readiness                               struct{ TCPPorts []int }
					Disks                                   []struct {
						Name, Type, Encryption string
						Required               bool
						MinSizeGiB             int
					}
				}
				Artifacts []struct {
					Tee, Digest       string
					Sizes             []string
					ReferenceManifest struct{ Digest string }
				}
			}
			if json.Unmarshal(raw, &item) != nil {
				return errors.New("invalid catalog response")
			}
			if item.Family+"@"+item.Version != want {
				continue
			}
			matches++
			l := item.Launch
			if item.Status != "active" || l.Access != "launchKey" || !slices.Equal(l.InitDataFormats, []string{"c8s-launch/v1"}) || l.UserData || l.Containers || l.AttestationPublic || l.AttestationPort != 8443 || l.MinMemoryGiB != 8 || len(l.Readiness.TCPPorts) != 0 {
				return errors.New("catalog launch contract differs")
			}
			artifacts := 0
			for _, a := range item.Artifacts {
				if a.Tee == "tdx" {
					artifacts++
					if a.Digest != r.cfg.DiskDigest || a.ReferenceManifest.Digest != r.cfg.ManifestDigest || !slices.Contains(a.Sizes, r.cfg.Size) {
						return errors.New("catalog does not admit the exact paired artifact and size")
					}
				}
			}
			if artifacts != 1 {
				return errors.New("catalog TDX artifact is ambiguous")
			}
			cds := want == r.cfg.CDSImage
			if len(l.Disks) != 2 || l.Disks[0].Name != "data" || l.Disks[0].Type != "scratch" || l.Disks[0].Encryption != "guest" || l.Disks[0].Required != cds || l.Disks[1].Name != "containerd" || l.Disks[1].Required {
				return errors.New("catalog scratch contract differs")
			}
			minimum := 1
			if cds {
				minimum = 64
			}
			if l.Disks[0].MinSizeGiB != minimum {
				return errors.New("catalog scratch size differs")
			}
		}
		if matches != 1 {
			return errors.New("paired Cloud catalog version is not admitted")
		}
	}
	var limits struct {
		Caller struct {
			Instances, VCPUs *struct {
				Limit *int64
				InUse int64
			}
			Sizes, Locations *struct{ Allowed []string }
		}
	}
	if err = r.api.do(ctx, http.MethodGet, "/v1/limits", "", nil, &limits); err != nil {
		return err
	}
	for _, q := range []struct {
		limit *struct {
			Limit *int64
			InUse int64
		}
		need int64
	}{{limits.Caller.Instances, r.cfg.instanceCount()}, {limits.Caller.VCPUs, r.cfg.instanceCount() * r.cfg.VCPUs}} {
		if q.limit != nil && q.limit.Limit != nil && *q.limit.Limit-q.limit.InUse < q.need {
			return errors.New("credential lacks capacity for the selected scenario")
		}
	}
	if limits.Caller.Sizes != nil && !slices.Contains(limits.Caller.Sizes.Allowed, r.cfg.Size) || limits.Caller.Locations != nil && !slices.Contains(limits.Caller.Locations.Allowed, r.cfg.Location) {
		return errors.New("credential shape/location limits exclude the run")
	}
	sizes, err := r.items(ctx, "sizes")
	if err != nil {
		return err
	}
	found := false
	for _, raw := range sizes {
		var s struct {
			ID               string
			VCPUs, MemoryGiB int64
			Tees             []string
		}
		if json.Unmarshal(raw, &s) == nil && s.ID == r.cfg.Size {
			found = s.VCPUs == r.cfg.VCPUs && s.MemoryGiB*1024 == r.cfg.MemoryMiB && slices.Contains(s.Tees, "tdx")
		}
	}
	if !found {
		return errors.New("Cloud shape does not match advertised provider resources")
	}
	locations, err := r.items(ctx, "locations")
	if err != nil {
		return err
	}
	found = false
	for _, raw := range locations {
		var l struct {
			ID                  string
			Tees, PublicIPModes []string
		}
		if json.Unmarshal(raw, &l) == nil && l.ID == r.cfg.Location {
			found = slices.Contains(l.Tees, "tdx") && slices.Contains(l.PublicIPModes, "shared") && slices.Contains(l.PublicIPModes, "dedicated")
		}
	}
	if !found {
		return errors.New("Cloud location does not support the required TDX/public-IP modes")
	}
	before, err := r.items(ctx, "instances")
	if err != nil {
		return err
	}
	for _, raw := range before {
		var receipt cloudReceipt
		if json.Unmarshal(raw, &receipt) != nil || receipt.ID == "" {
			return errors.New("invalid pre-existing instance identity")
		}
		r.ledger.Before[receipt.ID] = receipt
	}
	return r.save()
}

func (r *cloudRun) getOwned(ctx context.Context, side string) (*instance, error) {
	o, handle, err := r.ownedSnapshot(side)
	if err != nil {
		return nil, err
	}
	id := ""
	if o.Receipt != nil {
		id = o.Receipt.ID
	} else {
		found, err := r.api.Find(ctx, o.Key)
		if err != nil {
			return nil, err
		}
		if found == nil {
			return nil, nil
		}
		id = found.ID
	}
	var receipt cloudReceipt
	if err := r.api.do(ctx, http.MethodGet, "/v1/instances/"+url.PathEscape(id), "", nil, &receipt); err != nil {
		return nil, err
	}
	if err := r.checkOwned(o, receipt); err != nil {
		return nil, err
	}
	if o.Receipt == nil {
		if err := r.updateLedger(func(ledger *cloudLedger) error {
			current := ledger.Owned[handle]
			if current == nil || current.Key != o.Key {
				return errors.New("owned intent changed while obtaining its receipt")
			}
			if current.Receipt != nil && !reflect.DeepEqual(*current.Receipt, receipt) {
				return errors.New("owned receipt changed during lookup")
			}
			current.Receipt = &receipt
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return r.api.Get(ctx, receipt.ID)
}

func (r *cloudRun) checkOwned(o *cloudOwned, in cloudReceipt) error {
	if !o.Attempted {
		return errors.New("refusing an instance without a durable create attempt")
	}
	r.ledgerMu.Lock()
	_, exists := r.ledger.Before[in.ID]
	r.ledgerMu.Unlock()
	if exists {
		return errors.New("refusing a pre-existing Cloud instance")
	}
	launch := "c8s-pod/1"
	if o.Image == r.cfg.CDSImage {
		launch = "c8s-node/1"
	}
	if !regexp.MustCompile(`^i-[a-z0-9]+$`).MatchString(in.ID) || in.Name != o.Key || in.Tee != "tdx" || in.Size != r.cfg.Size || in.Location != r.cfg.Location || !maps.Equal(in.Labels, o.Labels) || in.Image.Family+"@"+in.Image.Version != o.Image || in.Image.Launch != launch || in.Image.Digest != r.cfg.DiskDigest || in.Attestation.ReferenceManifest.Digest != r.cfg.ManifestDigest || in.Attestation.LaunchBinding.SHA256 != cloudHash([]byte(o.LaunchKey)) || in.CreatedAt.Before(o.IntentAt.Add(-2*time.Minute)) || in.CreatedAt.After(o.IntentAt.Add(150*time.Minute)) {
		return errors.New("Cloud instance does not match durable owned intent")
	}
	if o.Receipt != nil {
		a, _ := json.Marshal(o.Receipt)
		b, _ := json.Marshal(in)
		if !bytes.Equal(a, b) {
			return errors.New("owned immutable Cloud identity changed")
		}
	}
	return nil
}

func (r *cloudRun) cleanup(ctx context.Context) error {
	var failures []error
	for _, side := range r.ownedHandles() {
		o, _, snapshotErr := r.ownedSnapshot(side)
		if snapshotErr != nil {
			failures = append(failures, snapshotErr)
			continue
		}
		if o == nil || o.Terminated {
			continue
		}
		// An uncertain sibling must not starve cleanup of known owned instances.
		budget := r.cleanupBudget
		if budget == 0 {
			budget = 3 * time.Minute
		}
		perInstance, cancel := context.WithTimeout(ctx, budget)
		err := r.cleanupOwned(perInstance, side)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("owned %s cleanup: %w", side, err))
		}
	}
	for id, before := range r.ledger.Before {
		var after cloudReceipt
		if err := r.api.do(ctx, http.MethodGet, "/v1/instances/"+url.PathEscape(id), "", nil, &after); err != nil {
			failures = append(failures, err)
			continue
		}
		a, _ := json.Marshal(before)
		b, _ := json.Marshal(after)
		if !bytes.Equal(a, b) {
			failures = append(failures, errors.New("pre-existing instance identity changed"))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return r.updateLedger(func(ledger *cloudLedger) error { ledger.Complete = true; return nil })
}

func (r *cloudRun) cleanupOwned(ctx context.Context, side string) error {
	o, handle, err := r.ownedSnapshot(side)
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		in, err := r.getOwned(ctx, side)
		if err != nil {
			return err
		}
		if in == nil {
			if !o.Attempted {
				break
			}
			// A lost POST response can become visible later. Absence is not a deletion
			// receipt and must never turn an uncertain create into a successful cleanup.
			if err = cloudPause(ctx, 5*time.Second); err != nil {
				return errors.New("uncertain create has no recovery receipt; retain state and retry cleanup")
			}
			continue
		}
		if in.Status == "terminated" {
			break
		}
		if err = r.api.Delete(ctx, in.ID); err != nil {
			return err
		}
		if err = cloudPause(ctx, 5*time.Second); err != nil {
			return err
		}
	}
	return r.updateLedger(func(ledger *cloudLedger) error {
		ledger.Owned[handle].Terminated = true
		return nil
	})
}

func cloudPause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cloudEndpoint(in *instance, name string) (endpoint, error) {
	var result endpoint
	count := 0
	for _, e := range in.Endpoints {
		if e.Name == name {
			result = e
			count++
		}
	}
	address, err := netip.ParseAddr(result.Host)
	if count != 1 || err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || result.Port < 1 || result.Port > 65535 {
		return result, fmt.Errorf("missing valid owned %s endpoint", name)
	}
	return result, nil
}
