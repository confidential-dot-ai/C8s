package nriimagepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const (
	podRecoveryDirectory   = "pod-recovery"
	podRecoveryStateFile   = "state.json"
	podRecoveryPendingFile = "pending"
	maxPodRecoveryBytes    = 16 << 20
)

// The state is meaningful only inside this protected guest boot. A pending
// fence deliberately makes an interrupted transition unrecoverable.
type podRecoveryStore struct {
	root         *os.Root
	lock         *os.File
	state        *podRecoveryState
	configDigest string
	kernelBootID string
	processes    map[string]podRecoveredProcess
	sandbox      *podRecoveredSandbox
	active       bool
	failed       error
}

type podRecoveryState struct {
	Version          int                              `json:"version"`
	KernelBootID     string                           `json:"kernelBootID"`
	ConfigDigest     string                           `json:"configDigest"`
	BootID           string                           `json:"bootID"`
	Terminal         string                           `json:"terminal"`
	Revision         uint64                           `json:"revision"`
	Sandbox          *podRecoveredSandbox             `json:"sandbox"`
	Processes        map[string]podRecoveredProcess   `json:"processes"`
	Histories        map[string]json.RawMessage       `json:"histories"`
	Containers       map[string]podRecoveredContainer `json:"containers"`
	Denials          map[string]podRecoveredDenial    `json:"denials"`
	Sandboxes        []string                         `json:"sandboxes"`
	Mesh             map[string]podRecoveredMesh      `json:"mesh"`
	Digests          []string                         `json:"digests"`
	Policy           podPolicyCheckpoint              `json:"policy"`
	CredentialSource string                           `json:"credentialSource"`
	CredentialIssuer string                           `json:"credentialIssuer"`
	CredentialDevice uint64                           `json:"credentialDevice"`
	CredentialInode  uint64                           `json:"credentialInode"`
}

type podRecoveredSandbox struct {
	ID        string `json:"id"`
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	PID       uint32 `json:"pid"`
	Birth     uint64 `json:"birth"`
}

type podRecoveredProcess struct {
	SandboxID string `json:"sandboxID"`
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	Role      string `json:"role"`
	LaunchKey string `json:"launchKey"`
	PID       uint32 `json:"pid"`
	Birth     uint64 `json:"birth"`
	Removed   bool   `json:"removed"`
}

type podRecoveredContainer struct {
	SandboxID string   `json:"sandboxID"`
	Name      string   `json:"name"`
	Digest    string   `json:"digest"`
	Argv      []string `json:"argv"`
}
type podRecoveredDenial struct {
	Permanent string            `json:"permanent"`
	Creations map[string]string `json:"creations"`
}
type podRecoveredRole struct {
	Role   string   `json:"role"`
	Digest string   `json:"digest"`
	Argv   []string `json:"argv"`
}
type podRecoveredMesh struct {
	NamespacePath   string             `json:"namespacePath"`
	Device          uint64             `json:"device"`
	Inode           uint64             `json:"inode"`
	Refusal         string             `json:"refusal"`
	MeshStarted     bool               `json:"meshStarted"`
	WorkloadCreated bool               `json:"workloadCreated"`
	KubeNamespace   string             `json:"kubeNamespace"`
	Roles           []podRecoveredRole `json:"roles"`
	ExitEntry       string             `json:"exitEntry"`
	Exits           []exit             `json:"exits"`
}

// openPodRecovery owns the journal-writer lock BEFORE openMeasurer can repair
// the measurement register. Waiting generic guests acquire the same lock but
// create no assignment checkpoint.
func openPodRecovery(cfg *config) (*podRecoveryStore, error) {
	if !cfg.podRole() {
		return nil, nil
	}
	configBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(configBytes)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("read guest boot identity: %w", err)
	}
	boot = bytes.TrimSpace(boot)
	if len(boot) != 36 {
		return nil, errors.New("invalid kernel boot identity")
	}
	dir := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("pod recovery directory is not private")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return nil, errors.New("pod recovery directory is not root-owned")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*podRecoveryStore, error) { root.Close(); return nil, err }
	if err := fileutil.RequireRAMBackedRoot(root); err != nil {
		return fail(err)
	}
	lock, err := root.OpenFile("service.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fail(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return fail(fmt.Errorf("pod recovery writer already active: %w", err))
	}
	store := &podRecoveryStore{root: root, lock: lock, configDigest: hex.EncodeToString(digest[:]), kernelBootID: string(boot), processes: map[string]podRecoveredProcess{}}
	failed := func(err error) (*podRecoveryStore, error) { store.Close(); return nil, err }
	if _, err := root.Lstat(podRecoveryPendingFile); !errors.Is(err, os.ErrNotExist) {
		return failed(errors.New("pod recovery has an interrupted transition"))
	}
	raw, err := readPodRecoveryFile(root, podRecoveryStateFile)
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Lstat(filepath.Join(cfg.WorkloadClaims.SocketDir, podBrokerMarker)); !errors.Is(markerErr, os.ErrNotExist) {
			return failed(errors.New("pod recovery lost its claimed boot history"))
		}
		digests, journalErr := armtls.ReadRuntimeExtensions(filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal))
		if journalErr != nil || len(digests) != 0 {
			return failed(errors.New("pod recovery lost its measured admission history"))
		}
		return store, nil
	}
	if err != nil {
		return failed(err)
	}
	if strictjson.Validate(raw) != nil {
		return failed(errors.New("invalid Pod recovery JSON"))
	}
	var state podRecoveryState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return failed(err)
	}
	if state.Version != 1 || state.KernelBootID != store.kernelBootID || state.ConfigDigest != store.configDigest || cfg.podWaiting() || state.Processes == nil || state.Histories == nil || state.Containers == nil || state.Denials == nil || state.Mesh == nil || state.Sandboxes == nil {
		return failed(errors.New("pod recovery identity or complete state is invalid"))
	}
	if state.Terminal != "" {
		return failed(errors.New("pod identity previously ended"))
	}
	bootID, err := hex.DecodeString(state.BootID)
	if err != nil || len(bootID) != 32 {
		return failed(errors.New("pod recovery lost its original boot identity"))
	}
	store.state = &state
	store.processes = state.Processes
	store.sandbox = state.Sandbox
	return store, nil
}

func readPodRecoveryFile(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("pod recovery file is not private root-owned regular data")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPodRecoveryBytes+1))
	if err != nil || len(raw) > maxPodRecoveryBytes {
		return nil, errors.New("pod recovery file is unreadable or oversized")
	}
	return raw, nil
}

func (s *podRecoveryStore) Close() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.lock.Close(), s.root.Close())
}

func (s *podRecoveryStore) begin() error {
	if s == nil {
		return nil
	}
	if s.failed != nil {
		return s.failed
	}
	if s.active {
		return errors.New("overlapping Pod recovery transition")
	}
	fence, err := s.root.OpenFile(podRecoveryPendingFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		err = fence.Close()
	}
	if err != nil {
		s.failed = fmt.Errorf("cannot fence Pod authority transition: %w", err)
		return s.failed
	}
	s.active = true
	return nil
}

func (s *podRecoveryStore) commit(state *podRecoveryState) error {
	if s == nil {
		return nil
	}
	if !s.active {
		return errors.New("pod checkpoint has no transition fence")
	}
	raw, err := json.Marshal(state)
	if err == nil && len(raw) > maxPodRecoveryBytes {
		err = errors.New("pod recovery checkpoint exceeds size bound")
	}
	if err == nil {
		err = fileutil.WriteAtomicRoot(s.root, podRecoveryStateFile, raw, 0600)
	}
	if err == nil {
		err = s.root.Remove(podRecoveryPendingFile)
	}
	if err != nil {
		s.failed = fmt.Errorf("cannot commit Pod recovery state: %w", err)
		return s.failed
	}
	s.state = state
	s.active = false
	return nil
}
