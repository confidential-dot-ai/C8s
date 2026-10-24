//go:build c8s_dev

package cds

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// Test-only hooks for the multi-process CDS-HA integration test
// (test/integration/cdsha). They exist only in c8s_dev builds, which already
// run without a TEE (mock attestor, plain HTTP); a release build has neither.
//
//   - --ha-attestor=mock with --ha-measurement, and the Raft timing flags
//     (--ha-heartbeat ... --ha-tick), which only the harness sets.
//   - C8S_DEV_KUBE_DIR=<dir>: the "Kubernetes API" is a directory of ConfigMap
//     JSON files shared by every replica process (decrees, their status and
//     the sealed backups), since an in-process fake client cannot span
//     processes.
//   - C8S_DEV_TEST_ROUTES=1: PUT /secrets/* without armTLS (operator writes
//     only), and GET /dev/ha/secrets, which dumps this replica's secret store
//     so the test can compare replicas; GET /dev/pprof/<profile> (heap,
//     allocs, goroutine) and GET /dev/memstats (Go memory classes and the
//     process RSS), for the memory tests.
func init() {
	bindDevHAFlags = func(flags *pflag.FlagSet, c *haConfig) {
		flags.StringVar(&c.measurement, "ha-measurement", "", "this replica's measurement as reported by the mock attestor")
		flags.DurationVar(&c.timing.Heartbeat, "ha-heartbeat", c.timing.Heartbeat, "Raft heartbeat timeout")
		flags.DurationVar(&c.timing.Election, "ha-election", c.timing.Election, "Raft election timeout")
		flags.DurationVar(&c.timing.Lease, "ha-lease", c.timing.Lease, "a follower stops issuing and releasing this long after it last heard from the leader")
		flags.DurationVar(&c.timing.DeadAfter, "ha-dead-after", c.timing.DeadAfter, "the leader removes a member that failed heartbeats this long")
		flags.DurationVar(&c.timing.Stabilize, "ha-stabilize", c.timing.Stabilize, "a non-voter must be healthy this long before it takes a seat")
		flags.DurationVar(&c.timing.Apply, "ha-apply-timeout", c.timing.Apply, "bound on one replicated write")
		flags.DurationVar(&c.timing.Backup, "ha-backup-interval", c.timing.Backup, "the leader seals and stores a backup of changed state at most this often")
		flags.DurationVar(&c.timing.Tick, "ha-tick", c.timing.Tick, "membership and decree loop period")
	}
	nodeAttestor := newHAAttestor
	newHAAttestor = func(cfg config) (cdsha.Attestor, error) {
		if cfg.ha.attestor == "mock" {
			return cdsha.MockAttestor{Measurement: cfg.ha.measurement}, nil
		}
		return nodeAttestor(cfg)
	}
	if dir := os.Getenv("C8S_DEV_KUBE_DIR"); dir != "" {
		newInClusterKubeClientset = func() (kubernetes.Interface, error) { return dirKube(dir), nil }
	}
	if os.Getenv("C8S_DEV_TEST_ROUTES") == "1" {
		devHARoutes = devTestRoutes
		devUngated = devDiagnosticPath
	}
}

// devDiagnosticPath names the diagnostic test routes that a replica serves
// even while it is not serving (see devUngated).
func devDiagnosticPath(path string) bool {
	return strings.HasPrefix(path, "/dev/pprof/") || path == "/dev/memstats"
}

// devTestRoutes adds the test routes in front of the CDS router.
func devTestRoutes(next http.Handler, store secrets.Store, mem *secrets.MemoryStore, authorize allowlist.WriteAuthorizer, mountPut bool) http.Handler {
	put := secrets.OperatorHandler{Store: store, Authorize: authorize, MaxBodyBytes: allowlistWriteBodyCap}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dev/ha/secrets":
			dump := mem.Dump()
			sort.Slice(dump, func(i, j int) bool { return dump[i].Path < dump[j].Path })
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(dump)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dev/pprof/"):
			// Profiles for the memory soak (heap, allocs, goroutine, ...).
			pprof.Handler(strings.TrimPrefix(r.URL.Path, "/dev/pprof/")).ServeHTTP(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/dev/memstats":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(devMemStats())
		case mountPut && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/secrets/"):
			put.ServeHTTP(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// devMemStats is the Go runtime's memory classes and the process's RSS,
// so a test can tell Go heap from memory outside it (SQLite's allocator).
func devMemStats() map[string]uint64 {
	var samples []metrics.Sample
	for _, d := range metrics.All() {
		if strings.HasPrefix(d.Name, "/memory/classes/") || d.Name == "/gc/heap/goal:bytes" || d.Name == "/gc/gomemlimit:bytes" {
			samples = append(samples, metrics.Sample{Name: d.Name})
		}
	}
	metrics.Read(samples)
	out := map[string]uint64{}
	for _, s := range samples {
		if s.Value.Kind() == metrics.KindUint64 {
			out[s.Name] = s.Value.Uint64()
		}
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && (k == "VmRSS" || k == "VmHWM" || k == "RssAnon") {
				var kb uint64
				if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d kB", &kb); err == nil {
					out["/proc/"+k+":bytes"] = kb << 10
				}
			}
		}
	}
	return out
}

// dirKube is a fake clientset whose ConfigMaps live in dir/<namespace>/<name>.json.
func dirKube(dir string) kubernetes.Interface {
	cs := fake.NewClientset()
	d := &cmDir{root: dir}
	cs.PrependReactor("*", "configmaps", d.react)
	// Dev only: client-go's testing.Fake keeps a deep copy of every action
	// it handles, for tests that inspect them, and never drops one. A replica
	// runs for hours and writes every backup through here (multi-MB every
	// backup interval), so the record grew without bound (GiBs of heap in the
	// chaos soak). Nothing reads it; drop it periodically. It cannot be
	// dropped from the reactor: Invokes holds the Fake's lock around it.
	every := dirKubeClearEvery
	go func() {
		for range time.Tick(every) {
			cs.ClearActions()
		}
	}()
	return cs
}

// dirKubeClearEvery is how often dirKube drops the fake's action record; a
// var so the test can shorten it.
var dirKubeClearEvery = 10 * time.Second

type cmDir struct {
	root string
	mu   sync.Mutex // within one process; across processes writes are atomic renames
}

func (d *cmDir) path(ns, name string) string { return filepath.Join(d.root, ns, name+".json") }

func (d *cmDir) read(ns, name string) (*corev1.ConfigMap, error) {
	raw, err := os.ReadFile(d.path(ns, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, apierrors.NewNotFound(corev1.Resource("configmaps"), name)
	}
	if err != nil {
		return nil, err
	}
	var cm corev1.ConfigMap
	if err := json.Unmarshal(raw, &cm); err != nil {
		return nil, err
	}
	return &cm, nil
}

func (d *cmDir) write(cm *corev1.ConfigMap) error {
	raw, err := json.Marshal(cm)
	if err != nil {
		return err
	}
	p := d.path(cm.Namespace, cm.Name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return fileutil.WriteAtomic(p, raw, 0o600)
}

func (d *cmDir) react(action k8stesting.Action) (bool, runtime.Object, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ns := action.GetNamespace()
	switch action.GetVerb() {
	case "get":
		cm, err := d.read(ns, action.(k8stesting.GetAction).GetName())
		return true, cm, err
	case "list":
		sel := action.(k8stesting.ListAction).GetListRestrictions().Labels
		out := &corev1.ConfigMapList{}
		ents, err := os.ReadDir(filepath.Join(d.root, ns))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, nil, err
		}
		for _, e := range ents {
			name, ok := strings.CutSuffix(e.Name(), ".json")
			if !ok || strings.HasPrefix(name, ".") {
				continue
			}
			cm, err := d.read(ns, name)
			if err != nil {
				continue // removed meanwhile
			}
			if sel == nil || sel.Matches(labels.Set(cm.Labels)) {
				out.Items = append(out.Items, *cm)
			}
		}
		return true, out, nil
	case "create":
		cm, ok := action.(k8stesting.CreateAction).GetObject().(*corev1.ConfigMap)
		if !ok {
			return true, nil, errors.New("dirkube: not a ConfigMap")
		}
		cm = cm.DeepCopy()
		cm.Namespace = ns
		if _, err := os.Stat(d.path(ns, cm.Name)); err == nil {
			return true, nil, apierrors.NewAlreadyExists(corev1.Resource("configmaps"), cm.Name)
		}
		return true, cm, d.write(cm)
	case "update":
		cm, ok := action.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		if !ok {
			return true, nil, errors.New("dirkube: not a ConfigMap")
		}
		cm = cm.DeepCopy()
		cm.Namespace = ns
		if _, err := os.Stat(d.path(ns, cm.Name)); err != nil {
			return true, nil, apierrors.NewNotFound(corev1.Resource("configmaps"), cm.Name)
		}
		return true, cm, d.write(cm)
	case "delete":
		name := action.(k8stesting.DeleteAction).GetName()
		err := os.Remove(d.path(ns, name))
		if errors.Is(err, os.ErrNotExist) {
			err = apierrors.NewNotFound(corev1.Resource("configmaps"), name)
		}
		return true, nil, err
	}
	return true, nil, errors.New("dirkube: unsupported " + action.GetVerb())
}
