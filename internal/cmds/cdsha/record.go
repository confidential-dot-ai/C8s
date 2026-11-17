package cdsha

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// record is what the CLI keeps per cluster.
type record struct {
	Cluster      string        `json:"cluster"`
	Genesis      cdschain.Hash `json:"genesis"`
	Acknowledged cdschain.Head `json:"acknowledged"`
}

func (o *options) recordDir() (string, error) {
	if o.stateDir != "" {
		return o.stateDir, nil
	}
	config, err := os.UserConfigDir()
	return filepath.Join(config, "c8s", "cds-ha"), err
}

func (o *options) recordPath(cluster string) (string, error) {
	dir, err := o.recordDir()
	return filepath.Join(dir, cluster+".json"), err
}

// records reads every cluster's record, by cluster. Taken before a request,
// it is what an answer is held to: a record a concurrent command writes
// while the request is in flight may be newer than the answer, legally.
func (o *options) records() (map[string]*record, error) {
	dir, err := o.recordDir()
	if err != nil {
		return nil, err
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]*record{}
	for _, p := range paths {
		cluster := strings.TrimSuffix(filepath.Base(p), ".json")
		if out[cluster], err = o.record(cluster); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// record reads the cluster's record, nil when there is none.
func (o *options) record(cluster string) (*record, error) {
	path, err := o.recordPath(cluster)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec record
	return &rec, json.Unmarshal(data, &rec)
}

// acknowledge records head, answered done on the chain of genesis. The
// record never goes down: concurrent commands take turns under a lock file.
func (o *options) acknowledge(genesis cdschain.Hash, head cdschain.Head) error {
	path, err := o.recordPath(head.Cluster)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking the record: %w", err)
	}
	rec, err := o.record(head.Cluster)
	switch {
	case err != nil:
		return err
	case rec != nil && rec.Genesis != genesis:
		return fmt.Errorf("cluster %s is recorded with genesis %s, not %s; after a re-root, remove the record", head.Cluster, rec.Genesis, genesis)
	case rec != nil && head.Seq <= rec.Acknowledged.Seq:
		return nil
	}
	data, err := json.MarshalIndent(record{Cluster: head.Cluster, Genesis: genesis, Acknowledged: head}, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(data, '\n'), 0o600)
}
