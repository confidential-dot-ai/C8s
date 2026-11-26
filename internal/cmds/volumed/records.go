package volumed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/volume"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/fileutil"
)

// Record is what volumed remembers about one volume it opened, in the state
// directory that outlives the process. Without it the next volumed would close
// a mapping under the pod still using it, because device-mapper state alone
// does not say which pod a mapping belongs to.
type Record struct {
	Volume  string    `json:"volume"`
	Pod     PodCgroup `json:"pod"`
	Device  string    `json:"device"`
	Mutable bool      `json:"mutable"`
	// Mapper is the crypt mapping; an immutable volume's verity mapping above
	// it is derived from the pod and the volume.
	Mapper string `json:"mapper"`
	Target string `json:"target"`
	// Commitment is the mapping's binding to the key and mode that opened it,
	// so a sidecar repeating its open after a restart is answered as the same
	// request rather than refused.
	Commitment string `json:"commitment"`
}

// MountRecords is volumed's memory of the volumes open on this node.
type MountRecords interface {
	Put(rec Record) error
	Remove(podUID, volumeName string) error
	List() ([]Record, error)
}

// FileRecords keeps one file per open volume under Dir.
type FileRecords struct {
	Dir string
}

func (f FileRecords) Put(rec Record) error {
	name, err := recordFile(rec.Pod.UID, rec.Volume)
	if err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("volumed: encode mount record: %w", err)
	}
	if err := fileutil.WriteAtomic(filepath.Join(f.Dir, name), data, 0o600); err != nil {
		return fmt.Errorf("volumed: write mount record: %w", err)
	}
	return nil
}

func (f FileRecords) Remove(podUID, volumeName string) error {
	name, err := recordFile(podUID, volumeName)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(f.Dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("volumed: remove mount record: %w", err)
	}
	return nil
}

// List returns the records in the state directory. A file that does not decode
// covers nothing this daemon can adopt, so the mapping it named is treated as
// unrecorded and closed.
func (f FileRecords) List() ([]Record, error) {
	entries, err := os.ReadDir(f.Dir)
	if err != nil {
		return nil, fmt.Errorf("volumed: read %s: %w", f.Dir, err)
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != recordExt {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.Dir, e.Name()))
		if err != nil {
			continue
		}
		var rec Record
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

const recordExt = ".json"

// recordFile names a record after the pod and the volume its mapping is scoped
// to. Both are validated: this is where they become a path written as root.
func recordFile(podUID, volumeName string) (string, error) {
	if !podUIDRE.MatchString(podUID) {
		return "", fmt.Errorf("volumed: pod uid %q is not a uuid", podUID)
	}
	if err := volume.ValidVolumeName(volumeName); err != nil {
		return "", fmt.Errorf("volumed: %w", err)
	}
	return podUID + "-" + volumeName + recordExt, nil
}

// recordFor is the record of a live mount.
func recordFor(m *mount) Record {
	return Record{
		Volume:     m.name,
		Pod:        m.pod,
		Device:     m.device,
		Mutable:    m.mutable,
		Mapper:     m.cryptDev,
		Target:     m.target,
		Commitment: hex.EncodeToString(m.commitment[:]),
	}
}

// mount rebuilds the live volume a record describes, so an adopted mapping is
// held exactly like one this process opened. Every field is checked, because a
// record decides what cryptsetup is asked to close and where a mount is
// unmounted from.
func (r Record) mount() (*mount, error) {
	if _, err := recordFile(r.Pod.UID, r.Volume); err != nil {
		return nil, err
	}
	if r.Mapper != mapperName(cryptKind, r.Pod.UID, r.Volume) {
		return nil, fmt.Errorf("volumed: record mapper %q is not %s's mapping", r.Mapper, r.Volume)
	}
	if r.Device == "" || r.Target == "" {
		return nil, fmt.Errorf("volumed: record for %s names no device or target", r.Volume)
	}
	commitment, err := hex.DecodeString(r.Commitment)
	if err != nil || len(commitment) != sha256.Size {
		return nil, fmt.Errorf("volumed: record for %s has no usable commitment", r.Volume)
	}
	m := &mount{
		pod:      r.Pod,
		name:     r.Volume,
		device:   r.Device,
		mutable:  r.Mutable,
		cryptDev: r.Mapper,
		target:   r.Target,
	}
	copy(m.commitment[:], commitment)
	return m, nil
}
