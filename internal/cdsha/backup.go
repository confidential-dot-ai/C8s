package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A backup is the whole replicated state (the Raft snapshot: core, mesh CA
// key, allowlist, secrets, bindings), sealed with HPKE (RFC 9180,
// DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM) to the operator's offline
// recovery key. Only that key opens it, so it can sit in the untrusted
// control plane; its metadata is authenticated (bound into the HPKE info),
// not secret. The snapshot is already zstd-compressed.

const backupInfo = "c8s-cds-ha-backup-v2\n"

// BackupMeta says which state a backup holds. The operator compares it with
// their own record before restoring: an older backup would roll back
// decrees, policy and secrets.
type BackupMeta struct {
	ClusterID      string   `json:"cluster_id"`
	Epoch          uint64   `json:"epoch"`
	Index          uint64   `json:"index"`
	AppliedDecrees []string `json:"applied_decrees"`
	TakenAtMS      int64    `json:"taken_at_ms"`
	CAFingerprint  string   `json:"ca_fingerprint"`
}

// Backup is one sealed backup. Ciphertext is the HPKE encapsulated key
// followed by the sealed snapshot.
type Backup struct {
	Meta       BackupMeta `json:"meta"`
	Ciphertext []byte     `json:"ciphertext"`
}

// info binds the metadata into the HPKE key schedule.
func (m BackupMeta) info() ([]byte, error) {
	j, err := json.Marshal(m)
	return append([]byte(backupInfo), j...), err
}

// SealBackup encrypts a snapshot to the recovery public key (P-256).
func SealBackup(recovery *ecdsa.PublicKey, meta BackupMeta, snapshot []byte) (Backup, error) {
	if recovery.Curve != elliptic.P256() {
		return Backup{}, errors.New("recovery key must be ECDSA P-256")
	}
	rec, err := recovery.ECDH()
	if err != nil {
		return Backup{}, fmt.Errorf("recovery key: %w", err)
	}
	pk, err := hpke.NewDHKEMPublicKey(rec)
	if err != nil {
		return Backup{}, fmt.Errorf("recovery key: %w", err)
	}
	info, err := meta.info()
	if err != nil {
		return Backup{}, err
	}
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, snapshot)
	if err != nil {
		return Backup{}, err
	}
	return Backup{Meta: meta, Ciphertext: ct}, nil
}

// OpenBackup decrypts a backup with the recovery private key. The metadata is
// authenticated: changing it fails decryption.
func OpenBackup(recovery *ecdsa.PrivateKey, b Backup) ([]byte, error) {
	rec, err := recovery.ECDH()
	if err != nil {
		return nil, fmt.Errorf("recovery key: %w", err)
	}
	sk, err := hpke.NewDHKEMPrivateKey(rec)
	if err != nil {
		return nil, fmt.Errorf("recovery key: %w", err)
	}
	info, err := b.Meta.info()
	if err != nil {
		return nil, err
	}
	snapshot, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, b.Ciphertext)
	if err != nil {
		return nil, errors.New("backup does not open with this recovery key (wrong key, or the backup or its metadata was changed)")
	}
	return snapshot, nil
}

// SnapshotSHA256 names a snapshot in a Restore decree.
func SnapshotSHA256(snapshot []byte) string {
	sum := sha256.Sum256(snapshot)
	return hex.EncodeToString(sum[:])
}

// Backups are ConfigMaps in the decree namespace: a manifest
// (cds-backup-<cluster>) and ciphertext parts small enough for one object.
var backupPartBytes = 900 << 10

const (
	keyBackup   = "backup"
	keyPart     = "part"
	LabelBackup = "c8s.confidential.ai/cds-backup"
)

// BackupName is the manifest object of a cluster's backup.
func BackupName(clusterID string) string { return "cds-backup-" + clusterID }

type backupManifest struct {
	Meta   BackupMeta `json:"meta"`
	Parts  int        `json:"parts"`
	SHA256 string     `json:"sha256"`
	Gen    string     `json:"gen"` // names this backup's parts: <manifest>-<gen>-<i>
}

func (m backupManifest) partName(clusterID string, i int) string {
	return BackupName(clusterID) + "-" + m.Gen + "-" + strconv.Itoa(i)
}

// ErrBackupNotNewer refuses to replace a stored backup with an older one: a
// deposed leader, or a replica cut off from the majority, must never
// overwrite the majority's backup with its own stale state.
var ErrBackupNotNewer = errors.New("cds-ha: a newer backup is already stored")

// Newer reports whether m is later state than o: a later epoch (every decree,
// Restore and Recover raises it), or the same epoch at a later log index.
func (m BackupMeta) Newer(o BackupMeta) bool {
	if m.Epoch != o.Epoch {
		return m.Epoch > o.Epoch
	}
	return m.Index > o.Index
}

// PutBackup writes the parts under names of their own, then switches the
// manifest to them, then deletes stale parts (deleteStaleParts). The stored
// backup therefore stays whole if the writer dies part way (the moment a
// total loss is likeliest), and two writers cannot mix parts. It refuses a
// backup that is not newer than the stored one (ErrBackupNotNewer), and the
// switch is conditional on the manifest it checked, so a writer that raced
// another loses rather than overwriting it. The stored manifest is only the
// host's word, so a forged one can block backups (as deleting them could);
// it cannot make a restore pick old state: recover checks the operator's own
// record (--min-epoch/--min-index).
func (s KubeDecrees) PutBackup(ctx context.Context, b Backup) error {
	name := BackupName(s.ClusterID)
	cur, err := s.cms().Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		cur = nil
	case err != nil:
		return err
	default:
		var man backupManifest
		if json.Unmarshal([]byte(cur.Data[keyBackup]), &man) == nil && !b.Meta.Newer(man.Meta) {
			return fmt.Errorf("%w (stored epoch %d index %d, this one epoch %d index %d)", ErrBackupNotNewer,
				man.Meta.Epoch, man.Meta.Index, b.Meta.Epoch, b.Meta.Index)
		}
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	sum := sha256.Sum256(b.Ciphertext)
	man := backupManifest{Meta: b.Meta, SHA256: hex.EncodeToString(sum[:]),
		Gen: fmt.Sprintf("e%d-i%d-%s", b.Meta.Epoch, b.Meta.Index, hex.EncodeToString(nonce[:]))}
	labels := map[string]string{LabelBackup: s.ClusterID}
	for off := 0; off < len(b.Ciphertext) || man.Parts == 0; off += backupPartBytes {
		end := min(off+backupPartBytes, len(b.Ciphertext))
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: man.partName(s.ClusterID, man.Parts), Namespace: s.Namespace,
			Labels: labels}, BinaryData: map[string][]byte{keyPart: b.Ciphertext[off:end]}}
		if _, err := s.cms().Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			for i := range man.Parts { // only this writer's: no manifest names them
				_ = s.cms().Delete(ctx, man.partName(s.ClusterID, i), metav1.DeleteOptions{})
			}
			return err
		}
		man.Parts++
	}
	data, err := json.Marshal(man)
	if err != nil {
		return err
	}
	mcm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: labels},
		Data: map[string]string{keyBackup: string(data)}}
	if cur == nil {
		_, err = s.cms().Create(ctx, mcm, metav1.CreateOptions{})
	} else {
		mcm.ResourceVersion = cur.ResourceVersion // only over the manifest checked above
		_, err = s.cms().Update(ctx, mcm, metav1.UpdateOptions{})
	}
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
		err = fmt.Errorf("%w (another writer stored a backup meanwhile)", ErrBackupNotNewer)
	}
	s.deleteStaleParts(ctx)
	return err
}

// deleteStaleParts removes backup parts that the stored manifest does not
// name and that are not newer than it: earlier backups' and dead writers'.
// A newer part belongs to a writer that may still switch the manifest to it
// (two leaders overlap at a leader change). Best effort; the next backup
// retries.
func (s KubeDecrees) deleteStaleParts(ctx context.Context) {
	list, err := s.cms().List(ctx, metav1.ListOptions{LabelSelector: LabelBackup + "=" + s.ClusterID})
	if err != nil {
		return
	}
	name := BackupName(s.ClusterID)
	i := slices.IndexFunc(list.Items, func(cm corev1.ConfigMap) bool { return cm.Name == name })
	var man backupManifest
	if i < 0 || json.Unmarshal([]byte(list.Items[i].Data[keyBackup]), &man) != nil {
		return // no manifest yet, or cannot tell which parts are live: delete nothing
	}
	keep := map[string]bool{name: true}
	for i := range man.Parts {
		keep[man.partName(s.ClusterID, i)] = true
	}
	for _, cm := range list.Items {
		var part BackupMeta
		_, err := fmt.Sscanf(strings.TrimPrefix(cm.Name, name+"-"), "e%d-i%d-", &part.Epoch, &part.Index)
		if !keep[cm.Name] && err == nil && !part.Newer(man.Meta) {
			_ = s.cms().Delete(ctx, cm.Name, metav1.DeleteOptions{})
		}
	}
}

// BackupFromConfigMaps reassembles a backup from its objects, as listed by
// the API (the CLI reads a `kubectl get configmaps -o json` export).
func BackupFromConfigMaps(clusterID string, cms []corev1.ConfigMap) (Backup, error) {
	byName := map[string]corev1.ConfigMap{}
	for _, cm := range cms {
		byName[cm.Name] = cm
	}
	mcm, ok := byName[BackupName(clusterID)]
	if !ok {
		return Backup{}, fmt.Errorf("no backup manifest %s", BackupName(clusterID))
	}
	var man backupManifest
	if err := json.Unmarshal([]byte(mcm.Data[keyBackup]), &man); err != nil {
		return Backup{}, fmt.Errorf("backup manifest: %w", err)
	}
	if man.Meta.ClusterID != clusterID || man.Parts < 1 || man.Gen == "" {
		return Backup{}, errors.New("backup manifest is for another cluster or names no parts")
	}
	var ct []byte
	for i := range man.Parts {
		p, ok := byName[man.partName(clusterID, i)]
		if !ok {
			return Backup{}, fmt.Errorf("backup part %d is missing", i)
		}
		ct = append(ct, p.BinaryData[keyPart]...)
	}
	if sum := sha256.Sum256(ct); hex.EncodeToString(sum[:]) != man.SHA256 {
		return Backup{}, errors.New("backup parts do not match their manifest (a write in progress, or tampering)")
	}
	return Backup{Meta: man.Meta, Ciphertext: ct}, nil
}

// GetBackup reads the stored backup.
func (s KubeDecrees) GetBackup(ctx context.Context) (Backup, error) {
	list, err := s.cms().List(ctx, metav1.ListOptions{LabelSelector: LabelBackup + "=" + s.ClusterID})
	if err != nil {
		return Backup{}, err
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	return BackupFromConfigMaps(s.ClusterID, list.Items)
}
