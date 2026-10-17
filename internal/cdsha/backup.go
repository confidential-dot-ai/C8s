package cdsha

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A backup is the whole replicated state (the Raft snapshot: core, mesh CA
// key, allowlist, secrets, bindings), gzipped and encrypted to the operator's
// offline recovery key. Only that key opens it, so it can sit in the
// untrusted control plane; its metadata is authenticated, not secret.

const backupInfo = "c8s-cds-ha-backup-v1"

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

// Backup is one sealed backup.
type Backup struct {
	Meta         BackupMeta `json:"meta"`
	EphemeralPub []byte     `json:"ephemeral_pub"` // uncompressed P-256 point
	Nonce        []byte     `json:"nonce"`
	Ciphertext   []byte     `json:"ciphertext"`
}

func backupKey(shared, ephPub, recPub []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), recPub...), backupInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealBackup encrypts a snapshot to the recovery public key.
func SealBackup(recovery *ecdsa.PublicKey, meta BackupMeta, snapshot []byte) (Backup, error) {
	rec, err := recovery.ECDH()
	if err != nil {
		return Backup{}, fmt.Errorf("recovery key: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Backup{}, err
	}
	shared, err := eph.ECDH(rec)
	if err != nil {
		return Backup{}, err
	}
	aead, err := backupKey(shared, eph.PublicKey().Bytes(), rec.Bytes())
	if err != nil {
		return Backup{}, err
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(snapshot); err != nil {
		return Backup{}, err
	}
	if err := zw.Close(); err != nil {
		return Backup{}, err
	}
	aad, err := json.Marshal(meta)
	if err != nil {
		return Backup{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Backup{}, err
	}
	return Backup{Meta: meta, EphemeralPub: eph.PublicKey().Bytes(), Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, z.Bytes(), aad)}, nil
}

// OpenBackup decrypts a backup with the recovery private key. The metadata is
// authenticated: changing it fails decryption.
func OpenBackup(recovery *ecdsa.PrivateKey, b Backup) ([]byte, error) {
	rec, err := recovery.ECDH()
	if err != nil {
		return nil, fmt.Errorf("recovery key: %w", err)
	}
	eph, err := ecdh.P256().NewPublicKey(b.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("backup ephemeral key: %w", err)
	}
	shared, err := rec.ECDH(eph)
	if err != nil {
		return nil, err
	}
	aead, err := backupKey(shared, b.EphemeralPub, rec.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aad, err := json.Marshal(b.Meta)
	if err != nil {
		return nil, err
	}
	z, err := aead.Open(nil, b.Nonce, b.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("backup does not open with this recovery key (wrong key, or the backup or its metadata was changed)")
	}
	zr, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(zr, 1<<30))
}

// SnapshotSHA256 names a snapshot in a Restore decree.
func SnapshotSHA256(snapshot []byte) string {
	sum := sha256.Sum256(snapshot)
	return hex.EncodeToString(sum[:])
}

// Backups are ConfigMaps in the decree namespace: a manifest
// (cds-backup-<cluster>) and ciphertext parts small enough for one object.
const (
	backupPartBytes = 900 << 10
	keyBackup       = "backup"
	keyPart         = "part"
	LabelBackup     = "c8s.confidential.ai/cds-backup"
)

// BackupName is the manifest object of a cluster's backup.
func BackupName(clusterID string) string { return "cds-backup-" + clusterID }

type backupManifest struct {
	Meta         BackupMeta `json:"meta"`
	EphemeralPub []byte     `json:"ephemeral_pub"`
	Nonce        []byte     `json:"nonce"`
	Parts        int        `json:"parts"`
	SHA256       string     `json:"sha256"`
}

// PutBackup writes the parts, then the manifest that names them, so a
// reader never sees a manifest whose parts are not there yet.
func (s KubeDecrees) PutBackup(ctx context.Context, b Backup) error {
	var parts int
	for off := 0; off < len(b.Ciphertext) || parts == 0; off += backupPartBytes {
		end := min(off+backupPartBytes, len(b.Ciphertext))
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: BackupName(s.ClusterID) + "-" + strconv.Itoa(parts), Namespace: s.Namespace,
			Labels: map[string]string{LabelBackup: s.ClusterID}}, BinaryData: map[string][]byte{keyPart: b.Ciphertext[off:end]}}
		if err := s.upsert(ctx, cm); err != nil {
			return err
		}
		parts++
	}
	sum := sha256.Sum256(b.Ciphertext)
	man, err := json.Marshal(backupManifest{Meta: b.Meta, EphemeralPub: b.EphemeralPub, Nonce: b.Nonce, Parts: parts, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	return s.upsert(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: BackupName(s.ClusterID), Namespace: s.Namespace,
		Labels: map[string]string{LabelBackup: s.ClusterID}}, Data: map[string]string{keyBackup: string(man)}})
}

func (s KubeDecrees) upsert(ctx context.Context, cm *corev1.ConfigMap) error {
	cur, err := s.cms().Get(ctx, cm.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = s.cms().Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	cm.ResourceVersion = cur.ResourceVersion
	_, err = s.cms().Update(ctx, cm, metav1.UpdateOptions{})
	return err
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
	if man.Meta.ClusterID != clusterID || man.Parts < 1 {
		return Backup{}, errors.New("backup manifest is for another cluster or names no parts")
	}
	var ct []byte
	for i := range man.Parts {
		p, ok := byName[BackupName(clusterID)+"-"+strconv.Itoa(i)]
		if !ok {
			return Backup{}, fmt.Errorf("backup part %d is missing", i)
		}
		ct = append(ct, p.BinaryData[keyPart]...)
	}
	if sum := sha256.Sum256(ct); hex.EncodeToString(sum[:]) != man.SHA256 {
		return Backup{}, errors.New("backup parts do not match their manifest (a write in progress, or tampering)")
	}
	return Backup{Meta: man.Meta, EphemeralPub: man.EphemeralPub, Nonce: man.Nonce, Ciphertext: ct}, nil
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
