// A backup is the whole replicated state at one log index, sealed to the
// cluster's recovery key: what a lost cluster is restored from. It lies on a
// board outside the trust boundary, so:
//
//   - HPKE (RFC 9180, DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM) seals the
//     state to the recovery key, whose private half stays offline with the
//     operator. The metadata is bound into the key schedule: authenticated,
//     and not secret.
//   - HPKE base mode authenticates no sender, so the mesh CA of the sealed
//     state signs the metadata together with the exact ciphertext.
//   - Recovery checks that signature against a CA fingerprint kept from the
//     live cluster (VerifyBackupSource), never against one the backup
//     carries, and then the state inside against the metadata
//     (ValidateRecoverySnapshot).

package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The domains the backup's two signatures are taken over: the key schedule
// the state is sealed under, and the message its mesh CA signs.
const (
	backupInfo   = "c8s-cds-ha-backup-v1\n"
	backupSource = "c8s-cds-ha-backup-source-v1\n"
)

// What HPKE adds to the state it seals: the encapsulated key, which is one
// uncompressed P-256 point, and the AEAD tag.
const (
	encapsulatedKeyBytes = 65
	aeadTagBytes         = 16
)

// BackupMeta says which state a backup holds. The operator compares it with
// their own record of the cluster: an older backup would take back decrees,
// allowlist writes and secrets.
type BackupMeta struct {
	ClusterID string `json:"cluster_id"`
	// Version is the operator commands the state had applied, and Index the
	// log index it was captured at.
	Version uint64 `json:"version"`
	Index   uint64 `json:"index"`
	// AppliedDecrees are the intents the cluster had accounted for, oldest
	// first.
	AppliedDecrees []string `json:"applied_decrees,omitempty"`
	// SealedAtMS is the clock of the leader that sealed the backup. Which
	// state is the later one is Version and Index, never this.
	SealedAtMS int64 `json:"sealed_at_ms"`
	// StateDigest names the state the backup seals, as every replica of the
	// cluster digests it at a checkpoint (digest.go), so an operator reads
	// off the board what the cluster reported while it lived.
	StateDigest digest `json:"state_digest"`
}

// Backup is one sealed backup, as one object of the board.
type Backup struct {
	Meta BackupMeta `json:"meta"`
	// Ciphertext is the HPKE encapsulated key and the sealed state.
	Ciphertext []byte `json:"ciphertext"`
	// SourceCert is the mesh CA certificate in DER whose key signed this
	// backup, and Signature that signature.
	SourceCert []byte `json:"source_cert"`
	Signature  string `json:"signature"`
}

// SealBackup seals the state body carries to the recovery key and signs it
// under the mesh CA that state holds, so the backup is of a cluster whose CA
// the operator knows.
func SealBackup(recovery *ecdsa.PublicKey, body []byte, sealedAt time.Time) (Backup, error) {
	sn, err := decodeSnapshot(bytes.NewReader(body), Format, stateBounds())
	if err != nil {
		return Backup{}, err
	}
	ca, err := meshCA(sn.ClusterState.MeshCACert, sn.MeshCAKey)
	if err != nil {
		return Backup{}, err
	}
	meta := metaOf(sn, sealedAt)
	sealed, err := sealToRecoveryKey(recovery, meta, body)
	if err != nil {
		return Backup{}, err
	}
	backup := Backup{Meta: meta, Ciphertext: sealed, SourceCert: sn.ClusterState.MeshCACert}
	message, err := backup.sourceMessage()
	if err != nil {
		return Backup{}, err
	}
	backup.Signature, err = operatorauth.SignDetached(ca.Key, message)
	return backup, err
}

// metaOf says which state a snapshot holds.
func metaOf(sn snapshot, sealedAt time.Time) BackupMeta {
	return BackupMeta{
		ClusterID:      sn.ClusterState.ClusterID,
		Version:        sn.ClusterState.Version,
		Index:          sn.Index,
		AppliedDecrees: sn.ClusterState.AppliedDecrees,
		SealedAtMS:     sealedAt.UnixMilli(),
		StateDigest:    sn.Digests.State,
	}
}

// sealToRecoveryKey seals body under a key schedule the metadata is bound
// into, so metadata changed on the board opens nothing.
func sealToRecoveryKey(recovery *ecdsa.PublicKey, meta BackupMeta, body []byte) ([]byte, error) {
	key, err := sealingKey(recovery)
	if err != nil {
		return nil, err
	}
	info, err := meta.info()
	if err != nil {
		return nil, err
	}
	return hpke.Seal(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info, body)
}

// sealingKey is the recovery key a state seals to.
func sealingKey(recovery *ecdsa.PublicKey) (hpke.PublicKey, error) {
	if err := sealsToTheKEM(recovery.Curve); err != nil {
		return nil, err
	}
	exchange, err := recovery.ECDH()
	if err != nil {
		return nil, fmt.Errorf("cds-ha: the cluster's recovery key: %w", err)
	}
	return hpke.NewDHKEMPublicKey(exchange)
}

// openingKey is the operator's half of it.
func openingKey(recovery *ecdsa.PrivateKey) (hpke.PrivateKey, error) {
	if err := sealsToTheKEM(recovery.Curve); err != nil {
		return nil, err
	}
	exchange, err := recovery.ECDH()
	if err != nil {
		return nil, fmt.Errorf("cds-ha: the recovery key: %w", err)
	}
	return hpke.NewDHKEMPrivateKey(exchange)
}

// sealsToTheKEM refuses a key of another curve than the backup's KEM.
func sealsToTheKEM(curve elliptic.Curve) error {
	if curve != elliptic.P256() {
		return errors.New("cds-ha: a backup seals to a P-256 recovery key")
	}
	return nil
}

// OpenBackup decrypts a backup with the operator's recovery key. It
// authenticates no source: VerifyBackupSource comes first.
func OpenBackup(recovery *ecdsa.PrivateKey, b Backup) ([]byte, error) {
	key, err := openingKey(recovery)
	if err != nil {
		return nil, err
	}
	info, err := b.Meta.info()
	if err != nil {
		return nil, err
	}
	body, err := hpke.Open(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info, b.Ciphertext)
	if err != nil {
		return nil, errors.New("cds-ha: the backup does not open with this recovery key: another key, or the backup or its metadata was changed")
	}
	return body, nil
}

// info is the key schedule's info: the domain and the metadata the seal
// authenticates.
func (m BackupMeta) info() ([]byte, error) {
	authenticated, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(backupInfo), authenticated...), nil
}

// sourceMessage is what the mesh CA of the sealed state signs: the metadata
// and the digest of the exact ciphertext, which binds the encapsulated key
// and the sealed bytes.
func (b Backup) sourceMessage() ([]byte, error) {
	signed, err := json.Marshal(struct {
		Meta             BackupMeta `json:"meta"`
		CiphertextSHA256 string     `json:"ciphertext_sha256"`
	}{b.Meta, ciphertextDigest(b.Ciphertext)})
	if err != nil {
		return nil, err
	}
	return append([]byte(backupSource), signed...), nil
}

// Object is the backup as the board holds it.
func (b Backup) Object() ([]byte, error) {
	return json.Marshal(b)
}

// ParseBackup reads one object of the board, whose every byte is whoever can
// write to that board's. Nothing of it is trusted until VerifyBackupSource
// and ValidateRecoverySnapshot have passed.
func ParseBackup(object []byte) (Backup, error) {
	var b Backup
	if err := decodeStrict(object, &b); err != nil {
		return Backup{}, fmt.Errorf("cds-ha: the board object is no sealed backup: %w", err)
	}
	if sealed := int64(len(b.Ciphertext)); sealed > maxSealedBytes() {
		return Backup{}, fmt.Errorf("cds-ha: the backup seals %d bytes, and a state of this cluster seals to at most %d", sealed, maxSealedBytes())
	}
	return b, nil
}

// maxSealedBytes is the most a sealed state takes: the snapshot stream a
// replica reads, and what HPKE adds to it.
func maxSealedBytes() int64 {
	return stateBounds().stream + encapsulatedKeyBytes + aeadTagBytes
}

// MaxBackupObjectBytes bounds the board object a sealed backup lies in: the
// sealed state as the base64 of JSON carries it, and the metadata and
// signature around it, which the decree record's share of the state bounds.
func MaxBackupObjectBytes() int64 {
	return int64(base64.StdEncoding.EncodedLen(int(maxSealedBytes()))) + headerShare
}

// VerifyBackupSource authenticates a backup against the fingerprint of a mesh
// CA the operator kept from the live cluster. A fingerprint read from the
// backup itself authenticates nothing, and an unsigned backup is refused.
func VerifyBackupSource(b Backup, keptCA string) error {
	kept, err := keptFingerprint(keptCA)
	if err != nil {
		return err
	}
	if certutil.CertFingerprint(b.SourceCert) != kept {
		return errors.New("cds-ha: the backup was signed by another mesh CA than the one kept from the cluster")
	}
	signer, err := meshCASigner(b.SourceCert)
	if err != nil {
		return err
	}
	message, err := b.sourceMessage()
	if err != nil {
		return err
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{signer}, message, b.Signature); err != nil {
		return fmt.Errorf("cds-ha: the backup's source signature: %w", err)
	}
	return nil
}

// keptFingerprint is the mesh CA the operator kept, in the one form a
// certificate's fingerprint takes here: lowercase hexadecimal SHA-256.
func keptFingerprint(keptCA string) (string, error) {
	kept, err := hex.DecodeString(keptCA)
	if err != nil || len(kept) != sha256.Size {
		return "", errors.New("cds-ha: the mesh CA kept from the cluster is 64 hexadecimal characters of SHA-256")
	}
	return hex.EncodeToString(kept), nil
}

// meshCASigner is the key a mesh CA certificate signs under. A backup opens
// long after that certificate expired, so its validity window binds nothing;
// the kept fingerprint is what names the signer.
func meshCASigner(der []byte) (*ecdsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cds-ha: the backup's source certificate: %w", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("cds-ha: the backup's source certificate is no CA")
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cds-ha: the backup's source certificate is not ECDSA")
	}
	return key, nil
}

// ValidateRecoverySnapshot checks the state a backup opened against the
// metadata its source signature covers, and against the floor the operator
// names: a cluster is restored from state at least as new as the operator
// knows it reached.
func ValidateRecoverySnapshot(body []byte, b Backup, minVersion, minIndex uint64) error {
	sn, err := decodeSnapshot(bytes.NewReader(body), Format, stateBounds())
	if err != nil {
		return err
	}
	if err := checkSnapshotDigests(sn); err != nil {
		return err
	}
	switch {
	case !b.describes(sn):
		return errors.New("cds-ha: the backup's metadata says another state than the one it seals")
	case b.Meta.olderThan(minVersion, minIndex):
		return fmt.Errorf("cds-ha: the backup holds version %d at log index %d, below the floor of version %d at index %d",
			b.Meta.Version, b.Meta.Index, minVersion, minIndex)
	}
	return nil
}

// describes reports the snapshot a backup says it holds: the cluster, the
// place in its log, the state digest, the decrees it accounted for, and the
// mesh CA that state serves under, which is the one whose key signed the
// backup.
func (b Backup) describes(sn snapshot) bool {
	return b.Meta.ClusterID == sn.ClusterState.ClusterID &&
		b.Meta.Version == sn.ClusterState.Version &&
		b.Meta.Index == sn.Index &&
		b.Meta.StateDigest == sn.Digests.State &&
		slices.Equal(b.Meta.AppliedDecrees, sn.ClusterState.AppliedDecrees) &&
		bytes.Equal(b.SourceCert, sn.ClusterState.MeshCACert)
}

// olderThan reports state the operator knows their cluster moved past: an
// earlier version, or an earlier log index of the version they name.
func (m BackupMeta) olderThan(version, index uint64) bool {
	if m.Version != version {
		return m.Version < version
	}
	return m.Index < index
}

// Follows reports m as later state of o's history: the decrees o accounted
// for are the first m accounted for, and m holds state o's is older than. The
// backups of one cluster's life follow one another; a second Genesis and a
// cluster restored from an older backup begin a history of their own.
func (m BackupMeta) Follows(o BackupMeta) bool {
	if m.ClusterID != o.ClusterID || !m.carriesOnTheDecreesOf(o) {
		return false
	}
	return o.olderThan(m.Version, m.Index)
}

// carriesOnTheDecreesOf reports state whose decree record begins with every
// decree o accounted for.
func (m BackupMeta) carriesOnTheDecreesOf(o BackupMeta) bool {
	accounted := o.AppliedDecrees
	return len(m.AppliedDecrees) >= len(accounted) && slices.Equal(m.AppliedDecrees[:len(accounted)], accounted)
}

// ciphertextDigest is the hex SHA-256 the source signature binds the sealed
// bytes by.
func ciphertextDigest(sealed []byte) string {
	sum := sha256.Sum256(sealed)
	return hex.EncodeToString(sum[:])
}
