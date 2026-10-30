package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// A sealed backup is the whole replicated state, bound to the metadata it
// says it holds and signed by the mesh CA of that state. The tests below open
// one with the cluster's recovery key, and refuse every backup the board
// could have changed under the operator.

// startedState is the state of a cluster that started, as the snapshot stream
// a backup seals.
func startedState(t *testing.T) (*replica, []byte) {
	t.Helper()
	r := newReplica(t)
	r.genesis()
	captured, err := r.Snapshot()
	if err != nil {
		t.Fatalf("capture the state: %v", err)
	}
	var body bytes.Buffer
	if err := captured.Encode(&body); err != nil {
		t.Fatalf("encode the state: %v", err)
	}
	return r, body.Bytes()
}

// sealedState is that state sealed to the cluster's recovery key.
func sealedState(t *testing.T) (*replica, []byte, Backup) {
	t.Helper()
	r, body := startedState(t)
	backup, err := SealBackup(&r.recovery.PublicKey, body, time.Now())
	if err != nil {
		t.Fatalf("seal the state: %v", err)
	}
	return r, body, backup
}

// keptCA is the mesh CA fingerprint an operator keeps from the live cluster,
// which is the only thing a backup is authenticated against.
func (c cluster) keptCA() string {
	return certutil.CertFingerprint(c.minted.Cert.Raw)
}

func TestABackupOpensWithTheClustersRecoveryKeyAndNamesTheStateItHolds(t *testing.T) {
	r, body, backup := sealedState(t)
	if err := VerifyBackupSource(backup, r.keptCA()); err != nil {
		t.Fatalf("VerifyBackupSource = %v", err)
	}
	opened, err := OpenBackup(r.recovery, backup)
	if err != nil {
		t.Fatalf("OpenBackup = %v", err)
	}
	if !bytes.Equal(opened, body) {
		t.Fatalf("the backup holds %d bytes of state, and the cluster sealed %d", len(opened), len(body))
	}
	if err := ValidateRecoverySnapshot(opened, backup, 0, 0); err != nil {
		t.Fatalf("ValidateRecoverySnapshot = %v", err)
	}
	core := r.ClusterState()
	meta := backup.Meta
	if meta.ClusterID != core.ClusterID || meta.Version != core.Version || meta.Index != r.AppliedIndex() {
		t.Fatalf("the backup says cluster %q at version %d, index %d; the state is %q at version %d, index %d",
			meta.ClusterID, meta.Version, meta.Index, core.ClusterID, core.Version, r.AppliedIndex())
	}
	if certutil.CertFingerprint(backup.SourceCert) != r.keptCA() {
		t.Fatalf("the backup is signed by mesh CA %s, and the state holds %s", certutil.CertFingerprint(backup.SourceCert), r.keptCA())
	}
}

func TestOnlyTheClustersRecoveryKeySealsAndOpensItsBackups(t *testing.T) {
	r, body, backup := sealedState(t)
	another, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(another, backup); err == nil {
		t.Fatal("a backup of this cluster opened with another key than its recovery key")
	}
	if _, err := SealBackup(&r.recovery.PublicKey, []byte("no snapshot"), time.Now()); err == nil {
		t.Fatal("bytes that are no snapshot of a cluster sealed as a backup")
	}
	onAnotherCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealBackup(&onAnotherCurve.PublicKey, body, time.Now()); err == nil {
		t.Fatal("a state sealed to a key of another curve than the backup's KEM")
	}
	if _, err := OpenBackup(onAnotherCurve, backup); err == nil {
		t.Fatal("a backup opened with a key of another curve than the backup's KEM")
	}
}

// The metadata is bound into the seal, so an operator who reads it off the
// board reads what the backup holds or opens nothing at all.
func TestMetadataChangedOnTheBoardOpensNothing(t *testing.T) {
	r, _, backup := sealedState(t)
	for name, changed := range map[string]func(*BackupMeta){
		"the version":      func(m *BackupMeta) { m.Version++ },
		"the index":        func(m *BackupMeta) { m.Index++ },
		"the cluster":      func(m *BackupMeta) { m.ClusterID = "another" },
		"the time taken":   func(m *BackupMeta) { m.SealedAtMS = 0 },
		"the state digest": func(m *BackupMeta) { m.StateDigest = digest{1} },
		"the decrees":      func(m *BackupMeta) { m.AppliedDecrees = nil },
	} {
		t.Run(name, func(t *testing.T) {
			onTheBoard := backup
			changed(&onTheBoard.Meta)
			if _, err := OpenBackup(r.recovery, onTheBoard); err == nil {
				t.Fatalf("a backup whose %s was changed opened", name)
			}
		})
	}
}

func TestABackupTheClustersMeshCADidNotSignIsRefused(t *testing.T) {
	r, _, backup := sealedState(t)
	another := mintCA(t)
	leaf := selfSignedLeaf(t)
	for name, tc := range map[string]struct {
		onTheBoard Backup
		keptCA     string
	}{
		"another mesh CA kept": {backup, certutil.CertFingerprint(another.Cert.Raw)},
		"a source signed by another mesh CA": {Backup{
			Meta:       backup.Meta,
			Ciphertext: backup.Ciphertext,
			SourceCert: another.Cert.Raw,
			Signature:  backup.Signature,
		}, certutil.CertFingerprint(another.Cert.Raw)},
		"a source that is no CA": {Backup{
			Meta:       backup.Meta,
			Ciphertext: backup.Ciphertext,
			SourceCert: leaf,
			Signature:  backup.Signature,
		}, certutil.CertFingerprint(leaf)},
		"no signature at all": {Backup{
			Meta:       backup.Meta,
			Ciphertext: backup.Ciphertext,
			SourceCert: backup.SourceCert,
		}, r.keptCA()},
		"a ciphertext changed on the board": {Backup{
			Meta:       backup.Meta,
			Ciphertext: append([]byte{0}, backup.Ciphertext...),
			SourceCert: backup.SourceCert,
			Signature:  backup.Signature,
		}, r.keptCA()},
		"a mesh CA that is no fingerprint": {backup, "the cluster's CA"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyBackupSource(tc.onTheBoard, tc.keptCA); err == nil {
				t.Fatalf("a backup with %s authenticated against the cluster's mesh CA", name)
			}
		})
	}
}

// selfSignedLeaf is a certificate that signs no other, so it is no mesh CA.
func selfSignedLeaf(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAnOperatorMustNotBeTakenForAnotherStateThanTheBackupHolds(t *testing.T) {
	_, body, backup := sealedState(t)
	for name, changed := range map[string]func(*Backup){
		"the version": func(b *Backup) { b.Meta.Version++ },
		"the index":   func(b *Backup) { b.Meta.Index++ },
		"the cluster": func(b *Backup) { b.Meta.ClusterID = "another" },
		"the mesh CA": func(b *Backup) { b.SourceCert = mintCA(t).Cert.Raw },
		"the state digest": func(b *Backup) {
			b.Meta.StateDigest = digest{1}
		},
		"the decrees": func(b *Backup) { b.Meta.AppliedDecrees = append(b.Meta.AppliedDecrees, "another-decree") },
	} {
		t.Run(name, func(t *testing.T) {
			said := backup
			changed(&said)
			if err := ValidateRecoverySnapshot(body, said, 0, 0); err == nil {
				t.Fatalf("a backup that says %s of another state validated", name)
			}
		})
	}
}

func TestStateBelowTheOperatorsFloorIsRefused(t *testing.T) {
	_, body, backup := sealedState(t)
	meta := backup.Meta
	for name, tc := range map[string]struct {
		minVersion, minIndex uint64
		restores             bool
	}{
		"no floor at all":               {0, 0, true},
		"the state the operator knows":  {meta.Version, meta.Index, true},
		"a version above it":            {meta.Version + 1, 0, false},
		"a later index of that version": {meta.Version, meta.Index + 1, false},
		"an index of a version above":   {meta.Version + 1, meta.Index + 1000, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateRecoverySnapshot(body, backup, tc.minVersion, tc.minIndex)
			if restored := err == nil; restored != tc.restores {
				t.Fatalf("a floor of version %d at index %d answered %v", tc.minVersion, tc.minIndex, err)
			}
		})
	}
}

// One cluster's backups follow one another. A cluster of another history
// reaches a later version and index without holding what the live cluster
// holds, so the version alone says nothing.
func TestOnlyLaterStateOfTheSameHistoryFollowsABackup(t *testing.T) {
	stored := BackupMeta{ClusterID: testCluster, Version: 4, Index: 90, AppliedDecrees: []string{"genesis", "pins"}}
	for name, tc := range map[string]struct {
		later   BackupMeta
		follows bool
	}{
		"a later index of the same version": {BackupMeta{ClusterID: testCluster, Version: 4, Index: 91, AppliedDecrees: stored.AppliedDecrees}, true},
		"a later version":                   {BackupMeta{ClusterID: testCluster, Version: 5, Index: 95, AppliedDecrees: []string{"genesis", "pins", "voters"}}, true},
		"the same state":                    {stored, false},
		"an earlier index":                  {BackupMeta{ClusterID: testCluster, Version: 4, Index: 89, AppliedDecrees: stored.AppliedDecrees}, false},
		"another cluster":                   {BackupMeta{ClusterID: "another", Version: 5, Index: 95, AppliedDecrees: stored.AppliedDecrees}, false},
		"a cluster started again": {BackupMeta{ClusterID: testCluster, Version: 9, Index: 200,
			AppliedDecrees: []string{"second-genesis"}}, false},
		"a history that dropped a decree": {BackupMeta{ClusterID: testCluster, Version: 5, Index: 95,
			AppliedDecrees: []string{"genesis", "voters"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if follows := tc.later.Follows(stored); follows != tc.follows {
				t.Fatalf("%+v following %+v = %v", tc.later, stored, follows)
			}
		})
	}
}

func TestABoardObjectIsReadThroughTheBoundsABackupHoldsTo(t *testing.T) {
	_, _, backup := sealedState(t)
	object, err := backup.Object()
	if err != nil {
		t.Fatal(err)
	}
	read, err := ParseBackup(object)
	if err != nil {
		t.Fatalf("ParseBackup = %v", err)
	}
	if !bytes.Equal(read.Ciphertext, backup.Ciphertext) || read.Signature != backup.Signature {
		t.Fatal("the backup read off the board is not the one appended to it")
	}
	for name, object := range map[string][]byte{
		"an object that is no backup": []byte(`{"meta":{},"what":1}`),
		"a sealed state larger than a state of this cluster": objectOf(t, Backup{
			Ciphertext: make([]byte, maxSealedBytes()+1),
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBackup(object); err == nil {
				t.Fatalf("%s was read as a backup of this cluster", name)
			}
		})
	}
}

func objectOf(t *testing.T, b Backup) []byte {
	t.Helper()
	object, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return object
}
