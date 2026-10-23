package cdsha

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func TestRecoveryAuthentication(t *testing.T) {
	recovery, _ := operatorKey(t)
	ca := mustCA(t)
	other := mustCA(t)
	key, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	sn := snapshot{Format: Format, Index: 12, Core: Core{Policy: FSMPolicy{Version: 1, LedgerTTLNS: int64(time.Hour), LedgerMax: 8, SecretsMaxPaths: 8, SecretsMaxPerHolder: 4, SecretsMaxValue: 64}, ClusterID: testCluster, Epoch: 4, RootCert: ca.Cert.Raw}, Key: key, Allowlist: []byte("image")}
	var buf bytes.Buffer
	if err := encodeSnapshot(&buf, sn); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	meta := BackupMeta{ClusterID: testCluster, Epoch: 4, Index: 12, CAFingerprint: certutil.CertFingerprint(ca.Cert.Raw)}
	b, err := SealAuthenticatedBackup(&recovery.PublicKey, meta, body, ca.Cert.Raw, key)
	if err != nil {
		t.Fatal(err)
	}
	pin := meta.CAFingerprint
	if err := VerifyBackupSource(b, pin); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(body, meta, 4, 12); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Backup){
		"unsigned":      func(b *Backup) { b.Signature = "" },
		"metadata":      func(b *Backup) { b.Meta.Epoch++ },
		"ciphertext":    func(b *Backup) { b.Ciphertext = bytes.Clone(b.Ciphertext); b.Ciphertext[0] ^= 1 },
		"attacker cert": func(b *Backup) { b.SourceCert = other.Cert.Raw },
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			mutate(&bad)
			if VerifyBackupSource(bad, pin) == nil {
				t.Fatal("accepted replacement")
			}
		})
	}
	if VerifyBackupSource(b, certutil.CertFingerprint(other.Cert.Raw)) == nil {
		t.Fatal("wrong pin")
	}
	renewed, err := issuer.SelfSignCA(ca.Key, "renewed", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealAuthenticatedBackup(&recovery.PublicKey, meta, body, renewed.Raw, key); err == nil {
		t.Fatal("renewed/different live certificate accepted for old snapshot")
	}
	for _, bad := range []BackupMeta{{ClusterID: testCluster, Epoch: 100, Index: 12, CAFingerprint: pin}, {ClusterID: "other", Epoch: 4, Index: 12, CAFingerprint: pin}, {ClusterID: testCluster, Epoch: 4, Index: 13, CAFingerprint: pin}, {ClusterID: testCluster, Epoch: 4, Index: 12, CAFingerprint: "bad"}, {ClusterID: testCluster, Epoch: 4, Index: 12, CAFingerprint: pin, AppliedDecrees: []string{"fake"}}} {
		if ValidateRecoverySnapshot(body, bad, 0, 0) == nil {
			t.Fatal("metadata mismatch")
		}
	}
	if ValidateRecoverySnapshot(body, meta, 4, 13) == nil || ValidateRecoverySnapshot(body, meta, 5, 0) == nil {
		t.Fatal("rollback")
	}
}
func TestRecoveryDecodeBoundsAndOldFormat(t *testing.T) {
	sn := snapshot{Format: Format, Core: Core{Format: Format}}
	header, _ := json.Marshal(sn)
	header = append(header, '\n')
	for _, n := range []int{1024, 1025} {
		raw := append(bytes.Clone(header), bytes.Repeat([]byte{'x'}, n)...)
		got, err := decodeSnapshotBody(bytes.NewReader(raw), Format, false, int64(len(header)), 1024)
		if n == 1024 && (err != nil || len(got.Allowlist) != n) {
			t.Fatalf("boundary: %v", err)
		}
		if n == 1025 && err == nil {
			t.Fatal("oversized image")
		}
	}
	if _, err := decodeSnapshotBody(strings.NewReader(strings.Repeat("x", 1025)), Format, false, 1024, 1024); err == nil {
		t.Fatal("oversized header")
	}
	// Actual former JSON-lines body, not the current SQLite encoder.
	old := []byte("{\"format\":2,\"core\":{\"format\":2}}\n{\"table\":\"documents\",\"rows\":[]}\n")
	if _, err := decodeSnapshotBody(bytes.NewReader(old), Format, false, 1024, 1024); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("format2: %v", err)
	}
}
