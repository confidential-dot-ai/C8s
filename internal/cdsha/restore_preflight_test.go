package cdsha

import (
	"bytes"
	"context"
	"crypto/x509"
	"math"
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Every refusal must leave this same target usable for the subsequent valid
// restore. No Run loop or external peer is needed. Execute with a package timeout.
func TestRestorePreflightPreservesFreshTarget(t *testing.T) {
	for _, mode := range []string{"policy", "compressed", "sqlite", "ca-key", "cluster", "operator", "epoch-overflow", "hash", "signature"} {
		t.Run(mode, func(t *testing.T) {
			key, pub := operatorKey(t)
			cfg := soloConfig(t, "n0", freeAddr(t), pub, nil)
			n, err := NewNode(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Start(); err != nil {
				t.Fatal(err)
			}
			defer n.shutdown()
			ca := mustCA(t)
			der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
			if err != nil {
				t.Fatal(err)
			}
			image, err := cfg.Allowlist.Dump()
			if err != nil {
				t.Fatal(err)
			}
			good := snapshot{Format: Format, Index: 9, Key: der, Allowlist: image,
				Core: Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 1,
					RootCert: ca.Cert.Raw, Policy: n.fsm.LocalPolicy(), Format: Format,
					Measurements: []string{"m1"}, Seats: 1}}
			encode := func(sn snapshot) []byte {
				t.Helper()
				var buf bytes.Buffer
				if err := encodeSnapshot(&buf, sn); err != nil {
					t.Fatal(err)
				}
				return buf.Bytes()
			}
			if mode == "epoch-overflow" {
				good.Core.Epoch = math.MaxUint64 - 1
			}
			bad := good
			switch mode {
			case "policy":
				bad.Core.Policy.LedgerTTLNS++
			case "sqlite":
				bad.Allowlist = []byte("not SQLite")
			case "ca-key":
				other := mustCA(t)
				bad.Key, err = x509.MarshalPKCS8PrivateKey(other.Key)
				if err != nil {
					t.Fatal(err)
				}
			case "cluster":
				bad.Core.ClusterID = "another-cluster"
			case "operator":
				_, bad.Core.OperatorPubKey = operatorKey(t)
			case "epoch-overflow":
				bad.Core.Epoch = math.MaxUint64
			}
			body := encode(bad)
			// The policy mismatch fixture is a genuine CA-signed, HPKE-encrypted backup,
			// exactly as CLI recovery authenticates it, not a hash-only corruption.
			if mode == "policy" {
				recovery, _ := operatorKey(t)
				meta := BackupMeta{ClusterID: testCluster, Epoch: bad.Core.Epoch, Index: bad.Index, CAFingerprint: certutil.CertFingerprint(ca.Cert.Raw)}
				backup, err := SealAuthenticatedBackup(&recovery.PublicKey, meta, body, ca.Cert.Raw, der)
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyBackupSource(backup, meta.CAFingerprint); err != nil {
					t.Fatal(err)
				}
				body, err = OpenBackup(recovery, backup)
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateRecoverySnapshot(body, meta, 1, 9); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "compressed" {
				body = []byte("not zstd")
			}
			sd := signDecree(t, key, Decree{Kind: Restore, BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(body)})
			if mode == "hash" {
				body = append(body, 0)
			}
			if mode == "signature" {
				other, _ := operatorKey(t)
				sd = signDecree(t, other, sd.Decree)
			}
			beforeCore := n.Core()
			beforeMembers := n.servers()
			beforeIndex := n.fsm.AppliedIndex()
			beforeLog := n.r().LastIndex()
			beforeSecrets := cfg.Secrets.Dump()
			beforeBindings := cfg.Ledger.Dump()
			beforeCA := n.fsm.CA()
			if _, err := n.Restore(context.Background(), sd, body); err == nil {
				t.Fatal("invalid restore accepted")
			}
			afterImage, err := cfg.Allowlist.Dump()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(n.servers(), beforeMembers) || n.member() ||
				!reflect.DeepEqual(n.Core(), beforeCore) || n.fsm.AppliedIndex() != beforeIndex ||
				n.r().LastIndex() != beforeLog || n.fsm.CA() != beforeCA ||
				!bytes.Equal(image, afterImage) || !reflect.DeepEqual(cfg.Secrets.Dump(), beforeSecrets) ||
				!reflect.DeepEqual(cfg.Ledger.Dump(), beforeBindings) {
				t.Fatal("refused restore changed membership, log, core or application stores")
			}
			validBody := encode(good)
			valid := signDecree(t, key, Decree{Kind: Restore, BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(validBody)})
			result, err := n.Restore(context.Background(), valid, validBody)
			if err != nil || result.Err != "" || !n.member() || !n.Core().Joined() || n.Core().Epoch != good.Core.Epoch+1 {
				t.Fatalf("same fresh target cannot restore valid backup: result=%+v err=%v core=%+v", result, err, n.Core())
			}
		})
	}
}
