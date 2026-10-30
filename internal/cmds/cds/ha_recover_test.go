package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// `ha recover` opens a backup with the recovery key the configuration names
// and hands the state to one replica, with a Restore decree naming that
// state, the images of the configuration the replicas boot now, and the
// version the restored cluster resumes above.

// restoringCluster is a cluster whose every replica is lost: the
// configuration they booted, the operator key that configuration pins, and
// the recovery key its backups seal to.
type restoringCluster struct {
	operatorCluster
	recovery     *ecdsa.PrivateKey
	recoveryPath string
}

func newRestoringCluster(t *testing.T) restoringCluster {
	t.Helper()
	c := newOperatorCluster(t)
	recovery, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.config = documentSealingTo(t, c.operatorPEM, &recovery.PublicKey)
	writeTestFile(t, c.configPath, c.config)
	writeTestFile(t, c.cdsPinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config))))
	keyPEM, err := certutil.MarshalECKeyPEM(recovery)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recovery.pem")
	writeTestFile(t, path, keyPEM)
	return restoringCluster{operatorCluster: c, recovery: recovery, recoveryPath: path}
}

// documentSealingTo is the configuration of a replicated cluster whose
// backups seal to one recovery key.
func documentSealingTo(t *testing.T, operatorPEM []byte, recovery *ecdsa.PublicKey) []byte {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(replicatedDocument(t, operatorPEM), &document); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(recovery)
	if err != nil {
		t.Fatal(err)
	}
	ha, named := document["ha"].(map[string]any)
	if !named {
		t.Fatalf("the replicated configuration names no replica set: %v", document["ha"])
	}
	ha["recoveryKey"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sealing, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return sealing
}

// restoreOptions are the flags of a restore the operator has already opened
// the backup for.
func (c restoringCluster) restoreOptions(t *testing.T, target replica) restoreOptions {
	t.Helper()
	return restoreOptions{
		decreeOptions: decreeOptions{
			config:      c.configPath,
			operatorKey: c.keyPath,
			expiresIn:   defaultDecreeValidity,
		},
		pins:          pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, smp2Digest)}},
		target:        target,
		recoveryKey:   c.recoveryPath,
		resumeVersion: 12,
		acknowledge:   true,
	}
}

// takenRestore is a replica that holds no cluster and answers a restore: it
// keeps what the operator posted, so a test reads the decree and the state it
// was handed.
type takenRestore struct {
	replica
	answer func(http.ResponseWriter)

	mu     sync.Mutex
	posted []byte
}

// targetTaking is a replica of this cluster answering status and taking a
// restore with answer.
func (c restoringCluster) targetTaking(t *testing.T, status cdsha.Status, answer func(http.ResponseWriter)) *takenRestore {
	t.Helper()
	taken := &takenRestore{answer: answer}
	handler := http.NewServeMux()
	handler.HandleFunc("GET "+statusPath, func(w http.ResponseWriter, _ *http.Request) {
		body, err := json.Marshal(status)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	handler.HandleFunc("POST "+restorePath, func(w http.ResponseWriter, r *http.Request) {
		posted, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		taken.keep(posted)
		taken.answer(w)
	})
	server := testutil.NewARMTLSServer(t, handler)
	taken.replica = replica{
		address:  strings.TrimPrefix(server.URL, "https://"),
		cdsPin:   c.cdsPinPath,
		verifier: c.verifier(),
	}
	return taken
}

func (r *takenRestore) keep(posted []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.posted = posted
}

// handed is the decree and the state the operator posted.
func (r *takenRestore) handed(t *testing.T) (cdsdecree.Signed, []byte) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	line, state, split := bytes.Cut(r.posted, []byte{'\n'})
	if !split {
		t.Fatalf("the replica was posted %d bytes carrying no decree line", len(r.posted))
	}
	signed, err := cdsdecree.Parse(line)
	if err != nil {
		t.Fatalf("the decree the replica was posted: %v", err)
	}
	return signed, state
}

// restored is a replica answering that it started the cluster again.
func restored(version uint64) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		body, _ := json.Marshal(cdsha.DecreeResult{Version: version})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// refusing is a replica that restores nothing, in the words it answers with.
func refusing(reason string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		http.Error(w, reason, http.StatusConflict)
	}
}

// unjoined is what a replica of this cluster that holds none and found no
// replica holding one reports.
func (c restoringCluster) unjoined() cdsha.Status {
	return cdsha.Status{
		ClusterID:       c.clusterID,
		ID:              targetMember,
		GenesisCA:       targetGenesis,
		AwaitingRestore: "this replica holds no cluster and reached no replica that holds one: the cluster may be lost",
	}
}

// restoring runs the delivery of one restore and answers with what the
// command printed.
func (c restoringCluster) restoring(t *testing.T, o restoreOptions, state []byte) (string, error) {
	t.Helper()
	return reading(t, func(cmd *cobra.Command) error {
		return o.deliver(cmd, c.decreed(t), state)
	})
}

// The decree the target acts on names the state it was handed, the process it
// reached, the images of the configuration its replicas boot now, and the
// version the restored cluster resumes above.
func TestARestoreHandsOneReplicaTheDecreeAndTheStateItNames(t *testing.T) {
	c := newRestoringCluster(t)
	state := []byte("the state the operator opened from a sealed backup")
	target := c.targetTaking(t, c.unjoined(), restored(42))
	o := c.restoreOptions(t, target.replica)

	printed, err := c.restoring(t, o, state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed, "version 42") {
		t.Fatalf("the command printed %q, want the version the restored cluster is at", printed)
	}
	signed, handed := target.handed(t)
	if !bytes.Equal(handed, state) {
		t.Fatalf("the replica was handed %q, want the state the backup held", handed)
	}
	decree := signed.Decree
	switch {
	case decree.Kind != cdsdecree.Restore:
		t.Fatalf("the operator posted a %s decree", decree.Kind)
	case decree.TargetMember != targetMember:
		t.Fatalf("the decree names member %q, and the replica reported %q", decree.TargetMember, targetMember)
	case decree.TargetAddress != target.address:
		t.Fatalf("the decree names address %q, want the one dialled %q", decree.TargetAddress, target.address)
	case decree.StateSHA256 != cdsha.StateSHA256(state):
		t.Fatalf("the decree names state %s, and the replica was handed %s", decree.StateSHA256, cdsha.StateSHA256(state))
	case decree.ResumeVersion != o.resumeVersion || decree.IssuedAtMS == 0:
		t.Fatalf("the decree resumes above %d, issued at %d", decree.ResumeVersion, decree.IssuedAtMS)
	case decree.Alone:
		t.Fatal("the decree says alone, and the operator did not")
	}
	if pins, err := decree.CDSPins.WithLaunchFile(c.config); err != nil || len(pins.Images) != 1 {
		t.Fatalf("the decree pins %+v of the configuration the replicas boot: %v", pins, err)
	}
	nodes, err := decree.NodePins.Images()
	if err != nil || nodes.Family != teetypes.FamilyTDX || len(nodes.Images) != 1 {
		t.Fatalf("the decree certifies %+v, want the configuration's nodes: %v", nodes, err)
	}
	if err := cdsdecree.Verify(signed, c.decreed(t).parsed.OperatorKeys.Keys(), c.clusterID); err != nil {
		t.Fatalf("the decree the operator posted: %v", err)
	}
}

// A replica that restored nothing answers why, and the operator is pointed at
// the decree record: a restore the replica committed before the connection
// broke is in it.
func TestARefusedRestoreIsReportedInTheReplicasWords(t *testing.T) {
	c := newRestoringCluster(t)
	target := c.targetTaking(t, c.unjoined(), refusing("cds-ha: a replica of this cluster holds it"))
	o := c.restoreOptions(t, target.replica)

	_, err := c.restoring(t, o, []byte("the state"))
	if err == nil {
		t.Fatal("a refused restore was reported as one that happened")
	}
	signed, _ := target.handed(t)
	for _, want := range []string{"a replica of this cluster holds it", signed.Decree.IntentID, "ha decrees"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("a refused restore answered %q, want %q in it", err, want)
		}
	}
}

// A restore starts a lost cluster again, so the target replica must hold
// none, and it must be a replica of this cluster.
func TestARestoreGoesToAReplicaOfThisClusterThatHoldsNone(t *testing.T) {
	c := newRestoringCluster(t)
	for name, status := range map[string]cdsha.Status{
		"a replica holding a cluster":   {ClusterID: c.clusterID, ID: targetMember, Joined: true},
		"a replica of another cluster":  {ClusterID: "another", ID: targetMember},
		"a replica reporting no member": {ClusterID: c.clusterID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkRestoreTarget(status, c.clusterID); err == nil {
				t.Fatal("the target was accepted")
			}
		})
	}
	if err := checkRestoreTarget(c.unjoined(), c.clusterID); err != nil {
		t.Fatalf("a replica of this cluster holding none was refused: %v", err)
	}
}

// Only the key the configuration seals its backups to opens one, so a key
// file that is not it is refused before the board is read.
func TestARestoreTakesTheRecoveryKeyTheConfigurationNames(t *testing.T) {
	c := newRestoringCluster(t)
	o := c.restoreOptions(t, replica{})
	if _, err := o.loadRecoveryKey(c.decreed(t)); err != nil {
		t.Fatalf("the key the configuration names was refused: %v", err)
	}
	another, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(another)
	if err != nil {
		t.Fatal(err)
	}
	o.recoveryKey = filepath.Join(t.TempDir(), "another.pem")
	writeTestFile(t, o.recoveryKey, keyPEM)
	if _, err := o.loadRecoveryKey(c.decreed(t)); err == nil {
		t.Fatal("a key the configuration does not name was taken as the recovery key")
	}
}
