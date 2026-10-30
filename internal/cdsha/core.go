package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// ClusterState is the state every replica of a cluster agrees on. It carries no
// signature of its own: the log is its history, and the log is read only
// inside the attested replicas.
type ClusterState struct {
	// Policy is the limits the cluster applies commands under, fixed by its
	// Genesis.
	Policy Policy `json:"policy"`
	// ClusterID and ConfigSHA256 name the cluster and the launch file every
	// replica of it boots.
	ClusterID    string `json:"cluster_id"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
	// Version counts the operator commands applied; a decree names the
	// version it applies on.
	Version uint64 `json:"version"`
	// MeshCACert is the mesh CA certificate in DER; its key never enters ClusterState.
	MeshCACert []byte `json:"mesh_ca_cert,omitempty"`
	// PinsDecree is the applied decree naming the images a CDS of this
	// cluster may run, which peers, nodes and clients all pin it by.
	PinsDecree *cdsdecree.Signed     `json:"pins_decree,omitempty"`
	NodeImages *cdsdecree.NodeImages `json:"node_images,omitempty"`
	Voters     int                   `json:"voters,omitempty"`
	// AppliedDecrees are the intents the cluster has accounted for, so none
	// of them applies or raises a doubt twice.
	AppliedDecrees []string `json:"applied_decrees,omitempty"`
	// StartedAtMS is when the cluster last started: its Genesis, or the
	// Recover since. Operator tokens issued before it are refused, and the
	// allowlist version never goes below it.
	StartedAtMS int64 `json:"started_at_ms,omitempty"`
	// Format is the encoding every replica writes; 0 is baseFormat.
	Format uint32 `json:"format,omitempty"`
	// Doubts are the Recover decrees no replica could confirm.
	Doubts []Doubt `json:"doubts,omitempty"`
}

// Doubt is a Recover decree whose member may be carrying the cluster on
// alone. Every replica fences until that member rejoins or a DismissRecover
// lifts the doubt.
type Doubt struct {
	Intent string `json:"intent"`
	Member string `json:"member"`
}

// Launch is what a replica booted with: the cluster it belongs to, the keys
// whose decrees it obeys, the digest of its own launch file and the voter
// seats a Genesis starts with. No log entry replaces them.
type Launch struct {
	ClusterID    string
	OperatorKeys []*ecdsa.PublicKey
	ConfigSHA256 string
	Voters       int
}

// check refuses a launch no replica can serve: without a launch file digest
// it would take a pin decree for any other cluster's, and without operator
// keys it could adopt no decree at all.
func (l Launch) check() error {
	switch {
	case l.ClusterID == "":
		return errors.New("cds-ha: a replica launches with the id of its cluster")
	case len(l.OperatorKeys) == 0:
		return errors.New("cds-ha: a replica launches with the operator keys whose decrees it obeys")
	case l.ConfigSHA256 == "":
		return errors.New("cds-ha: a replica launches with the digest of its own launch file")
	case l.Voters <= 0:
		return errors.New("cds-ha: a replica launches with the voter seats its cluster starts with")
	}
	return nil
}

// Joined reports a replica holding the cluster's mesh CA.
func (c ClusterState) Joined() bool {
	return len(c.MeshCACert) > 0
}

// accountedFor reports a decree the cluster has applied, or a Recover whose
// doubt it dismissed.
func (c ClusterState) accountedFor(intent string) bool {
	return slices.Contains(c.AppliedDecrees, intent)
}

// dealtWith reports a Recover decree that raises no doubt: the cluster
// applied it, dismissed its doubt, or holds that doubt already.
func (c ClusterState) dealtWith(intent string) bool {
	return c.accountedFor(intent) || c.doubted(intent)
}

func (c ClusterState) doubted(intent string) bool {
	return slices.ContainsFunc(c.Doubts, raisedBy(intent))
}

func raisedBy(intent string) func(Doubt) bool {
	return func(d Doubt) bool { return d.Intent == intent }
}

func withoutDoubt(doubts []Doubt, intent string) []Doubt {
	return slices.DeleteFunc(slices.Clone(doubts), raisedBy(intent))
}

// clone copies the state a reader holds while the log moves on. The decrees
// it names are immutable, so they are shared.
func (c ClusterState) clone() ClusterState {
	c.MeshCACert = slices.Clone(c.MeshCACert)
	c.AppliedDecrees = slices.Clone(c.AppliedDecrees)
	c.Doubts = slices.Clone(c.Doubts)
	return c
}

// DecreeEntry applies one operator decree. The leader stamps the time and,
// for the kinds that mint one, the mesh CA, so every replica reaches the same
// state; each replica verifies the operator's signature itself.
type DecreeEntry struct {
	Decree cdsdecree.Signed `json:"decree"`
	AtMS   int64            `json:"at_ms"`
	// Policy is fixed for the cluster's life by its Genesis.
	Policy Policy `json:"policy"`
	// MeshCACert and MeshCAKey are the minted mesh CA: DER and PKCS#8.
	MeshCACert []byte `json:"mesh_ca_cert,omitempty"`
	MeshCAKey  []byte `json:"mesh_ca_key,omitempty"`
}

func (de DecreeEntry) kind() cdsdecree.Kind {
	return de.Decree.Decree.Kind
}

// DecreeResult is what applying a decree, or recording a doubt about one,
// produced: the cluster's version afterwards, and why it was refused, which
// leaves the cluster as it was.
type DecreeResult struct {
	Version uint64 `json:"version"`
	Refused string `json:"refused,omitempty"`
}

// nextCore is the state after decree entry de applies on cur, or why it does
// not apply. It reads and returns values only, so every replica runs it over
// the same entry and reaches the same state or all refuse; its caller holds
// the lock and installs the state and its mesh CA together.
func nextCore(launch Launch, cur ClusterState, de DecreeEntry) (ClusterState, *issuer.CA, error) {
	if err := checkDecree(launch, cur, de); err != nil {
		return ClusterState{}, nil, err
	}
	next := cur.clone()
	var ca *issuer.CA
	if mintsMeshCA(de.kind()) {
		var err error
		if ca, err = adoptMeshCA(&next, de); err != nil {
			return ClusterState{}, nil, err
		}
	}
	d := de.Decree.Decree
	switch d.Kind {
	case cdsdecree.Genesis:
		if err := startCluster(launch, &next, de); err != nil {
			return ClusterState{}, nil, err
		}
	case cdsdecree.Recover:
		next.StartedAtMS = startMS(d, de.AtMS)
		next.Doubts = withoutDoubt(next.Doubts, d.IntentID)
	case cdsdecree.UpdateMeasurements:
		next.PinsDecree = &de.Decree
	case cdsdecree.SetVoters:
		next.Voters = d.Voters
	case cdsdecree.DismissRecover:
		next.Doubts = withoutDoubt(next.Doubts, d.RecoverIntent)
		// The dismissed Recover is accounted for, so the host cannot have it
		// doubted again.
		next.AppliedDecrees = append(next.AppliedDecrees, d.RecoverIntent)
	}
	next.countDecree(d)
	return next, ca, nil
}

// startCluster is the state a Genesis starts a cluster in: the policy and
// launch file of the replica applying it, the image sets the operator signed,
// and the voter seats its configuration names.
func startCluster(launch Launch, next *ClusterState, de DecreeEntry) error {
	d := de.Decree.Decree
	// INVARIANT: the mesh CA is the one the operator signed for. Whoever
	// logged the entry chose its bytes.
	if certutil.CertFingerprint(de.MeshCACert) != d.GenesisCA {
		return errors.New("the Genesis entry carries another mesh CA than the decree names")
	}
	next.Policy = de.Policy
	next.ConfigSHA256 = launch.ConfigSHA256
	next.PinsDecree = &de.Decree
	next.NodeImages = d.NodePins
	next.Voters = launch.Voters
	// A cluster starts at the oldest format its release reads, whatever the
	// replica that started it could write.
	next.Format = baseFormat
	next.StartedAtMS = startMS(d, de.AtMS)
	return nil
}

func (c *ClusterState) countDecree(d cdsdecree.Decree) {
	if d.ResumeVersion > c.Version {
		// Genesis and Recover resume above the highest version the operator
		// knows this cluster id reached.
		c.Version = d.ResumeVersion
	}
	c.Version++
	c.AppliedDecrees = append(c.AppliedDecrees, d.IntentID)
}

// startMS is the later of the operator's signature and the leader's stamp, so
// no replica clock moves a cluster's start outside that window.
func startMS(d cdsdecree.Decree, atMS int64) int64 {
	return max(d.IssuedAtMS, atMS)
}

// checkDecree is what a decree must satisfy before it changes any state: the
// operator's signature over everything it says, a place in the cluster's life,
// an expiry the leader's stamp is inside, an intent the cluster has not
// accounted for, and pins binding this replica's own launch file.
func checkDecree(launch Launch, cur ClusterState, de DecreeEntry) error {
	if err := cdsdecree.Verify(de.Decree, launch.OperatorKeys, launch.ClusterID); err != nil {
		return err
	}
	d := de.Decree.Decree
	if err := checkLife(cur, d); err != nil {
		return err
	}
	switch {
	case expired(d, de.AtMS):
		return fmt.Errorf("the %s decree expired at %s", d.Kind, d.ExpiresAt.UTC().Format(time.RFC3339))
	case cur.accountedFor(d.IntentID):
		return fmt.Errorf("decree %s has applied before", d.IntentID)
	case d.CDSPins != nil && d.CDSPins.LaunchFileSHA256 != launch.ConfigSHA256:
		return fmt.Errorf("the decree pins CDS images of launch file %s, and this replica boots %s", d.CDSPins.LaunchFileSHA256, launch.ConfigSHA256)
	}
	return nil
}

// expired judges a decree by the leader's stamp: one clock for the whole group.
func expired(d cdsdecree.Decree, atMS int64) bool {
	return !time.UnixMilli(atMS).Before(d.ExpiresAt)
}

// checkLife requires a decree's kind to have a place in the cluster's life: a
// Genesis starts one, every other kind carries one on from the version it
// names, and an Admit is answered by an unjoined replica rather than applied.
func checkLife(cur ClusterState, d cdsdecree.Decree) error {
	switch {
	case d.Kind == cdsdecree.Admit:
		return errors.New("an Admit decree admits an image to one unjoined replica; it never applies")
	case d.Kind == cdsdecree.Genesis && cur.Joined():
		return errors.New("a Genesis decree starts a cluster, and this one holds a mesh CA")
	case d.Kind != cdsdecree.Genesis && !cur.Joined():
		return fmt.Errorf("a %s decree carries a cluster on, and this replica holds none", d.Kind)
	case d.Kind != cdsdecree.Genesis && d.BaseVersion != cur.Version:
		return fmt.Errorf("the decree applies on version %d, and the cluster is at version %d", d.BaseVersion, cur.Version)
	case d.Kind == cdsdecree.DismissRecover && !cur.doubted(d.RecoverIntent):
		return fmt.Errorf("the cluster holds no doubt of Recover %s to dismiss", d.RecoverIntent)
	}
	return nil
}

func mintsMeshCA(kind cdsdecree.Kind) bool {
	return kind == cdsdecree.Genesis || kind == cdsdecree.RotateKey
}

func adoptMeshCA(next *ClusterState, de DecreeEntry) (*issuer.CA, error) {
	ca, err := meshCA(de.MeshCACert, de.MeshCAKey)
	if err != nil {
		return nil, err
	}
	next.MeshCACert = slices.Clone(de.MeshCACert)
	return ca, nil
}

// caEntryBytes is the certificate in DER and the key in PKCS#8, as a log entry
// carries them.
func caEntryBytes(ca *issuer.CA) (cert, key []byte, err error) {
	key, err = x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, nil, err
	}
	return ca.Cert.Raw, key, nil
}

// RenewCAEntry carries the mesh CA certificate the leader signed again under
// the key every replica already holds.
type RenewCAEntry struct {
	MeshCACert []byte `json:"mesh_ca_cert"`
}

// renewalOf is the cluster's mesh CA under the certificate der holds: its one
// key, and the issuer its live leaves name.
func renewalOf(ca *issuer.CA, der []byte) (*issuer.CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("renewed mesh CA certificate: %w", err)
	}
	if !speaksFor(cert, ca.Key) {
		return nil, errors.New("the renewed mesh CA certificate speaks for another key than the cluster's")
	}
	if !namesTheSameIssuer(ca.Cert, cert) {
		return nil, errors.New("the renewed mesh CA certificate names another issuer than the leaves of this cluster")
	}
	return &issuer.CA{Cert: cert, Key: ca.Key}, nil
}

func speaksFor(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	public, ecdsaKey := cert.PublicKey.(*ecdsa.PublicKey)
	return ecdsaKey && public.Equal(&key.PublicKey)
}

// namesTheSameIssuer: a leaf names the CA that signed it by subject and key
// identifier.
func namesTheSameIssuer(held, renewed *x509.Certificate) bool {
	return bytes.Equal(held.RawSubject, renewed.RawSubject) &&
		bytes.Equal(held.SubjectKeyId, renewed.SubjectKeyId)
}

// meshCA checks that a certificate in DER and a key in PKCS#8 belong together.
func meshCA(certDER, keyPKCS8 []byte) (*issuer.CA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("mesh CA certificate: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("mesh CA key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the mesh CA key is not ECDSA")
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return nil, errors.New("the mesh CA key does not match its certificate")
	}
	return &issuer.CA{
		Cert: cert,
		Key:  key,
	}, nil
}
