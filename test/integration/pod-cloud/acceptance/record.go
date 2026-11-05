package acceptance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// record is the durable intent behind one Cloud launch. A pod record holds the
// signed per-pod document; a generic record holds an unassigned document and,
// once the guest accepted it, the exact assignment bytes it was given. The
// run's ledger, not this file, authorizes cleanup; the record lets observers
// re-verify what the guest was launched and assigned with.
type record struct {
	Version         int           `json:"version"`
	ProviderID      string        `json:"providerID"`
	CloudURL        string        `json:"cloudURL"`
	CredentialHash  string        `json:"credentialHash"`
	UID             types.UID     `json:"uid"`
	Namespace       string        `json:"namespace"`
	Name            string        `json:"name"`
	Key             string        `json:"key"`
	Request         createRequest `json:"request"`
	Manifest        []byte        `json:"manifest"` // The image manifest readGuest attests against; the pod manifest is in the document.
	VCPUs           int64         `json:"vCPUs"`
	MemoryMiB       int64         `json:"memoryMiB"`
	CreatedAt       time.Time     `json:"createdAt"`
	CreateAttempted bool          `json:"createAttempted,omitempty"`
	InstanceID      string        `json:"instanceID,omitempty"`
	Generic         bool          `json:"generic,omitempty"`
	Allocation      string        `json:"allocation,omitempty"` // Pod record: the generic record key it was assigned to.
	Assignment      []byte        `json:"assignment,omitempty"`
	ServingKey      []byte        `json:"servingKey,omitempty"`
}

// document re-verifies the frozen launch and checks that the record's own
// identity fields are the ones the signed document names.
func (r *record) document() (*launchconfig.Document, error) {
	doc, err := signedDocument(r.Request.Trust)
	if err != nil {
		return nil, err
	}
	if doc.Role != launchconfig.Pod || doc.Node.Name != r.Key || doc.PodOperatorPublicKey != r.Request.Trust.LaunchKey {
		return nil, errors.New("stored launch identity differs from its signed document")
	}
	if r.Generic {
		if doc.Pod != nil || doc.Workloads != "" || r.UID != "" || r.Name != "" || r.Namespace != "" {
			return nil, errors.New("generic launch carries Pod authority")
		}
		return doc, nil
	}
	if doc.Pod == nil || doc.Pod.UID != string(r.UID) || doc.Pod.Name != r.Name || doc.Pod.Namespace != r.Namespace {
		return nil, errors.New("stored Pod identity differs from its signed launch")
	}
	return doc, nil
}

// assignmentPayload is what a generic guest is given: the pod manifest, the
// allowlist entries and the mesh peers of the pod record's signed document.
func assignmentPayload(rec *record) ([]byte, []byte, []byte, error) {
	doc, err := rec.document()
	if err != nil {
		return nil, nil, nil, err
	}
	if doc.Pod == nil {
		return nil, nil, nil, errors.New("generic launch has no Pod to assign")
	}
	peers := doc.Pod.MeshPeers
	if peers == nil {
		peers = []string{}
	}
	data, err := json.Marshal(peers)
	return []byte(doc.Pod.Manifest), []byte(doc.Workloads), data, err
}

func validateStoredAssignment(generic *record) error {
	req, err := podassign.Decode(generic.Assignment)
	if err != nil {
		return errors.New("stored assignment is malformed")
	}
	serving, err := x509.ParsePKIXPublicKey(generic.ServingKey)
	if err != nil {
		return errors.New("stored assignment serving key is invalid")
	}
	block, rest := pem.Decode([]byte(generic.Request.Trust.LaunchKey))
	if block == nil || len(rest) != 0 {
		return errors.New("stored assignment launch key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("stored assignment launch key is invalid")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || podassign.Verify(key, serving, req) != nil {
		return errors.New("stored assignment signature is invalid")
	}
	return nil
}

// assignmentMatches checks that the assignment a generic record holds is the
// pod record's frozen payload, signed by the launch key the guest trusts.
func assignmentMatches(rec, generic *record) error {
	if err := validateStoredAssignment(generic); err != nil {
		return err
	}
	req, err := podassign.Decode(generic.Assignment)
	if err != nil {
		return err
	}
	manifest, entries, peers, err := assignmentPayload(rec)
	if err != nil {
		return err
	}
	if !bytes.Equal(req.Manifest, manifest) || !bytes.Equal(req.Entries, entries) || !bytes.Equal(req.MeshPeers, peers) {
		return errors.New("stored assignment differs from the frozen Pod")
	}
	return nil
}

func credentialHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// signedDocument re-verifies a frozen request's launch document against the
// launch key the request itself carries before any field of it is trusted.
func signedDocument(trust trustSpec) (*launchconfig.Document, error) {
	if trust.InitData.Format != launchconfig.SchemaVersion {
		return nil, errors.New("stored launch format is invalid")
	}
	doc, err := launchconfig.Parse(trust.InitData.Document)
	if err != nil {
		return nil, errors.New("stored launch document is invalid")
	}
	block, rest := pem.Decode([]byte(trust.LaunchKey))
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid stored launch public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid stored launch public key")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid stored launch key type")
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{pub}, trust.InitData.Document, string(trust.InitData.Signature)); err != nil {
		return nil, errors.New("stored launch signature does not verify")
	}
	return doc, nil
}
