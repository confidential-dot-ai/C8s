package launchconfig

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// MaxSignatureSize bounds a detached launch signature.
const MaxSignatureSize = maxSignatureSize

// AuthenticateAgent checks, on the server, an agent document presented at
// enrollment: signed by one of this server's authorized agent keys, an agent
// of this cluster designating this server, and never this server's own name.
// It returns the document and the exact PEM of the key that signed it, which
// the caller must also find measured into the presenting agent's attestation.
//
// Launch documents are not measured, only their keys, and one agent key may
// sign many documents. So this proves the name was signed for some agent, not
// that it was signed for the agent presenting it.
func (s *Document) AuthenticateAgent(data []byte, signature string) (*Document, string, error) {
	if s.Role != Server {
		return nil, "", fmt.Errorf("only a server authenticates agent documents")
	}
	var signer string
	for _, pub := range s.AgentOperatorPublicKeys {
		key, err := parseLaunchKey(pub)
		if err != nil {
			return nil, "", fmt.Errorf("server agent key: %w", err)
		}
		if operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, data, signature) == nil {
			signer = pub
			break
		}
	}
	if signer == "" {
		return nil, "", fmt.Errorf("agent document is not signed by an authorized agent key")
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, "", err
	}
	if doc.Role != Agent {
		return nil, "", fmt.Errorf("enrolling document has role %s, not agent", doc.Role)
	}
	if doc.ClusterID != s.ClusterID {
		return nil, "", fmt.Errorf("agent document belongs to cluster %q", doc.ClusterID)
	}
	if doc.Node.Name == s.Node.Name {
		return nil, "", fmt.Errorf("agent document names the server node")
	}
	if !bytes.Equal([]byte(doc.Server.OperatorPublicKey), []byte(s.Server.OperatorPublicKey)) {
		return nil, "", fmt.Errorf("agent document designates another server")
	}
	key, err := parseLaunchKey(signer)
	if err != nil {
		return nil, "", err
	}
	if err := doc.authorizeKey([]byte(signer), key); err != nil {
		return nil, "", err
	}
	return doc, signer, nil
}
