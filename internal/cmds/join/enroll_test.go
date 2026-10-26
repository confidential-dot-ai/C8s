package join

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	testCluster    = "cluster-one"
	testServerName = "server-one"
	testAgentName  = "agent-one"
	testPassword   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// testServerLaunchKey signs the fixture server's own document; it is never an
// agent key.
var testServerLaunchKey, testServerLaunchPEM = newLaunchKey()

func newLaunchKey() (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func launchPlatform(p teetypes.PlatformType) string {
	if p == teetypes.PlatformSNP {
		return "snp"
	}
	return "tdx"
}

// testServerDoc is the server document a join-release fixture stages: its
// agent keys are exactly agentKeys, and its image is the policy's digestA.
func testServerDoc(platform teetypes.PlatformType, agentKeys ...[]byte) *launchconfig.Document {
	doc := &launchconfig.Document{
		SchemaVersion: launchconfig.SchemaVersion, ClusterID: testCluster, Role: launchconfig.Server,
		Image:  launchconfig.Image{Platform: launchPlatform(platform), Measurement: digestA},
		Node:   launchconfig.Node{Name: testServerName, IP: "192.0.2.10"},
		Server: launchconfig.ServerConfig{Address: "192.0.2.10", OperatorPublicKey: string(testServerLaunchPEM)},
	}
	if platform == teetypes.PlatformTDX {
		doc.Image.RTMRs = map[int]string{1: rtmr1A, 2: rtmr2A}
	}
	for _, key := range agentKeys {
		doc.AgentOperatorPublicKeys = append(doc.AgentOperatorPublicKeys, string(key))
	}
	return doc
}

// agentDocument derives the named agent's document from server, as add-agent
// does, and signs it with key.
func agentDocument(t *testing.T, server *launchconfig.Document, name string, key *ecdsa.PrivateKey, mutate func(*launchconfig.Document)) ([]byte, string) {
	t.Helper()
	doc := *server
	doc.Role = launchconfig.Agent
	doc.Node = launchconfig.Node{Name: name}
	if mutate != nil {
		mutate(&doc)
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := operatorauth.SignDetached(key, data)
	if err != nil {
		t.Fatal(err)
	}
	return data, signature + "\n"
}

// joinBody is the /join request an agent named name sends.
func joinBody(t *testing.T, server *launchconfig.Document, name string, key *ecdsa.PrivateKey, mutate func(*launchconfig.Document)) []byte {
	t.Helper()
	data, signature := agentDocument(t, server, name, key, mutate)
	body, err := json.Marshal(joinRequest{Document: data, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// writePasswordKey writes a node-password key as launch staging does.
func writePasswordKey(t *testing.T, dir string) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rke2-node-password-key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// readPasswordKey loads a key from ordinary test storage; production loads
// only from RAM-backed storage.
func readPasswordKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(data))
}

// writeStagedServer writes the server document where LoadStaged reads it.
func writeStagedServer(t *testing.T, dir string, doc *launchconfig.Document) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
