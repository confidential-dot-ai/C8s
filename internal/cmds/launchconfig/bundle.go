package launchconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A bundle is one cluster's complete launch input, laid out so each node's
// opkeydata disk is one directory and the operator's private material sits
// beside it, never inside it:
//
//	<dir>/server.key      server launch key; also the operator key that
//	                      get-kubeconfig and signed CDS writes use
//	<dir>/agent.key    the one agent launch key this cluster trusts
//	<dir>/server.json     client policy pinning the server (C8S_MEASUREMENTS_CONFIG)
//	<dir>/server/         pubkey, launch.yaml, launch.yaml.sig
//	<dir>/<agent>/     pubkey, launch.yaml, launch.yaml.sig, one per agent
const (
	serverKeyFile = "server.key"
	agentKeyFile  = "agent.key"
	serverPolicy  = "server.json"
	serverDir     = "server"
	pubkeyFile    = "pubkey"
	documentFile  = "launch.yaml"
	signatureFile = documentFile + ".sig"
)

// BundleOptions describes a new cluster's launch bundle.
type BundleOptions struct {
	Dir           string
	ClusterID     string
	ManifestPath  string
	VCPUs         int
	ServerName    string
	ServerAddress string
	Agents        []string
	TLSSAN        string
	WorkloadsPath string
}

// NewBundle generates the cluster's two launch keys, writes and signs the
// server document plus one agent document per name, and
// emits the client policy. Dir must not exist; a failed run removes it so a
// half-written bundle can never be attached.
func NewBundle(opts BundleOptions) (err error) {
	if opts.Dir == "" || opts.ClusterID == "" || opts.ManifestPath == "" {
		return errors.New("--out, --cluster-id and --image-manifest are required")
	}
	if opts.ServerName == "" {
		opts.ServerName = opts.ClusterID + "-server"
	}
	if opts.TLSSAN == "" {
		opts.TLSSAN = defaultTLSSAN
	}
	if len(opts.Agents) > 0 && opts.ServerAddress == "" {
		return errors.New("--server-address is required when the bundle has agents: an agent must be told where its server is")
	}
	image, err := imageFromManifest(opts.ManifestPath, opts.VCPUs)
	if err != nil {
		return err
	}
	var workloads string
	if opts.WorkloadsPath != "" {
		data, err := readBounded(opts.WorkloadsPath, MaxDocumentSize)
		if err != nil {
			return err
		}
		workloads = string(data)
	}
	if err := os.Mkdir(opts.Dir, 0o700); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(opts.Dir)
		}
	}()
	serverKey, serverPub, err := newLaunchKey(filepath.Join(opts.Dir, serverKeyFile))
	if err != nil {
		return err
	}
	_, agentPub, err := newLaunchKey(filepath.Join(opts.Dir, agentKeyFile))
	if err != nil {
		return err
	}
	server := Document{
		SchemaVersion:           SchemaVersion,
		ClusterID:               opts.ClusterID,
		Role:                    Server,
		Image:                   image,
		Node:                    Node{Name: opts.ServerName},
		Server:                  ServerConfig{Address: opts.ServerAddress, OperatorPublicKey: serverPub},
		AgentOperatorPublicKeys: []string{agentPub},
		TLSSAN:                  opts.TLSSAN,
		Workloads:               workloads,
	}
	if err := writeSignedDocument(filepath.Join(opts.Dir, serverDir), server, serverKey, serverPub); err != nil {
		return err
	}
	pins, err := server.referenceValues()
	if err != nil {
		return err
	}
	policy, err := refvalues.Format(refvalues.ReferenceValues{Family: pins.Family, Images: pins.Images[:1]})
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(opts.Dir, serverPolicy), policy, 0o644); err != nil {
		return err
	}
	for _, name := range opts.Agents {
		if err := AddAgent(opts.Dir, name, opts.ServerAddress); err != nil {
			return err
		}
	}
	return nil
}

// AddAgent derives an agent document from the bundle's server document
// (same cluster, image, keys and SAN; the document carries no credentials),
// signs it with the bundle's agent key and writes <dir>/<name>. It works
// on a bundle created earlier, so a cluster can grow without regenerating or
// re-signing anything the server already booted with.
func AddAgent(dir, name, serverAddress string) (err error) {
	if !dnsLabel(name) {
		return fmt.Errorf("agent name %q must be an RFC1123 label", name)
	}
	if name == serverDir {
		return fmt.Errorf("agent name %q is reserved for the server", name)
	}
	serverData, err := readBounded(filepath.Join(dir, serverDir, documentFile), MaxDocumentSize)
	if err != nil {
		return fmt.Errorf("bundle has no server document: %w", err)
	}
	server, err := Parse(serverData)
	if err != nil {
		return fmt.Errorf("bundle server document: %w", err)
	}
	if server.Role != Server {
		return errors.New("bundle server document does not carry the server role")
	}
	if name == server.Node.Name {
		return fmt.Errorf("agent name %q is the server's node name", name)
	}
	key, err := certutil.LoadECPrivateKeyFile(filepath.Join(dir, agentKeyFile))
	if err != nil {
		return fmt.Errorf("bundle agent key: %w", err)
	}
	pub, err := publicKeyPEM(key)
	if err != nil {
		return err
	}
	if serverAddress == "" {
		if server.Server.Address == "" {
			return errors.New("--server-address is required: the server document leaves its address to autodetection, and an agent must be told where its server is")
		}
		serverAddress = server.Server.Address
	}
	agent := *server
	agent.Role = Agent
	agent.Node = Node{Name: name}
	agent.Server.Address = serverAddress
	return writeSignedDocument(filepath.Join(dir, name), agent, key, pub)
}

// imageFromManifest turns the build's provenanced manifest into the launch
// document's image pins. The manifest's shape names the platform; an SNP
// manifest carries one launch digest per vCPU count, so vcpus selects one
// unless the manifest has only one.
func imageFromManifest(path string, vcpus int) (Image, error) {
	identity, err := runtimemeasure.LoadImageManifest(path)
	if err != nil {
		return Image{}, fmt.Errorf("--image-manifest: %w", err)
	}
	variants := identity.LaunchDigests()
	var image Image
	switch identity.Family() {
	case teetypes.FamilyTDX:
		if vcpus != 0 {
			return Image{}, errors.New("--vcpus applies to SNP manifests only: a TDX image has one measurement for every VM shape")
		}
		image = Image{Platform: "tdx", Measurement: hex.EncodeToString(variants[0].Digest[:]), RTMRs: map[int]string{}}
		for idx, value := range identity.RTMRs() {
			image.RTMRs[idx] = hex.EncodeToString(value[:])
		}
	case teetypes.FamilySNP:
		// An SNP launch digest covers one vCPU count, so a manifest with a
		// single variant still boots at exactly that count, not at any count.
		// Omitting --vcpus takes that sole variant; it never means "all".
		if vcpus == 0 && len(variants) > 1 {
			return Image{}, fmt.Errorf("--vcpus is required: %s pins %d SNP launch digests, one per vCPU count", path, len(variants))
		}
		label := ""
		if vcpus != 0 {
			label = fmt.Sprintf("smp%d", vcpus)
		}
		for _, v := range variants {
			if label == "" || v.Label == label {
				image = Image{Platform: "snp", Measurement: hex.EncodeToString(v.Digest[:])}
			}
		}
		if image.Platform == "" {
			return Image{}, fmt.Errorf("--vcpus %d: %s pins no SNP launch digest for that vCPU count", vcpus, path)
		}
	default:
		return Image{}, fmt.Errorf("--image-manifest: %s pins TEE family %q, want tdx or sev-snp", path, identity.Family())
	}
	return image, nil
}

// writeSignedDocument renders doc, proves the rendering parses under the
// same strict rules the guest applies, signs it with key and writes the
// three opkeydata files into dir, which must not exist yet.
func writeSignedDocument(dir string, doc Document, key *ecdsa.PrivateKey, pub string) (err error) {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("render launch document: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return fmt.Errorf("rendered launch document for %s: %w", doc.Node.Name, err)
	}
	signature, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	if err := writeNew(filepath.Join(dir, pubkeyFile), []byte(pub), 0o644); err != nil {
		return err
	}
	// The document is public policy; keep it operator-only anyway so a
	// bundle directory never hands out more than its ISO must.
	if err := writeNew(filepath.Join(dir, documentFile), data, 0o600); err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, signatureFile), []byte(signature+"\n"), 0o600)
}

func newLaunchKey(path string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate launch key: %w", err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, "", err
	}
	if err := writeNew(path, keyPEM, 0o600); err != nil {
		return nil, "", err
	}
	pub, err := publicKeyPEM(key)
	if err != nil {
		return nil, "", err
	}
	return key, pub, nil
}

func publicKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encode launch public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
