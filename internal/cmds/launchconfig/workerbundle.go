package launchconfig

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// A worker bundle is one pool's launch input, the same for every node of it:
//
//	<dir>/worker.key  the pool's launch key (unless --launch-key names one)
//	<dir>/worker/     pubkey, launch.yaml, launch.yaml.sig: each node's opkeydata
//
// Each node's opkeydata also carries its own unsigned provider-id.
const (
	workerKeyFile = "worker.key"
	workerDir     = "worker"
)

// WorkerBundleOptions describes one worker pool's signed launch document.
type WorkerBundleOptions struct {
	Dir                 string
	ClusterID           string
	ManifestPath        string
	VCPUs               int
	LaunchKeyPath       string
	ServerAddress       string
	ServerPublicKeyPath string
	Kubernetes          Kubernetes
	CAPath              string
}

// NewWorkerBundle writes a signed role-worker document. Dir must not exist;
// a failed run removes it.
func NewWorkerBundle(opts WorkerBundleOptions) (err error) {
	if opts.Dir == "" || opts.ClusterID == "" || opts.ManifestPath == "" || opts.ServerAddress == "" || opts.ServerPublicKeyPath == "" || opts.CAPath == "" {
		return errors.New("--out, --cluster-id, --image-manifest, --server-address, --server-public-key and --api-ca are required")
	}
	if err := ValidateIPv4(opts.ServerAddress, true); err != nil {
		return fmt.Errorf("--server-address: %w", err)
	}
	serverPub, err := readBounded(opts.ServerPublicKeyPath, maxLaunchKeySize)
	if err != nil {
		return fmt.Errorf("--server-public-key: %w", err)
	}
	if _, err := parseLaunchKey(string(serverPub)); err != nil {
		return fmt.Errorf("--server-public-key: %w", err)
	}
	image, err := imageFromManifest(opts.ManifestPath, opts.VCPUs)
	if err != nil {
		return err
	}
	ca, err := readBounded(opts.CAPath, MaxDocumentSize)
	if err != nil {
		return fmt.Errorf("--api-ca: %w", err)
	}
	k := opts.Kubernetes
	k.CACertificate = string(ca)
	if err := os.Mkdir(opts.Dir, 0o700); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(opts.Dir)
		}
	}()
	key, pub, err := workerLaunchKey(opts)
	if err != nil {
		return err
	}
	doc := Document{
		SchemaVersion:           SchemaVersion,
		ClusterID:               opts.ClusterID,
		Role:                    Worker,
		Image:                   image,
		Server:                  ServerConfig{Address: opts.ServerAddress, OperatorPublicKey: string(serverPub)},
		AgentOperatorPublicKeys: []string{pub},
		Kubernetes:              &k,
	}
	return writeSignedDocument(filepath.Join(opts.Dir, workerDir), doc, key, pub)
}

func workerLaunchKey(opts WorkerBundleOptions) (key *ecdsa.PrivateKey, pub string, err error) {
	if opts.LaunchKeyPath == "" {
		key, err = newLaunchKey()
		if err != nil {
			return nil, "", err
		}
		pub, err = writeLaunchKey(filepath.Join(opts.Dir, workerKeyFile), key)
		return key, pub, err
	}
	key, err = certutil.LoadECPrivateKeyFile(opts.LaunchKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("--launch-key: %w", err)
	}
	pub, err = publicKeyPEM(key)
	return key, pub, err
}
