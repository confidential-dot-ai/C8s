package launchconfig

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// A pod bundle is one pod CVM's launch input:
//
//	<dir>/pod.key    the pod launch key (unless --launch-key names an existing one)
//	<dir>/pod/       pubkey, launch.yaml, launch.yaml.sig: the pod's opkeydata
const (
	podKeyFile = "pod.key"
	podDir     = "pod"
)

// PodBundleOptions describes one pod CVM's signed generic launch document.
type PodBundleOptions struct {
	Dir                 string
	ClusterID           string
	ManifestPath        string
	NodeName            string
	LaunchKeyPath       string
	ServerAddress       string
	ServerPublicKeyPath string
	CDSAddress          string
	CDSImagePolicyPath  string
}

// NewPodBundle writes a signed role-pod document. It names no pod: the guest
// boots generic and waits for an assignment. Dir must not exist; a failed run
// removes it.
func NewPodBundle(opts PodBundleOptions) (err error) {
	if opts.Dir == "" || opts.ClusterID == "" || opts.ManifestPath == "" || opts.NodeName == "" || opts.ServerAddress == "" || opts.ServerPublicKeyPath == "" || opts.CDSAddress == "" || opts.CDSImagePolicyPath == "" {
		return errors.New("--out, --cluster-id, --image-manifest, --name, --server-address, --server-public-key, --cds-address and --cds-image-policy-file are required")
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
	cdsPolicy, err := readBounded(opts.CDSImagePolicyPath, MaxDocumentSize)
	if err != nil {
		return fmt.Errorf("--cds-image-policy-file: %w", err)
	}
	cds := CDS{Address: opts.CDSAddress, Measurements: string(cdsPolicy)}
	if err := cds.validate(); err != nil {
		return err
	}
	identity, err := runtimemeasure.LoadImageManifest(opts.ManifestPath)
	if err != nil {
		return fmt.Errorf("--image-manifest: %w", err)
	}
	if identity.Family() != teetypes.FamilyTDX {
		return errors.New("--image-manifest: the pod role is TDX-only")
	}
	image, err := imageFromManifest(opts.ManifestPath, 0)
	if err != nil {
		return err
	}
	if err := os.Mkdir(opts.Dir, 0o700); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(opts.Dir)
		}
	}()
	key, pub, err := podLaunchKey(opts)
	if err != nil {
		return err
	}
	doc := Document{
		SchemaVersion:        SchemaVersion,
		ClusterID:            opts.ClusterID,
		Role:                 Pod,
		Image:                image,
		Node:                 Node{Name: opts.NodeName},
		Server:               ServerConfig{Address: opts.ServerAddress, OperatorPublicKey: string(serverPub)},
		PodOperatorPublicKey: pub,
		CDS:                  cds,
	}
	return writeSignedDocument(filepath.Join(opts.Dir, podDir), doc, key, pub)
}

func podLaunchKey(opts PodBundleOptions) (key *ecdsa.PrivateKey, pub string, err error) {
	if opts.LaunchKeyPath == "" {
		key, err = newLaunchKey()
		if err != nil {
			return nil, "", err
		}
		pub, err = writeLaunchKey(filepath.Join(opts.Dir, podKeyFile), key)
		return key, pub, err
	}
	key, err = certutil.LoadECPrivateKeyFile(opts.LaunchKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("--launch-key: %w", err)
	}
	pub, err = publicKeyPEM(key)
	return key, pub, err
}
