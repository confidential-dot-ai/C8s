package launchconfig

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

// PodBundleOptions describes one pod CVM's signed launch document.
type PodBundleOptions struct {
	Dir                 string
	ClusterID           string
	ManifestPath        string
	VCPUs               int
	NodeName            string
	LaunchKeyPath       string
	ServerAddress       string
	ServerPublicKeyPath string
	PodManifest         string
	WorkloadsPath       string
	MeshPeers           []string
}

// NewPodBundle writes a signed role-pod document. The pod's UID, namespace
// and name come from the manifest's metadata. Dir must not exist; a failed
// run removes it.
func NewPodBundle(opts PodBundleOptions) (err error) {
	if opts.Dir == "" || opts.ClusterID == "" || opts.ManifestPath == "" || opts.PodManifest == "" || opts.WorkloadsPath == "" || opts.ServerAddress == "" || opts.ServerPublicKeyPath == "" {
		return errors.New("--out, --cluster-id, --image-manifest, --pod-manifest, --workloads, --server-address and --server-public-key are required")
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
	manifest, err := readBounded(opts.PodManifest, MaxDocumentSize)
	if err != nil {
		return err
	}
	pod, err := ParsePodManifest(manifest)
	if err != nil {
		return err
	}
	workloads, err := readBounded(opts.WorkloadsPath, MaxDocumentSize)
	if err != nil {
		return err
	}
	if opts.NodeName == "" {
		opts.NodeName = "p-" + string(pod.UID)
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
		Workloads:            string(workloads),
		Pod:                  &PodSpec{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, Manifest: string(manifest), MeshPeers: opts.MeshPeers},
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
