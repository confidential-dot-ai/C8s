package podlaunch

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
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A pod bundle is one pod CVM's launch input:
//
//	<dir>/pod.key    the pod launch key (unless --launch-key names an existing one)
//	<dir>/pod/       pubkey, launch.yaml, launch.yaml.sig: the pod's opkeydata
const (
	podKeyFile    = "pod.key"
	podDir        = "pod"
	pubkeyFile    = "pubkey"
	documentFile  = "launch.yaml"
	signatureFile = documentFile + ".sig"
)

// PodBundleOptions describes one pod CVM's signed generic launch document.
type PodBundleOptions struct {
	Dir                string
	ClusterID          string
	ManifestPath       string
	NodeName           string
	LaunchKeyPath      string
	CDSAddress         string
	CDSImagePolicyPath string
	// CDSChain, "<seq>:<hash>", pins a CDS replica set by an entry of its chain.
	CDSChain string
}

// NewPodBundle writes a signed role-pod document. It names no pod: the guest
// boots generic and waits for an assignment. Dir must not exist; a failed run
// removes it.
func NewPodBundle(opts PodBundleOptions) (err error) {
	if opts.Dir == "" || opts.ClusterID == "" || opts.ManifestPath == "" || opts.NodeName == "" || opts.CDSAddress == "" || opts.CDSImagePolicyPath == "" {
		return errors.New("--out, --cluster-id, --image-manifest, --name, --cds-address and --cds-image-policy-file are required")
	}
	cdsPolicy, err := readBounded(opts.CDSImagePolicyPath, MaxDocumentSize)
	if err != nil {
		return fmt.Errorf("--cds-image-policy-file: %w", err)
	}
	cds := cmdsutil.CDS{Address: opts.CDSAddress, Measurements: string(cdsPolicy), Chain: opts.CDSChain}
	if _, err := cds.Parse(); err != nil {
		return err
	}
	identity, err := runtimemeasure.LoadImageManifest(opts.ManifestPath)
	if err != nil {
		return fmt.Errorf("--image-manifest: %w", err)
	}
	if identity.Family() != teetypes.FamilyTDX {
		return errors.New("--image-manifest: the pod role is TDX-only")
	}
	image, err := ImageFromManifest(opts.ManifestPath, 0)
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
		PodOperatorPublicKey: pub,
		CDS:                  cds,
	}
	return writeSignedDocument(filepath.Join(opts.Dir, podDir), doc, key, pub)
}

func podLaunchKey(opts PodBundleOptions) (key *ecdsa.PrivateKey, pub string, err error) {
	if opts.LaunchKeyPath == "" {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("generate launch key: %w", err)
		}
		keyPEM, err := certutil.MarshalECKeyPEM(key)
		if err != nil {
			return nil, "", err
		}
		if err := writeNew(filepath.Join(opts.Dir, podKeyFile), keyPEM, 0o600); err != nil {
			return nil, "", err
		}
		pub, err = publicKeyPEM(key)
		return key, pub, err
	}
	key, err = certutil.LoadECPrivateKeyFile(opts.LaunchKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("--launch-key: %w", err)
	}
	pub, err = publicKeyPEM(key)
	return key, pub, err
}

// ImageFromManifest derives launch pins from a measured image's manifest. The
// provider and bundle CLI share the same platform and vCPU selection rules.
func ImageFromManifest(path string, vcpus int) (Image, error) {
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
func writeSignedDocument(dir string, doc Document, key *ecdsa.PrivateKey, pub string) error {
	data, signature, err := SignDocument(doc, key)
	if err != nil {
		return err
	}
	return fileutil.WriteNewDir(dir, 0o700, []fileutil.NewFile{
		{Name: pubkeyFile, Data: []byte(pub), Mode: 0o644},
		{Name: documentFile, Data: data, Mode: 0o600},
		{Name: signatureFile, Data: []byte(signature + "\n"), Mode: 0o600},
	})
}

// SignDocument renders doc, proves the rendering parses under the strict
// rules the guest applies and returns the bytes with their detached signature.
func SignDocument(doc Document, key *ecdsa.PrivateKey) (data []byte, signature string, err error) {
	data, err = yaml.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("render launch document: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return nil, "", fmt.Errorf("rendered launch document for %s: %w", doc.Node.Name, err)
	}
	signature, err = operatorauth.SignDetached(key, data)
	if err != nil {
		return nil, "", err
	}
	return data, signature, nil
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
