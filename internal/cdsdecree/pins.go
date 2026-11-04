package cdsdecree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// document is a measurements document a decree carries, exactly as the
// operator signed it. Its bytes stay closed: a reader reaches the pins it
// names only through the type that owns them.
type document struct {
	json json.RawMessage
}

func (d document) MarshalJSON() ([]byte, error) {
	if len(d.json) == 0 {
		return nil, errors.New("decree carries an empty measurements document")
	}
	return d.json, nil
}

func (d *document) UnmarshalJSON(object []byte) error {
	d.json = slices.Clone(object)
	return nil
}

// ElidedImages is the CDS image set a decree carries, with every entry's
// launch file taken out. It pins no CDS on its own: only
// [PinDocument.WithLaunchFile] hands out a pin set, and only once the launch
// file the operator signed it for is back in every entry.
type ElidedImages struct {
	document
}

// NodeImages is the node image set a decree carries: the measurements document
// the cluster certifies nodes by.
type NodeImages struct {
	document
}

// NewNodeImages carries a node pin document into a decree.
func NewNodeImages(measurements []byte) (*NodeImages, error) {
	if _, err := refvalues.Parse(measurements); err != nil {
		return nil, err
	}
	return &NodeImages{document{json: slices.Clone(measurements)}}, nil
}

// Images are the node pins the decree names.
func (n NodeImages) Images() (refvalues.ReferenceValues, error) {
	return refvalues.Parse(n.json)
}

// PinDocument is the image set a decree pins a CDS to: the cluster's
// measurements document with every entry's launch file elided, and the
// SHA-256 of the file they all bind. Every CDS of a cluster boots the same
// launch file, so the digest names it and a decree stays small enough to keep
// in the cluster's state.
type PinDocument struct {
	Images           ElidedImages `json:"document"`
	LaunchFileSHA256 string       `json:"launch_file_sha256"`
}

// NewPinDocument elides the launch file from a CDS pin document. Every entry
// must bind the one file, which the digest then names.
func NewPinDocument(measurements []byte) (*PinDocument, error) {
	images, err := refvalues.Parse(measurements)
	if err != nil {
		return nil, err
	}
	file, err := cmdsutil.CDSLaunchFile(images)
	if err != nil {
		return nil, fmt.Errorf("a CDS pin document %w", err)
	}
	for i := range images.Images {
		images.Images[i].LaunchFile = nil
	}
	elided, err := refvalues.Format(images)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(file)
	return &PinDocument{
		Images:           ElidedImages{document{json: elided}},
		LaunchFileSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

// WithLaunchFile is the pin set a reader holds its CDS to: the decree's
// entries bound to the launch file the reader holds, which must be the file
// the operator signed them for.
func (p PinDocument) WithLaunchFile(file []byte) (refvalues.ReferenceValues, error) {
	bound, err := p.launchDigest()
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	if digest := sha256.Sum256(file); !bytes.Equal(digest[:], bound) {
		return refvalues.ReferenceValues{}, fmt.Errorf("the decree pins launch file %s, and this one is %x", p.LaunchFileSHA256, digest)
	}
	images, err := p.elided()
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	for i := range images.Images {
		images.Images[i].LaunchFile = file
	}
	return images, nil
}

// check is what a decree's pins must be before any reader binds them to a
// launch file.
func (p PinDocument) check() error {
	if _, err := p.launchDigest(); err != nil {
		return err
	}
	_, err := p.elided()
	return err
}

// elided are the decree's entries as they are signed, with no launch binding
// of their own: launch_file_sha256 is the only one a decree carries.
func (p PinDocument) elided() (refvalues.ReferenceValues, error) {
	images, err := refvalues.Parse(p.Images.json)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	if images.HasLaunchBindings() {
		return refvalues.ReferenceValues{}, errors.New("an entry carries its own launch binding, which launch_file_sha256 replaces")
	}
	return images, nil
}

// launchDigest is the launch file the entries bind, as the digest naming it.
func (p PinDocument) launchDigest() ([]byte, error) {
	digest, err := hex.DecodeString(p.LaunchFileSHA256)
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("launch_file_sha256 %q is not a SHA-256 digest in hex", p.LaunchFileSHA256)
	}
	return digest, nil
}
