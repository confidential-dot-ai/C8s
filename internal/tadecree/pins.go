package tadecree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
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

// ElidedImages is the Trust Authority image set a decree carries, with every entry's
// launch file taken out. It pins no Trust Authority on its own: only
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

// RequireLaunchBindings requires every entry to bind the launch of the nodes
// it certifies: an entry binding none certifies its image however the host
// launched it. A set already in a cluster's log applies without it.
func (n NodeImages) RequireLaunchBindings() error {
	images, err := n.Images()
	if err != nil {
		return err
	}
	for _, image := range images.Images {
		if !EntryBindsLaunch(image) {
			return fmt.Errorf("entry %q binds no launch: give it an approver_key, launch_file or launch_file_digest", image.Name)
		}
	}
	return nil
}

// EntryBindsLaunch reports whether one entry binds the launch of the guests
// it admits: by approver key, launch file or launch file digest.
func EntryBindsLaunch(image remote.ImagePin) bool {
	return image.Anchor != nil || image.LaunchFile != nil || image.LaunchFileDigest != nil
}

// PinDocument is the image set a decree pins a Trust Authority to: the cluster's
// measurements document with every entry's launch file elided, and the
// SHA-256 of the file they all bind. Every Trust Authority of a cluster boots the same
// launch file, so the digest names it and a decree stays small enough to keep
// in the cluster's state.
//
// LaunchFileField is where the entries read that file on TDX: empty for
// RTMR[3], or "init_data" for MRCONFIGID. An entry cannot say so itself once
// its launch file is gone, so the document says it for all of them.
type PinDocument struct {
	Images           ElidedImages `json:"document"`
	LaunchFileSHA256 string       `json:"launch_file_sha256"`
	LaunchFileField  string       `json:"launch_file_field,omitempty"`
}

// launchFileFieldInitData is the one value launch_file_field takes.
const launchFileFieldInitData = "init_data"

// NewPinDocument elides the launch file from a Trust Authority pin document. Every entry
// must bind the one file, which the digest then names.
func NewPinDocument(measurements []byte) (*PinDocument, error) {
	images, err := refvalues.Parse(measurements)
	if err != nil {
		return nil, err
	}
	file, err := cmdsutil.TALaunchFile(images)
	if err != nil {
		return nil, fmt.Errorf("a Trust Authority pin document %w", err)
	}
	field, err := launchFileField(images)
	if err != nil {
		return nil, err
	}
	for i := range images.Images {
		images.Images[i].LaunchFile = nil
		images.Images[i].LaunchFileInInitData = false
	}
	elided, err := refvalues.Format(images)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(file)
	return &PinDocument{
		Images:           ElidedImages{document{json: elided}},
		LaunchFileSHA256: hex.EncodeToString(digest[:]),
		LaunchFileField:  field,
	}, nil
}

// launchFileField is the one field every entry reads its launch file from.
// One Trust Authority boots one way, so entries naming different fields name
// no one VM.
func launchFileField(images refvalues.ReferenceValues) (string, error) {
	inInitData := images.Images[0].LaunchFileInInitData
	for _, image := range images.Images {
		if image.LaunchFileInInitData != inInitData {
			return "", fmt.Errorf("entry %q reads its launch file from another field than entry %q, and one pin names one Trust Authority", image.Name, images.Images[0].Name)
		}
	}
	if inInitData {
		return launchFileFieldInitData, nil
	}
	return "", nil
}

// WithLaunchFile is the pin set a reader holds its Trust Authority to: the decree's
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
	return p.bound(images, file), nil
}

// bound puts file back in every entry, read from the field the decree names.
func (p PinDocument) bound(images refvalues.ReferenceValues, file []byte) refvalues.ReferenceValues {
	for i := range images.Images {
		images.Images[i].LaunchFile = file
		images.Images[i].LaunchFileInInitData = p.LaunchFileField == launchFileFieldInitData
	}
	return images
}

// check is what a decree's pins must be before any reader binds them to a
// launch file.
func (p PinDocument) check() error {
	if _, err := p.launchDigest(); err != nil {
		return err
	}
	images, err := p.elided()
	if err != nil {
		return err
	}
	switch p.LaunchFileField {
	case "":
		return nil
	case launchFileFieldInitData:
		// Any launch file stands in: the checks are on the entries, which must
		// name one Trust Authority VM however they are later bound.
		if _, err := cmdsutil.TALaunchFile(p.bound(images, []byte{0})); err != nil {
			return fmt.Errorf("launch_file_field %q: the entries %w", p.LaunchFileField, err)
		}
		return nil
	default:
		return fmt.Errorf("launch_file_field %q, want %q or none", p.LaunchFileField, launchFileFieldInitData)
	}
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
