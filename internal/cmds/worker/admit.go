//go:build !c8s_node

package worker

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// AdmitInputs are what a worker document is admitted against: the customer's
// CDS pin, the worker image's measurements, and the node images the cluster
// certifies now, as the node-images decree's --cds-pin, --worker-image and
// --nodes carry them.
type AdmitInputs struct {
	CDSPin      []byte
	WorkerImage []byte
	Nodes       []byte
}

// Admission is a worker document that passed every check. Nodes is the set
// admitting it: every entry of AdmitInputs.Nodes, then each worker image entry
// bound to the document's launch file digest.
type Admission struct {
	Nodes    []byte
	document *Document
	ca       *x509.Certificate
	digest   []byte
	added    []string
}

// launchDigestSchema is the measurements schema that reads
// launch_file_digest.
const launchDigestSchema = "2"

// Admit checks a worker document and returns the node image set that admits
// workers launched with it. It reads the document once, so the entries it
// adds bind the bytes Parse checked.
func Admit(document io.Reader, in AdmitInputs) (Admission, error) {
	data, err := readutil.ReadAll(document, launchconfig.MaxDocumentSize)
	if err != nil {
		return Admission{}, fmt.Errorf("--worker-document: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return Admission{}, err
	}
	ca, err := caCertificate(doc.Kubernetes.CACertificate)
	if err != nil {
		return Admission{}, err
	}
	if err := checkCDSPin(doc.CDS, in.CDSPin); err != nil {
		return Admission{}, err
	}
	nodes, image, err := nodesAndWorkerImage(in)
	if err != nil {
		return Admission{}, err
	}
	digest, err := runtimemeasure.LaunchFileDigest(nodes.Family, data)
	if err != nil {
		return Admission{}, err
	}
	added := boundTo(image, digest)
	if err := checkNotAdmitted(nodes, added); err != nil {
		return Admission{}, err
	}
	nodes.Images = append(nodes.Images, added...)
	set, err := admittedSet(nodes)
	if err != nil {
		return Admission{}, fmt.Errorf("--nodes with the worker image added: %w", err)
	}
	names := make([]string, len(added))
	for i, pin := range added {
		names[i] = pin.Name
	}
	return Admission{Nodes: set, document: doc, ca: ca, digest: digest, added: names}, nil
}

// nodesAndWorkerImage are the set in force and the worker image's
// measurements, of one TEE family, the worker image binding no launch yet.
func nodesAndWorkerImage(in AdmitInputs) (nodes, image refvalues.ReferenceValues, err error) {
	if nodes, err = refvalues.Parse(in.Nodes); err != nil {
		return nodes, image, fmt.Errorf("--nodes: %w", err)
	}
	if image, err = refvalues.Parse(in.WorkerImage); err != nil {
		return nodes, image, fmt.Errorf("--worker-image: %w", err)
	}
	if image.Family != nodes.Family {
		return nodes, image, fmt.Errorf("--worker-image pins a %s image and --nodes %s ones: one node image set holds one TEE family", image.Family, nodes.Family)
	}
	for _, pin := range image.Images {
		if cdsdecree.EntryBindsLaunch(pin) {
			return nodes, image, fmt.Errorf("--worker-image entry %q binds a launch already: pass the image's measurements as 'c8s measurements derive' writes them", pin.Name)
		}
	}
	return nodes, image, nil
}

// boundTo is each entry of image bound to the launch file of digest, named
// apart from the image bound to another document.
func boundTo(image refvalues.ReferenceValues, digest []byte) []remote.ImagePin {
	bound := slices.Clone(image.Images)
	for i := range bound {
		bound[i].Name = fmt.Sprintf("%s-%x", bound[i].Name, digest[:6])
		bound[i].LaunchFileDigest = digest
	}
	return bound
}

// checkNotAdmitted refuses entries the set in force already holds, by name or
// by what they admit.
func checkNotAdmitted(nodes refvalues.ReferenceValues, added []remote.ImagePin) error {
	for _, pin := range added {
		if slices.ContainsFunc(nodes.Images, func(held remote.ImagePin) bool { return held.Name == pin.Name }) {
			return fmt.Errorf("--nodes already holds an entry named %q", pin.Name)
		}
	}
	if missing, _ := refvalues.Diff(refvalues.ReferenceValues{Images: added}, nodes); len(missing) != len(added) {
		return errors.New("--nodes already admits the worker image with this document")
	}
	return nil
}

// admittedSet is the node image set a node-images decree accepts, under the
// schema that reads its launch file digests.
func admittedSet(nodes refvalues.ReferenceValues) ([]byte, error) {
	set, err := refvalues.Format(nodes)
	if err != nil {
		return nil, err
	}
	var declared struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(set, &declared); err != nil {
		return nil, err
	}
	if declared.SchemaVersion != launchDigestSchema {
		return nil, fmt.Errorf("schema_version is %q, want %q, which reads launch_file_digest", declared.SchemaVersion, launchDigestSchema)
	}
	images, err := cdsdecree.NewNodeImages(set)
	if err != nil {
		return nil, err
	}
	if err := images.RequireLaunchBindings(); err != nil {
		return nil, err
	}
	return set, nil
}

// checkCDSPin requires the document to pin the CDS the customer pins: the
// same images, each bound to the same configuration. The CDS VM's family need
// not be the workers'.
func checkCDSPin(cds cmdsutil.CDS, own []byte) error {
	mine, err := refvalues.Parse(own)
	if err != nil {
		return fmt.Errorf("--cds-pin: %w", err)
	}
	theirs, err := refvalues.Parse([]byte(cds.Measurements))
	if err != nil {
		return fmt.Errorf("cds.measurements: %w", err)
	}
	if theirs.Family != mine.Family {
		return fmt.Errorf("cds.measurements pins a %s CDS and --cds-pin a %s one", theirs.Family, mine.Family)
	}
	if missing, extra := refvalues.Diff(mine, theirs); len(missing) > 0 || len(extra) > 0 {
		return errors.New("cds.measurements pins another CDS than --cds-pin: a worker launched with this document would trust it")
	}
	return nil
}

// Report prints the facts the customer checks before signing, one per line,
// and the node images signing certifies. The CA subject is the one free-text
// fact, so it is quoted.
func (a Admission) Report(w io.Writer) error {
	var b strings.Builder
	fact := func(name string, value any) {
		fmt.Fprintf(&b, "  %-18s%v\n", name, value)
	}
	hostnames := "none"
	if r := a.document.Router; r != nil && len(r.Hostnames) > 0 {
		hostnames = strings.Join(r.Hostnames, ", ")
	}
	k := a.document.Kubernetes
	b.WriteString("The worker document says:\n")
	fact("API server", k.APIServer)
	fact("CA subject", strconv.Quote(a.ca.Subject.String()))
	fact("CA SHA-256", certutil.CertFingerprint(a.ca.Raw))
	fact("pod range", k.PodCIDR)
	fact("Service range", k.ServiceCIDR)
	fact("cluster DNS", k.ClusterDNS)
	fact("CDS address", a.document.CDS.Address)
	fact("CDS pin floor", a.document.CDS.PinFloor)
	fact("router TLS SAN", a.document.TLSSAN)
	fact("router hostnames", hostnames)
	set, err := refvalues.Parse(a.Nodes)
	if err != nil {
		return err
	}
	b.WriteString("Signing certifies these node images:\n")
	for _, pin := range set.Images {
		if slices.Contains(a.added, pin.Name) {
			fmt.Fprintf(&b, "  %s  bound to this document, launch_file_digest %x\n", pin.Name, a.digest)
			continue
		}
		fmt.Fprintf(&b, "  %s\n", pin.Name)
	}
	_, err = io.WriteString(w, b.String())
	return err
}
