package nodeservices

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// FloorInputs are what Prepare completes the measured NRI floor with, and the
// public files it publishes beside it.
type FloorInputs struct {
	// CDS is where the plugin pulls from and the credential role dials; its
	// pin is published as cds.json.
	CDS launchconfig.CDS
	// ClusterRanges, when given, are the cluster's pod and Service ranges,
	// the mesh policy's cluster_ranges; none keeps the baked ones.
	ClusterRanges []string
	// Resolver, when given, is the cluster DNS address, the mesh policy's
	// resolver; empty keeps the baked one.
	Resolver string
	// Placeholders give each "<flag>=<placeholder>" in the measured base its
	// value; an empty value drops the flag.
	Placeholders map[string]string
	// Outputs are published under PublicDir, each a publicOutputNames entry.
	Outputs map[string][]byte
}

// PrepareNode prepares a server's or an agent's workload inputs from the
// verified launch document loaded by LoadStaged.
func PrepareNode(rootDir string, d *launchconfig.Document) error {
	if err := validateRole(d); err != nil {
		return err
	}
	peers, err := readPeerPolicy(filepath.Join(rootDir, launchDir+"peers.json"), d.Image.Platform)
	if err != nil {
		return err
	}
	outputs := map[string][]byte{"peers.json": peers}
	if d.Role == launchconfig.Server {
		server, err := serverOutputs(d)
		if err != nil {
			return err
		}
		maps.Copy(outputs, server)
	}
	return Prepare(rootDir, FloorInputs{
		CDS:          d.CDS,
		Placeholders: nodeValues(d.Node),
		Outputs:      outputs,
	})
}

// Prepare publishes the CDS pin as cds.json, in.Outputs and the measured NRI
// floor completed with in, and removes every other public output. rootDir
// rebases paths for tests. The root bootstrap service owns these files; pods
// mount them read-only.
func Prepare(rootDir string, in FloorInputs) error {
	path := func(name string) string { return filepath.Join(rootDir, name) }
	cds, err := in.CDS.Policy()
	if err != nil {
		return err
	}
	outputs := map[string][]byte{CDSOutput: cds}
	for name, data := range in.Outputs {
		if err := refuseReservedOutput(name); err != nil {
			return err
		}
		outputs[name] = data
	}
	bakedData, err := os.ReadFile(path("/usr/lib/c8s/allowlist-seed.json"))
	if err != nil {
		return err
	}
	bakedSeed, err := allowlist.ParseJSON(bakedData)
	if err != nil {
		return fmt.Errorf("baked workload seed: %w", err)
	}

	data, err := os.ReadFile(path("/usr/lib/c8s/image-policy.yaml"))
	if err != nil {
		return err
	}
	var floor map[string]any
	if err := yaml.Unmarshal(data, &floor); err != nil {
		return fmt.Errorf("baked NRI policy: %w", err)
	}
	a, ok := floor["allowlist"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing allowlist")
	}
	pull, ok := a["pull"].(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI policy missing pull")
	}
	base, err := bakedBase(a["base"])
	if err != nil {
		return err
	}
	if err := fillNodeValues(base, in.Placeholders); err != nil {
		return err
	}
	if err := mergeBakedSeed(base, bakedSeed); err != nil {
		return fmt.Errorf("merge chart seed into NRI base: %w", err)
	}
	a["base"] = base
	port, err := in.CDS.Port()
	if err != nil {
		return err
	}
	pull["url"] = cmdsutil.CDSURL(in.CDS.Address)
	pull["cds_measurements_config"] = PublicDir + "/" + CDSOutput
	pull["cds_pin_floor"] = in.CDS.PinFloor
	mesh, declared := floor["mesh"]
	if !declared {
		return fmt.Errorf("baked NRI policy missing mesh")
	}
	policy, ok := mesh.(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI mesh policy is %T, not a mapping", mesh)
	}
	if err := appendCredentialRole(policy, port); err != nil {
		return err
	}
	if err := setClusterRanges(policy, in.ClusterRanges); err != nil {
		return err
	}
	if err := setResolver(policy, in.Resolver); err != nil {
		return err
	}
	data, err = yaml.Marshal(floor)
	if err != nil {
		return err
	}

	// Validate every input before publishing anything. The node's runtime
	// only starts after this preparation succeeds, so pods never observe
	// partially staged input.
	publicPath := path(PublicDir)
	if err := os.MkdirAll(publicPath, 0755); err != nil {
		return err
	}
	if err := os.Chmod(publicPath, 0755); err != nil {
		return err
	}
	if err := removeOutputs(publicPath, unpublishedOutputs(outputs)); err != nil {
		return err
	}
	for name, data := range outputs {
		dst := filepath.Join(publicPath, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := fileutil.WriteAtomic(dst, data, 0644); err != nil {
			return err
		}
	}
	policyPath := path(floorConfigPath)
	if err := os.MkdirAll(filepath.Dir(policyPath), 0755); err != nil {
		return err
	}
	return fileutil.WriteAtomic(policyPath, data, 0600)
}

// floorConfigPath is the NRI plugin's configuration Prepare writes.
const floorConfigPath = "/etc/nri/conf.d/image-policy.yaml"

// Clear removes every output Prepare writes.
func Clear(rootDir string) error {
	policy := os.Remove(filepath.Join(rootDir, floorConfigPath))
	if errors.Is(policy, fs.ErrNotExist) {
		policy = nil
	}
	return errors.Join(policy, removeOutputs(filepath.Join(rootDir, PublicDir), publicOutputNames))
}

// refuseReservedOutput refuses a caller's output that is Prepare's own CDS
// pin, or one Prepare does not clear.
func refuseReservedOutput(name string) error {
	if name == CDSOutput {
		return fmt.Errorf("output %q is the CDS pin Prepare writes", name)
	}
	if !slices.Contains(publicOutputNames, name) {
		return fmt.Errorf("output %q is not a public output Prepare clears", name)
	}
	return nil
}

// unpublishedOutputs are the public outputs outputs does not hold.
func unpublishedOutputs(outputs map[string][]byte) []string {
	var names []string
	for _, name := range publicOutputNames {
		if _, published := outputs[name]; !published {
			names = append(names, name)
		}
	}
	return names
}

// setClusterRanges completes the measured mesh policy with this cluster's
// ranges, if given. A policy that declares another set is one this step would
// contradict.
func setClusterRanges(policy map[string]any, ranges []string) error {
	if len(ranges) == 0 {
		return nil
	}
	if declared, ok := policy["cluster_ranges"]; ok {
		baked, err := stringList(declared)
		if err != nil {
			return fmt.Errorf("baked NRI mesh cluster_ranges %w", err)
		}
		if !sameSet(baked, ranges) {
			return fmt.Errorf("baked NRI mesh cluster_ranges %v contradict this cluster's %v", baked, ranges)
		}
	}
	policy["cluster_ranges"] = ranges
	return nil
}

// setResolver completes the measured mesh policy with this cluster's DNS
// address, if given. A policy that declares another is one this step would
// contradict.
func setResolver(policy map[string]any, resolver string) error {
	if resolver == "" {
		return nil
	}
	if declared, ok := policy["resolver"]; ok && declared != resolver {
		return fmt.Errorf("baked NRI mesh resolver %v contradicts this cluster's %s", declared, resolver)
	}
	policy["resolver"] = resolver
	return nil
}

// stringList is a decoded YAML sequence of strings.
func stringList(declared any) ([]string, error) {
	items, ok := declared.([]any)
	if !ok {
		return nil, fmt.Errorf("is %T, not a list", declared)
	}
	list := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("holds %T, not a string", item)
		}
		list = append(list, s)
	}
	return list, nil
}

func sameSet(a, b []string) bool {
	set := func(s []string) []string {
		return slices.Compact(slices.Sorted(slices.Values(s)))
	}
	return slices.Equal(set(a), set(b))
}

// bakedBase decodes the measured base out of the boot config it is written in.
// It is read as YAML, not through the JSON ingest, because a declared platform
// role is a YAML-only field: the JSON path refuses it so that a document CDS
// serves can never claim a role.
func bakedBase(declared any) (*allowlist.Allowlist, error) {
	data, err := yaml.Marshal(declared)
	if err != nil {
		return nil, fmt.Errorf("baked NRI base: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var base allowlist.Allowlist
	if err := dec.Decode(&base); err != nil {
		return nil, fmt.Errorf("baked NRI base: %w", err)
	}
	if err := base.Normalize(); err != nil {
		return nil, fmt.Errorf("baked NRI base: %w", err)
	}
	return &base, nil
}

// A measured floor pins a static-pod flag as "<flag>=<placeholder>"
// (images/node-guest/worker/image-policy.yaml.in); each preparation gives the
// values of the placeholders its node fills.
const (
	NodeNamePlaceholder = "${NODE_NAME}"
	PodCIDRPlaceholder  = "${POD_CIDR}"
)

const nodeAdvertiseAddressPlaceholder = "${NODE_ADVERTISE_ADDRESS}"

// floorPlaceholders are every placeholder a measured floor may name.
var floorPlaceholders = []string{NodeNamePlaceholder, nodeAdvertiseAddressPlaceholder, PodCIDRPlaceholder}

// NamedPlaceholder is the first floor placeholder data names, or "".
func NamedPlaceholder(data []byte) string {
	for _, p := range floorPlaceholders {
		if bytes.Contains(data, []byte(p)) {
			return p
		}
	}
	return ""
}

// nodeValues are a server's or an agent's placeholder values, from its launch
// document. An empty address drops its flag, as RKE2 then passes none.
func nodeValues(node launchconfig.Node) map[string]string {
	return map[string]string{
		NodeNamePlaceholder:             node.Name,
		nodeAdvertiseAddressPlaceholder: node.AdvertiseAddress(),
	}
}

// fillNodeValues gives each placeholder flag in the base's argv pins its
// value.
func fillNodeValues(base *allowlist.Allowlist, values map[string]string) error {
	for placeholder := range values {
		if !slices.Contains(floorPlaceholders, placeholder) {
			return fmt.Errorf("%s is not a placeholder a floor names", placeholder)
		}
	}
	for name, w := range base.Workloads {
		for i := range w.InitContainers {
			if err := fillContainer(&w.InitContainers[i], values); err != nil {
				return fmt.Errorf("baked NRI base workload %q: %w", name, err)
			}
		}
		for i := range w.Containers {
			if err := fillContainer(&w.Containers[i], values); err != nil {
				return fmt.Errorf("baked NRI base workload %q: %w", name, err)
			}
		}
		base.Workloads[name] = w
	}
	return nil
}

func fillContainer(c *allowlist.Container, values map[string]string) error {
	for _, policy := range []*allowlist.ArgvPolicy{&c.Command, &c.Args} {
		argv, err := ArgvWithValues(policy.Argv, values)
		if err != nil {
			return err
		}
		policy.Argv = argv
	}
	return nil
}

// ArgvWithValues is argv with each "<flag>=<placeholder>" element given its
// value, and left out where the value is empty. An element that names a
// placeholder in any other way, or one values gives no value, is an error.
// Any other "${" is literal: a pinned shell script expands its own variables.
func ArgvWithValues(argv []string, values map[string]string) ([]string, error) {
	filled := make([]string, 0, len(argv))
	for _, element := range argv {
		flag, placeholder, isFlag := strings.Cut(element, "=")
		namesPlaceholder := isFlag && strings.HasPrefix(flag, "-") && strings.HasPrefix(placeholder, "${")
		for _, p := range floorPlaceholders {
			namesPlaceholder = namesPlaceholder || strings.Contains(element, p)
		}
		if !namesPlaceholder {
			filled = append(filled, element)
			continue
		}
		if !isFlag {
			return nil, fmt.Errorf("argv element %q names a placeholder outside \"<flag>=<placeholder>\"", element)
		}
		value, defined := values[placeholder]
		if !defined {
			return nil, fmt.Errorf("argv element %q sets a placeholder this preparation has no value for", element)
		}
		if value != "" {
			filled = append(filled, flag+"="+value)
		}
	}
	return filled, nil
}

// appendCredentialRole completes the measured mesh policy with the one binding
// only a launched node can know: the injected credential clients reach the
// port this cluster's CDS serves on, outside the cluster, and nothing else. A
// policy that already names that role, or its reserved identity, is a measured
// policy this step would contradict.
func appendCredentialRole(policy map[string]any, port uint16) error {
	declared, ok := policy["roles"]
	if !ok {
		declared = []any{}
	}
	roles, ok := declared.([]any)
	if !ok {
		return fmt.Errorf("baked NRI mesh roles are %T, not a list", declared)
	}
	for _, declared := range roles {
		role, ok := declared.(map[string]any)
		if !ok {
			return fmt.Errorf("baked NRI mesh role is %T, not a mapping", declared)
		}
		if role["name"] == nriimagepolicy.CredentialRole {
			return fmt.Errorf("baked NRI mesh policy already binds the %s role", nriimagepolicy.CredentialRole)
		}
		if uid, declared := role["uid"]; declared && fmt.Sprint(uid) == fmt.Sprint(workloadclaims.CredentialsUID) {
			return fmt.Errorf("baked NRI mesh role %v holds uid %v, reserved for the %s role", role["name"], uid, nriimagepolicy.CredentialRole)
		}
	}
	policy["roles"] = append(roles, map[string]any{
		"name": nriimagepolicy.CredentialRole,
		"uid":  workloadclaims.CredentialsUID,
		"port": port,
	})
	return nil
}

// serverOutputNames are the outputs only a server publishes. The router
// files are always written, empty when unset, so the router pod never waits on
// a missing file.
var serverOutputNames = []string{
	"operator-pubkey",
	"tls-san",
	"router/tls.conf",
	"router/hostnames",
	"router/acme-email",
	"router/acme-directory-url",
	"router/front-door-mode",
	"router/request-body.conf",
}

// publicOutputNames are every file Prepare may publish under PublicDir. It
// removes each one it does not publish, so a demoted node keeps none.
var publicOutputNames = append([]string{CDSOutput, "peers.json"}, serverOutputNames...)

// CDSOutput is the CDS pin Prepare publishes under PublicDir.
const CDSOutput = "cds.json"

// RouterTLSSnippetDir is where the node image installs tls-cds.conf and
// tls-acme.conf and the baked router mounts them; router/tls.conf includes the
// one the front-door mode selects. The chart's router.bakedNginxDir must equal
// it.
const RouterTLSSnippetDir = "/usr/lib/c8s/router-nginx"

// line renders an optional single-line value: empty stays empty.
func line(s string) []byte {
	if s == "" {
		return []byte{}
	}
	return []byte(s + "\n")
}

// RouterOutputs are the router's public inputs from r, a document's router
// block or nil when it has none. Every file is returned, empty when unset.
func RouterOutputs(r *launchconfig.Router) (map[string][]byte, error) {
	var router launchconfig.Router
	if r != nil {
		router = *r
	}
	// The document was validated; check the hostnames again, so no path can
	// publish an injectable file.
	for _, name := range router.Hostnames {
		if err := launchconfig.ValidateHostname(name); err != nil {
			return nil, fmt.Errorf("staged router hostname: %w", err)
		}
	}
	mode := "cds"
	if len(router.Hostnames) > 0 {
		mode = "acme"
	}
	hostnames := []byte{}
	for _, name := range router.Hostnames {
		hostnames = append(hostnames, name+"\n"...)
	}
	return map[string][]byte{
		// nginx includes this in its server block to pick the certificate.
		"router/tls.conf":           []byte(fmt.Sprintf("include %s/tls-%s.conf;\n", RouterTLSSnippetDir, mode)),
		"router/hostnames":          hostnames,
		"router/acme-email":         line(router.ACMEEmail),
		"router/acme-directory-url": line(router.ACMEDirectoryURL),
		"router/front-door-mode":    []byte(mode + "\n"),
		// nginx includes this in its application location.
		"router/request-body.conf": []byte(fmt.Sprintf("client_max_body_size %d;\n", router.RequestBodyLimit())),
	}, nil
}

// serverOutputs validates the server-only fields of the staged document and
// returns the files they publish. It writes nothing: Prepare publishes only
// after every input has been validated.
func serverOutputs(d *launchconfig.Document) (map[string][]byte, error) {
	if err := launchconfig.ValidateHostname(d.TLSSAN); err != nil {
		return nil, fmt.Errorf("staged TLS SAN: %w", err)
	}
	pub := []byte(d.Server.OperatorPublicKey)
	if _, err := operatorauth.ParsePublicKeysPEM(pub); err != nil {
		return nil, fmt.Errorf("staged server operator key: %w", err)
	}
	files, err := RouterOutputs(d.Router)
	if err != nil {
		return nil, err
	}
	files["operator-pubkey"] = pub
	files["tls-san"] = []byte(d.TLSSAN + "\n")
	return files, nil
}

// removeOutputs removes the named outputs from the public directory, trying
// every one.
func removeOutputs(publicPath string, names []string) error {
	var errs []error
	for _, name := range names {
		if err := os.Remove(filepath.Join(publicPath, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// readPeerPolicy accepts the launch identities this cluster's nodes boot
// with, refusing partial pins even when the staged file parses: the
// authenticated launcher emits an anchored tuple for every permitted role, on
// the family this node booted.
func readPeerPolicy(path, platform string) ([]byte, error) {
	family, err := teetypes.ParseFamily(platform)
	if err != nil {
		return nil, fmt.Errorf("staged image platform: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pins, err := refvalues.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("staged identity policy %s: %w", path, err)
	}
	if pins.Family != family {
		return nil, fmt.Errorf("staged identity policy %s does not pin this node's TEE family", path)
	}
	if !policyPinsComplete(pins) {
		return nil, fmt.Errorf("staged identity policy %s requires complete image and operator pins", path)
	}
	return data, nil
}

// policyPinsComplete reports whether every image pin carries an anchor and,
// on TDX, the kernel and operator registers the launch verifier compares.
func policyPinsComplete(pins refvalues.ReferenceValues) bool {
	for _, pin := range pins.Images {
		if len(pin.Anchor) == 0 {
			return false
		}
		if pins.Family == teetypes.FamilyTDX && (len(pin.Registers[1]) == 0 || len(pin.Registers[2]) == 0) {
			return false
		}
	}
	return true
}

// mergeBakedSeed adds the baked component seed to the measured NRI base: both
// are measured bootstrap sources, so an entry present in each must be
// identical rather than replaced.
func mergeBakedSeed(base, seed *allowlist.Allowlist) error {
	for name, workload := range seed.Workloads {
		existing, exists := base.Workloads[name]
		if !exists {
			base.Workloads[name] = workload
			continue
		}
		old, err := json.Marshal(existing)
		if err != nil {
			return err
		}
		incoming, err := json.Marshal(workload)
		if err != nil {
			return err
		}
		// Both inputs were normalized by ParseJSON. Compare every field, so
		// a collision cannot loosen the measured policy.
		if !bytes.Equal(old, incoming) {
			return fmt.Errorf("workload %q replaces a baked component", name)
		}
	}
	// Validate the combined document as well as each individual input.
	if err := base.Normalize(); err != nil {
		return fmt.Errorf("combined workload policy: %w", err)
	}
	return nil
}
