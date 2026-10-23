package nodeservices

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Prepare publishes a fixed set of nonsecret workload inputs from the
// verified launch document loaded by LoadStaged. rootDir rebases paths for tests.
// The root bootstrap service owns these files; pods mount them read-only.
func Prepare(rootDir string, d *launchconfig.Document) error {
	if err := validateRole(d); err != nil {
		return err
	}
	path := func(name string) string { return filepath.Join(rootDir, name) }
	outputs := make(map[string][]byte)
	for _, name := range []string{"peers.json", "cds.json"} {
		// cds.json pins exactly the server, plus one entry per cds launch key
		// when the cluster runs an HA CDS, each on every accepted image;
		// peers.json pins every role.
		want := 0
		if name == "cds.json" {
			want = (1 + len(d.CDSOperatorPublicKeys)) * (1 + len(d.PeerImages))
		}
		data, err := readPolicy(path(launchDir+name), d.Image.Platform, want)
		if err != nil {
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
	// Every node publishes which CDS flavour the signed document selected, so
	// the baked singleton can yield on an HA cluster without reading the
	// root-only staged document (which carries join tokens).
	outputs[CDSModeFile] = []byte(CDSModeSingleton + "\n")
	if d.CDSHA != nil {
		outputs[CDSModeFile] = []byte(CDSModeHA + "\n")
	}
	nodeSeed := bakedSeed
	switch d.Role {
	case launchconfig.Server:
		server, err := serverOutputs(d, bakedData)
		if err != nil {
			return err
		}
		maps.Copy(outputs, server.files())
	case launchconfig.CDS:
		cds, err := cdsOutputs(d, bakedData)
		if err != nil {
			return err
		}
		maps.Copy(outputs, cds)
		// A cds-role node admits the cds floor instead of the chart seed: the
		// HA CDS replica with its exact argv and the per-node DaemonSets,
		// nothing else of the chart (the operator image carries the same c8s
		// binary).
		floorData, err := os.ReadFile(path("/usr/lib/c8s/cds-floor.json"))
		if err != nil {
			return fmt.Errorf("cds role needs the baked cds floor: %w", err)
		}
		if nodeSeed, err = allowlist.ParseJSON(floorData); err != nil {
			return fmt.Errorf("baked cds floor: %w", err)
		}
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
	if err := mergeWorkloads(base, nodeSeed, true); err != nil {
		return fmt.Errorf("merge chart seed into NRI base: %w", err)
	}
	a["base"] = base
	if d.Role == launchconfig.CDS {
		// A cds node admits only the measured floor: no served allowlist, so
		// no allowlisted image can land beside a replica and share its quote.
		delete(a, "pull")
	} else {
		pull["url"] = d.CDSURL()
		pull["cds_measurements_config"] = launchDir + "cds.json"
		if d.CDSHA != nil {
			// What the enforcer needs to follow the operator's signed CDS
			// pin decrees across a CDS image rollout.
			pull["cds_decrees"] = map[string]any{"cluster_id": d.ClusterID, "decree_key": d.CDSHA.DecreeKey, "pin_floor": d.CDSHA.PinFloor}
			pull["cds_decrees_state"] = "/run/nri-image-policy/cds-decree-state.json"
		}
		delete(pull, "cds_measurements")
		delete(pull, "cds_rtmrs")
	}
	// Every role binds the credential role: the measured base names the
	// credential workloads on every node (a cds node included), and the
	// runtime refuses a base whose credential role is unbound.
	mesh, declared := floor["mesh"]
	if !declared {
		return fmt.Errorf("baked NRI policy missing mesh")
	}
	policy, ok := mesh.(map[string]any)
	if !ok {
		return fmt.Errorf("baked NRI mesh policy is %T, not a mapping", mesh)
	}
	address, err := d.CDSAddrPort()
	if err != nil {
		return err
	}
	if err := appendCredentialRole(policy, address); err != nil {
		return err
	}
	data, err = yaml.Marshal(floor)
	if err != nil {
		return err
	}

	// Validate every input before publishing anything. RKE2 only starts after
	// this preparation succeeds, so pods never observe partially staged input.
	publicPath := path(PublicDir)
	if err := os.MkdirAll(publicPath, 0755); err != nil {
		return err
	}
	if err := os.Chmod(publicPath, 0755); err != nil {
		return err
	}
	// Remove every public file this role does not publish, so a node whose
	// signed document changed role or dropped cdsHA keeps no stale input.
	for _, name := range append([]string{cdsHAFile}, serverOutputNames...) {
		if _, ok := outputs[name]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(publicPath, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
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
	if d.Role == launchconfig.Server {
		if err := selectCDSFlavour(path(rke2ManifestsDir), d.CDSHA != nil); err != nil {
			return err
		}
	}
	policyPath := path("/etc/nri/conf.d/image-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0755); err != nil {
		return err
	}
	return fileutil.WriteAtomic(policyPath, data, 0600)
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

// appendCredentialRole completes the measured mesh policy with the one binding
// only a launched node can know: the injected credential clients reach this
// cluster's CDS and nothing else. A policy that already names that role, or
// its reserved identity, is a measured policy this step would contradict.
func appendCredentialRole(policy map[string]any, address netip.AddrPort) error {
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
		"name":         nriimagepolicy.CredentialRole,
		"uid":          workloadclaims.CredentialsUID,
		"destinations": []any{address.String()},
	})
	return nil
}

// serverConfig holds the inputs only a server publishes. An agent must never
// carry them, so they are produced and removed as one named set rather than
// as loose strings spread across Prepare.
type serverConfig struct {
	operatorPubKey []byte
	allowlistSeed  []byte
	tlsSAN         string
	router         launchconfig.Router
}

// serverOutputNames is the set both roles agree on: a server writes exactly
// these, and an agent clears exactly these. The router files are always
// written, empty when unset, so the router pod never waits on a missing file.
var serverOutputNames = []string{
	"operator-pubkey", "allowlist-seed.json", "tls-san",
	"router/tls.conf", "router/hostnames",
	"router/acme-email", "router/acme-directory-url", "router/front-door-mode",
}

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

func (c serverConfig) files() map[string][]byte {
	mode := "cds"
	if len(c.router.Hostnames) > 0 {
		mode = "acme"
	}
	hostnames := []byte{}
	for _, name := range c.router.Hostnames {
		hostnames = append(hostnames, name+"\n"...)
	}
	files := map[string][]byte{
		"operator-pubkey":     c.operatorPubKey,
		"allowlist-seed.json": c.allowlistSeed,
		"tls-san":             []byte(c.tlsSAN + "\n"),
		// nginx includes this in its server block to pick the certificate.
		"router/tls.conf":           []byte(fmt.Sprintf("include %s/tls-%s.conf;\n", RouterTLSSnippetDir, mode)),
		"router/hostnames":          hostnames,
		"router/acme-email":         line(c.router.ACMEEmail),
		"router/acme-directory-url": line(c.router.ACMEDirectoryURL),
		"router/front-door-mode":    []byte(mode + "\n"),
	}
	// A server output an agent does not clear would survive a demotion, so
	// the two sets must not drift apart.
	if len(files) != len(serverOutputNames) {
		panic("serverConfig.files and serverOutputNames disagree")
	}
	for _, name := range serverOutputNames {
		if _, ok := files[name]; !ok {
			panic("serverOutputNames lists an unwritten server output: " + name)
		}
	}
	return files
}

// serverOutputs validates the server-only fields of the staged document and
// merges the operator's workloads over the baked seed. It writes nothing:
// Prepare publishes only after every input has been validated.
func serverOutputs(d *launchconfig.Document, bakedData []byte) (serverConfig, error) {
	if err := launchconfig.ValidateHostname(d.TLSSAN); err != nil {
		return serverConfig{}, fmt.Errorf("staged TLS SAN: %w", err)
	}
	pub := []byte(d.Server.OperatorPublicKey)
	if _, err := operatorauth.ParsePublicKeysPEM(pub); err != nil {
		return serverConfig{}, fmt.Errorf("staged server operator key: %w", err)
	}
	seed, err := mergedSeed(bakedData, d.Workloads)
	if err != nil {
		return serverConfig{}, err
	}
	var router launchconfig.Router
	if d.Router != nil {
		router = *d.Router
	}
	// LoadStaged validated the document; check the hostnames again, so no
	// path can publish an injectable file.
	for _, name := range router.Hostnames {
		if err := launchconfig.ValidateHostname(name); err != nil {
			return serverConfig{}, fmt.Errorf("staged router hostname: %w", err)
		}
	}
	return serverConfig{operatorPubKey: pub, allowlistSeed: seed, tlsSAN: d.TLSSAN, router: router}, nil
}

// readPolicy refuses partial pins even when the staged file parses. The
// authenticated launcher emits an anchored tuple for every permitted role.
func readPolicy(path, platform string, wantImages int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pins, err := refvalues.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("staged identity policy %s: %w", path, err)
	}
	if !policyMatchesPlatform(pins, platform, wantImages) {
		return nil, fmt.Errorf("staged identity policy %s has invalid family or image count", path)
	}
	if !policyPinsComplete(pins) {
		return nil, fmt.Errorf("staged identity policy %s requires complete image and operator pins", path)
	}
	return data, nil
}

// policyMatchesPlatform checks the family and, when wantImages > 0, that
// the policy holds exactly that many image pins.
func policyMatchesPlatform(pins refvalues.ReferenceValues, platform string, wantImages int) bool {
	family, err := teetypes.ParseFamily(platform)
	if err != nil || pins.Family != family || len(pins.Images) == 0 {
		return false
	}
	return wantImages == 0 || len(pins.Images) == wantImages
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

func mergedSeed(data []byte, workloads string) ([]byte, error) {
	seed, err := allowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("baked workload seed: %w", err)
	}
	if workloads != "" {
		extra, err := allowlist.ParseJSON([]byte(workloads))
		if err != nil {
			return nil, fmt.Errorf("launch workloads: %w", err)
		}
		if err := mergeWorkloads(seed, extra, false); err != nil {
			return nil, fmt.Errorf("launch workloads: %w", err)
		}
	}
	return seed.Canonical()
}

// allowIdentical is used only for the two measured bootstrap sources. Signed
// tenant workloads may never replace a component, even with identical content.
func mergeWorkloads(base, extra *allowlist.Allowlist, allowIdentical bool) error {
	for name, workload := range extra.Workloads {
		existing, exists := base.Workloads[name]
		if !exists {
			base.Workloads[name] = workload
			continue
		}
		if !allowIdentical {
			return fmt.Errorf("workload %q replaces a baked component", name)
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

// CDSModeFile names the public file holding CDSModeSingleton or CDSModeHA.
const (
	CDSModeFile      = "cds-mode"
	CDSModeSingleton = "singleton"
	CDSModeHA        = "ha"
)

// cdsHAFile is the CDS pod's HA configuration on a cds-role node, published
// from the signed launch document so none of its trust roots is a pod flag.
const cdsHAFile = "cds-ha.json"

// CDSHAConfig is the content of cds-ha.json.
type CDSHAConfig struct {
	ClusterID   string             `json:"cluster_id"`
	DecreeKey   string             `json:"decree_key"`
	Replicas    int                `json:"replicas"`
	RecoveryKey string             `json:"recovery_key,omitempty"`
	Image       launchconfig.Image `json:"image"`
}

// cdsOutputs publishes what a CDS replica on a cds-role node needs: the
// server's operator key and allowlist seed (as on the server; CDS serves the
// same policy), the TLS SAN, and the HA configuration.
func cdsOutputs(d *launchconfig.Document, bakedData []byte) (map[string][]byte, error) {
	pub := []byte(d.Server.OperatorPublicKey)
	if _, err := operatorauth.ParsePublicKeysPEM(pub); err != nil {
		return nil, fmt.Errorf("staged server operator key: %w", err)
	}
	seed, err := mergedSeed(bakedData, d.Workloads)
	if err != nil {
		return nil, err
	}
	ha, err := json.Marshal(CDSHAConfig{ClusterID: d.ClusterID, DecreeKey: d.CDSHA.DecreeKey, Replicas: d.CDSHA.Replicas, RecoveryKey: d.CDSHA.RecoveryKey, Image: d.Image})
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"operator-pubkey":     pub,
		"allowlist-seed.json": seed,
		"tls-san":             []byte(d.TLSSAN + "\n"),
		cdsHAFile:             ha,
	}, nil
}

// rke2ManifestsDir is where RKE2 applies the baked AddOns from.
const rke2ManifestsDir = "/var/lib/rancher/rke2/server/manifests"

// selectCDSFlavour makes RKE2 apply only the CDS flavour the signed launch
// document selects: a <file>.skip sibling makes RKE2 ignore an AddOn.
func selectCDSFlavour(dir string, ha bool) error {
	skip, keep := "c8s-cds-ha.yaml.skip", "c8s-cds-singleton.yaml.skip"
	if ha {
		skip, keep = keep, skip
	}
	if err := os.Remove(filepath.Join(dir, keep)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(dir, skip), []byte("# not selected by the launch document (cdsHA)\n"), 0o644)
}
