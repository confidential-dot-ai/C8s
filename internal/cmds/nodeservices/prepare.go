package nodeservices

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

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
		data, err := readPolicy(path(launchDir+name), d.Image.Platform, name == "cds.json")
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
	if d.Role == launchconfig.Server {
		server, err := serverOutputs(d, bakedData)
		if err != nil {
			return err
		}
		for name, data := range server.files() {
			outputs[name] = data
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
	if err := mergeWorkloads(base, bakedSeed, true); err != nil {
		return fmt.Errorf("merge chart seed into NRI base: %w", err)
	}
	a["base"] = base
	pull["url"] = d.CDSURL()
	pull["cds_measurements_config"] = launchDir + "cds.json"
	delete(pull, "cds_measurements")
	delete(pull, "cds_rtmrs")
	// A node carrying no mesh policy hosts no member pods, so there is no
	// role to bind.
	if mesh, declared := floor["mesh"]; declared {
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
	if d.Role == launchconfig.Agent {
		if err := removeServerOutputs(publicPath); err != nil {
			return err
		}
	}
	for name, data := range outputs {
		if err := fileutil.WriteAtomic(filepath.Join(publicPath, name), data, 0644); err != nil {
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
}

// serverOutputNames is the set both roles agree on: a server writes exactly
// these, and an agent clears exactly these.
var serverOutputNames = []string{"operator-pubkey", "allowlist-seed.json", "tls-san"}

func (c serverConfig) files() map[string][]byte {
	files := map[string][]byte{
		"operator-pubkey":     c.operatorPubKey,
		"allowlist-seed.json": c.allowlistSeed,
		"tls-san":             []byte(c.tlsSAN + "\n"),
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
	if net.ParseIP(d.TLSSAN) != nil {
		return serverConfig{}, fmt.Errorf("staged TLS SAN must be a DNS hostname")
	}
	if err := cmdsutil.ValidateDNSName(d.TLSSAN); err != nil {
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
	return serverConfig{operatorPubKey: pub, allowlistSeed: seed, tlsSAN: d.TLSSAN}, nil
}

// removeServerOutputs clears the server-only inputs from an agent's public
// directory, so a node demoted to agent cannot keep serving stale ones.
func removeServerOutputs(publicPath string) error {
	for _, name := range serverOutputNames {
		if err := os.Remove(filepath.Join(publicPath, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// readPolicy refuses partial pins even when the staged file parses. The
// authenticated launcher emits an anchored tuple for every permitted role.
func readPolicy(path, platform string, serverOnly bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pins, err := refvalues.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("staged identity policy %s: %w", path, err)
	}
	if !policyMatchesPlatform(pins, platform, serverOnly) {
		return nil, fmt.Errorf("staged identity policy %s has invalid family or image count", path)
	}
	if !policyPinsComplete(pins) {
		return nil, fmt.Errorf("staged identity policy %s requires complete image and operator pins", path)
	}
	return data, nil
}

// policyMatchesPlatform reports whether the policy targets the booted TEE
// family and pins the number of images the role permits: at least one, and
// exactly one when the policy is server-only.
func policyMatchesPlatform(pins refvalues.ReferenceValues, platform string, serverOnly bool) bool {
	family, err := teetypes.ParseFamily(platform)
	if err != nil || pins.Family != family || len(pins.Images) == 0 {
		return false
	}
	return !serverOnly || len(pins.Images) == 1
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
