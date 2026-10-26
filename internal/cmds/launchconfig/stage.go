package launchconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	utilnet "k8s.io/apimachinery/pkg/util/net"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const (
	serverMarker     = "/run/confos/role-server"
	agentMarker      = "/run/confos/role-agent"
	rke2FragmentPath = "/etc/rancher/rke2/config.yaml.d/50-role.yaml"
	nodePasswordPath = NodePasswordPath
	// RKE2 reads this when it writes containerd's registry hosts;
	// rke2-role.service runs before the RKE2 units, as for the role fragment.
	rke2RegistriesPath = "/etc/rancher/rke2/registries.yaml"
)

const (
	// AgentTokenPath is the RAM-backed RKE2 agent credential: the server mints
	// it before RKE2 starts, and an agent's attested enrollment stages it there.
	AgentTokenPath = "/run/confos/rke2-agent-token"
	// NodePasswordKeyPath is the server's RAM-backed key for node passwords
	// (NodePassword). It lives as long as RKE2's in-RAM cluster state.
	NodePasswordKeyPath = "/run/confos/rke2-node-password-key"
	// NodePasswordPath is where RKE2 keeps the secret that proves this node's
	// name to the server. /etc/rancher is per-boot scratch, so a random one
	// would lock a rebooted node out of its own name: the server stages its
	// own derived password here, and an agent's attested enrollment stages
	// the one the server derived for its name.
	NodePasswordPath = "/etc/rancher/node/password"
	// SignedDocumentFile and SignatureFile, under Dir, are an agent's verified
	// launch document and its signature exactly as launched. Enrollment
	// presents them so the server learns the agent's name from operator-signed
	// bytes; neither is secret.
	SignedDocumentFile = "launch.yaml"
	SignatureFile      = "launch.sig"
)

// Stage authenticates the launch document and writes only fixed boot paths.
// Both role markers are cleared before verification, and the selected marker
// is written last: an invalid document or failed write cannot start a role.
// Services require the oneshot stage unit and must never consume these files
// independently of its successful completion. Role changes require relaunch.
func Stage(ctx context.Context, cfg Config) error {
	if err := clearOutputs(cfg); err != nil {
		return err
	}
	verified, err := Verify(ctx, cfg)
	if err != nil {
		return err
	}
	return stageVerified(cfg, verified)
}

func (c Config) path(absolute string) string {
	if c.RootDir == "" {
		return absolute
	}
	return filepath.Join(c.RootDir, strings.TrimPrefix(absolute, "/"))
}

func clearOutputs(cfg Config) error {
	// Clear authorization verdicts first, even when removing another stale
	// output fails. Collect errors so a blocked first marker never prevents
	// attempting to remove the other.
	//
	// The agent token and node-password key are never staged inputs: the
	// server generates them in RAM on first staging and they belong to the
	// running cluster, so they are kept across restaging, including a failed
	// verification. The role gates still close, so nothing can use them until
	// the document verifies again.
	var errs []error
	paths := []string{serverMarker, agentMarker, rke2FragmentPath, nodePasswordPath, rke2RegistriesPath}
	for _, name := range []string{"peers.json", "cds.json", "agents.json", "operator-pubkey", "config.json", "workloads.json", SignedDocumentFile, SignatureFile} {
		paths = append(paths, Dir+"/"+name)
	}
	for _, path := range paths {
		if err := os.Remove(cfg.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove stale %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

type outputFile struct {
	path string
	data []byte
}

func stageVerified(cfg Config, v *Verified) error {
	doc := &v.document
	if doc.Role == Server && doc.Server.Address == "" {
		address := doc.Node.IP
		if address == "" {
			var err error
			address, err = PrimaryIPv4()
			if err != nil {
				return fmt.Errorf("resolve server address: %w", err)
			}
		}
		if err := ValidateIPv4(address, true); err != nil {
			return fmt.Errorf("resolved server address: %w", err)
		}
		doc.Server.Address = address
		doc.Node.IP = address
	}
	peers, err := refvalues.Format(v.pins)
	if err != nil {
		return fmt.Errorf("format node peer policy: %w", err)
	}
	cds, err := refvalues.Format(v.cdsPins)
	if err != nil {
		return fmt.Errorf("format server policy: %w", err)
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode staged config: %w", err)
	}
	fragment, err := yaml.Marshal(rke2Fragment(doc))
	if err != nil {
		return fmt.Errorf("encode RKE2 role fragment: %w", err)
	}
	outputs := []outputFile{
		{Dir + "/peers.json", peers},
		{Dir + "/cds.json", cds},
		{Dir + "/operator-pubkey", v.operatorPub},
		{Dir + "/config.json", append(encoded, '\n')},
		{rke2FragmentPath, fragment},
	}
	if doc.Workloads != "" {
		outputs = append(outputs, outputFile{Dir + "/workloads.json", []byte(doc.Workloads)})
	}
	if len(doc.RegistryMirrors) > 0 {
		registries, err := yaml.Marshal(registriesFile(doc))
		if err != nil {
			return fmt.Errorf("encode RKE2 registries: %w", err)
		}
		outputs = append(outputs, outputFile{rke2RegistriesPath, registries})
	}
	marker := agentMarker
	if doc.Role == Server {
		// RKE2 generates its privileged server token itself; the separate
		// agent token is minted here so it can never alias the server one.
		if err := initializeSecret(cfg.path(AgentTokenPath), "agent token"); err != nil {
			return err
		}
		// The server is not enrolled through join: it derives its own node
		// password from the key it releases agents' passwords under.
		password, err := serverNodePassword(cfg, doc.Node.Name)
		if err != nil {
			return err
		}
		outputs = append(outputs, outputFile{nodePasswordPath, []byte(password + "\n")})
		// Agents enroll over attested TLS against this policy: every image and
		// launch-key tuple the signed document authorizes, minus the server's.
		if len(v.pins.Images) > 1 {
			agents, err := refvalues.Format(refvalues.ReferenceValues{Family: v.pins.Family, Images: v.pins.Images[1:]})
			if err != nil {
				return fmt.Errorf("format agent enrollment policy: %w", err)
			}
			outputs = append(outputs, outputFile{Dir + "/agents.json", agents})
		}
		marker = serverMarker
	} else {
		outputs = append(outputs,
			outputFile{Dir + "/" + SignedDocumentFile, v.raw},
			outputFile{Dir + "/" + SignatureFile, v.signature})
	}
	for _, out := range outputs {
		path := cfg.path(out.path)
		// /run/confos/launch holds the authenticated boot policy, never a
		// credential from launch media.
		// Existing parent directories retain their established permissions.
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create output parent: %w", err)
		}
		if err := fileutil.WriteAtomic(path, out.data, 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", out.path, err)
		}
	}
	// No fallible work follows publishing the role authorization verdict.
	return fileutil.WriteAtomic(cfg.path(marker), nil, 0o600)
}

type roleFragment struct {
	TokenFile      string `yaml:"token-file,omitempty"`
	AgentTokenFile string `yaml:"agent-token-file,omitempty"`
	Server         string `yaml:"server,omitempty"`
	NodeName       string `yaml:"node-name"`
	NodeIP         string `yaml:"node-ip,omitempty"`
	NodeExternalIP string `yaml:"node-external-ip,omitempty"`
}

// rke2Registries is the mirrors section of RKE2's registries.yaml. Only the
// mirror is listed; containerd tries the registry itself last regardless.
type rke2Registries struct {
	Mirrors map[string]rke2Mirror `yaml:"mirrors"`
}

type rke2Mirror struct {
	Endpoint []string `yaml:"endpoint"`
}

func registriesFile(doc *Document) rke2Registries {
	out := rke2Registries{Mirrors: make(map[string]rke2Mirror, len(doc.RegistryMirrors))}
	for registry, endpoint := range doc.RegistryMirrors {
		out.Mirrors[registry] = rke2Mirror{Endpoint: []string{endpoint}}
	}
	return out
}

func rke2Fragment(doc *Document) roleFragment {
	out := roleFragment{NodeName: doc.Node.Name, NodeIP: doc.Node.IP, NodeExternalIP: doc.Node.ExternalIP}
	if doc.Role == Server {
		// No token-file: RKE2 generates its privileged token inside the guest.
		out.AgentTokenFile = AgentTokenPath
	} else {
		out.TokenFile = AgentTokenPath
		out.Server = "https://" + doc.Server.Address + ":9345"
	}
	return out
}

func serverNodePassword(cfg Config, name string) (string, error) {
	path := cfg.path(NodePasswordKeyPath)
	if err := initializeSecret(path, "node password key"); err != nil {
		return "", err
	}
	key, err := LoadNodePasswordKey(path)
	if err != nil {
		return "", err
	}
	defer clear(key)
	return NodePassword(key, name), nil
}

// chooseHostInterface is a package var so tests can fake the host's routes.
var chooseHostInterface = utilnet.ChooseHostInterface

// PrimaryIPv4 uses Kubernetes' route-aware host-address selection, so the
// address published to agents matches the node's own RKE2 registration.
func PrimaryIPv4() (string, error) {
	ip, err := chooseHostInterface()
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}
