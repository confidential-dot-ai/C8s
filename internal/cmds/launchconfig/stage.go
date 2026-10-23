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
	podMarker        = "/run/confos/role-pod"
	serverTokenPath  = "/run/confos/rke2-server-token"
	agentTokenPath   = "/run/confos/rke2-agent-token"
	rke2FragmentPath = "/etc/rancher/rke2/config.yaml.d/50-role.yaml"
	// nodePasswordPath is where RKE2 keeps the secret that proves this node's
	// name to the server. /etc/rancher is per-boot scratch, so a random one
	// would lock a rebooted node out of its own name: the document's
	// rke2.nodePassword is staged here instead.
	nodePasswordPath = "/etc/rancher/node/password"
	// RKE2 reads this when it writes containerd's registry hosts;
	// rke2-role.service runs before the RKE2 units, as for the role fragment.
	rke2RegistriesPath = "/etc/rancher/rke2/registries.yaml"
)

// Stage authenticates the launch document and writes only fixed boot paths.
// Every role marker is cleared before verification, and the selected marker
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
	var errs []error
	paths := []string{serverMarker, agentMarker, podMarker, serverTokenPath, agentTokenPath, rke2FragmentPath, nodePasswordPath, rke2RegistriesPath}
	for _, name := range []string{"peers.json", "cds.json", "pods.json", "operator-pubkey", "config.json", "workloads.json"} {
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
	outputs := []outputFile{
		{Dir + "/peers.json", peers},
		{Dir + "/cds.json", cds},
		{Dir + "/operator-pubkey", v.operatorPub},
		{Dir + "/config.json", append(encoded, '\n')},
	}
	if doc.Role == Server {
		// Empty explicitly disables Pod issuance; it never falls back to peers.
		outputs = append(outputs, outputFile{Dir + "/pods.json", []byte(doc.PodImagePolicy)})
	}
	if doc.RKE2.NodePassword != "" {
		// Without one (an older bundle), RKE2 generates its own per boot.
		outputs = append(outputs, outputFile{nodePasswordPath, []byte(doc.RKE2.NodePassword + "\n")})
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
	if doc.Role == Pod {
		// No RKE2 token or fragment: nothing in a pod boot joins a cluster.
		// nodeservices writes the static pod from config.json.
		return publish(cfg, outputs, podMarker)
	}
	fragment, err := yaml.Marshal(rke2Fragment(doc))
	if err != nil {
		return fmt.Errorf("encode RKE2 role fragment: %w", err)
	}
	outputs = append(outputs,
		outputFile{agentTokenPath, []byte(doc.RKE2.AgentToken)},
		outputFile{rke2FragmentPath, fragment},
	)
	marker := agentMarker
	if doc.Role == Server {
		outputs = append(outputs,
			outputFile{serverTokenPath, []byte(doc.RKE2.ServerToken)},
		)
		marker = serverMarker
	}
	return publish(cfg, outputs, marker)
}

// publish writes every output, then the role marker last.
func publish(cfg Config, outputs []outputFile, marker string) error {
	for _, out := range outputs {
		path := cfg.path(out.path)
		// /run/confos/launch contains a copy of the signed join credentials.
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
	TokenFile      string `yaml:"token-file"`
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
	out := roleFragment{TokenFile: agentTokenPath, NodeName: doc.Node.Name, NodeIP: doc.Node.IP, NodeExternalIP: doc.Node.ExternalIP}
	if doc.Role == Server {
		out.TokenFile = serverTokenPath
		out.AgentTokenFile = agentTokenPath
	} else {
		out.Server = "https://" + doc.Server.Address + ":9345"
	}
	return out
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
