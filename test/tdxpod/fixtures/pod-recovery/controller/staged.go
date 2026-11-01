package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

const baselineLaunchSchema = "c8s-launch/v1"
const baselineStagedLimit = 6 << 20

// The immutable baseline052 role service has already authenticated and validated
// this root-owned staged file before starting the fixture. This reader checks
// that baseline's generic-boot precondition; it is not a launch authentication
// API and must never be used for host input or by production launchconfig.
func requireBaselineLaunch(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > baselineStagedLimit {
		return errors.New("baseline staged launch is not a bounded protected regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, baselineStagedLimit+1))
	if err != nil {
		return err
	}
	return checkBaselineLaunch(data)
}

func checkBaselineLaunch(data []byte) error {
	if len(data) == 0 || len(data) > baselineStagedLimit {
		return errors.New("baseline staged launch exceeds its bounds")
	}
	// Only the baseline wire fields are recognized. Types shared with the current
	// launcher describe version-independent fields; no current schema validator
	// is applied to an already-validated historical launch.
	var doc struct {
		SchemaVersion string             `json:"schema_version"`
		ClusterID     string             `json:"cluster_id"`
		Role          string             `json:"role"`
		Image         launchconfig.Image `json:"image"`
		Node          launchconfig.Node  `json:"node"`
		RKE2          struct {
			ServerToken string `json:"server_token"`
			AgentToken  string `json:"agent_token"`
		} `json:"rke2"`
		Server                  launchconfig.ServerConfig `json:"server"`
		AgentOperatorPublicKeys []string                  `json:"agent_operator_public_keys"`
		PodOperatorPublicKey    string                    `json:"pod_operator_public_key"`
		TLSSAN                  string                    `json:"tls_san"`
		Workloads               string                    `json:"workloads"`
		PodImagePolicy          string                    `json:"pod_image_policy"`
		Router                  json.RawMessage           `json:"router"`
		RegistryMirrors         map[string]string         `json:"registry_mirrors"`
		Pod                     json.RawMessage           `json:"pod"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return errors.New("baseline staged launch is malformed")
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("baseline staged launch contains trailing data")
	}
	if doc.SchemaVersion != baselineLaunchSchema || doc.Role != string(launchconfig.Pod) || len(doc.Pod) != 0 || doc.Workloads != "" || doc.PodImagePolicy != "" ||
		doc.RKE2.ServerToken != "" || doc.RKE2.AgentToken != "" || len(doc.AgentOperatorPublicKeys) != 0 || len(doc.Router) != 0 ||
		doc.ClusterID == "" || doc.Node.Name == "" || doc.PodOperatorPublicKey == "" || doc.Server.OperatorPublicKey == "" || doc.Server.Address == "" || !doc.Image.HasRuntimeRegister() {
		return errors.New("baseline c8s-launch/v1 generic Pod launch required")
	}
	return nil
}
