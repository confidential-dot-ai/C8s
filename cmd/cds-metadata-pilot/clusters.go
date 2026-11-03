package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
)

func privateFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open private configuration file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("configuration must be a private, bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("cannot read private configuration file")
	}
	return data, nil
}

// The manifest carries token file paths, never bearer values. As with the
// single-cluster command, all secret files must be provisioned privately.
func clusterConfigs(path string) ([]metadatapilot.ClusterConfig, error) {
	data, err := privateFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var manifest []struct {
		Namespace string `json:"namespace"`
		TokenFile string `json:"token_file"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, errors.New("invalid clusters manifest")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing clusters manifest data")
	}
	if len(manifest) == 0 || len(manifest) > metadatapilot.MaxClusters {
		return nil, errors.New("clusters manifest requires 1..256 entries")
	}
	configs := make([]metadatapilot.ClusterConfig, 0, len(manifest))
	for _, entry := range manifest {
		token, err := privateFile(entry.TokenFile, 4097)
		if err != nil {
			return nil, err
		}
		configs = append(configs, metadatapilot.ClusterConfig{Namespace: entry.Namespace, Token: strings.TrimSpace(string(token))})
		clear(token)
	}
	return configs, nil
}
