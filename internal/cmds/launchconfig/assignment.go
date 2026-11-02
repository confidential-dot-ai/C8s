package launchconfig

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// AssignedPod derives the validated workload configuration for a generic boot.
// It does not mutate the launch document or write guest state. The renderer must
// additionally refuse collisions with the endpoint declaration in its measured
// floor before the assignment is committed.
func AssignedPod(doc *Document, manifest, entries, meshPeers []byte) (*Document, error) {
	if doc == nil || doc.Role != Pod || doc.Pod != nil {
		return nil, errors.New("assignment requires an unassigned generic Pod document")
	}
	assigned := *doc
	if err := assigned.validate(); err != nil {
		return nil, err
	}
	if len(manifest) > MaxDocumentSize || len(entries) > MaxDocumentSize || len(meshPeers) > MaxDocumentSize {
		return nil, errors.New("assignment payload exceeds document limit")
	}
	pod, err := ParsePodManifest(manifest)
	if err != nil {
		return nil, err
	}
	if _, err := allowlist.ParseJSON(entries); err != nil {
		return nil, fmt.Errorf("assignment entries: %w", err)
	}
	var peers []string
	if err := json.Unmarshal(meshPeers, &peers); err != nil || peers == nil {
		return nil, errors.New("assignment meshPeers must be a JSON array of strings")
	}
	assigned.Pod = &PodSpec{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, Manifest: string(manifest), MeshPeers: peers}
	assigned.Workloads = string(entries)
	if err := assigned.validate(); err != nil {
		return nil, err
	}
	return &assigned, nil
}
