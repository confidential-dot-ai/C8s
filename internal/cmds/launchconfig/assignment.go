package launchconfig

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// AssignedPod is a generic pod document together with the pod assigned to the
// boot it describes: the pod, its allowlist entries and its mesh peers. The
// document itself never carries them.
type AssignedPod struct {
	Document
	Pod     PodSpec
	Entries string
}

// Assign derives the validated workload configuration of a generic boot from
// an assignment's payload. It does not mutate the launch document or write
// guest state. The renderer must additionally refuse collisions with the
// endpoint declaration in its measured floor before the assignment is
// committed.
func Assign(doc *Document, manifest, entries, meshPeers []byte) (*AssignedPod, error) {
	if doc == nil || doc.Role != Pod {
		return nil, errors.New("assignment requires a Pod document")
	}
	assigned := AssignedPod{Document: *doc}
	if err := assigned.Document.validate(); err != nil {
		return nil, err
	}
	if len(manifest) > MaxDocumentSize || len(entries) > MaxDocumentSize || len(meshPeers) > MaxDocumentSize {
		return nil, errors.New("assignment payload exceeds document limit")
	}
	pod, err := ParsePodManifest(manifest)
	if err != nil {
		return nil, err
	}
	if !json.Valid(entries) {
		return nil, errors.New("assignment entries must be one valid JSON document")
	}
	if _, err := allowlist.ParseJSON(entries); err != nil {
		return nil, fmt.Errorf("assignment entries: %w", err)
	}
	var peers []string
	if err := json.Unmarshal(meshPeers, &peers); err != nil || peers == nil {
		return nil, errors.New("assignment meshPeers must be a JSON array of strings")
	}
	assigned.Pod = PodSpec{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, Manifest: string(manifest), MeshPeers: peers}
	assigned.Entries = string(entries)
	if err := assigned.Pod.validate(); err != nil {
		return nil, err
	}
	return &assigned, nil
}
