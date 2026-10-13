package workloadclaims

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The supported sandbox size documented on maxResponseBytes must fit in it.
func TestSupportedSandboxFitsResponseCap(t *testing.T) {
	const admissions, variables, mounts = 64, 64, 16
	containers := make([]SandboxContainer, admissions)
	for i := range containers {
		entries := make([]string, variables)
		for v := range entries {
			entries[v] = fmt.Sprintf("%s_%02d=value-%d", strings.Repeat("N", 61), v, i)
		}
		env, err := allowlist.ObserveEnv(entries)
		if err != nil {
			t.Fatal(err)
		}
		c := SandboxContainer{Env: env, Digest: digestA, Argv: []string{strings.Repeat("a", 1<<10)}}
		for m := range mounts {
			c.Mounts = append(c.Mounts, allowlist.ObservedMount{Destination: fmt.Sprintf("/%s/%02d", strings.Repeat("d", 60), m), Class: "data", Storage: "projected"})
		}
		containers[i] = c
	}
	b, err := json.Marshal(SandboxDigestsResponse{Digests: []string{digestA}, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxResponseBytes {
		t.Fatalf("supported sandbox encodes to %d bytes, over the %d-byte cap", len(b), maxResponseBytes)
	}
}

// An inventory past the cap must refuse, never answer with a truncated history.
func TestFetchSandboxRefusesOversizedHistory(t *testing.T) {
	c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SandboxDigestsResponse{
			Digests:    []string{digestA},
			Containers: []SandboxContainer{{Digest: digestA, Argv: []string{strings.Repeat("a", maxResponseBytes)}}},
		})
	}))
	c.http.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	if _, err := c.FetchSandbox(context.Background(), host, "sandbox-1"); err == nil {
		t.Fatal("FetchSandbox accepted a response over the cap")
	}
}
