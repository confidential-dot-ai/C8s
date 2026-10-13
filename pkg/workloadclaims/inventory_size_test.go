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

// encodedInventory returns the encoded size of the documented history: 64
// admissions, each with 64 variables, 16 mounts and 1 KiB of argv. Variable
// names and mount destinations are nameBytes of ASCII JSON leaves unescaped.
func encodedInventory(t *testing.T, nameBytes int) int {
	t.Helper()
	const admissions, variables, mounts, argvBytes = 64, 64, 16, 1 << 10
	containers := make([]SandboxContainer, admissions)
	for i := range containers {
		entries := make([]string, variables)
		for v := range entries {
			entries[v] = fmt.Sprintf("%s_%02d=value-%d", strings.Repeat("N", nameBytes-3), v, i)
		}
		env, err := allowlist.ObserveEnv(entries)
		if err != nil {
			t.Fatal(err)
		}
		c := SandboxContainer{Env: env, Digest: digestA, Argv: []string{strings.Repeat("a", argvBytes)}}
		for m := range mounts {
			c.Mounts = append(c.Mounts, allowlist.ObservedMount{Destination: fmt.Sprintf("/%s/%02d", strings.Repeat("d", nameBytes-4), m), Class: "data", Storage: "projected"})
		}
		containers[i] = c
	}
	b, err := json.Marshal(SandboxDigestsResponse{Digests: []string{digestA}, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// The supported sandbox size documented on MaxResponseBytes must fit in it,
// and the cap is on encoded bytes: the same counts with long paths do not fit.
func TestSupportedSandboxFitsResponseCap(t *testing.T) {
	if n := encodedInventory(t, 64); n > MaxResponseBytes {
		t.Fatalf("supported sandbox encodes to %d bytes, over the %d-byte cap", n, MaxResponseBytes)
	}
	if n := encodedInventory(t, 1<<10); n <= MaxResponseBytes {
		t.Fatalf("sandbox with 1 KiB mount destinations encodes to %d bytes, within the %d-byte cap", n, MaxResponseBytes)
	}
}

// An inventory past the cap must refuse, never answer with a truncated history.
func TestFetchSandboxRefusesOversizedHistory(t *testing.T) {
	c, host := clientAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SandboxDigestsResponse{
			Digests:    []string{digestA},
			Containers: []SandboxContainer{{Digest: digestA, Argv: []string{strings.Repeat("a", MaxResponseBytes)}}},
		})
	}))
	c.http.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	if _, err := c.FetchSandbox(context.Background(), host, "sandbox-1"); err == nil {
		t.Fatal("FetchSandbox accepted a response over the cap")
	}
}
