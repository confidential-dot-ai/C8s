package workloadclaims

import (
	"fmt"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// No entry publishes DigestsPort, however well it pins its launch.
func TestNoEntryPublishesTheDigestsPort(t *testing.T) {
	document := func(hostPort int) []byte {
		return []byte(fmt.Sprintf(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"sha256:%s","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"}}],"hostPorts":[{"protocol":"TCP","hostPort":%d,"containerPort":8080}]}}}`, strings.Repeat("a", 64), hostPort))
	}
	if _, err := allowlist.ParseJSON(document(DigestsPort)); err == nil {
		t.Fatalf("ParseJSON accepted an entry publishing host port %d", DigestsPort)
	}
	if _, err := allowlist.ParseJSON(document(DigestsPort + 1)); err != nil {
		t.Fatalf("ParseJSON refused the same entry on an ordinary port: %v", err)
	}
}
