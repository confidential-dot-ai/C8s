//go:build linux

package armtlsmesh

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestAccessLogEntryLogTo(t *testing.T) {
	entry := &accessLogEntry{
		connID:       1,
		dir:          "outbound",
		src:          "10.0.0.1:1234",
		dst:          "10.0.0.2:443",
		bytesFwd:     100,
		bytesRev:     200,
		dur:          5 * time.Millisecond,
		certMode:     "cds",
		result:       "success",
		node:         "node-1",
		local:        "10.0.0.3:8080",
		tlsHandshake: 2 * time.Millisecond,
		ttfb:         1 * time.Millisecond,
		err:          "boom",
	}

	// Disabled: nothing should be written.
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	entry.logTo(log, false)
	if buf.Len() != 0 {
		t.Fatalf("expected no output when disabled, got %q", buf.String())
	}

	// Enabled: full entry with all optional fields present.
	buf.Reset()
	entry.logTo(log, true)
	out := buf.String()
	for _, want := range []string{"conn_id=1", "dir=outbound", "result=success", "node=node-1", "local=", "tls_handshake=", "ttfb=", "error=boom"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output %q missing %q", out, want)
		}
	}

	// Enabled: minimal entry omits optional fields.
	buf.Reset()
	minimal := &accessLogEntry{connID: 2, dir: "inbound", result: "success"}
	minimal.logTo(log, true)
	out = buf.String()
	for _, absent := range []string{"node=", "local=", "tls_handshake=", "ttfb=", "error="} {
		if strings.Contains(out, absent) {
			t.Errorf("minimal log output %q should not contain %q", out, absent)
		}
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "min valid", port: 1},
		{name: "max valid", port: 65535},
		{name: "typical", port: 15001},
		{name: "zero", port: 0, wantErr: true},
		{name: "negative", port: -1, wantErr: true},
		{name: "above range", port: 65536, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePort("--some-port", tt.port)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "out of range") {
					t.Errorf("error %q does not mention range", err.Error())
				}
				if !strings.Contains(err.Error(), "--some-port") {
					t.Errorf("error %q does not include the flag name", err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDefaultMeshExcludedSourceNamespacesCSV(t *testing.T) {
	csv := defaultMeshExcludedSourceNamespacesCSV()
	if !strings.Contains(csv, "kube-system") {
		t.Fatalf("default excluded namespaces %q should contain kube-system", csv)
	}
	// The CSV must round-trip through parseExcludedNamespaces.
	parsed := parseExcludedNamespaces(csv)
	if _, ok := parsed["kube-system"]; !ok {
		t.Fatalf("parsed default CSV %q missing kube-system", csv)
	}
}

func TestParseExcludedNamespaces(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string // expected keys
	}{
		{name: "empty", raw: "", want: nil},
		{name: "only commas", raw: ",,,", want: nil},
		{name: "single", raw: "kube-system", want: []string{"kube-system"}},
		{name: "multiple", raw: "a,b,c", want: []string{"a", "b", "c"}},
		{name: "trims whitespace", raw: " a , b ,  ", want: []string{"a", "b"}},
		{name: "duplicates collapse", raw: "a,a,b", want: []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseExcludedNamespaces(tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries (%v), want %d (%v)", len(got), got, len(tt.want), tt.want)
			}
			for _, ns := range tt.want {
				if _, ok := got[ns]; !ok {
					t.Errorf("missing namespace %q in result %v", ns, got)
				}
			}
		})
	}
}

func TestPodEligibleForMeshEndpoint(t *testing.T) {
	pod := func(hostNet bool, phase corev1.PodPhase) *corev1.Pod {
		p := &corev1.Pod{}
		p.Spec.HostNetwork = hostNet
		p.Status.Phase = phase
		return p
	}
	tests := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{name: "running", pod: pod(false, corev1.PodRunning), want: true},
		{name: "pending", pod: pod(false, corev1.PodPending), want: true},
		{name: "host network", pod: pod(true, corev1.PodRunning), want: false},
		{name: "succeeded", pod: pod(false, corev1.PodSucceeded), want: false},
		{name: "failed", pod: pod(false, corev1.PodFailed), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podEligibleForMeshEndpoint(tt.pod); got != tt.want {
				t.Fatalf("podEligibleForMeshEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPodEligibleForMeshSource(t *testing.T) {
	excluded := parseExcludedNamespaces("kube-system,monitoring")
	mkPod := func(ns string, hostNet bool, phase corev1.PodPhase) *corev1.Pod {
		p := &corev1.Pod{}
		p.Namespace = ns
		p.Spec.HostNetwork = hostNet
		p.Status.Phase = phase
		return p
	}
	tests := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{name: "eligible app namespace", pod: mkPod("default", false, corev1.PodRunning), want: true},
		{name: "excluded namespace", pod: mkPod("kube-system", false, corev1.PodRunning), want: false},
		{name: "other excluded namespace", pod: mkPod("monitoring", false, corev1.PodRunning), want: false},
		{name: "eligible namespace but host network", pod: mkPod("default", true, corev1.PodRunning), want: false},
		{name: "eligible namespace but terminated", pod: mkPod("default", false, corev1.PodSucceeded), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podEligibleForMeshSource(tt.pod, excluded); got != tt.want {
				t.Fatalf("podEligibleForMeshSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertModeStr(t *testing.T) {
	p := &Proxy{metrics: &metrics{}}

	if got := p.certModeStr(); got != "self-signed" {
		t.Fatalf("certModeStr() = %q, want self-signed (default)", got)
	}

	p.metrics.certMode.Store(1)
	if got := p.certModeStr(); got != "cds" {
		t.Fatalf("certModeStr() = %q, want cds", got)
	}

	p.metrics.certMode.Store(0)
	if got := p.certModeStr(); got != "self-signed" {
		t.Fatalf("certModeStr() = %q, want self-signed", got)
	}
}

func TestMakeAttestFunc_InvalidHexReportData(t *testing.T) {
	client := attestclient.NewClient("")
	attestFunc := makeAttestFunc(client, "http://unused.invalid")

	_, err := attestFunc(context.Background(), "not-hex!!")
	if err == nil {
		t.Fatal("expected error for invalid hex report data")
	}
	if !strings.Contains(err.Error(), "decode report data hex") {
		t.Fatalf("error %q does not mention hex decode", err.Error())
	}
}

func TestMakeAttestFunc_AttestationAPIError(t *testing.T) {
	// Point the client at an address that will fail to connect, exercising the
	// GenerateEvidence error path without any real network dependency.
	client := attestclient.NewClient("")
	// 127.0.0.1:1 is reserved/closed; the dial fails fast and deterministically.
	attestFunc := makeAttestFunc(client, "http://127.0.0.1:1")

	// Valid 64-byte hex report data so we get past the decode/slice steps.
	customData := hex.EncodeToString(make([]byte, 64))

	_, err := attestFunc(context.Background(), customData)
	if err == nil {
		t.Fatal("expected error when attestation-api is unreachable")
	}
	if !strings.Contains(err.Error(), "attestation-api") {
		t.Fatalf("error %q does not wrap attestation-api failure", err.Error())
	}
}
