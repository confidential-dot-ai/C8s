package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	"golang.org/x/net/netutil"
)

const (
	nativeWorkloadSchema = "c8s-cds-native-workload/v1"
	nativeWorkloadAPI    = "http://127.0.0.1:8400"
	nativeWorkloadConfig = "/run/confai/operator-pubkey"
	nativeWorkloadBinary = "/usr/local/bin/cds-native-workload.test"
	nativeWorkloadName   = "object-native"
)

func nativeWorkloadArgv() []string {
	return []string{
		nativeWorkloadBinary,
		"-test.run=^TestObjectNativeWorkloadGuest$",
		"-test.timeout=0",
	}
}

type nativeWorkloadLaunch struct {
	Schema           string `yaml:"schemaVersion" json:"schemaVersion"`
	RunID            string `yaml:"runID" json:"runID"`
	ExecutableSHA256 string `yaml:"executableSHA256" json:"executableSHA256"`
	OwnerClientCA    string `yaml:"ownerClientCA" json:"ownerClientCA"`
}

func parseNativeWorkloadLaunch(raw []byte) (nativeWorkloadLaunch, *x509.Certificate, error) {
	var launch nativeWorkloadLaunch
	if err := yamlutil.Decode(
		raw,
		&launch,
	); err != nil {
		return launch, nil, err
	}
	if launch.Schema != nativeWorkloadSchema || len(launch.RunID) != 32 {
		return launch, nil, errors.New("native workload: fixed schema and 16-byte hexadecimal run ID required")
	}
	for _, value := range []string{
		launch.RunID,
		launch.ExecutableSHA256,
	} {
		if _, err := hex.DecodeString(value); err != nil || strings.ToLower(value) != value {
			return launch, nil, errors.New("native workload: canonical hexadecimal identity required")
		}
	}
	if len(launch.ExecutableSHA256) != 64 {
		return launch, nil, errors.New("native workload: executable SHA256 required")
	}
	block, rest := pem.Decode([]byte(launch.OwnerClientCA))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return launch, nil, errors.New("native workload: one owner CA certificate required")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		ca.CheckSignatureFrom(ca) != nil || time.Now().Before(ca.NotBefore) || !time.Now().Before(ca.NotAfter) {
		return launch, nil, errors.New("native workload: valid self-signed owner CA required")
	}
	return launch, ca, nil
}

// This is an opt-in guest entrypoint, never a hardware proof when run on the
// development host. The measured image must fix this invocation and environment,
// cover this executable and its boot chain, and expose no shell or key export.
// A generic firmware pin or a host-selected go test invocation is insufficient.
func TestObjectNativeWorkloadGuest(t *testing.T) {
	if os.Getenv("C8S_OBJECT_NATIVE_WORKLOAD") != "1" {
		t.Skip("requires the separately measured native workload guest")
	}
	if !reflect.DeepEqual(
		os.Args,
		nativeWorkloadArgv(),
	) {
		t.Fatal("native workload requires its fixed measured invocation")
	}
	ctx, stop := signal.NotifyContext(
		t.Context(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()
	if err := runNativeWorkloadGuest(ctx); err != nil {
		// Do not print an upstream response body or a retained secret on failure.
		t.Fatal("native workload guest failed")
	}
}

func runNativeWorkloadGuest(ctx context.Context) error {
	file, err := os.Open(nativeWorkloadConfig)
	if err != nil {
		return err
	}
	raw, err := readutil.ReadAll(
		file,
		64<<10,
	)
	file.Close()
	if err != nil {
		return err
	}
	launch, owner, err := parseNativeWorkloadLaunch(raw)
	if err != nil {
		return err
	}
	binary, err := os.Open(nativeWorkloadBinary)
	if err != nil {
		return err
	}
	digest := sha256.New()
	n, err := io.Copy(
		digest,
		io.LimitReader(
			binary,
			256<<20+1,
		),
	)
	binary.Close()
	if err != nil || n > 256<<20 || hex.EncodeToString(digest.Sum(nil)) != launch.ExecutableSHA256 {
		return errors.New("native workload: executable differs from measured fixture declaration")
	}
	family, err := launchbinding.VerifyMeasuredLaunchFile(
		ctx,
		nativeWorkloadAPI,
		raw,
	)
	if err != nil || (family != teetypes.FamilySNP && family != teetypes.FamilyTDX) {
		return errors.New("native workload: native SNP or TDX measured launch required")
	}
	fixture, err := newNativeWorkload(
		ctx,
		raw,
		launch,
		owner,
		family,
	)
	if err != nil {
		return err
	}
	defer fixture.stop()
	tlsConfig, certificates, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform: family.String(),
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(
			attestclient.NewClient(""),
			nativeWorkloadAPI,
		),
		ClientCA:   owner,
		ClientAuth: tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		return err
	}
	warm, cancel := context.WithTimeout(
		ctx,
		30*time.Second,
	)
	err = certificates.WarmUp(warm)
	cancel()
	if err != nil {
		return err
	}
	go certificates.RunRotation(ctx)
	server := &http.Server{
		Addr:              ":8443",
		Handler:           fixture,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      130 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	shutdown := context.AfterFunc(
		ctx,
		func() { _ = server.Close() },
	)
	defer shutdown()
	listener, err := net.Listen(
		"tcp",
		server.Addr,
	)
	if err != nil {
		return err
	}
	err = server.ServeTLS(
		netutil.LimitListener(
			listener,
			32,
		),
		"",
		"",
	)
	if errors.Is(
		err,
		http.ErrServerClosed,
	) {
		return nil
	}
	return err
}

// This declaration is a qualification fixture, not an OCI/NRI admission
// observation. The measured test process owns the only signing keys and reports
// its verified executable and fixed argv. No external token endpoint exists.
type nativeWorkloadInventory struct {
	launch nativeWorkloadLaunch
}

func (i nativeWorkloadInventory) SandboxForPeer(workloadclaims.Peer) (workloadclaims.CallerSandbox, error) {
	return workloadclaims.CallerSandbox{}, errors.New("native fixture issues no external sandbox tokens")
}

func (i nativeWorkloadInventory) DigestsForSandbox(id string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	if id != i.launch.RunID {
		return nil, nil, false, nil
	}
	environment, err := allowlist.ObserveEnv([]string{"C8S_OBJECT_NATIVE_WORKLOAD=1"})
	if err != nil {
		return nil, nil, false, err
	}
	digest := "sha256:" + i.launch.ExecutableSHA256
	return []string{digest}, []workloadclaims.SandboxContainer{{
		Digest: digest,
		Argv:   nativeWorkloadArgv(),
		Env:    environment,
		Mounts: []allowlist.ObservedMount{},
	}}, true, nil
}

func (f *nativeWorkload) startInventory(pins refvalues.ReferenceValues) error {
	return workloadclaims.StartDigestsEndpoint(
		f.ctx,
		slog.New(slog.NewTextHandler(
			io.Discard,
			nil,
		)),
		nativeWorkloadInventory{launch: f.launch},
		f.signer.PublicKeyDER(),
		f.family.String(),
		attestclient.MakeSNPARMTLSAttestFunc(
			attestclient.NewClient(""),
			nativeWorkloadAPI,
		),
		nativeWorkloadAPI,
		armtls.FixedPins(pins),
		"",
		true,
	)
}

func TestNativeWorkloadLaunchAndInventory(t *testing.T) {
	ca, _, _ := ownerClientIdentity(t)
	launch := nativeWorkloadLaunch{
		Schema: nativeWorkloadSchema,
		RunID: strings.Repeat(
			"a",
			32,
		),
		ExecutableSHA256: strings.Repeat(
			"b",
			64,
		),
		OwnerClientCA: string(ca),
	}
	// JSON is accepted by the same strict YAML decoder; tests never attest it.
	raw := nativeWorkloadJSON(
		t,
		launch,
	)
	parsed, owner, err := parseNativeWorkloadLaunch(raw)
	if err != nil || owner == nil || parsed.RunID != launch.RunID {
		t.Fatalf(
			"valid fixture launch rejected: %v",
			err,
		)
	}
	for _, bad := range [][]byte{
		bytes.Replace(
			raw,
			[]byte(`"schemaVersion"`),
			[]byte(`"unknown"`),
			1,
		),
		bytes.Replace(
			raw,
			[]byte(launch.ExecutableSHA256),
			[]byte("short"),
			1,
		),
		append(
			bytes.Clone(raw),
			[]byte("\n{}")...,
		),
	} {
		if _, _, err := parseNativeWorkloadLaunch(bad); err == nil {
			t.Fatal("invalid fixture launch accepted")
		}
	}
	i := nativeWorkloadInventory{launch: launch}
	_, containers, known, err := i.DigestsForSandbox(launch.RunID)
	if err != nil || !known || len(containers) != 1 || containers[0].Mounts == nil || containers[0].Env == nil {
		t.Fatal("fixture inventory lost explicit launch evidence")
	}
	containers[0].Argv[0] = "modified"
	_, again, _, _ := i.DigestsForSandbox(launch.RunID)
	if again[0].Argv[0] != nativeWorkloadBinary {
		t.Fatal("caller mutated fixed inventory")
	}
	if _, _, known, _ := i.DigestsForSandbox("other"); known {
		t.Fatal("fixture vouched for another sandbox")
	}
}
