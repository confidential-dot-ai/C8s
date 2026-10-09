package armtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// testMeshSandboxID is the workload instance a mesh leaf names.
const testMeshSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

// meshLeafSpec builds the CDS-shaped leaves a mesh verifier is handed. Its
// zero value is a valid leaf: both TLS purposes, a P-256 key, a one-hour
// window around now and the sandbox-ID extension for testMeshSandboxID.
type meshLeafSpec struct {
	purposes      []x509.ExtKeyUsage // nil means serverAuth and clientAuth
	key           *ecdsa.PrivateKey  // nil generates a P-256 key
	notBefore     time.Time
	notAfter      time.Time
	omitSandboxID bool            // the leaf carries no sandbox-ID extension
	sandboxExt    *pkix.Extension // replaces the well-formed sandbox-ID extension
	armtlsExt     *pkix.Extension // an armTLS attestation extension the leaf also carries
}

func signMeshLeaf(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, spec meshLeafSpec) *tls.Certificate {
	t.Helper()
	key := spec.key
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	purposes := spec.purposes
	if purposes == nil {
		purposes = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	if spec.notBefore.IsZero() {
		spec.notBefore = time.Now().Add(-time.Hour)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = time.Now().Add(time.Hour)
	}
	var extensions []pkix.Extension
	switch {
	case spec.sandboxExt != nil:
		extensions = []pkix.Extension{*spec.sandboxExt}
	case !spec.omitSandboxID:
		extensions = []pkix.Extension{mustSandboxExt(t, testMeshSandboxID)}
	}
	if spec.armtlsExt != nil {
		extensions = append(extensions, *spec.armtlsExt)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(700),
		Subject:         pkix.Name{CommonName: "mesh-peer"},
		NotBefore:       spec.notBefore,
		NotAfter:        spec.notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     purposes,
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

func meshLeafDER(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate) []byte {
	t.Helper()
	return signMeshLeaf(t, caKey, ca, meshLeafSpec{}).Leaf.Raw
}

// meshCA signs a CA certificate under parent, or a self-signed root when
// parent is nil. purposes is what that CA permits a chain below it; nil
// permits every purpose.
func meshCA(t *testing.T, parentKey *ecdsa.PrivateKey, parent *x509.Certificate, serial int64, purposes []x509.ExtKeyUsage) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("mesh CA %d", serial)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           purposes,
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// A mesh peer is authenticated by its chain and the instance it names, and by
// nothing else: no evidence can stand in for a chain that does not verify.
func TestChainVerifyPeerCallback(t *testing.T) {
	caKey, caCert := generateCACert(t)
	foreignKey, foreignCert := generateCACert(t)
	_, _, attested := testAttestedCert(t, nil)

	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ia5SandboxID, err := asn1.MarshalWithParams(testMeshSandboxID, "ia5")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	rootKey, rootCert := meshCA(t, nil, nil, 710, nil)
	openKey, openCert := meshCA(t, rootKey, rootCert, 711, nil)
	clientOnlyKey, clientOnlyCert := meshCA(t, rootKey, rootCert, 712, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	throughOpen := [][]byte{meshLeafDER(t, openKey, openCert), openCert.Raw}
	throughClientOnly := [][]byte{meshLeafDER(t, clientOnlyKey, clientOnlyCert), clientOnlyCert.Raw}

	tests := []struct {
		name    string
		peer    [][]byte
		ca      *x509.Certificate
		wantErr bool
	}{
		{"mesh leaf", [][]byte{meshLeafDER(t, caKey, caCert)}, caCert, false},
		{"no certificate", nil, caCert, true},
		{"garbage certificate", [][]byte{{0x01, 0x02}}, caCert, true},
		{"another mesh CA", [][]byte{meshLeafDER(t, foreignKey, foreignCert)}, caCert, true},
		{"self-signed attested peer", [][]byte{attested.Raw}, caCert, true},
		{
			"no sandbox ID",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{omitSandboxID: true}).Leaf.Raw},
			caCert, true,
		},
		{
			"sandbox ID as an IA5String",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{sandboxExt: &pkix.Extension{
				Id:    OIDSandboxID,
				Value: ia5SandboxID,
			}}).Leaf.Raw},
			caCert, true,
		},
		{
			// CDS copies the requester's armTLS extension onto the leaf, and
			// the chain path reads neither it nor its contents:
			// the CA signature is what authenticates this leaf. The "mesh
			// leaf" row above carries none at all.
			"leaf carrying a malformed armTLS extension",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{
				armtlsExt: &pkix.Extension{Id: OIDARMTLSAttestation, Value: []byte{0x30, 0x03, 0x02, 0x01}},
			}).Leaf.Raw},
			caCert, false,
		},
		{
			"client-only purpose",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{purposes: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}).Leaf.Raw},
			caCert, true,
		},
		{
			"intermediate that permits every purpose",
			throughOpen,
			rootCert, false,
		},
		{
			"intermediate that forbids the peer's purpose",
			throughClientOnly,
			rootCert, true,
		},
		{
			"P-521 key",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{key: p521}).Leaf.Raw},
			caCert, true,
		},
		{
			"expired leaf",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{
				notBefore: now.Add(-2 * time.Hour),
				notAfter:  now.Add(-time.Minute),
			}).Leaf.Raw},
			caCert, true,
		},
		{
			"leaf valid two minutes from now",
			[][]byte{signMeshLeaf(t, caKey, caCert, meshLeafSpec{
				notBefore: now.Add(2 * time.Minute),
				notAfter:  now.Add(time.Hour),
			}).Leaf.Raw},
			caCert, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := chainVerifyPeerCallback(tt.ca, x509.ExtKeyUsageServerAuth)(tt.peer, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verify err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMeshTLSConfigShape(t *testing.T) {
	provider := &mockProvider{
		cert: generateSimpleCert(t),
		ttl:  time.Hour,
	}
	_, caCert := generateCACert(t)
	cfg := &MeshConfig{
		CertProvider: provider,
		MeshCA:       caCert,
	}
	server, _, err := NewMeshServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := NewMeshClientTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if server.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("server ClientAuth = %v, want RequireAnyClientCert", server.ClientAuth)
	}
	if server.GetCertificate == nil || client.GetClientCertificate == nil {
		t.Error("a mesh endpoint must present its own leaf in both roles")
	}
	if !client.InsecureSkipVerify {
		t.Error("the mesh client must leave peer verification to the chain callback")
	}
	for name, cfg := range map[string]*tls.Config{"server": server, "client": client} {
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("%s MinVersion = %v, want TLS 1.3", name, cfg.MinVersion)
		}
		if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != MeshALPN {
			t.Errorf("%s NextProtos = %v, want [%s]", name, cfg.NextProtos, MeshALPN)
		}
		if cfg.VerifyPeerCertificate == nil || cfg.VerifyConnection == nil {
			t.Errorf("%s has no peer verification", name)
		}
	}
	if _, _, err := NewMeshServerTLSConfig(&MeshConfig{MeshCA: caCert}); err == nil {
		t.Error("a mesh endpoint without a CertProvider was configured")
	}
	if _, _, err := NewMeshServerTLSConfig(&MeshConfig{CertProvider: provider}); err == nil {
		t.Error("a mesh endpoint with no mesh CA was configured")
	}
}

// Resumption re-runs no verification in crypto/tls, so no armTLS
// configuration may offer it.
func TestEveryConfigRefusesResumption(t *testing.T) {
	configs := map[string]func(t *testing.T) (*tls.Config, *CertManager, error){
		"evidence server": func(t *testing.T) (*tls.Config, *CertManager, error) {
			cfg := testServerConfig()
			cfg.ClientPolicy = &VerifyPolicy{AttestationApiURL: "http://unused.invalid"}
			return NewServerTLSConfig(cfg)
		},
		"dual-verification server": func(t *testing.T) (*tls.Config, *CertManager, error) {
			_, caCert := generateCACert(t)
			cfg := testServerConfig()
			cfg.ClientPolicy = &VerifyPolicy{AttestationApiURL: "http://unused.invalid"}
			cfg.CACert = []*x509.Certificate{caCert}
			return NewServerTLSConfig(cfg)
		},
		"client-CA server": func(t *testing.T) (*tls.Config, *CertManager, error) {
			_, caCert := generateCACert(t)
			cfg := testServerConfig()
			cfg.ClientCAs = []*x509.Certificate{caCert}
			return NewServerTLSConfig(cfg)
		},
		"evidence client": func(t *testing.T) (*tls.Config, *CertManager, error) {
			return NewClientTLSConfig(&ClientConfig{
				Policy: &VerifyPolicy{},
				CertProvider: &mockProvider{
					cert: generateSimpleCert(t),
					ttl:  time.Hour,
				},
			})
		},
		"mesh server": func(t *testing.T) (*tls.Config, *CertManager, error) {
			return NewMeshServerTLSConfig(meshConfig(t))
		},
		"mesh client": func(t *testing.T) (*tls.Config, *CertManager, error) {
			return NewMeshClientTLSConfig(meshConfig(t))
		},
	}
	for name, build := range configs {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := build(t)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.SessionTicketsDisabled {
				t.Error("SessionTicketsDisabled is false: the server would issue resumption tickets")
			}
			if cfg.ClientSessionCache != nil {
				t.Error("ClientSessionCache is set: the client would attempt resumption")
			}
		})
	}
}

func meshConfig(t *testing.T) *MeshConfig {
	t.Helper()
	_, caCert := generateCACert(t)
	return &MeshConfig{
		CertProvider: &mockProvider{
			cert: generateSimpleCert(t),
			ttl:  time.Hour,
		},
		MeshCA: caCert,
	}
}

// meshPair wires a mesh server and client over loopback against one mesh CA.
func meshPair(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caKey, caCert := generateCACert(t)
	serverCert := signMeshLeaf(t, caKey, caCert, meshLeafSpec{})
	clientCert := signMeshLeaf(t, caKey, caCert, meshLeafSpec{})
	server, _, err := NewMeshServerTLSConfig(&MeshConfig{
		CertProvider: &mockProvider{
			cert: serverCert,
			ttl:  time.Hour,
		},
		MeshCA: caCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := NewMeshClientTLSConfig(&MeshConfig{
		CertProvider: &mockProvider{
			cert: clientCert,
			ttl:  time.Hour,
		},
		MeshCA: caCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

// meshHandshake dials a one-connection mesh listener and returns the client's
// connection state.
func meshHandshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.HandshakeContext(context.Background())
		}
		conn.Close()
	}()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), client)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

func TestMeshHandshakeRequiresTheMeshALPN(t *testing.T) {
	server, client := meshPair(t)
	state, err := meshHandshake(t, server, client)
	if err != nil {
		t.Fatalf("mesh handshake failed: %v", err)
	}
	if state.NegotiatedProtocol != MeshALPN {
		t.Fatalf("negotiated protocol = %q, want %q", state.NegotiatedProtocol, MeshALPN)
	}

	for name, protocols := range map[string][]string{"another protocol": {"h2"}, "no protocol": nil} {
		t.Run(name, func(t *testing.T) {
			peer := client.Clone()
			peer.NextProtos = protocols
			if _, err := meshHandshake(t, server, peer); err == nil {
				t.Fatalf("a peer offering %v completed the mesh handshake", protocols)
			}
		})
	}
}

// A client holding a session cache still gets a full handshake, because the
// mesh server issues no tickets.
func TestMeshHandshakeDoesNotResume(t *testing.T) {
	server, client := meshPair(t)
	client.ClientSessionCache = tls.NewLRUClientSessionCache(8)

	for attempt := range 2 {
		state, err := meshHandshake(t, server, client)
		if err != nil {
			t.Fatalf("handshake %d failed: %v", attempt, err)
		}
		if state.DidResume {
			t.Fatalf("handshake %d resumed: no verification runs on a resumed handshake", attempt)
		}
	}
}

// The extension declares the TEE family the evidence itself names, never the
// configured platform, and leaves certChain to an envelope's own collateral.
func TestSelfSignedProviderDerivesTEETypeFromEvidence(t *testing.T) {
	tdxEnvelope := `{"platform":"tdx","evidence":{"quote":"dGR4LXF1b3Rl"}}`

	tests := []struct {
		name     string
		platform string
		evidence func(reportData [64]byte) string
		want     TEEType
		wantErr  bool
	}{
		{"raw SEV-SNP report", "sev-snp", func(rd [64]byte) string {
			return string(fakeSNPReport(rd))
		}, TEETypeSEVSNP, false},
		{"TDX envelope", "tdx", func([64]byte) string {
			return tdxEnvelope
		}, TEETypeTDX, false},
		{"TDX envelope on an SNP platform", "sev-snp", func([64]byte) string {
			return tdxEnvelope
		}, "", true},
		{"no evidence", "sev-snp", func([64]byte) string {
			return ""
		}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &SelfSignedProvider{
				Platform: tt.platform,
				AttestFunc: func(_ context.Context, customData string) (string, error) {
					var reportData [64]byte
					fmt.Sscanf(customData, "%x", &reportData)
					return tt.evidence(reportData), nil
				},
				Opts: &CertOptions{TTL: time.Hour},
			}
			cert, _, err := provider.Provision(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatal("evidence the platform does not produce was embedded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			att, err := ExtractAttestation(cert.Leaf)
			if err != nil {
				t.Fatal(err)
			}
			if att.Family != tt.want {
				t.Errorf("extension teeType = %v, want %v", att.Family, tt.want)
			}
			if len(att.CertChain) != 0 {
				t.Errorf("extension certChain carries %d bytes, want none", len(att.CertChain))
			}
		})
	}
}
