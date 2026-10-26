package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// TestPublicKeyPEMFromPrivateMatchesMarshal confirms deriving the pubkey from a
// private key yields the PKIX PEM the launcher put on the opkeydata disk (the
// same encoding openssl ec -pubout / x509.MarshalPKIXPublicKey produce), so the
// RTMR[3] expected value matches. Both SEC1 and PKCS#8 private-key PEMs work.
func TestPublicKeyPEMFromPrivate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	want := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wantDER})

	// SEC1 "EC PRIVATE KEY"
	sec1, _ := x509.MarshalECPrivateKey(key)
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	got, err := publicKeyPEMFromPrivate(sec1PEM)
	if err != nil {
		t.Fatalf("SEC1: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("SEC1 derived pubkey != MarshalPKIXPublicKey")
	}

	// PKCS#8 "PRIVATE KEY"
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	got, err = publicKeyPEMFromPrivate(pkcs8PEM)
	if err != nil {
		t.Fatalf("PKCS8: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("PKCS8 derived pubkey != MarshalPKIXPublicKey")
	}
}

// loadKubeconfig parses kc and returns its single cluster and user, failing
// the test unless the context ties both to name.
func loadKubeconfig(t *testing.T, kc []byte, name string) (*clientcmdapi.Cluster, *clientcmdapi.AuthInfo) {
	t.Helper()
	cfg, err := clientcmd.Load(kc)
	if err != nil {
		t.Fatalf("clientcmd.Load: %v\n%s", err, kc)
	}
	if cfg.CurrentContext != name || len(cfg.Clusters) != 1 || len(cfg.AuthInfos) != 1 || len(cfg.Contexts) != 1 {
		t.Fatalf("kubeconfig is not a single %q context\n%s", name, kc)
	}
	ctx := cfg.Contexts[name]
	if ctx == nil || ctx.Cluster != name || ctx.AuthInfo != name {
		t.Fatalf("context %q = %+v, want cluster and user %q", name, ctx, name)
	}
	cluster, user := cfg.Clusters[name], cfg.AuthInfos[name]
	if cluster == nil || user == nil {
		t.Fatalf("kubeconfig lacks cluster or user %q\n%s", name, kc)
	}
	return cluster, user
}

func TestBuildKubeconfig(t *testing.T) {
	cert := []byte("CERTPEM")
	key := []byte("KEYPEM")
	ca := []byte("CAPEM")
	for _, tc := range []struct {
		name, server, tlsServerName string
	}{
		{name: "tls-server-name", server: "https://node:6443", tlsServerName: "c8s-cvm"},
		{name: "no tls-server-name", server: "https://node:6443"},
		{name: "IPv6 server", server: "https://[fd00::5]:6443", tlsServerName: "c8s-cvm"},
		// Run refuses such a URL; the serialiser must still keep it one value.
		{name: "injected YAML in server", server: "https://10.0.0.5:6443\n    insecure-skip-tls-verify: true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kc, err := buildKubeconfig(tc.server, "c8s", tc.tlsServerName, cert, key, ca)
			if err != nil {
				t.Fatalf("buildKubeconfig: %v", err)
			}
			cluster, user := loadKubeconfig(t, kc, "c8s")
			if cluster.Server != tc.server {
				t.Errorf("server = %q, want %q", cluster.Server, tc.server)
			}
			if cluster.InsecureSkipTLSVerify {
				t.Error("insecure-skip-tls-verify = true, want false")
			}
			if cluster.TLSServerName != tc.tlsServerName {
				t.Errorf("tls-server-name = %q, want %q", cluster.TLSServerName, tc.tlsServerName)
			}
			if string(cluster.CertificateAuthorityData) != string(ca) ||
				string(user.ClientCertificateData) != string(cert) ||
				string(user.ClientKeyData) != string(key) {
				t.Errorf("kubeconfig CA/cert/key do not round-trip\n%s", kc)
			}
			if tc.tlsServerName == "" && strings.Contains(string(kc), "tls-server-name") {
				t.Errorf("empty tlsServerName should omit the key\n%s", kc)
			}
		})
	}
}
