package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
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

// TestBuildKubeconfig checks the assembled kubeconfig is well-formed: the
// context/cluster/user names, the server URL, and base64 of the cert/key/CA.
func TestBuildKubeconfig(t *testing.T) {
	cert := []byte("CERTPEM")
	key := []byte("KEYPEM")
	ca := []byte("CAPEM")
	kc := string(buildKubeconfig("https://node:6443", "c8s", "c8s-cvm", cert, key, ca))

	for _, want := range []string{
		"current-context: c8s",
		"server: https://node:6443",
		"tls-server-name: c8s-cvm",
		"certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca),
		"client-certificate-data: " + base64.StdEncoding.EncodeToString(cert),
		"client-key-data: " + base64.StdEncoding.EncodeToString(key),
	} {
		if !strings.Contains(kc, want) {
			t.Errorf("kubeconfig missing %q\n%s", want, kc)
		}
	}

	// Empty tls-server-name omits the line entirely.
	kc2 := string(buildKubeconfig("https://node:6443", "c8s", "", cert, key, ca))
	if strings.Contains(kc2, "tls-server-name") {
		t.Errorf("empty tlsServerName should omit the line\n%s", kc2)
	}
}
