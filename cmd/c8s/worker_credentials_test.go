//go:build !c8s_node

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// signingClientset is a clientset whose signer issues a certificate, with
// subject, for every request once it is approved.
func signingClientset(t *testing.T, subject func(*x509.CertificateRequest) pkix.Name) *fake.Clientset {
	t.Helper()
	client := fake.NewClientset()
	client.PrependReactor("update", "certificatesigningrequests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update := action.(k8stesting.UpdateAction)
		if update.GetSubresource() != "approval" {
			return false, nil, nil
		}
		approved := update.GetObject().(*certificatesv1.CertificateSigningRequest).DeepCopy()
		block, _ := pem.Decode(approved.Spec.Request)
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      subject(request),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		approved.Status.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := client.Tracker().Update(action.GetResource(), approved, ""); err != nil {
			t.Fatal(err)
		}
		return true, approved, nil
	})
	return client
}

// Each controller user gets a kubeconfig, private to its owner even over an
// earlier file, at the admin kubeconfig's cluster, whose key is the
// certificate's; each request is approved as made and deleted once issued.
func TestControllerKubeconfigsCarryTheirOwnCertificates(t *testing.T) {
	client := signingClientset(t, func(r *x509.CertificateRequest) pkix.Name { return r.Subject })
	cluster := &clientcmdapi.Cluster{Server: "https://127.0.0.1:6443", CertificateAuthorityData: []byte("ca")}
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	earlier := filepath.Join(dir, operatorUser+".kubeconfig")
	if err := os.WriteFile(earlier, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A link to the earlier file sees any write made through it.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Link(earlier, link); err != nil {
		t.Fatal(err)
	}
	cfg := workerCredentialsConfig{outputDir: dir, duration: time.Hour}
	if err := issueControllerKubeconfigs(context.Background(), client, cluster, cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, user := range controllerUsers {
		path := filepath.Join(dir, user+".kubeconfig")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", path, info.Mode().Perm())
		}
		config, err := clientcmd.LoadFromFile(path)
		if err != nil {
			t.Fatal(err)
		}
		auth := config.AuthInfos[config.Contexts[config.CurrentContext].AuthInfo]
		got := config.Clusters[config.Contexts[config.CurrentContext].Cluster]
		if got.Server != cluster.Server || string(got.CertificateAuthorityData) != "ca" {
			t.Fatalf("%s cluster = %+v, want the admin kubeconfig's", user, got)
		}
		block, _ := pem.Decode(auth.ClientCertificateData)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != user {
			t.Fatalf("certificate names %q, want %q", cert.Subject.CommonName, user)
		}
		if err := checkIssued(auth.ClientCertificateData, parseECKey(t, auth.ClientKeyData), user); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(link); err != nil || len(data) != 0 {
		t.Fatalf("the key was written through the earlier file (%d bytes): %v", len(data), err)
	}
	csrs, err := client.CertificatesV1().CertificateSigningRequests().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(csrs.Items) != 0 {
		t.Fatalf("%d CertificateSigningRequests left behind", len(csrs.Items))
	}
}

// A certificate the signer issues to anyone but the user alone fails.
func TestControllerCredentialsRefuseAnotherSubject(t *testing.T) {
	client := signingClientset(t, func(r *x509.CertificateRequest) pkix.Name {
		return pkix.Name{CommonName: r.Subject.CommonName, Organization: []string{"system:masters"}}
	})
	cfg := workerCredentialsConfig{outputDir: t.TempDir(), duration: time.Hour}
	err := issueControllerKubeconfigs(context.Background(), client, &clientcmdapi.Cluster{Server: "https://127.0.0.1:6443"}, cfg, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "want \"c8s-operator\" alone") {
		t.Fatalf("err = %v, want the grouped certificate refused", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.outputDir, operatorUser+".kubeconfig")); !os.IsNotExist(err) {
		t.Fatalf("a refused certificate was written: %v", err)
	}
}

// A certificate for another key fails.
func TestCheckIssuedRefusesAnotherKey(t *testing.T) {
	mine, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: operatorUser}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &other.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIssued(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), mine, operatorUser); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Fatalf("err = %v, want the other key refused", err)
	}
}

// The admin kubeconfig's current cluster comes with its CA file inline.
func TestKubeconfigClusterInlinesItsCA(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, []byte("ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := clientcmdapi.Config{
		Clusters:       map[string]*clientcmdapi.Cluster{"a": {Server: "https://a"}, "b": {Server: "https://b", CertificateAuthority: ca}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"admin": {}},
		Contexts:       map[string]*clientcmdapi.Context{"a": {Cluster: "a", AuthInfo: "admin"}, "b": {Cluster: "b", AuthInfo: "admin"}},
		CurrentContext: "b",
	}
	cluster, err := kubeconfigCluster(config)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Server != "https://b" || string(cluster.CertificateAuthorityData) != "ca" || cluster.CertificateAuthority != "" {
		t.Fatalf("cluster = %+v, want b's with its CA inline", cluster)
	}
}

func parseECKey(t *testing.T, data []byte) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A request replaced between its creation and approval is neither approved nor
// deleted.
func TestControllerCredentialsApproveOnlyTheirOwnRequest(t *testing.T) {
	client := signingClientset(t, func(r *x509.CertificateRequest) pkix.Name { return r.Subject })
	var deletes []metav1.DeleteOptions
	client.PrependReactor("delete", "certificatesigningrequests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deletes = append(deletes, action.(k8stesting.DeleteAction).GetDeleteOptions())
		return false, nil, nil
	})
	client.PrependReactor("get", "certificatesigningrequests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		replaced := &certificatesv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: action.(k8stesting.GetAction).GetName(), UID: "someone-else"}}
		return true, replaced, nil
	})
	cfg := workerCredentialsConfig{outputDir: t.TempDir(), duration: time.Hour}
	err := issueControllerKubeconfigs(context.Background(), client, &clientcmdapi.Cluster{Server: "https://127.0.0.1:6443"}, cfg, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "replaced before approval") {
		t.Fatalf("err = %v, want the replaced request left unapproved", err)
	}
	for _, opts := range deletes {
		if opts.Preconditions == nil || opts.Preconditions.UID == nil {
			t.Fatal("the request was deleted by name alone, so a replacement could go with it")
		}
	}
	if len(deletes) == 0 {
		t.Fatal("the request was left behind")
	}
}

// The store credential is the store account's non-expiring token Secret, in a
// file only its owner reads, in the form the replicas' store accepts. A Secret
// that is not that account's token is refused.
func TestStoreKubeconfigIsACredentialTheStoreTakes(t *testing.T) {
	secret := func(account string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: cdsStoreTokenSecret, Namespace: cdsStoreNamespace, Annotations: map[string]string{corev1.ServiceAccountNameKey: account}},
			Type:       corev1.SecretTypeServiceAccountToken,
			Data:       map[string][]byte{corev1.ServiceAccountTokenKey: []byte("store-token")},
		}
	}
	cluster := &clientcmdapi.Cluster{Server: "https://192.0.2.1:6443", CertificateAuthorityData: testCAPEM(t)}
	cfg := workerCredentialsConfig{outputDir: t.TempDir(), duration: 48 * time.Hour}
	if err := issueStoreKubeconfig(context.Background(), fake.NewClientset(secret("someone-else")), cluster, cfg, io.Discard); err == nil {
		t.Fatal("took the token of another account")
	}
	if err := issueStoreKubeconfig(context.Background(), fake.NewClientset(secret(cdsStoreAccount)), cluster, cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.outputDir, "c8s-cds-store.kubeconfig")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cdsha.OpenKube(data, "acme"); err != nil {
		t.Fatalf("the store refuses the credential: %v", err)
	}
	config, err := clientcmd.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	current := config.Contexts[config.CurrentContext]
	if current.Namespace != cdsStoreNamespace || config.AuthInfos[current.AuthInfo].Token != "store-token" {
		t.Fatalf("context %+v, want the store namespace and the account's token", current)
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cluster-ca"}, NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
