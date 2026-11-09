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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// operatorUser is the user c8s's operator authenticates as, beside the
// workers' control plane.
const operatorUser = "c8s-operator"

// ciliumOperatorUser is the user the Cilium operator authenticates as, beside
// the workers' control plane.
const ciliumOperatorUser = "c8s-cilium-operator"

// The account a CDS replica set's store credential carries a token of, which
// the control-plane render creates.
const (
	cdsStoreNamespace   = "c8s-cds"
	cdsStoreAccount     = "cds-store"
	cdsStoreTokenSecret = "cds-store-token"
)

// controllerUsers are the users of the controllers beside a workers' control
// plane, each with a kubeconfig of its own.
var controllerUsers = []string{operatorUser, ciliumOperatorUser}

type workerCredentialsConfig struct {
	kubeconfig string
	outputDir  string
	duration   time.Duration
}

func newWorkerCredentialsCmd() *cobra.Command {
	var cfg workerCredentialsConfig
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Issue the kubeconfigs of the controllers beside a workers' control plane",
		Long: `Issue a client certificate for each of the users c8s-operator and
c8s-cilium-operator through the cluster's CertificateSigningRequest API, approve
it with --kubeconfig's credentials, and write <user>.kubeconfig (mode 0600) to
--output-dir. Each key is generated here and stays in its file; the cluster's
kube-apiserver-client signer issues the certificate, capped at its signing
duration. Also write c8s-cds-store.kubeconfig, the non-expiring token of the
c8s-cds/cds-store account, for a CDS replica set's store ('c8s cds ha
store-credential').`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeWorkerCredentials(cmd.Context(), cfg, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.kubeconfig, "kubeconfig", "", "a kubeconfig that may create and approve CertificateSigningRequests (required)")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for the kubeconfigs (required)")
	f.DurationVar(&cfg.duration, "duration", 30*24*time.Hour, "certificate lifetime to request")
	return cmd
}

func writeWorkerCredentials(ctx context.Context, cfg workerCredentialsConfig, out io.Writer) error {
	if cfg.kubeconfig == "" || cfg.outputDir == "" {
		return fmt.Errorf("--kubeconfig and --output-dir are required")
	}
	admin, err := clientcmd.LoadFromFile(cfg.kubeconfig)
	if err != nil {
		return err
	}
	cluster, err := kubeconfigCluster(*admin)
	if err != nil {
		return err
	}
	rest, err := clientcmd.NewDefaultClientConfig(*admin, nil).ClientConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(rest)
	if err != nil {
		return err
	}
	if err := issueControllerKubeconfigs(ctx, client, cluster, cfg, out); err != nil {
		return err
	}
	return issueStoreKubeconfig(ctx, client, cluster, cfg, out)
}

// issueStoreKubeconfig writes the store credential of a CDS replica set to
// cfg.outputDir: the store account's token, at cluster, in its namespace. The
// token is the account's token Secret, which the render creates and which
// never expires: every replica holds the same one, so an expiry would stop
// them all at once.
func issueStoreKubeconfig(ctx context.Context, client kubernetes.Interface, cluster *clientcmdapi.Cluster, cfg workerCredentialsConfig, out io.Writer) error {
	var token []byte
	// The token controller fills a new Secret shortly after the render applies it.
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		secret, err := client.CoreV1().Secrets(cdsStoreNamespace).Get(ctx, cdsStoreTokenSecret, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if secret.Type != corev1.SecretTypeServiceAccountToken || secret.Annotations[corev1.ServiceAccountNameKey] != cdsStoreAccount {
			return false, fmt.Errorf("%s/%s is not the token Secret of %s", cdsStoreNamespace, cdsStoreTokenSecret, cdsStoreAccount)
		}
		token = secret.Data[corev1.ServiceAccountTokenKey]
		return len(token) > 0, nil
	})
	if err != nil {
		return fmt.Errorf("%s/%s token: %w", cdsStoreNamespace, cdsStoreTokenSecret, err)
	}
	data, err := clientcmd.Write(clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{"cluster": cluster},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{cdsStoreAccount: {Token: string(token)}},
		Contexts: map[string]*clientcmdapi.Context{cdsStoreAccount: {
			Cluster:   "cluster",
			AuthInfo:  cdsStoreAccount,
			Namespace: cdsStoreNamespace,
		}},
		CurrentContext: cdsStoreAccount,
	})
	if err != nil {
		return err
	}
	path := filepath.Join(cfg.outputDir, "c8s-cds-store.kubeconfig")
	if err := fileutil.WriteAtomic(path, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n", path)
	return nil
}

// issueControllerKubeconfigs writes a kubeconfig for each controller user to
// cfg.outputDir, at cluster, with a certificate client's cluster issues.
func issueControllerKubeconfigs(ctx context.Context, client kubernetes.Interface, cluster *clientcmdapi.Cluster, cfg workerCredentialsConfig, out io.Writer) error {
	if err := os.MkdirAll(cfg.outputDir, 0o700); err != nil {
		return err
	}
	for _, user := range controllerUsers {
		key, cert, err := issueClientCertificate(ctx, client, user, cfg.duration)
		if err != nil {
			return fmt.Errorf("%s: %w", user, err)
		}
		path := filepath.Join(cfg.outputDir, user+".kubeconfig")
		data, err := clientcmd.Write(userKubeconfig(cluster, user, key, cert))
		if err != nil {
			return err
		}
		if err := fileutil.WriteAtomic(path, data, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", path)
	}
	return nil
}

// kubeconfigCluster is config's current cluster with its CA inline.
func kubeconfigCluster(config clientcmdapi.Config) (*clientcmdapi.Cluster, error) {
	if err := clientcmdapi.MinifyConfig(&config); err != nil {
		return nil, err
	}
	if err := clientcmdapi.FlattenConfig(&config); err != nil {
		return nil, err
	}
	for _, cluster := range config.Clusters {
		return cluster, nil
	}
	return nil, fmt.Errorf("the kubeconfig names no cluster")
}

func userKubeconfig(cluster *clientcmdapi.Cluster, user string, key, cert []byte) clientcmdapi.Config {
	return clientcmdapi.Config{
		Clusters:       map[string]*clientcmdapi.Cluster{"cluster": cluster},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{user: {ClientKeyData: key, ClientCertificateData: cert}},
		Contexts:       map[string]*clientcmdapi.Context{user: {Cluster: "cluster", AuthInfo: user}},
		CurrentContext: user,
	}
}

// issueClientCertificate has the cluster's kube-apiserver-client signer issue
// user a certificate for a key generated here, approving the request it made.
func issueClientCertificate(ctx context.Context, client kubernetes.Interface, user string, duration time.Duration) (keyPEM, certPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	request, err := certutil.MakeCSR(key, &pkix.Name{CommonName: user}, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	usages := []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature, certificatesv1.UsageClientAuth}
	name, uid, err := csr.RequestCertificateWithContext(ctx, client, request, "", certificatesv1.KubeAPIServerClientSignerName, &duration, usages, key)
	if err != nil {
		return nil, nil, err
	}
	csrs := client.CertificatesV1().CertificateSigningRequests()
	defer func() {
		_ = csrs.Delete(context.WithoutCancel(ctx), name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	}()
	pending, err := csrs.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	// INVARIANT: approve only the request made above.
	if pending.UID != uid {
		return nil, nil, fmt.Errorf("CertificateSigningRequest %s was replaced before approval", name)
	}
	pending.Status.Conditions = append(pending.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:    certificatesv1.CertificateApproved,
		Status:  "True",
		Reason:  "C8sWorkerCredentials",
		Message: "c8s worker control-plane credentials",
	})
	if _, err := csrs.UpdateApproval(ctx, name, pending, metav1.UpdateOptions{}); err != nil {
		return nil, nil, fmt.Errorf("approve: %w", err)
	}
	wait, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	certPEM, err = csr.WaitForCertificate(wait, client, name, uid)
	if err != nil {
		return nil, nil, err
	}
	if err := checkIssued(certPEM, key, user); err != nil {
		return nil, nil, err
	}
	keyPEM, err = keyutil.MarshalPrivateKeyToPEM(key)
	return keyPEM, certPEM, err
}

// checkIssued holds an issued certificate to the key and user requested.
func checkIssued(certPEM []byte, key *ecdsa.PrivateKey, user string) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("the signer issued no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return fmt.Errorf("the signer issued a certificate for another key")
	}
	if cert.Subject.CommonName != user || len(cert.Subject.Organization) > 0 {
		return fmt.Errorf("the signer issued a certificate for %q in %v, want %q alone", cert.Subject.CommonName, cert.Subject.Organization, user)
	}
	return nil
}
