//go:build integration && linux

// Package etcdtest runs three disposable etcd processes on loopback with mTLS.
// The test goroutine owns process lifecycle; it never touches a cloud cluster.
package etcdtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type Cluster struct {
	t                      *testing.T
	Dir, binary, ClusterID string
	URLs, peers            []string
	args                   [][]string
	processes              []*exec.Cmd
	TLS                    *tls.Config
	client                 *http.Client
}

func localURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return "https://" + l.Addr().String()
}

func New(t *testing.T) *Cluster {
	t.Helper()
	binary := os.Getenv("CDSHA_ETCD_BIN")
	if binary == "" {
		t.Skip("set CDSHA_ETCD_BIN to a verified etcd release binary")
	}
	p := &Cluster{t: t, binary: binary, Dir: t.TempDir(), processes: make([]*exec.Cmd, 3), args: make([][]string, 3)}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable etcd test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "disposable etcd test identity"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for name, b := range map[string][]byte{"ca.pem": caPEM, "cert.pem": leafPEM, "key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(p.Dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	p.TLS = &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	p.client = &http.Client{Transport: &http.Transport{TLSClientConfig: p.TLS}, Timeout: time.Second}
	t.Cleanup(func() {
		for i := range p.processes {
			p.Stop(i)
		}
		p.client.CloseIdleConnections()
	})
	var initial []string
	for i := range 3 {
		p.URLs = append(p.URLs, localURL(t))
		p.peers = append(p.peers, localURL(t))
		initial = append(initial, fmt.Sprintf("m%d=%s", i, p.peers[i]))
	}
	for i := range 3 {
		p.args[i] = []string{"--name", fmt.Sprintf("m%d", i), "--data-dir", filepath.Join(p.Dir, fmt.Sprintf("m%d", i)),
			"--listen-client-urls", p.URLs[i], "--advertise-client-urls", p.URLs[i], "--listen-peer-urls", p.peers[i],
			"--initial-advertise-peer-urls", p.peers[i], "--initial-cluster", strings.Join(initial, ","),
			"--initial-cluster-token", filepath.Base(p.Dir), "--initial-cluster-state", "new",
			"--client-cert-auth=true", "--trusted-ca-file", filepath.Join(p.Dir, "ca.pem"),
			"--cert-file", filepath.Join(p.Dir, "cert.pem"), "--key-file", filepath.Join(p.Dir, "key.pem"),
			"--peer-client-cert-auth=true", "--peer-trusted-ca-file", filepath.Join(p.Dir, "ca.pem"),
			"--peer-cert-file", filepath.Join(p.Dir, "cert.pem"), "--peer-key-file", filepath.Join(p.Dir, "key.pem"),
			"--quota-backend-bytes=67108864", "--max-request-bytes=2097152", "--log-level=error"}
		p.Start(i)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		good := true
		for i := range 3 {
			status, err := p.Status(i)
			if err != nil || status.Leader == "" || status.Leader == "0" {
				good = false
				break
			}
			if p.ClusterID == "" {
				p.ClusterID = status.Header.ClusterID
			}
			if p.ClusterID != status.Header.ClusterID {
				t.Fatal("members belong to different clusters")
			}
		}
		if good {
			return p
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("three etcd members did not become ready; inspect owned fixture logs")
	return nil
}

func (p *Cluster) Start(i int) {
	p.t.Helper()
	log, err := os.OpenFile(filepath.Join(p.Dir, fmt.Sprintf("m%d.log", i)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		p.t.Fatal(err)
	}
	defer log.Close()
	if p.processes[i] != nil {
		p.t.Fatal("owned etcd process already running")
	}
	c := exec.Command(p.binary, p.args[i]...)
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	c.Stdout = log
	c.Stderr = log
	if err := c.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.processes[i] = c
}
func (p *Cluster) Stop(i int) {
	if p.processes[i] != nil {
		_ = p.processes[i].Process.Kill()
		_ = p.processes[i].Wait()
		p.processes[i] = nil
	}
}

type Status struct {
	Header struct {
		ClusterID string `json:"cluster_id"`
		MemberID  string `json:"member_id"`
	} `json:"header"`
	Leader string `json:"leader"`
}

func (p *Cluster) Status(i int) (Status, error) {
	var s Status
	r, err := p.client.Post(p.URLs[i]+"/v3/maintenance/status", "application/json", strings.NewReader("{}"))
	if err != nil {
		return s, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return s, fmt.Errorf("status HTTP %d", r.StatusCode)
	}
	err = json.NewDecoder(r.Body).Decode(&s)
	return s, err
}
