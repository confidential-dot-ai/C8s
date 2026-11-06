//go:build integration && linux

package metadataha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type etcdProcesses struct {
	t                      *testing.T
	dir, binary, clusterID string
	urls, peers            []string
	args                   [][]string
	processes              []*exec.Cmd
	tls                    *tls.Config
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

func newEtcdProcesses(t *testing.T) *etcdProcesses {
	t.Helper()
	binary := os.Getenv("CDSHA_ETCD_BIN")
	if binary == "" {
		t.Skip("set CDSHA_ETCD_BIN to a verified etcd release binary")
	}
	p := &etcdProcesses{t: t, binary: binary, dir: t.TempDir(), processes: make([]*exec.Cmd, 3), args: make([][]string, 3)}
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
		if err := os.WriteFile(filepath.Join(p.dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	p.tls = &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	p.client = &http.Client{Transport: &http.Transport{TLSClientConfig: p.tls}, Timeout: time.Second}
	t.Cleanup(func() {
		for i := range p.processes {
			p.stop(i)
		}
		p.client.CloseIdleConnections()
	})
	var initial []string
	for i := range 3 {
		p.urls = append(p.urls, localURL(t))
		p.peers = append(p.peers, localURL(t))
		initial = append(initial, fmt.Sprintf("m%d=%s", i, p.peers[i]))
	}
	for i := range 3 {
		p.args[i] = []string{"--name", fmt.Sprintf("m%d", i), "--data-dir", filepath.Join(p.dir, fmt.Sprintf("m%d", i)),
			"--listen-client-urls", p.urls[i], "--advertise-client-urls", p.urls[i], "--listen-peer-urls", p.peers[i],
			"--initial-advertise-peer-urls", p.peers[i], "--initial-cluster", strings.Join(initial, ","),
			"--initial-cluster-token", filepath.Base(p.dir), "--initial-cluster-state", "new",
			"--client-cert-auth=true", "--trusted-ca-file", filepath.Join(p.dir, "ca.pem"),
			"--cert-file", filepath.Join(p.dir, "cert.pem"), "--key-file", filepath.Join(p.dir, "key.pem"),
			"--peer-client-cert-auth=true", "--peer-trusted-ca-file", filepath.Join(p.dir, "ca.pem"),
			"--peer-cert-file", filepath.Join(p.dir, "cert.pem"), "--peer-key-file", filepath.Join(p.dir, "key.pem"),
			"--quota-backend-bytes=67108864", "--max-request-bytes=2097152", "--log-level=error"}
		p.start(i)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		good := true
		for i := range 3 {
			status, err := p.status(i)
			if err != nil || status.Leader == "" || status.Leader == "0" {
				good = false
				break
			}
			if p.clusterID == "" {
				p.clusterID = status.Header.ClusterID
			}
			if p.clusterID != status.Header.ClusterID {
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

func (p *etcdProcesses) start(i int) {
	p.t.Helper()
	log, err := os.OpenFile(filepath.Join(p.dir, fmt.Sprintf("m%d.log", i)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		p.t.Fatal(err)
	}
	defer log.Close()
	c := exec.Command(p.binary, p.args[i]...)
	c.Stdout = log
	c.Stderr = log
	if err := c.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.processes[i] = c
}
func (p *etcdProcesses) stop(i int) {
	if p.processes[i] != nil {
		_ = p.processes[i].Process.Kill()
		_ = p.processes[i].Wait()
		p.processes[i] = nil
	}
}

type etcdStatus struct {
	Header struct {
		ClusterID string `json:"cluster_id"`
		MemberID  string `json:"member_id"`
	} `json:"header"`
	Leader string `json:"leader"`
}

func (p *etcdProcesses) status(i int) (etcdStatus, error) {
	var s etcdStatus
	r, err := p.client.Post(p.urls[i]+"/v3/maintenance/status", "application/json", strings.NewReader("{}"))
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
func (p *etcdProcesses) backend() *Etcd {
	p.t.Helper()
	e, err := NewEtcd(EtcdConfig{Endpoints: p.urls, ClusterID: p.clusterID, TLS: p.tls})
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(e.Close)
	return e
}

func TestEtcdQuorumTransactions(t *testing.T) {
	p := newEtcdProcesses(t)
	e := p.backend()
	ctx := context.Background()
	key := strings.Repeat("a", 64)
	create := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: key}}, Writes: []metadatapilot.Record{{Key: key, Version: "0000000000000001", Value: []byte("ciphertext-1")}}}
	var won, conflict atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			err := e.Commit(ctx, "cluster-a", create)
			if err == nil {
				won.Add(1)
			} else if errors.Is(err, objectwal.ErrConflict) {
				conflict.Add(1)
			} else {
				t.Errorf("CAS: %v", err)
			}
		})
	}
	wg.Wait()
	if won.Load() != 1 || conflict.Load() != 15 {
		t.Fatalf("CAS winners=%d conflicts=%d", won.Load(), conflict.Load())
	}
	read := func() error {
		rows, err := e.Read(ctx, "cluster-a", []string{key})
		if err == nil && (rows[0].Version != "0000000000000001" || string(rows[0].Value) != "ciphertext-1") {
			return errors.New("acknowledged state changed")
		}
		return err
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	// A successful send whose reply is lost must never be resubmitted.
	lost := p.backend()
	if _, err := lost.Read(ctx, "cluster-a", []string{key}); err != nil {
		t.Fatal(err)
	}
	transport := lost.client.Transport
	t.Cleanup(transport.(*http.Transport).CloseIdleConnections)
	var sends atomic.Int32
	lost.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sends.Add(1)
		resp, err := transport.RoundTrip(r)
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	})
	ambiguous := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: strings.Repeat("b", 64)}}, Writes: []metadatapilot.Record{{Key: strings.Repeat("b", 64), Version: "0000000000000001", Value: []byte("lost-reply")}}}
	if err := lost.Commit(ctx, "cluster-a", ambiguous); !errors.Is(err, objectwal.ErrInDoubt) || sends.Load() != 1 {
		t.Fatalf("ambiguous commit: %v sends=%d", err, sends.Load())
	}
	rows, err := e.Read(ctx, "cluster-a", []string{ambiguous.Checks[0].Key})
	if err != nil || rows[0].Version != "0000000000000001" {
		t.Fatalf("lost reply did not leave exactly one commit: %v", err)
	}
	leader := -1
	for i := range 3 {
		s, err := p.status(i)
		if err == nil && s.Header.MemberID == s.Leader {
			leader = i
		}
	}
	if leader < 0 {
		t.Fatal("no leader")
	}
	p.stop(leader)
	deadline := time.Now().Add(10 * time.Second)
	var available bool
	for time.Now().Before(deadline) {
		if read() == nil {
			available = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !available {
		t.Fatal("majority did not retain acknowledged state after leader crash")
	}
	second := (leader + 1) % 3
	p.stop(second)
	ctxMinority, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := e.Read(ctxMinority, "cluster-a", []string{key}); err == nil {
		t.Fatal("minority served a purportedly current read")
	}
	writeMinority, stopMinority := context.WithTimeout(ctx, 3*time.Second)
	defer stopMinority()
	if err := e.Commit(writeMinority, "cluster-a", ambiguous); err == nil || errors.Is(err, objectwal.ErrConflict) {
		t.Fatal("minority claimed a successful or definite conditional commit")
	}
	p.start(second)
	deadline = time.Now().Add(10 * time.Second)
	available = false
	for time.Now().Before(deadline) {
		if read() == nil {
			available = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !available {
		t.Fatal("restored quorum did not retain acknowledged state")
	}
	wrong := p.backend()
	wrong.clusterID = "1"
	if _, err := wrong.Read(ctx, "cluster-a", []string{key}); !errors.Is(err, objectwal.ErrCorrupt) {
		t.Fatal("foreign metadata cluster accepted")
	}
	foreignKey := strings.Repeat("e", 64)
	foreignTxn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: foreignKey}}, Writes: []metadatapilot.Record{{Key: foreignKey, Version: "0000000000000001", Value: []byte("must-not-write")}}}
	if err := wrong.Commit(ctx, "cluster-a", foreignTxn); err == nil {
		t.Fatal("foreign cluster accepted a commit")
	}
	rows, err = e.Read(ctx, "cluster-a", []string{foreignKey})
	if err != nil || rows[0].Version != "" {
		t.Fatal("identity was checked only after mutating a foreign cluster")
	}
	t.Log("three real members: one CAS winner, ambiguous commit sent once, leader crash recovery, minority fail-closed, quorum restoration, cluster pin")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEtcdAtomicReadSet(t *testing.T) {
	p := newEtcdProcesses(t)
	e := p.backend()
	ctx := context.Background()
	a, b := strings.Repeat("c", 64), strings.Repeat("d", 64)
	var done atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		defer done.Store(true)
		version := ""
		for i := range 64 {
			next, _ := metadatapilot.NextVersion(version)
			txn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: a, Version: version}, {Key: b, Version: version}}, Writes: []metadatapilot.Record{{Key: a, Version: next, Value: []byte{byte(i + 1)}}, {Key: b, Version: next, Value: []byte{byte(i + 1)}}}}
			if err := e.Commit(ctx, "atomic", txn); err != nil {
				t.Error(err)
				return
			}
			version = next
		}
	})
	for range 8 {
		wg.Go(func() {
			last := ""
			for !done.Load() {
				rows, err := e.Read(ctx, "atomic", []string{a, b})
				if err != nil {
					t.Error(err)
					return
				}
				if rows[0].Version != rows[1].Version || !bytes.Equal(rows[0].Value, rows[1].Value) || rows[0].Version < last {
					t.Error("torn or regressing current snapshot")
					return
				}
				last = rows[0].Version
			}
		})
	}
	wg.Wait()
	rows, err := e.Read(ctx, "atomic", []string{a, b})
	if err != nil || rows[0].Version != "0000000000000040" {
		t.Fatalf("final pair: %v", err)
	}
}
