package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// fakeReport is an all-zero SEV-SNP report: the tool never verifies evidence,
// but armtls.ExtractAttestation (which the tests use) parses its shape.
func fakeReport() []byte {
	rep := make([]byte, 1184)
	rep[0] = 2
	return rep
}

// testCert mints a certificate carrying fakeReport as its evidence.
func testCert(t *testing.T, o certOptions) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := buildCert(key, &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: fakeReport()}, o)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// serve runs a TLS 1.3 listener demanding a client certificate, as the mesh
// inbound proxy does; verify stands in for its VerifyPeerCertificate and
// handle for handleInbound once the handshake is done.
func serve(t *testing.T, verify func([][]byte, [][]*x509.Certificate) error, handle func(net.Conn)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{testCert(t, certOptions{notAfter: time.Hour})},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verify,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					return
				}
				handle(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDialRejectedCertificate(t *testing.T) {
	addr := serve(t,
		func([][]byte, [][]*x509.Certificate) error { return errors.New("armtls: peer attestation failed") },
		func(net.Conn) { t.Error("handler ran after a rejected certificate") })

	r := dial(context.Background(), addr, "10.0.0.2:80", testCert(t, certOptions{notAfter: time.Hour}), 5*time.Second)
	if !r.TLS || r.Bytes != 0 || r.Status != 0 || r.Body != "" {
		t.Fatalf("report = %+v, want tls true and nothing received", r)
	}
	if !strings.Contains(r.Error, "bad certificate") {
		t.Fatalf("error = %q, want the server's bad certificate alert", r.Error)
	}
	t.Logf("rejected certificate reports error %q", r.Error)
}

func TestDialAccepted(t *testing.T) {
	const dest = "10.0.0.2:8080"
	addr := serve(t, nil, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		header, err := br.ReadString('\n')
		if err != nil || header != dest+"\n" {
			t.Errorf("destination header = %q, %v; want %q", header, err, dest+"\n")
			return
		}
		request, err := br.ReadString('\n')
		if err != nil || request != "GET / HTTP/1.0\r\n" {
			t.Errorf("request line = %q, %v", request, err)
			return
		}
		conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	})

	r := dial(context.Background(), addr, dest, testCert(t, certOptions{notAfter: time.Hour}), 5*time.Second)
	if r.Error != "" || r.Status != 200 || r.Body != "hello" || r.Bytes == 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestDialClosedWithoutBytes(t *testing.T) {
	addr := serve(t, nil, func(net.Conn) {})
	r := dial(context.Background(), addr, "10.0.0.2:80", testCert(t, certOptions{notAfter: time.Hour}), 5*time.Second)
	if !r.TLS || r.Bytes != 0 || r.Error != "EOF" {
		t.Fatalf("report = %+v, want tls true and EOF before any byte", r)
	}
}

func TestDialNonHTTPReply(t *testing.T) {
	addr := serve(t, nil, func(conn net.Conn) {
		bufio.NewReader(conn).ReadString('\n')
		conn.Write(bytes.Repeat([]byte("x"), 2*maxBody))
	})
	r := dial(context.Background(), addr, "10.0.0.2:80", testCert(t, certOptions{notAfter: time.Hour}), 5*time.Second)
	if r.Status != 0 || r.Bytes != 2*maxBody || len(r.Body) != maxBody {
		t.Fatalf("report = %+v (body %d bytes)", r, len(r.Body))
	}
}

func TestDialUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	r := dial(context.Background(), addr, "10.0.0.2:80", testCert(t, certOptions{notAfter: time.Hour}), time.Second)
	if r.TLS || r.Bytes != 0 || r.Error == "" {
		t.Fatalf("report = %+v", r)
	}
}

// TestRunWritesCertificate drives the write mode: the files it leaves are
// what --cert/--key read back, and the report of that dial names them.
func TestRunWritesCertificate(t *testing.T) {
	addr := serve(t,
		func([][]byte, [][]*x509.Certificate) error { return errors.New("no") },
		func(net.Conn) {})
	dir := t.TempDir()
	cert := testCert(t, certOptions{notAfter: time.Hour})
	certFile, keyFile := dir+"/out.crt", dir+"/out.key"
	if err := writePEM(cert, certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--cert", certFile, "--key", keyFile, addr, "10.0.0.2:80"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, stderr %q", code, stderr.String())
	}
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if !r.TLS || !strings.Contains(r.Error, "bad certificate") {
		t.Fatalf("report = %+v", r)
	}
	for _, args := range [][]string{
		{"--self-signed", "--platform", "sev-snp", "--attestation-url", "http://127.0.0.1:1", "--write-cert", certFile},
		{"--self-signed", "--platform", "sev-snp", "--attestation-url", "http://127.0.0.1:1", "--write-cert", certFile, "--write-key", keyFile, addr, "10.0.0.2:80"},
		{"--cert", certFile, "--key", keyFile, "--write-cert", certFile, "--write-key", keyFile},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(args, &stdout, &stderr); code != exitUsage || stderr.Len() == 0 {
			t.Errorf("run(%q) = %d, stderr %q; want usage error", args, code, stderr.String())
		}
	}
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{"127.0.0.1:1", "10.0.0.2:80"},
		{"--self-signed", "--cert", "a", "--key", "b", "127.0.0.1:1", "10.0.0.2:80"},
		{"--cert", "a", "127.0.0.1:1", "10.0.0.2:80"},
		{"--cert", "a", "--key", "b", "--issuer-differs", "127.0.0.1:1", "10.0.0.2:80"},
		{"--self-signed", "--platform", "sev-snp", "127.0.0.1:1", "10.0.0.2:80"},
		{"--self-signed", "--platform", "sev-snp", "--attestation-url", "http://127.0.0.1:1", "127.0.0.1:1"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("run(%q) = %d, stdout %q, stderr %q; want usage error", args, code, stdout.String(), stderr.String())
		}
	}
}

// TestRunReport drives the CLI end to end against a rejecting server with a
// certificate from files, and checks the report is the only stdout line.
func TestRunReport(t *testing.T) {
	addr := serve(t,
		func([][]byte, [][]*x509.Certificate) error { return errors.New("no") },
		func(net.Conn) {})
	dir := t.TempDir()
	cert := testCert(t, certOptions{notAfter: time.Hour})
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := writePEM(cert, certFile, keyFile); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--cert", certFile, "--key", keyFile, "--rewrite-not-after", "-1h", addr, "10.0.0.2:80"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("run = %d, stderr %q", code, stderr.String())
	}
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil || strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("stdout %q is not one JSON line: %v", stdout.String(), err)
	}
	if r.Bytes != 0 || !strings.Contains(r.Error, "bad certificate") {
		t.Fatalf("report = %+v", r)
	}
}
