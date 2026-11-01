package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	kubecert "k8s.io/client-go/util/cert"

	fixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-recovery"
)

func TestReadOnlyReceiptCannotTriggerOrRepeatFaults(t *testing.T) {
	c := &controller{receipt: fixture.Receipt{Schema: 1, Scope: fixture.Scope, State: "baseline", Phases: []fixture.Phase{}}}
	before := c.receipt
	h := c.handler(http.NotFoundHandler())
	for _, req := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, fixture.ReceiptPath, http.StatusOK},
		{http.MethodPost, fixture.ReceiptPath, http.StatusMethodNotAllowed},
		{http.MethodPost, "/restart", http.StatusNotFound},
		{http.MethodPost, "/v1/assign", http.StatusNotFound},
		{http.MethodGet, "/etc/confai/pubkey", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, httptest.NewRequest(req.method, req.path, strings.NewReader(`{"unit":"other.service"}`)))
		if response.Code != req.status {
			t.Fatalf("%s %s returned %d", req.method, req.path, response.Code)
		}
		if !reflect.DeepEqual(c.receipt, before) {
			t.Fatal("HTTP observation changed fixture state")
		}
	}
}

func TestRetainedPolicyChangesCannotHideBehindRevision(t *testing.T) {
	a, err := stableHistory([]byte(`{"revision":1,"policy":{"version":1,"document":{"rules":"new"},"digest":"a"},"histories":{"old":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := stableHistory([]byte(`{"revision":2,"policy":{"version":1,"document":{"rules":"new"},"digest":"a"},"histories":{"old":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("revision alone changed retained state")
	}
	for _, bad := range []string{
		`{"revision":2,"policy":{"version":1,"document":{"rules":"old"},"digest":"b"},"histories":{"old":true}}`,
		`{"revision":2,"histories":{"old":true}}`,
		`{"revision":2,"policy":{"version":1,"document":{"rules":"new"},"digest":"a"},"histories":{}}`,
	} {
		got, err := stableHistory([]byte(bad))
		if err != nil {
			t.Fatal(err)
		}
		if a == got {
			t.Fatal("lost policy or history was hidden")
		}
	}
}

func TestKubeletTLSUsesLocalLeafIdentityAndStandardVerification(t *testing.T) {
	type material struct {
		pem  []byte
		pair tls.Certificate
	}
	parse := func(cert, key []byte) material {
		t.Helper()
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		return material{cert, pair}
	}
	selfSigned := func(expired, loopback bool) material {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		end := time.Now().Add(time.Hour)
		if expired {
			end = time.Now().Add(-time.Minute)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"kubelet.test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if loopback {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return parse(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	}
	valid, wrong, expired, loopback := selfSigned(false, false), selfSigned(false, false), selfSigned(true, false), selfSigned(false, true)
	certPEM, keyPEM, err := kubecert.GenerateSelfSignedCertKey("kubelet.test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kubelet := parse(certPEM, keyPEM)
	for _, tc := range []struct {
		name          string
		trusted, peer material
		serverName    string
		accept        bool
	}{
		{"self-signed DNS leaf over loopback", valid, valid, "kubelet.test", true},
		{"actual kubelet leaf and private CA", kubelet, kubelet, "kubelet.test", true},
		{"prefer valid loopback SAN", loopback, loopback, "127.0.0.1", true},
		{"wrong certificate with same SAN", valid, wrong, "kubelet.test", false},
		{"expired pinned certificate", expired, expired, "kubelet.test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := kubeletTLSConfig(tc.trusted.pem)
			if err != nil {
				t.Fatal(err)
			}
			if config.ServerName != tc.serverName || config.InsecureSkipVerify {
				t.Fatal("standard local identity verification disabled")
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tc.peer.pair}}
			server.StartTLS()
			defer server.Close()
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
			defer client.CloseIdleConnections()
			response, err := client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != tc.accept {
				t.Fatalf("accept=%v, handshake error=%v", tc.accept, err)
			}
		})
	}
}

func TestRecoveryDeadlineFitsBeforeCheckerCompletion(t *testing.T) {
	app, err := os.ReadFile("../../pod-connected/app.py")
	if err != nil {
		t.Fatal(err)
	}
	seconds := func(pattern string, index int) time.Duration {
		t.Helper()
		match := regexp.MustCompile(pattern).FindSubmatch(app)
		if len(match) <= index {
			t.Fatal("connected checker timing unavailable")
		}
		n, err := strconv.Atoi(string(match[index]))
		if err != nil {
			t.Fatal(err)
		}
		return time.Duration(n) * time.Second
	}
	soak := seconds(`if age >= ([0-9]+) and healthy`, 1)
	dip := seconds(`if healthy and ([0-9]+) <= age < ([0-9]+) and not`, 2) - seconds(`if healthy and ([0-9]+) <= age < ([0-9]+) and not`, 1)
	budget := baselineTimeout + baselineGrace + time.Duration(len(fixture.Phases))*(phaseTimeout+phaseInterval)
	if budget >= fixture.ControllerTimeout || fixture.ControllerTimeout >= soak || snapshotTimeout <= dip {
		t.Fatalf("incompatible recovery budgets: total=%v controller=%v soak=%v snapshot=%v dip=%v", budget, fixture.ControllerTimeout, soak, snapshotTimeout, dip)
	}
	unit, err := os.ReadFile("../profile/mkosi.extra/etc/systemd/system/pod-recovery-fixture.service")
	if err != nil {
		t.Fatal(err)
	}
	limit := regexp.MustCompile(`(?m)^RuntimeMaxSec=([0-9]+)min$`).FindSubmatch(unit)
	if len(limit) != 2 {
		t.Fatal("fixture systemd deadline unavailable")
	}
	minutes, err := strconv.Atoi(string(limit[1]))
	if err != nil || time.Duration(minutes)*time.Minute != fixture.ControllerTimeout {
		t.Fatal("controller and systemd deadlines differ")
	}
}
