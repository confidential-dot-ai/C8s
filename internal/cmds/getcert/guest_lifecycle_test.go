package getcert

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestGuestRunRecoversRenewsAndWithdrawsOnShutdown(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("C8S_REQUIRE_NFT") == "1" {
			t.Fatal("guest credential lifecycle requires root")
		}
		t.Skip("guest credential lifecycle requires root")
	}
	root, err := os.OpenRoot(ramBackedDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	claims := guestTestClaims(t)
	ca := newTestCA(t)
	stamp := namedLeaf(t).Extensions
	attester := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"platform":"tdx","evidence":{"quote":"fake"}}`)
	}))
	defer attester.Close()
	var outage atomic.Bool
	outage.Store(true)
	failed := make(chan struct{}, 1)
	cds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() {
			http.Error(w, "CDS unavailable", http.StatusServiceUnavailable)
			select {
			case failed <- struct{}{}:
			default:
			}
			return
		}
		if r.URL.Path == "/authenticate" {
			_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
			return
		}
		var req types.AttestRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		csr, err := attestation.ParseAndVerifyCSR(req.CSR)
		if err != nil {
			t.Error(err)
			return
		}
		pub, err := attestation.ECDSAPublicKeyFromCSR(csr)
		if err != nil {
			t.Error(err)
			return
		}
		chain, err := ca.issue(pub, claims.InstanceID(), time.Hour, stamp...)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.WriteString(w, chain)
	}))
	defer cds.Close()
	changes := make(chan struct{}, 1)
	published := make(chan struct{}, 1)
	guest := GuestConfig{
		CDSURL: cds.URL, HTTPClient: cds.Client(), AttestationAPIURL: attester.URL,
		VolumeRoot: root, InstanceID: claims.InstanceID(), Changes: changes,
		Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return claims, nil },
		Commit: func(got workloadclaims.PodClaims, publish func() error) error {
			if got.InstanceID() != claims.InstanceID() || got.Revision != claims.Revision {
				t.Error("publication used a different observation snapshot")
			}
			if err := publish(); err != nil {
				return err
			}
			published <- struct{}{}
			return nil
		},
	}
	// A named generation renews far beyond this deadline, so later publications
	// depend on Changes rather than the normal renewal or unnamed timers.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = RunGuest(ctx, guest)
		close(done)
	}()
	stop := func() {
		t.Helper()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("RunGuest did not stop after cancellation")
		}
	}
	defer stop()
	wait := func(event <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-event:
		case <-ctx.Done():
			t.Fatal(message)
		}
	}
	wait(failed, "initial outage was not exercised")
	if _, err := root.Lstat(pointerName); !os.IsNotExist(err) {
		t.Fatalf("outage published credentials: %v", err)
	}
	outage.Store(false)
	volume := credentialVolume{root: root, leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	bound, err := issuerKeyIDOf(ca.cert)
	if err != nil {
		t.Fatal(err)
	}
	var previousKey []byte
	for range 3 {
		changes <- struct{}{}
		wait(published, "Changes did not issue a fresh generation")
		reader := volume
		reader.dir = root.Name()
		g, err := storedGeneration(reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateGeneration(g, claims.InstanceID(), bound, time.Now()); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(g.KeyPEM, previousKey) {
			t.Fatal("renewal reused the previous private key")
		}
		previousKey = g.KeyPEM
	}
	parent, err := root.Open(generationsSubdir)
	if err != nil {
		t.Fatal(err)
	}
	entries, readErr := parent.ReadDir(-1)
	closeErr := parent.Close()
	if readErr != nil || closeErr != nil || len(entries) != 2 {
		t.Fatalf("did not retain only current and previous generations: %d %v %v", len(entries), readErr, closeErr)
	}
	stop()
	if runErr != nil {
		t.Fatal(runErr)
	}
	for _, name := range append(volume.names(), pointerName) {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("shutdown retained reader %q: %v", name, err)
		}
	}
	if got, err := loadIssuerRecord(volume); err != nil || got != bound {
		t.Fatalf("shutdown lost issuer binding: %q %v", got, err)
	}
}

func TestGuestRunRejectsLostVolumeCustodyAndIssuerBinding(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("C8S_REQUIRE_NFT") == "1" {
			t.Fatal("guest credential custody requires root")
		}
		t.Skip("guest credential custody requires root")
	}
	for _, mode := range []string{"writable by others", "different owner", "corrupted issuer binding"} {
		t.Run(mode, func(t *testing.T) {
			root, err := os.OpenRoot(ramBackedDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			claims := guestTestClaims(t)
			volume := credentialVolume{root: root, leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
			creds := &credentials{volume: volume, instanceID: claims.InstanceID()}
			g, err := issueFor(newTestCA(t), creds, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := creds.publish(g, time.Now()); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "writable by others":
				err = root.Chmod(".", 0770)
			case "different owner":
				err = root.Chown(".", 1234, guestMeshGID)
			case "corrupted issuer binding":
				err = root.WriteFile(issuerRecordName, []byte("corrupt\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int64
			cds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				http.Error(w, "must refuse locally", http.StatusServiceUnavailable)
			}))
			defer cds.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err = RunGuest(ctx, GuestConfig{
				CDSURL: cds.URL, HTTPClient: cds.Client(), VolumeRoot: root, InstanceID: claims.InstanceID(),
				Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return claims, nil },
				Commit:   func(_ workloadclaims.PodClaims, publish func() error) error { return publish() },
			})
			if err == nil || ctx.Err() != nil || requests.Load() != 0 {
				t.Fatalf("unsafe custody reached issuance or waited for cancellation: %v, requests=%d", err, requests.Load())
			}
			for _, name := range append(volume.names(), pointerName) {
				if _, err := root.Lstat(name); !os.IsNotExist(err) {
					t.Fatalf("unsafe custody retained reader %q: %v", name, err)
				}
			}
		})
	}
}
