package getcert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func guestTempRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func guestRootVolume(root *os.Root) credentialVolume {
	return credentialVolume{root: root, leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
}

// stageGuestReaders leaves the reader paths a previous broker published.
func stageGuestReaders(t *testing.T, root *os.Root) {
	t.Helper()
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if err := root.WriteFile(name, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := root.Symlink(filepath.Join(generationsSubdir, "old"), pointerName); err != nil {
		t.Fatal(err)
	}
}

func TestRunGuestRejectsIncompleteConfig(t *testing.T) {
	claims := guestTestClaims(t)
	valid := func(t *testing.T) GuestConfig {
		return GuestConfig{
			CDSURL: "https://cds.example", HTTPClient: &http.Client{}, VolumeRoot: guestTempRoot(t), InstanceID: claims.InstanceID(),
			Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return claims, nil },
			Commit:   func(_ workloadclaims.PodClaims, publish func() error) error { return publish() },
		}
	}
	for name, tt := range map[string]struct {
		mutate func(*GuestConfig)
		want   string
	}{
		"unparseable CDS URL":  {func(g *GuestConfig) { g.CDSURL = "://cds" }, "CDSURL: "},
		"plaintext CDS URL":    {func(g *GuestConfig) { g.CDSURL = "http://cds.example" }, "https URL with a host"},
		"CDS URL without host": {func(g *GuestConfig) { g.CDSURL = "https:///attest" }, "https URL with a host"},
		"no HTTP client":       {func(g *GuestConfig) { g.HTTPClient = nil }, "HTTPClient is required"},
		"no volume root":       {func(g *GuestConfig) { g.VolumeRoot = nil }, "volume root is required"},
		"no snapshot":          {func(g *GuestConfig) { g.Snapshot = nil }, "snapshot and commit callbacks are required"},
		"no commit":            {func(g *GuestConfig) { g.Commit = nil }, "snapshot and commit callbacks are required"},
		"malformed instance":   {func(g *GuestConfig) { g.InstanceID = "../instance" }, "instance ID: "},
	} {
		t.Run(name, func(t *testing.T) {
			guest := valid(t)
			tt.mutate(&guest)
			err := RunGuest(t.Context(), guest)
			if err == nil || !strings.Contains(err.Error(), "guest credential broker: ") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("RunGuest = %v, want %q", err, tt.want)
			}
		})
	}
}

// An unverified volume is refused before any request, and whatever an earlier
// broker advertised there is withdrawn while the issuer binding stays.
func TestRunGuestWithdrawsFromUnverifiedVolume(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-owned temporary directory may pass the volume check")
	}
	root := guestTempRoot(t)
	stageGuestReaders(t, root)
	if err := root.WriteFile(issuerRecordName, []byte(strings.Repeat("ab", 32)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	cds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "must refuse locally", http.StatusServiceUnavailable)
	}))
	defer cds.Close()
	claims := guestTestClaims(t)
	err := RunGuest(t.Context(), GuestConfig{
		CDSURL: cds.URL, HTTPClient: cds.Client(), VolumeRoot: root, InstanceID: claims.InstanceID(),
		Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return claims, nil },
		Commit:   func(_ workloadclaims.PodClaims, publish func() error) error { return publish() },
	})
	if err == nil || requests.Load() != 0 {
		t.Fatalf("unverified volume reached issuance: %v, requests=%d", err, requests.Load())
	}
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt", pointerName} {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("refused volume retained reader %q: %v", name, err)
		}
	}
	if _, err := root.Lstat(issuerRecordName); err != nil {
		t.Fatalf("refusal erased the issuer binding: %v", err)
	}
}

func TestGuestVolumeRefusesUnverifiedRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-owned temporary directory may pass the volume check")
	}
	root := guestTempRoot(t)
	if err := requireGuestRoot(root); err == nil {
		t.Fatal("a user-owned disk directory was accepted as a guest volume")
	}
	if binding, err := GuestIssuerBinding(root); err == nil || binding != "" {
		t.Fatalf("unverified volume yielded a binding: %q, %v", binding, err)
	}
	creds := &credentials{volume: guestRootVolume(root), instanceID: testInstanceID}
	g, err := issueFor(newTestCA(t), creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishGeneration(creds.volume, g); err == nil {
		t.Fatal("generation was published on an unverified volume")
	}
	entries, err := os.ReadDir(root.Name())
	if err != nil || len(entries) != 0 {
		t.Fatalf("refused publication left %d entries: %v", len(entries), err)
	}
}

func TestGuestVolumeRefusesUserOwnedTmpfs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-created tmpfs directory is a valid guest volume")
	}
	root, err := os.OpenRoot(ramBackedDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	const want = "root-owned, non-writable volume"
	if err := requireGuestRoot(root); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("requireGuestRoot = %v, want %q", err, want)
	}
	if _, err := GuestIssuerBinding(root); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("GuestIssuerBinding = %v, want %q", err, want)
	}
}

// systemGuestRoot is a directory with a guest volume's custody: root-owned,
// RAM-backed and not writable by this process.
func systemGuestRoot(t *testing.T) *os.Root {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("needs a verified volume this process cannot write")
	}
	root, err := os.OpenRoot("/run")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := requireGuestRoot(root); err != nil {
		t.Skipf("no root-owned RAM-backed directory: %v", err)
	}
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt", pointerName, issuerRecordName, generationsSubdir} {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			t.Skipf("%s holds %s", root.Name(), name)
		}
	}
	return root
}

// Until admission evidence is available the broker keeps retrying, publishes
// nothing, and stops cleanly on cancellation.
func TestRunGuestRetriesWithoutEvidenceUntilCancelled(t *testing.T) {
	root := systemGuestRoot(t)
	if binding, err := GuestIssuerBinding(root); err != nil || binding != "" {
		t.Fatalf("never-issued volume binding = %q, %v", binding, err)
	}
	claims := guestTestClaims(t)
	asked := make(chan struct{}, 1)
	var commits atomic.Int64
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunGuest(ctx, GuestConfig{
			CDSURL: "https://cds.invalid", HTTPClient: &http.Client{}, VolumeRoot: root, InstanceID: claims.InstanceID(),
			Snapshot: func(context.Context) (workloadclaims.PodClaims, error) {
				select {
				case asked <- struct{}{}:
				default:
				}
				return workloadclaims.PodClaims{}, errors.New("admission not yet observed")
			},
			Commit: func(_ workloadclaims.PodClaims, publish func() error) error {
				commits.Add(1)
				return publish()
			},
		})
	}()
	select {
	case <-asked:
	case <-ctx.Done():
		t.Fatal("broker never asked for admission evidence")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunGuest = %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunGuest did not stop after cancellation")
	}
	if commits.Load() != 0 {
		t.Fatal("a generation was committed without admission evidence")
	}
}

func TestGuestRootPublicationFailsOnUnwritableVolume(t *testing.T) {
	root := systemGuestRoot(t)
	creds := &credentials{volume: guestRootVolume(root), instanceID: testInstanceID}
	g, err := issueFor(newTestCA(t), creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishGeneration(creds.volume, g); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("publishGeneration = %v, want a permission error", err)
	}
	if _, err := root.Lstat(generationsSubdir); !os.IsNotExist(err) {
		t.Fatalf("refused publication created generations: %v", err)
	}
}

func TestGuestIssuanceRefusesSnapshotOfAnotherInstance(t *testing.T) {
	claims := guestTestClaims(t)
	other := claims
	other.SandboxID = "another-sandbox"
	v := credentialVolume{dir: t.TempDir(), leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	creds := &credentials{volume: v, instanceID: claims.InstanceID()}
	guest := GuestConfig{InstanceID: claims.InstanceID(), Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return other, nil }}
	err := obtainGuestCert(t.Context(), guest, attestclient.Client{}, creds)
	if err == nil || !strings.Contains(err.Error(), "snapshot changed instance") || creds.current != nil {
		t.Fatalf("obtainGuestCert = %v", err)
	}
}

func TestGuestRootWithdrawalKeepsIssuerRecord(t *testing.T) {
	root := guestTempRoot(t)
	v := guestRootVolume(root)
	stageGuestReaders(t, root)
	want := issuerKeyID(strings.Repeat("cd", 32))
	if err := writeIssuerRecord(v, want); err != nil {
		t.Fatal(err)
	}
	if err := withdrawGeneration(v); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(v.names(), pointerName) {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("withdrawal retained %q: %v", name, err)
		}
	}
	if got, err := loadIssuerRecord(v); err != nil || got != want {
		t.Fatalf("issuer record = %q, %v; want %q", got, err, want)
	}
	if err := withdrawGeneration(v); err != nil {
		t.Fatalf("withdrawing an empty volume failed: %v", err)
	}
	if err := root.MkdirAll(filepath.Join("tls.key", "held"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := withdrawGeneration(v); err == nil {
		t.Fatal("an unremovable reader path was reported withdrawn")
	}
}

// guestCDS answers the challenge and returns chain for every certificate
// request, or fails every request when chain is empty.
func guestCDS(t *testing.T, chain string) (cds, attester *httptest.Server) {
	t.Helper()
	attester = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"platform":"tdx","evidence":{"quote":"fake"}}`)
	}))
	t.Cleanup(attester.Close)
	cds = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if chain == "" {
			http.Error(w, "CDS unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/authenticate" {
			_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(make([]byte, 32))})
			return
		}
		_, _ = io.WriteString(w, chain)
	}))
	t.Cleanup(cds.Close)
	return cds, attester
}

func TestGuestIssuanceFailureCommitsNothing(t *testing.T) {
	for name, chain := range map[string]string{
		"CDS unavailable":    "",
		"chain without a CA": testCertificatePEM(t),
	} {
		t.Run(name, func(t *testing.T) {
			claims := guestTestClaims(t)
			cds, attester := guestCDS(t, chain)
			v := credentialVolume{dir: t.TempDir(), leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
			creds := &credentials{volume: v, instanceID: claims.InstanceID()}
			var commits atomic.Int64
			guest := GuestConfig{InstanceID: claims.InstanceID(), AttestationAPIURL: attester.URL,
				Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return claims, nil },
				Commit: func(_ workloadclaims.PodClaims, publish func() error) error {
					commits.Add(1)
					return publish()
				}}
			err := obtainGuestCert(t.Context(), guest, attestclient.NewClientWithHTTP(cds.URL, cds.Client()), creds)
			if err == nil || commits.Load() != 0 || creds.current != nil {
				t.Fatalf("failed issuance committed: %v, commits=%d", err, commits.Load())
			}
			if _, err := os.Lstat(v.pointerPath()); !os.IsNotExist(err) {
				t.Fatalf("failed issuance left a pointer: %v", err)
			}
		})
	}
}

func TestGuestEvidenceLossFailsClosedWhenWithdrawalFails(t *testing.T) {
	v := credentialVolume{dir: t.TempDir(), leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	if err := os.MkdirAll(filepath.Join(v.pointerPath(), "held"), 0o755); err != nil {
		t.Fatal(err)
	}
	claims := guestTestClaims(t)
	denied := errors.New("admission denied")
	guest := GuestConfig{InstanceID: claims.InstanceID(), Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return workloadclaims.PodClaims{}, denied }}
	creds := &credentials{volume: v, instanceID: claims.InstanceID()}
	err := obtainCert(t.Context(), config{guest: &guest}, attestclient.Client{}, creds)
	if !errors.Is(err, denied) || !errors.Is(err, errFailClosed) {
		t.Fatalf("unwithdrawable credentials did not fail closed: %v", err)
	}
}

func TestGuestRenewalLoopFollowsChanges(t *testing.T) {
	attempts := stubObtainCertFailing(t)
	changes := make(chan struct{})
	guest := GuestConfig{Changes: changes}
	cfg := config{RenewInterval: time.Hour, InitialRetryInterval: time.Hour, guest: &guest}
	creds := &credentials{volume: credentialVolume{dir: t.TempDir(), leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}, instanceID: testInstanceID}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, attestclient.Client{}, allowlistclient.Client{}, creds) }()
	changes <- struct{}{}
	waitForAttempts(t, attempts, 1)
	changes <- struct{}{}
	close(changes)
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("renewal loop returned %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not stop after its changes closed")
	}
	if n := len(attempts()); n != 1 {
		t.Fatalf("a change during the retry backoff re-requested: %d attempts", n)
	}
}

// In a guest, a pod change after a successful renewal renews again.
func TestRenewLoopRenewsOnEachGuestPodChange(t *testing.T) {
	attempts := stubObtainCert(t, newTestCA(t), func(int) (time.Duration, error) {
		return time.Hour, nil
	})
	changes := make(chan struct{})
	cfg := config{
		RenewInterval:        time.Hour,
		InitialRetryInterval: time.Hour,
		guest:                &GuestConfig{Changes: changes},
	}
	startRenewLoop(t, cfg, "", &credentials{volume: testVolume(t), instanceID: testInstanceID})

	changes <- struct{}{}
	waitForAttempts(t, attempts, 1)
	changes <- struct{}{}
	waitForAttempts(t, attempts, 2)
}

// A closed guest change channel is not a pod change.
func TestRenewLoopIgnoresClosedGuestChanges(t *testing.T) {
	ca := newTestCA(t)
	creds := publishedCredentials(t, ca, time.Hour)
	named, err := issueNamedFor(ca, creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(named, time.Now()); err != nil {
		t.Fatal(err)
	}
	attempts := stubObtainCertFailing(t)
	changes := make(chan struct{})
	close(changes)
	cfg := config{
		RenewInterval: time.Hour,
		guest:         &GuestConfig{Changes: changes},
	}
	startRenewLoop(t, cfg, "", creds)

	time.Sleep(100 * time.Millisecond)
	if n := len(attempts()); n != 0 {
		t.Fatalf("%d renewals after the change channel closed, want 0", n)
	}
}
