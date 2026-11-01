package getcert

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func guestTestClaims(t *testing.T) workloadclaims.PodClaims {
	t.Helper()
	env, err := allowlist.ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	return workloadclaims.PodClaims{Version: 1, BootID: strings.Repeat("b", 64), AssignedPodUID: "assigned", RuntimePodUID: "runtime", SandboxID: "sandbox", Revision: 1,
		RuntimeExtensions: []string{d}, Containers: []workloadclaims.SandboxContainer{{Digest: d, Argv: []string{"/app"}, Env: env, Mounts: []allowlist.ObservedMount{}}}}
}

func TestGuestIssuanceChecksSnapshotBeforePublishing(t *testing.T) {
	for _, mode := range []string{"publish", "stale snapshot", "cancelled", "wrong instance"} {
		t.Run(mode, func(t *testing.T) {
			claims := guestTestClaims(t)
			ca := newTestCA(t)
			nonce := bytes.Repeat([]byte{3}, 32)
			var report []byte
			attester := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req remote.AttestRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				report = req.ReportData
				_, _ = io.WriteString(w, `{"platform":"tdx","evidence":{"quote":"fake"}}`)
			}))
			defer attester.Close()
			cds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/authenticate" {
					_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(nonce)})
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
				if len(csr.Extensions) != 0 || len(req.SandboxToken) != 0 || req.RuntimeExtensions != nil {
					t.Error("guest requested node profile")
				}
				decoded, err := workloadclaims.DecodePodClaims(req.PodClaims)
				if err != nil {
					t.Error(err)
					return
				}
				want, err := workloadclaims.PodReportData(pub, nonce, req.PodClaims)
				if err != nil || !bytes.Equal(want, report) {
					t.Error("client quote binding differs from transmitted claims")
				}
				instance := decoded.InstanceID()
				if mode == "wrong instance" {
					instance = "another"
				}
				chain, err := ca.issue(pub, instance, time.Hour)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.WriteString(w, chain)
			}))
			defer cds.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v := credentialVolume{dir: t.TempDir(), leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
			creds := &credentials{volume: v, instanceID: claims.InstanceID()}
			stale := errors.New("admission changed")
			guest := GuestConfig{InstanceID: claims.InstanceID(), AttestationAPIURL: attester.URL, Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return claims, nil },
				Commit: func(got workloadclaims.PodClaims, publish func() error) error {
					if got.Revision != claims.Revision {
						t.Error("wrong revision")
					}
					if mode == "stale snapshot" {
						return stale
					}
					if mode == "cancelled" {
						cancel()
					}
					return publish()
				}}
			err := obtainGuestCert(ctx, guest, attestclient.NewClientWithHTTP(cds.URL, cds.Client()), creds)
			if mode == "publish" {
				if err != nil || creds.current == nil {
					t.Fatalf("no generation: %v", err)
				}
				return
			}
			if err == nil || creds.current != nil {
				t.Fatalf("unsafe generation published: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(v.dir, "current")); !os.IsNotExist(err) {
				t.Fatalf("rejected request left pointer: %v", err)
			}
		})
	}
}

func TestGuestRootPublicationStaysWithHeldVolume(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned guest publication requires root")
	}
	base := ramBackedDir(t)
	path := filepath.Join(base, "volume")
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	held := filepath.Join(base, "held")
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	v := credentialVolume{root: root, leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	creds := &credentials{volume: v, instanceID: testInstanceID}
	g, err := issueFor(newTestCA(t), creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(g, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "tls.key")); !os.IsNotExist(err) {
		t.Fatal("replaced path received key")
	}
	info, err := os.Stat(filepath.Join(held, "tls.key"))
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("key permissions: %v %v", info, err)
	}
	if err := withdrawGeneration(v); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("current"); !os.IsNotExist(err) {
		t.Fatal("withdrawal retained pointer")
	}
}

func TestGuestEvidenceLossWithdrawsWithoutRebindingCA(t *testing.T) {
	v := credentialVolume{dir: t.TempDir(), leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	claims := guestTestClaims(t)
	creds := &credentials{volume: v, instanceID: claims.InstanceID()}
	g, err := issueFor(newTestCA(t), creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(g, time.Now()); err != nil {
		t.Fatal(err)
	}
	bound := creds.issuer
	denied := errors.New("admission denied")
	guest := GuestConfig{InstanceID: claims.InstanceID(), Snapshot: func(context.Context) (workloadclaims.PodClaims, error) { return workloadclaims.PodClaims{}, denied }}
	err = obtainGuestCert(context.Background(), guest, attestclient.Client{}, creds)
	if !errors.Is(err, denied) || creds.current != nil || creds.issuer != bound {
		t.Fatalf("did not withdraw bound generation: %v", err)
	}
	if _, err := os.Lstat(v.pointerPath()); !os.IsNotExist(err) {
		t.Fatal("evidence loss retained current pointer")
	}
	if recorded, err := loadIssuerRecord(v); err != nil || recorded != bound {
		t.Fatal("evidence loss erased CA binding")
	}
}
