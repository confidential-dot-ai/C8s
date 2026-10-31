package nriimagepolicy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const decreeClusterID = "lane"

// decreeVersion is the cluster version the test decrees apply at.
const decreeVersion = 7

// clusterLaunchFile is the launch file the replicas of one cluster boot.
func clusterLaunchFile(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	block := strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), "\n")
	return "schemaVersion: c8s-cds/v1\nclusterID: " + decreeClusterID + "\noperatorPublicKeys: |\n  " +
		strings.ReplaceAll(block, "\n", "\n  ") + "\nha:\n  voters: 3\n"
}

func decreeOperatorKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// clusterPinDecree signs the decree moving the cluster to measurement.
func clusterPinDecree(t *testing.T, key *ecdsa.PrivateKey, launchFile, measurement string) *cdsdecree.Signed {
	t.Helper()
	digest, err := hex.DecodeString(measurement)
	if err != nil {
		t.Fatal(err)
	}
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:       "cds",
			Digest:     digest,
			LaunchFile: []byte(launchFile),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pins, err := cdsdecree.NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(cdsdecree.Decree{
		ClusterID:   decreeClusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.UpdateMeasurements,
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseVersion: decreeVersion,
		CDSPins:     pins,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &signed
}

// followingNode is a node whose enforcer follows one decree the cluster serves.
func followingNode(t *testing.T, launchFile string, served *cdsdecree.Signed) (*plugin, *followedPins) {
	t.Helper()
	renderInTempDir(t)
	pin := cdsPinFile(t, testutil.CDSPinDocument(testutil.TestMeasurement, launchFile))
	bootstrap, err := refvalues.Load(pin)
	if err != nil {
		t.Fatal(err)
	}
	source, err := cdspins.New(cdspins.Config{
		Bootstrap:   bootstrap,
		Attested:    func(context.Context, refvalues.ReferenceValues) (*cdsdecree.Signed, error) { return served, nil },
		Fetch:       func(context.Context) (*cdsdecree.Signed, error) { return nil, nil },
		StateFile:   filepath.Join(t.TempDir(), decreeStateName),
		MinInterval: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("cdspins.New: %v", err)
	}
	decrees := &followedPins{
		Source: source,
		logger: discardLogger(),
	}
	p := testPlugin(t, &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: pin}},
	})
	if err := p.prepareCDSPins(decrees); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	holdContainersForFirstDecree(p, decrees)
	return p, decrees
}

// mountedPins is the policy the plugin hands its credential clients.
func mountedPins(t *testing.T, p *plugin) refvalues.ReferenceValues {
	t.Helper()
	set, err := refvalues.Load(p.cdsPins)
	if err != nil {
		t.Fatalf("the mounted policy does not load: %v", err)
	}
	return set
}

// Every CDS client of a node moves together: the enforcer writes the decree it
// followed into the policy it mounts, so a pod reads the new set.
func TestTheEnforcerHandsTheFollowedPinsToItsCredentialClients(t *testing.T) {
	key := decreeOperatorKey(t)
	launchFile := clusterLaunchFile(t, key)
	p, decrees := followingNode(t, launchFile, clusterPinDecree(t, key, launchFile, testutil.NextCDSImage))

	if got := hex.EncodeToString(mountedPins(t, p).Images[0].Digest); got != testutil.TestMeasurement {
		t.Fatalf("the mounted policy names %s, want the launch document's image", got)
	}
	if err := decrees.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := hex.EncodeToString(mountedPins(t, p).Images[0].Digest); got != testutil.NextCDSImage {
		t.Fatalf("the mounted policy names %s, want the decreed image", got)
	}
}

// A running pod's bind mount holds the file's inode, so the enforcer
// truncates and writes it rather than renaming a new file over it.
func TestTheFollowedPinsAreWrittenToTheSameInode(t *testing.T) {
	key := decreeOperatorKey(t)
	launchFile := clusterLaunchFile(t, key)
	p, decrees := followingNode(t, launchFile, clusterPinDecree(t, key, launchFile, testutil.NextCDSImage))
	before, err := os.Stat(p.cdsPins)
	if err != nil {
		t.Fatal(err)
	}

	if err := decrees.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	after, err := os.Stat(p.cdsPins)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the enforcer replaced the file its pods have bind-mounted")
	}
}

// A rebooted node holds no decree, so a container handed its CDS pins before
// the first look settles is refused and the kubelet retries it.
func TestContainersWaitForTheFirstDecree(t *testing.T) {
	key := decreeOperatorKey(t)
	launchFile := clusterLaunchFile(t, key)
	p, decrees := followingNode(t, launchFile, clusterPinDecree(t, key, launchFile, testutil.NextCDSImage))
	pod := routerNodeMountPod()
	ctr := makeCtr(pod.Id, workloadclaims.AttestContainerName)
	ctr.User = &api.User{Uid: workloadclaims.UpstreamUID}

	if !p.awaitingDecree.Load() {
		t.Fatal("a node that follows decrees serves containers before its first look")
	}
	if _, err := p.credentialMounts(t.Context(), pod, ctr); err == nil {
		t.Fatal("a container was handed the node's pins before the first decree settled")
	}
	p.serveAfterFirstDecreeLook(decrees)
	if p.awaitingDecree.Load() {
		t.Fatal("the plugin still holds containers back after the first look")
	}
	if _, err := p.credentialMounts(t.Context(), pod, ctr); err != nil {
		t.Fatalf("a container was refused after the first decree: %v", err)
	}
}

// The router is no credential client, so it reads the same followed pins at
// a path of its own.
func TestTheRouterTakesTheFollowedPinsAtItsOwnPath(t *testing.T) {
	p := routerNodeMountPlugin(t)
	pod := routerNodeMountPod()
	ctr := makeCtr(pod.Id, workloadclaims.AttestContainerName)
	ctr.User = &api.User{Uid: workloadclaims.UpstreamUID}

	adjustment := mustCredentialMounts(t, p, pod, ctr)
	mount := mountTo(adjustment, workloadclaims.RouterCDSPinsPath)
	if mount == nil || mount.GetSource() != p.cdsPins {
		t.Fatalf("the router's pin mount = %v, want the node's own policy", mount)
	}
	if mountTo(adjustment, workloadclaims.CDSPinsPath) != nil {
		t.Fatal("the router was handed a credential client's pin path")
	}
}

// A node whose CDS runs alone follows nothing: that CDS answers for its own
// image, and no decree ever moves it.
func TestANodePinningASingleCDSFollowsNoDecree(t *testing.T) {
	renderInTempDir(t)
	pin := cdsPinFile(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile))
	pins, decrees, err := pullConfig{
		CDSMeasurementsConfig: pin,
		URL:                   "https://cds.example",
	}.cdsPinSource(discardLogger())
	if err != nil {
		t.Fatalf("the node's CDS pins: %v", err)
	}
	if decrees != nil {
		t.Fatal("a node pinning a single CDS followed its decrees")
	}
	if got := hex.EncodeToString(pins.Current().Images[0].Digest); got != testutil.TestMeasurement {
		t.Fatalf("pins name %s, want the launch document's image", got)
	}
}

// The floor the launch document carries reaches the decrees the node reads, so
// a host cannot replay an older one to bring a retired image back.
func TestADecreeBelowTheNodesFloorIsRefused(t *testing.T) {
	key := decreeOperatorKey(t)
	launchFile := clusterLaunchFile(t, key)
	cds := servingDecree(t, clusterPinDecree(t, key, launchFile, testutil.NextCDSImage))
	for name, floor := range map[string]uint64{
		"above the decree": decreeVersion + 1,
		"at the decree":    decreeVersion,
	} {
		t.Run(name, func(t *testing.T) {
			renderInTempDir(t)
			pin := cdsPinFile(t, testutil.CDSPinDocument(testutil.TestMeasurement, launchFile))
			bootstrap, err := refvalues.Load(pin)
			if err != nil {
				t.Fatal(err)
			}
			decrees, err := pullConfig{
				CDSMeasurementsConfig: pin,
				URL:                   cds,
				AttestationApiURL:     "http://127.0.0.1:1",
				CDSPinFloor:           floor,
			}.cdsDecrees(bootstrap, discardLogger())
			if err != nil {
				t.Fatalf("cdsDecrees: %v", err)
			}

			err = decrees.Refresh()
			held := hex.EncodeToString(decrees.Current().Images[0].Digest)
			if floor > decreeVersion {
				if err == nil || held != testutil.TestMeasurement {
					t.Fatalf("refresh = %v leaving %s, want a decree below the floor refused", err, held)
				}
				return
			}
			if err != nil || held != testutil.NextCDSImage {
				t.Fatalf("refresh = %v leaving %s, want the decree at the floor followed", err, held)
			}
		})
	}
}

// servingDecree is a CDS no client can attest, serving one pin decree.
func servingDecree(t *testing.T, decree *cdsdecree.Signed) string {
	t.Helper()
	body, err := json.Marshal(decree)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ha/pins" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}
