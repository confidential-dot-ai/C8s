//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// CDS has a measured launch file, not a PEM launch key or signed node document.
// Keep its wire type separate so even empty key/signature fields cannot leak in.
type cloudCDSCreateRequest struct {
	Image     string            `json:"image"`
	Size      string            `json:"size"`
	Location  string            `json:"location"`
	Tee       string            `json:"tee"`
	Name      string            `json:"name"`
	Count     int               `json:"count"`
	Labels    map[string]string `json:"labels"`
	Network   networkSpec       `json:"network"`
	Readiness readinessSpec     `json:"readiness"`
	Trust     struct {
		InitData struct {
			Format   string `json:"format"`
			Document []byte `json:"document"`
		} `json:"initData"`
	} `json:"trust"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (r *cloudRun) cdsRequest(key string, labels map[string]string, document []byte) cloudCDSCreateRequest {
	req := cloudCDSCreateRequest{Image: r.cfg.CDSImage, Size: r.cfg.Size, Location: r.cfg.Location, Tee: "tdx", Name: key, Count: 1, Labels: labels, Network: networkSpec{PublicIP: "dedicated", Ingress: []ingress{{Name: "cds", Port: 8443}}}, Readiness: readinessSpec{TCPPorts: []int{}}, ExpiresAt: time.Now().Add(150 * time.Minute).UTC()}
	req.Trust.InitData.Format = cdsconfig.SchemaVersion
	req.Trust.InitData.Document = document
	return req
}

func (r *cloudRun) imagePolicy(public []byte, name string) ([]byte, error) {
	images, err := refvalues.FromImageManifest(r.cfg.ManifestFile, name, teetypes.FamilyTDX)
	if err != nil || len(images) != 1 {
		return nil, errors.New("single TDX Pod image measurement required")
	}
	images[0].Anchor = public
	return refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: images})
}

func (r *cloudRun) cdsBundle(ctx context.Context, workloadsPath, podPublicPath string) ([]byte, error) {
	for _, name := range []string{"server", "cds-operator"} {
		if _, err := r.cli(ctx, "keys", "new", "--out", filepath.Join(r.dir, name+".key"), "--pub-out", filepath.Join(r.dir, name+".pub")); err != nil {
			return nil, err
		}
	}
	podPublic, err := os.ReadFile(podPublicPath)
	if err != nil {
		return nil, err
	}
	serverPublic, err := os.ReadFile(filepath.Join(r.dir, "server.pub"))
	if err != nil {
		return nil, err
	}
	operatorPublic, err := os.ReadFile(filepath.Join(r.dir, "cds-operator.pub"))
	if err != nil {
		return nil, err
	}
	if err = cloudDistinctAuthorities(podPublic, serverPublic, operatorPublic); err != nil {
		return nil, err
	}
	operators, err := operatorauth.ParseKeyBundle(operatorPublic)
	if err != nil {
		return nil, err
	}
	nodes, err := r.imagePolicy(serverPublic, "unused-server")
	if err != nil {
		return nil, err
	}
	pods, err := r.imagePolicy(podPublic, "pod")
	if err != nil {
		return nil, err
	}
	if err = cloudWriteBytes(filepath.Join(r.dir, "node-policy.json"), nodes); err != nil {
		return nil, err
	}
	if err = cloudWriteBytes(filepath.Join(r.dir, "pod-policy.json"), pods); err != nil {
		return nil, err
	}
	workloads, err := cloudPrivateRead(workloadsPath, 64<<10)
	if err != nil {
		return nil, err
	}
	// The current schema requires a node authority. This separate server key
	// is never launched; it grants no Pod assignment or policy-write authority.
	expected, pin, err := cdsconfig.Build(cdsconfig.Inputs{ClusterID: r.ledger.Run, OperatorKeys: operators, ComponentSeed: workloads, Nodes: nodes, PodImagePolicy: pods, NodeCIDRs: []string{"10.0.0.0/24"}, ClusterCIDRs: []string{"10.52.0.0/16", "10.53.0.0/16"}, LeafDNSPatterns: []string{cmdsutil.ServiceDNSSANPattern}, ManifestPath: r.cfg.CDSManifestFile, Family: teetypes.FamilyTDX})
	if err != nil {
		return nil, err
	}
	if len(expected) == 0 || len(expected) > 64<<10 {
		return nil, errors.New("measured CDS configuration exceeds Cloud document bound")
	}
	bundle := filepath.Join(r.dir, "cds")
	if _, err = r.cli(ctx, "cds", "config", "new", "--out", bundle, "--cluster-id", r.ledger.Run,
		"--operator-keys", filepath.Join(r.dir, "cds-operator.pub"), "--allowlist-seed", workloadsPath,
		"--node-pins", filepath.Join(r.dir, "node-policy.json"), "--pod-image-policy-file", filepath.Join(r.dir, "pod-policy.json"),
		"--node-cidr", "10.0.0.0/24", "--pod-cidr", "10.52.0.0/16", "--service-cidr", "10.53.0.0/16",
		"--image-manifest", r.cfg.CDSManifestFile, "--platform", "tdx"); err != nil {
		return nil, err
	}
	for _, file := range []struct {
		name     string
		expected []byte
	}{{cdsconfig.ConfigFile, expected}, {cdsconfig.PinFile, pin}} {
		path := filepath.Join(bundle, file.name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return nil, errors.New("regular bounded CDS generator output required")
		}
		if err = os.Chmod(path, 0600); err != nil {
			return nil, err
		}
		actual, err := cloudPrivateRead(path, 1<<20)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(actual, file.expected) {
			return nil, errors.New("CDS generator output differs from exact measured inputs")
		}
	}
	return expected, nil
}

// No authenticated export is learned as the expected initial policy: it must
// equal the complete policy already bound into the CDS launch configuration.
func (r *cloudRun) cdsInitialPolicy(ctx context.Context, cds endpoint, workloadsPath string) error {
	raw, err := cloudPrivateRead(workloadsPath, 64<<10)
	if err != nil {
		return err
	}
	policy, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		return err
	}
	expected, err := policy.Canonical()
	if err != nil {
		return err
	}
	_, actual, err := r.policy(ctx, cds)
	if err != nil {
		return err
	}
	if err = r.cdsPolicyRequire("initial-measured", expected, actual); err != nil {
		return err
	}
	return r.cdsAccessControl(ctx, cds, expected)
}

func cloudDistinctAuthorities(public ...[]byte) error {
	var bundles []operatorauth.KeyBundle
	for _, raw := range public {
		bundle, err := operatorauth.ParseKeyBundle(raw)
		if err != nil || len(bundle.Keys()) != 1 {
			return errors.New("one key per Cloud run authority required")
		}
		for _, previous := range bundles {
			if bundle.Keys()[0].Equal(previous.Keys()[0]) {
				return errors.New("Pod, server and CDS operator authorities must be distinct")
			}
		}
		bundles = append(bundles, bundle)
	}
	return nil
}

type cloudCDSAccessProof struct {
	InstanceID   string         `json:"instanceID"`
	ConfigSHA256 string         `json:"configSHA256"`
	Statuses     map[string]int `json:"statuses"`
}

// An actual authenticated HTTP 401 is evidence of refusal. Connection failures,
// rate limiting and unrelated HTTP errors must never satisfy this check.
func cloudCDSUnauthorized(ctx context.Context, client *http.Client, base string, body []byte, auth operatorauth.Authorizer) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/allowlist", bytes.NewReader(body))
	if auth != nil {
		request, err = operatorauth.NewRequest(ctx, http.MethodPut, base+"/allowlist", body, auth)
	}
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	check := *client
	check.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := check.Do(request)
	if err != nil {
		return 0, err
	}
	message, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err = errors.Join(readErr, response.Body.Close()); err != nil {
		return response.StatusCode, err
	}
	if len(message) > 4096 || strings.TrimSpace(string(message)) != "unauthorized" || response.StatusCode != http.StatusUnauthorized {
		return response.StatusCode, errors.New("CDS did not refuse the unauthorized policy write")
	}
	return response.StatusCode, nil
}

func (r *cloudRun) cdsAccessControl(ctx context.Context, cds endpoint, baseline []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	owned, err := r.getOwned(ctx, "cds")
	if err != nil {
		return err
	}
	if owned == nil || owned.Status != "running" {
		return errors.New("owned CDS is not running")
	}
	current, err := cloudEndpoint(owned, "cds")
	if err != nil || current != cds {
		return errors.New("CDS access check lost its owned endpoint")
	}
	base := "https://" + net.JoinHostPort(cds.Host, strconv.Itoa(cds.Port))
	options := cdsconn.Options{URL: base, MeasurementsConfig: filepath.Join(r.dir, "cds/cds-pin.json"), DirectCDS: true, Timeout: 20 * time.Second}
	client, err := options.HTTPClient(ctx)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	proof := cloudCDSAccessProof{InstanceID: owned.ID, ConfigSHA256: r.ledger.Owned["cds"].LaunchFileSHA256, Statuses: map[string]int{}}
	for _, name := range []string{"unsigned", "provider", "server"} {
		var signer operatorauth.Authorizer
		if name != "unsigned" {
			key, err := cloudPrivateRead(filepath.Join(r.dir, name+".key"), 16<<10)
			if err != nil {
				return err
			}
			signer, err = operatorauth.NewSignerFromKeyPEM(key)
			if err != nil {
				return err
			}
		}
		if err = cloudWrite(filepath.Join(r.dir, "cds-access-"+name+"-intent.json"), map[string]any{"instanceID": owned.ID, "configSHA256": proof.ConfigSHA256, "bodySHA256": cloudHash(baseline), "authority": name}); err != nil {
			return err
		}
		status, refusal := cloudCDSUnauthorized(ctx, client, base, baseline, signer)
		proof.Statuses[name] = status
		if err = cloudWrite(filepath.Join(r.dir, "cds-access-observation.json"), proof); err != nil {
			return err
		}
		if refusal != nil {
			return refusal
		}
		_, after, err := r.policy(ctx, cds)
		if err != nil {
			return err
		}
		if err = r.cdsPolicyRequire("unauthorized-"+name, baseline, after); err != nil {
			return err
		}
	}
	return cloudWrite(filepath.Join(r.dir, "cds-access.json"), proof)
}

func (r *cloudRun) cdsAccessProofComplete() bool {
	owned := r.ledger.Owned["cds"]
	if owned == nil || owned.Receipt == nil || !cloudHex.MatchString(owned.LaunchFileSHA256) {
		return false
	}
	raw, err := cloudPrivateRead(filepath.Join(r.dir, "cds-access.json"), 16<<10)
	var proof cloudCDSAccessProof
	if err != nil || decode(raw, &proof) != nil || proof.InstanceID != owned.Receipt.ID || proof.ConfigSHA256 != owned.LaunchFileSHA256 || len(proof.Statuses) != 3 {
		return false
	}
	return proof.Statuses["unsigned"] == http.StatusUnauthorized && proof.Statuses["provider"] == http.StatusUnauthorized && proof.Statuses["server"] == http.StatusUnauthorized
}
