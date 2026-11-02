//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

type cloudHAState struct {
	Instance string               `json:"instance"`
	Boot     int64                `json:"boot"`
	Status   cdsha.Status         `json:"status"`
	Pins     cdsdecree.Signed     `json:"pins"`
	Decrees  []cdsha.DecreeRecord `json:"decrees"`
	CA       string               `json:"ca"`
}

// Every HTTP observation, including an expected refusal, uses the measured
// launch pin. A host-provided endpoint or status code alone proves nothing.
func (r *cloudRun) haHTTP(ctx context.Context, cds endpoint, method, path string, body []byte) (int, []byte, error) {
	owned, err := r.getOwned(ctx, "cds")
	if err != nil {
		return 0, nil, err
	}
	if owned == nil || owned.Status != "running" {
		return 0, nil, errors.New("HA CDS is not running")
	}
	current, err := cloudEndpoint(owned, "cds")
	if err != nil || current != cds {
		return 0, nil, errors.New("HA CDS lost its owned endpoint")
	}
	base := "https://" + net.JoinHostPort(cds.Host, strconv.Itoa(cds.Port))
	options := cdsconn.Options{URL: base, MeasurementsConfig: filepath.Join(r.dir, "cds/cds-pin.json"), DirectCDS: true, Timeout: 20 * time.Second}
	client, err := options.HTTPClient(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err = errors.Join(readErr, response.Body.Close()); err != nil {
		return response.StatusCode, nil, err
	}
	if len(raw) > 1<<20 {
		return response.StatusCode, nil, errors.New("HA response exceeds bound")
	}
	return response.StatusCode, raw, nil
}

func (r *cloudRun) haGet(ctx context.Context, cds endpoint, path string, out any) error {
	code, raw, err := r.haHTTP(ctx, cds, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("authenticated HA %s returned HTTP %d", path, code)
	}
	return json.Unmarshal(raw, out)
}

func (r *cloudRun) haState(ctx context.Context, cds endpoint) (cloudHAState, error) {
	var state cloudHAState
	owned, err := r.getOwned(ctx, "cds")
	if err != nil {
		return state, err
	}
	if owned == nil {
		return state, errors.New("HA CDS is missing")
	}
	state.Instance, state.Boot = owned.ID, owned.Boot.Count
	if err = r.haGet(ctx, cds, "/ha/status", &state.Status); err != nil {
		return state, err
	}
	if !state.Status.Joined {
		return state, nil
	}
	if err = r.haGet(ctx, cds, "/ha/pins", &state.Pins); err != nil {
		return state, err
	}
	if err = r.haGet(ctx, cds, "/ha/decrees", &state.Decrees); err != nil {
		return state, err
	}
	code, ca, err := r.haHTTP(ctx, cds, http.MethodGet, "/ca", nil)
	if err != nil {
		return state, err
	}
	block, rest := pem.Decode(ca)
	if code != http.StatusOK || block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return state, errors.New("HA CDS did not serve its single mesh CA")
	}
	state.CA = certutil.CertFingerprint(block.Bytes)
	if state.CA != state.Status.CAFingerprint {
		return state, errors.New("HA CA differs from authenticated status")
	}
	return state, nil
}

func cloudHAUnjoined(s cloudHAState, run string) error {
	if s.Instance == "" || s.Boot < 1 || s.Status.ClusterID != run || s.Status.ID == "" || s.Status.Joined || s.Status.Serving.OK || s.Status.Version != 0 || !cloudHex.MatchString(s.Status.GenesisCA) {
		return errors.New("expected an authenticated, unjoined single HA replica")
	}
	return nil
}

func cloudHAJoined(before, after cloudHAState, version uint64) error {
	s := after.Status
	if after.Instance != before.Instance || after.Boot != before.Boot || s.ID != before.Status.ID || s.ClusterID != before.Status.ClusterID || !s.Joined || !s.Serving.OK || s.Version != version || s.NodeImagesVersion != 1 || s.Stuck != "" || s.GenesisCA != "" || len(s.Voters) != 1 || s.Voters[0] != s.ID || len(s.NonVoters) != 0 || after.CA != before.Status.GenesisCA || s.CAFingerprint != after.CA {
		return errors.New("HA member, boot, CA, serving state or applied version changed unexpectedly")
	}
	return nil
}

func (r *cloudRun) haOutput(name string) ([]byte, error) {
	path := filepath.Join(r.dir, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("regular HA CLI output required")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	raw, err := cloudPrivateRead(path, 1<<20)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (r *cloudRun) haIssued(name string) (cdsdecree.Signed, error) {
	raw, err := r.haOutput(name)
	if err != nil {
		return cdsdecree.Signed{}, err
	}
	return cdsdecree.Parse(raw)
}

// Genesis is an asynchronous held decree. Only independently observed cluster
// state and its applied log count as success; a successful CLI exit does not.
func (r *cloudRun) haWait(ctx context.Context, cds endpoint, before cloudHAState, issued cdsdecree.Signed, version uint64) (cloudHAState, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		state, err := r.haState(ctx, cds)
		if err == nil && cloudHAJoined(before, state, version) == nil && len(state.Decrees) == int(version) && state.Decrees[version-1].Version == version && reflect.DeepEqual(state.Decrees[version-1].Decree, issued) && reflect.DeepEqual(state.Pins, issued) {
			return state, nil
		}
		if err = cloudPause(ctx, 3*time.Second); err != nil {
			return state, errors.New("HA signed decree was not independently observed as applied")
		}
	}
}

func (r *cloudRun) haBootstrap(ctx context.Context, cds endpoint) error {
	var before cloudHAState
	for {
		state, err := r.haState(ctx, cds)
		if err == nil {
			before = state
			break
		}
		if err = cloudPause(ctx, 5*time.Second); err != nil {
			return errors.New("HA replica did not expose attested prejoin status")
		}
	}
	if err := cloudHAUnjoined(before, r.ledger.Run); err != nil {
		return err
	}
	proof := cloudHAProof{Run: r.ledger.Run, Before: before, Unjoined: map[string]int{}}
	for _, path := range []string{"/readyz", "/ca"} {
		code, raw, err := r.haHTTP(ctx, cds, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		if code != http.StatusServiceUnavailable || strings.TrimSpace(string(raw)) != "cds-ha: this replica has not joined its cluster" {
			return errors.New("unjoined HA replica did not refuse serving with authenticated 503")
		}
		proof.Unjoined[path] = code
	}
	if err := cloudWrite(filepath.Join(r.dir, "ha-proof.json"), proof); err != nil {
		return err
	}
	host := net.JoinHostPort(cds.Host, strconv.Itoa(cds.Port))
	common := []string{"--config", filepath.Join(r.dir, "cds/cds-config.yaml"), "--operator-key", filepath.Join(r.dir, "cds-operator.key"), "--cds-pin", filepath.Join(r.dir, "cds/cds-pin.json"), "--platform", "tdx", "--image-manifest", r.cfg.CDSManifestFile}
	genesisArgs := append([]string{"cds", "ha", "decree", "genesis"}, common...)
	genesisArgs = append(genesisArgs, "--target", host, "--resume-version", "0", "--alone", "--out", filepath.Join(r.dir, "ha-genesis.json"))
	if _, err := r.cli(ctx, genesisArgs...); err != nil {
		return err
	}
	genesis, err := r.haIssued("ha-genesis.json")
	if err != nil {
		return err
	}
	if proof.Genesis, err = r.haWait(ctx, cds, before, genesis, 1); err != nil {
		return err
	}
	if err = cloudWrite(filepath.Join(r.dir, "ha-proof.json"), proof); err != nil {
		return err
	}
	pinsArgs := append([]string{"cds", "ha", "decree", "pins"}, common...)
	pinsArgs = append(pinsArgs, "--to", host, "--base-version", "1", "--out", filepath.Join(r.dir, "ha-pins-issued.json"))
	if _, err = r.cli(ctx, pinsArgs...); err != nil {
		return err
	}
	pins, err := r.haIssued("ha-pins-issued.json")
	if err != nil {
		return err
	}
	if proof.Applied, err = r.haWait(ctx, cds, before, pins, 2); err != nil {
		return err
	}
	if _, err = r.cli(ctx, "cds", "ha", "pin-policy", "--config", filepath.Join(r.dir, "cds/cds-config.yaml"), "--cds-pin", filepath.Join(r.dir, "cds/cds-pin.json"), "--url", host, "--out", filepath.Join(r.dir, "ha-applied-pins.json"), "--decree-out", filepath.Join(r.dir, "ha-applied-decree.json")); err != nil {
		return err
	}
	exported, err := r.haIssued("ha-applied-decree.json")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(exported, pins) {
		return errors.New("HA CLI exported another pin decree")
	}
	if err = r.haVerifyApplied(proof); err != nil {
		return err
	}
	return cloudWrite(filepath.Join(r.dir, "ha-proof.json"), proof)
}

func (r *cloudRun) haVerifyApplied(p cloudHAProof) error {
	launch, err := cloudPrivateRead(filepath.Join(r.dir, "cds/cds-config.yaml"), 64<<10)
	if err != nil {
		return err
	}
	cfg, err := cdsconfig.Parse(launch)
	if err != nil {
		return err
	}
	if r.ledger.Owned["cds"] == nil || cfg.HA == nil || cfg.HA.Voters != 1 || !reflect.DeepEqual(cfg.HA.Replicas, []string{"10.0.2.2"}) || cloudHash(launch) != r.ledger.Owned["cds"].LaunchFileSHA256 {
		return errors.New("HA proof lost exact measured single-replica configuration")
	}
	for _, state := range []cloudHAState{p.Genesis, p.Applied} {
		for _, entry := range state.Decrees {
			if err = cdsdecree.Verify(entry.Decree, cfg.OperatorKeys.Keys(), r.ledger.Run); err != nil {
				return err
			}
			if entry.AtMS == 0 {
				return errors.New("HA decree log has no application timestamp")
			}
		}
		if state.Pins.Decree.CDSPins == nil {
			return errors.New("HA applied decree has no pins")
		}
		want, err := state.Pins.Decree.CDSPins.WithLaunchFile(launch)
		if err != nil {
			return err
		}
		// This lane deliberately keeps the same actual CDS image. It proves a
		// policy version/floor advance, not an image roll or old-image refusal.
		for _, name := range []string{"cds/cds-pin.json", "ha-applied-pins.json"} {
			raw, err := r.haOutput(name)
			if err != nil {
				return err
			}
			got, err := refvalues.Parse(raw)
			// Decree CLI labels include the launch digest; the bootstrap
			// generator uses the plain name. All measurements remain exact.
			if name == "cds/cds-pin.json" {
				for i, image := range got.Images {
					got.Images[i].Name = fmt.Sprintf("%s@%.4x", image.Name, image.Digest)
				}
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				return errors.New("HA decree changed the exact CDS image or launch binding")
			}
		}
	}
	return nil
}
