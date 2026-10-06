// Package getvolume implements the get-volume subcommand: the sidecar that
// fetches a volume's key blob from CDS and hands it to the node's volumed,
// which opens the device and mounts it into this pod.
//
// It runs as a native sidecar rather than an init container for the same reason
// get-secret does: CDS only releases once every main container is running, so an
// init container would be asking before its siblings exist (docs/secrets.md).
// The volume therefore appears shortly after the workload starts, and a
// consumer must wait for it.
package getvolume

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volumed"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// config is everything the sidecar needs. The webhook renders all of it.
type config struct {
	sidecar.Config

	Volumes []volumeRequest
	// SocketDir holds the node's volumed socket, as this pod sees it.
	SocketDir string
}

// volumeRequest is one NAME=/store/path pair: which volume to open and where
// its key blob lives in the store.
type volumeRequest struct {
	Name string
	Path string
}

// parseVolumeSpec parses a NAME=/store/path pair. The name selects the device
// by serial and names the Kubernetes volume the plaintext is mounted into, so
// it must be a DNS-1123 label short enough for a disk serial.
func parseVolumeSpec(spec string) (volumeRequest, error) {
	name, path, ok := strings.Cut(spec, "=")
	if !ok {
		return volumeRequest{}, fmt.Errorf("volume %q must be NAME=/store/path", spec)
	}
	name = strings.TrimSpace(name)
	if err := volumed.ValidVolumeName(name); err != nil {
		return volumeRequest{}, err
	}
	// Canonicalised with the same code CDS matches grants against, so a path
	// this sidecar accepts is one the server can answer for.
	canonical, err := pkgallowlist.CanonicalSecretPath(strings.TrimSpace(path))
	if err != nil {
		return volumeRequest{}, fmt.Errorf("volume %q: %w", name, err)
	}
	return volumeRequest{Name: name, Path: canonical}, nil
}

func run(cfg config) error {
	if err := validate(&cfg); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pins, err := cfg.ParsePins()
	if err != nil {
		return err
	}

	// A done ctx is the pod terminating — mid-pass or after idling — and any
	// volume opened by then must be released before kubelet's cleanup runs.
	defer func() {
		if ctx.Err() != nil {
			closeVolumes(cfg)
		}
	}()

	if err := sidecar.Retry(ctx, cfg.Config, "volume", func(ctx context.Context) error {
		return openAll(ctx, cfg, pins)
	}); err != nil {
		return err
	}
	slog.Info("volumes opened", "count", len(cfg.Volumes))

	// A native sidecar that exits is restarted by the kubelet for the pod's
	// life, re-running the whole release check each time. Idling until the pod
	// is torn down leaves its status reflecting the workload rather than this
	// sidecar.
	<-ctx.Done()
	return nil
}

// closeTimeout bounds the termination-time release, inside the pod's remaining
// grace.
const closeTimeout = 10 * time.Second

// closeVolumes releases this pod's volumes at termination, before kubelet's
// volume cleanup runs (see volumed.ClosePath). Failure is logged, not fatal:
// the node's reaper collects whatever this misses.
func closeVolumes(cfg config) {
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	daemon, base := daemonClient(cfg)
	if err := closeWith(ctx, daemon, base); err != nil {
		slog.Warn("volumes not released; the node reaper will collect them", "error", err)
		return
	}
	slog.Info("volumes released")
}

// closeWith is closeVolumes once the client exists.
func closeWith(ctx context.Context, daemon *http.Client, base string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+volumed.ClosePath, nil)
	if err != nil {
		return err
	}
	resp, err := daemon.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("close volumes: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

// openAll fetches and opens every requested volume in one pass. The daemon is
// idempotent for a repeated identical request, so a pass that fails partway is
// safe to run again.
func openAll(ctx context.Context, cfg config, pins armtls.Pins) error {
	client, pub, err := sidecar.NewClient(cfg.Config, pins)
	if err != nil {
		return err
	}
	daemon, base := daemonClient(cfg)
	return openAllWith(ctx, cfg, client, pub, cfg.Endpoint(), daemon, base)
}

// openAllWith is openAll once the clients exist.
func openAllWith(ctx context.Context, cfg config, cds *http.Client, pub crypto.PublicKey, endpoint string, daemon *http.Client, daemonBase string) error {
	for _, v := range cfg.Volumes {
		blob, err := fetchBlob(ctx, cfg, cds, pub, endpoint, v.Path)
		if err != nil {
			return fmt.Errorf("volume %s: %w", v.Name, err)
		}
		if err := openOne(ctx, cfg, daemon, daemonBase, v.Name, blob); err != nil {
			return fmt.Errorf("volume %s: %w", v.Name, err)
		}
	}
	return nil
}

// fetchBlob reads one volume's key blob from the store.
//
// GET only. get-secret creates a value when the store holds none, because the
// first pod of a workload to ask is the one that defines it. A volume key is
// never minted: the operator put it there with `c8s volume create`, and a POST
// here would squat the path with random bytes that decrypt nothing, leaving the
// real key unwritable behind a 409.
func fetchBlob(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, endpoint, path string) (volume.Blob, error) {
	value, _, err := sidecar.Do(ctx, cfg.Config, client, pub, endpoint, http.MethodGet, path)
	if err != nil {
		return volume.Blob{}, err
	}
	return volume.DecodeBlob(value)
}

// openOne hands the blob to the node daemon, which resolves this pod from the
// socket's peer credentials and mounts the volume into it.
func openOne(ctx context.Context, cfg config, daemon *http.Client, daemonBase, name string, blob volume.Blob) error {
	body, err := json.Marshal(volumed.OpenRequest{Name: name, Blob: blob})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, daemonBase+volumed.VolumePath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := daemon.Do(req)
	if err != nil {
		return fmt.Errorf("open volume: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("open volume: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

// daemonClient reaches volumed through the socket directory NRI-mounted into
// this sidecar and returns the base URL to post to.
func daemonClient(cfg config) (*http.Client, string) {
	sock := filepath.Join(cfg.SocketDir, volumed.SocketName)
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
		// The host is ignored on a unix transport; the URL only has to parse.
	}}, "http://volumed"
}

func validate(cfg *config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if len(cfg.Volumes) == 0 {
		return fmt.Errorf("at least one --volume NAME=/store/path is required")
	}
	seen := map[string]bool{}
	for _, v := range cfg.Volumes {
		if seen[v.Name] {
			return fmt.Errorf("--volume name %q is repeated; each names a distinct device", v.Name)
		}
		seen[v.Name] = true
	}
	if cfg.SocketDir == "" {
		return fmt.Errorf("--socket-dir is required")
	}
	return nil
}
