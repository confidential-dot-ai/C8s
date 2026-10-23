// Package cdspins keeps a client's CDS pin set current across CDS image
// rollouts without relaunching the node.
//
// A client starts from the launch document's CDS pins (the bootstrap set).
// The operator changes which CDS images are accepted with a signed
// UpdateMeasurements decree that names the images; the replicas commit it and
// serve it at GET /ha/pins. When a client meets a CDS it does not recognise,
// it fetches that decree from any replica, checks the operator's signature
// with the decree key from its own launch document, and, if the decree is
// newer than the one it holds, pins CDS to the decree's images. The
// transport is untrusted: everything rests on the signature.
//
// Ordering is by the decree's base epoch, so an older decree replayed by the
// host is never taken. With a state file the newest decree survives a
// restart of the client. There is no expiry: a host that withholds decrees
// can only delay a client, and a fail-closed timer would turn that into an
// outage.
package cdspins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// ErrBelowFloor refuses a decree older than the node's launch-time floor.
var ErrBelowFloor = errors.New("cdspins: pin decree older than this node's floor")

// Fetcher returns the replicas' current pin decree, or nil when the pin set
// still is the bootstrap one.
type Fetcher func(ctx context.Context) (*cdsha.SignedDecree, error)

// Config describes a Source.
type Config struct {
	ClusterID string
	DecreeKey []byte // PKIX DER, from the launch document
	Bootstrap refvalues.ReferenceValues
	Fetch     Fetcher
	// StateFile, if set, keeps the decree in force across restarts.
	StateFile string
	// MinInterval spaces fetches; a burst of misses fetches once.
	MinInterval time.Duration
	// MinEpoch is the lowest decree base epoch taken (the launch document's
	// pin floor): a node launched after a decree never takes an older one,
	// though it holds no state yet that would refuse the replay.
	MinEpoch uint64
}

// Source is a client's current CDS pin set.
type Source struct {
	cfg Config

	mu      sync.Mutex
	gen     uint64
	cur     refvalues.ReferenceValues
	decree  *cdsha.SignedDecree // in force; nil while on the bootstrap set
	lastTry time.Time
}

// New starts from the bootstrap set, or from the decree in the state file.
func New(cfg Config) (*Source, error) {
	if cfg.ClusterID == "" || len(cfg.DecreeKey) == 0 {
		return nil, errors.New("cdspins: cluster id and decree key are required")
	}
	if cfg.MinInterval == 0 {
		cfg.MinInterval = 2 * time.Second
	}
	s := &Source{cfg: cfg, cur: cfg.Bootstrap}
	if cfg.StateFile != "" {
		data, err := os.ReadFile(cfg.StateFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("cdspins: state: %w", err)
		default:
			var sd cdsha.SignedDecree
			if err := json.Unmarshal(data, &sd); err != nil {
				return nil, fmt.Errorf("cdspins: state: %w", err)
			}
			// A stored decree below a newer launch document's floor is
			// simply outdated: start from the bootstrap set.
			if _, err := s.take(&sd); err != nil && !errors.Is(err, ErrBelowFloor) {
				return nil, fmt.Errorf("cdspins: state: %w", err)
			}
		}
	}
	return s, nil
}

// Current is the policy to verify CDS against now.
func (s *Source) Current() refvalues.ReferenceValues {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Generation changes whenever Current does.
func (s *Source) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// Epoch is the base epoch of the decree in force, and whether one is.
func (s *Source) Epoch() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decree == nil {
		return 0, false
	}
	return s.decree.Decree.BaseEpoch, true
}

// Refresh fetches the replicas' pin decree and takes it if it is newer. It
// reports whether the pin set changed. Call it when CDS fails the pin check,
// and on a timer if the client is long-lived.
func (s *Source) Refresh(ctx context.Context) (bool, error) {
	s.mu.Lock()
	if time.Since(s.lastTry) < s.cfg.MinInterval {
		s.mu.Unlock()
		return false, nil
	}
	s.lastTry = time.Now()
	s.mu.Unlock()
	sd, err := s.cfg.Fetch(ctx)
	if err != nil || sd == nil {
		return false, err
	}
	return s.take(sd)
}

// take verifies sd and makes it the pin set if it is newer than the one in
// force.
func (s *Source) take(sd *cdsha.SignedDecree) (bool, error) {
	if err := cdsha.VerifyPinDecree(*sd, s.cfg.ClusterID, s.cfg.DecreeKey); err != nil {
		return false, err
	}
	if sd.Decree.BaseEpoch < s.cfg.MinEpoch {
		return false, fmt.Errorf("%w: base epoch %d, this node's floor is %d", ErrBelowFloor, sd.Decree.BaseEpoch, s.cfg.MinEpoch)
	}
	pol, err := Policy(s.cfg.Bootstrap, sd.Decree.Images)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decree != nil && sd.Decree.BaseEpoch <= s.decree.Decree.BaseEpoch {
		return false, nil // the same decree, or an older one replayed
	}
	if s.cfg.StateFile != "" {
		data, err := json.Marshal(sd)
		if err != nil {
			return false, err
		}
		if err := os.MkdirAll(filepath.Dir(s.cfg.StateFile), 0o755); err != nil {
			return false, err
		}
		if err := fileutil.WriteAtomic(s.cfg.StateFile, data, 0o644); err != nil {
			return false, err
		}
	}
	s.cur, s.decree = pol, sd
	s.gen++
	return true, nil
}

// Policy pins CDS to images under the launch anchors of the bootstrap set:
// which keys may launch a CDS comes from the launch document, which images
// it may run comes from the decree.
func Policy(bootstrap refvalues.ReferenceValues, images []cdsha.DecreeImage) (refvalues.ReferenceValues, error) {
	if bootstrap.Family != teetypes.FamilyTDX {
		return refvalues.ReferenceValues{}, fmt.Errorf("cdspins: pin decrees name TDX images; the bootstrap set is for %q", bootstrap.Family)
	}
	if len(images) == 0 {
		return refvalues.ReferenceValues{}, errors.New("cdspins: a pin decree without images")
	}
	type anchor struct {
		name string
		key  []byte
	}
	var anchors []anchor
	for _, img := range bootstrap.Images {
		if !slices.ContainsFunc(anchors, func(a anchor) bool { return bytes.Equal(a.key, img.Anchor) }) {
			anchors = append(anchors, anchor{name: img.Name, key: img.Anchor})
		}
	}
	if len(anchors) == 0 {
		anchors = []anchor{{name: "cds"}}
	}
	out := refvalues.ReferenceValues{Family: bootstrap.Family}
	for _, a := range anchors {
		for _, im := range images {
			mrtd, err1 := hex.DecodeString(im.MRTD)
			r1, err2 := hex.DecodeString(im.RTMR1)
			r2, err3 := hex.DecodeString(im.RTMR2)
			if err := errors.Join(err1, err2, err3); err != nil {
				return refvalues.ReferenceValues{}, err
			}
			// Images of one firmware share their MRTD and differ in their
			// RTMRs (kernel, command line): name each pin by all three, so
			// two images of one firmware get distinct names.
			id := sha256.Sum256([]byte(im.MRTD + im.RTMR1 + im.RTMR2))
			out.Images = append(out.Images, remote.ImagePin{Name: a.name + "@" + hex.EncodeToString(id[:6]), Digest: mrtd,
				Registers: map[int][]byte{1: r1, 2: r2}, Anchor: slices.Clone(a.key)})
		}
	}
	// The shared parser is the schema check, as for launch documents.
	data, err := refvalues.Format(out)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	return refvalues.Parse(data)
}

// HTTPFetch fetches GET <cdsURL>/ha/pins. The TLS peer is not verified: a
// client calls this precisely because it no longer recognises the CDS, and
// the decree carries the operator's signature.
func HTTPFetch(cdsURL string) Fetcher {
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // content is signature-verified
	}}
	return func(ctx context.Context) (*cdsha.SignedDecree, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cdsURL+"/ha/pins", nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusNotFound:
			return nil, nil
		default:
			return nil, fmt.Errorf("cdspins: GET /ha/pins: %s", resp.Status)
		}
		body, err := readutil.ReadAll(resp.Body, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("cdspins: GET /ha/pins: %w", err)
		}
		var sd cdsha.SignedDecree
		if err := json.Unmarshal(body, &sd); err != nil {
			return nil, fmt.Errorf("cdspins: GET /ha/pins: %w", err)
		}
		return &sd, nil
	}
}
