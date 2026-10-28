// Package cdspins keeps a client's CDS pin set current across CDS image
// rollouts without relaunching the node.
//
// A client starts from the launch document's CDS pins (the bootstrap set).
// The operator changes which CDS images are accepted with a signed
// UpdateMeasurements decree that names the images; the replicas commit it and
// serve it at GET /ha/pins. When a client meets a CDS it does not recognise,
// it fetches that decree, checks the operator's signature with the decree
// key from its own launch document, and pins CDS to the decree's images.
//
// It asks a replica it already pins first (Attested): that answer is the
// decree the replicas applied, and is taken when it is newer than the one
// held or at the same base epoch with other content. Only when no replica
// under the current set answers does it fetch over an unverified channel
// (Fetch), where everything rests on the signature and only a strictly newer
// base epoch is taken, so an older decree replayed by the host is never
// taken. A decree taken that way is provisional: the next attested answer
// replaces it at any base epoch not below the last attested one, asked under
// the provisional pins and, when no replica passes those, under the last
// attested ones. A signed decree the replicas never applied, even with a
// higher base epoch, therefore never outlasts an attested fetch.
//
// With a state file the newest decree survives a restart of the client, not
// a reboot of the node (/run). There is no expiry: a host that withholds
// decrees can only delay a client, and a fail-closed timer would turn that
// into an outage.
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
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// ErrBelowFloor refuses a decree older than the node's launch-time floor.
var ErrBelowFloor = errors.New("cdspins: pin decree older than this node's floor")

// Fetcher returns the replicas' current pin decree, or nil when the pin set
// still is the bootstrap one.
type Fetcher func(ctx context.Context) (*cdsha.SignedDecree, error)

// AttestedFetcher is a Fetcher whose answer comes from a CDS that passed
// pins, the client's current set.
type AttestedFetcher func(ctx context.Context, pins refvalues.ReferenceValues) (*cdsha.SignedDecree, error)

// Config describes a Source.
type Config struct {
	ClusterID string
	DecreeKey []byte // PKIX DER, from the launch document
	Bootstrap refvalues.ReferenceValues
	// Attested, if set, is asked first; Fetch only when it fails.
	Attested AttestedFetcher
	Fetch    Fetcher
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

	mu     sync.Mutex
	gen    uint64
	cur    refvalues.ReferenceValues
	decree *cdsha.SignedDecree // in force; nil while on the bootstrap set
	// attested is the last decree an attested fetch delivered; nil before
	// the first. The decree in force is provisional when it is not this one.
	attested *cdsha.SignedDecree
	lastTry  time.Time
}

// state is the state file: the decree in force and the last attested one.
type pinState struct {
	InForce  *cdsha.SignedDecree `json:"in_force"`
	Attested *cdsha.SignedDecree `json:"attested"`
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
			var st pinState
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&st); err != nil || st.InForce == nil {
				return nil, fmt.Errorf("cdspins: state: not a pin state file: %v", err)
			}
			// A stored decree below a newer launch document's floor is
			// simply outdated: start from the bootstrap set. The attested
			// one is taken first, so the one in force keeps its standing.
			for _, sd := range []*cdsha.SignedDecree{st.Attested, st.InForce} {
				if sd == nil {
					continue
				}
				if _, err := s.take(sd, sd == st.Attested); err != nil && !errors.Is(err, ErrBelowFloor) {
					return nil, fmt.Errorf("cdspins: state: %w", err)
				}
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

// Refresh fetches the replicas' pin decree and takes it (see the package
// doc for which one). It reports whether the pin set changed. Call it when
// CDS fails the pin check, and on a timer if the client is long-lived.
func (s *Source) Refresh(ctx context.Context) (bool, error) {
	s.mu.Lock()
	if time.Since(s.lastTry) < s.cfg.MinInterval {
		s.mu.Unlock()
		return false, nil
	}
	s.lastTry = time.Now()
	asks := []refvalues.ReferenceValues{s.cur}
	if s.provisional() {
		// The provisional decree may pin images no replica runs: ask
		// under the last attested pins too.
		last, err := s.attestedPins()
		if err != nil {
			s.mu.Unlock()
			return false, err
		}
		asks = append(asks, last)
	}
	s.mu.Unlock()
	if s.cfg.Attested != nil {
		for _, pins := range asks {
			sd, err := s.cfg.Attested(ctx, pins)
			if err == nil {
				if sd == nil {
					return false, nil
				}
				return s.take(sd, true)
			}
		}
	}
	sd, err := s.cfg.Fetch(ctx)
	if err != nil || sd == nil {
		return false, err
	}
	return s.take(sd, false)
}

// provisional reports whether the decree in force was not delivered by an
// attested fetch. Callers hold s.mu.
func (s *Source) provisional() bool {
	return s.decree != nil && s.decree != s.attested
}

// attestedPins is the pin set of the last attested decree, or the bootstrap
// set before one. Callers hold s.mu.
func (s *Source) attestedPins() (refvalues.ReferenceValues, error) {
	if s.attested == nil {
		return s.cfg.Bootstrap, nil
	}
	return Policy(s.cfg.Bootstrap, s.attested.Decree.Images)
}

// take verifies sd and makes it the pin set if it replaces the one in force:
// a higher base epoch, or, from a replica the client pins (attested), the
// same base epoch with other content, or any base epoch not below the last
// attested decree's when the one in force is provisional.
//
// INVARIANT: the last attested decree's base epoch never decreases, and the
// decree in force is either that decree or one taken unverified with a
// higher base epoch, which the next attested answer replaces. An attested
// replica can thus deliver only what it could have had the host never served
// the unverified decree: nothing below the last attested base epoch.
func (s *Source) take(sd *cdsha.SignedDecree, attested bool) (bool, error) {
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
	nextAttested := s.attested
	if attested {
		if s.attested != nil && sd.Decree.BaseEpoch < s.attested.Decree.BaseEpoch {
			return false, nil // an older one replayed by a pinned replica
		}
		nextAttested = sd
	}
	changed := true
	if s.decree != nil {
		held := s.decree.Decree.BaseEpoch
		same := sameDecree(sd.Decree, s.decree.Decree)
		replaces := sd.Decree.BaseEpoch > held ||
			attested && sd.Decree.BaseEpoch == held && !same ||
			attested && s.provisional() && !same
		switch {
		case attested && s.provisional() && same:
			// The replicas applied the provisional decree: it is attested
			// now, and the pin set stays.
			changed = false
		case !replaces:
			return false, nil // the same decree, or an older one replayed
		}
	}
	next := sd
	if !changed {
		next = s.decree
		nextAttested = s.decree
	}
	if s.cfg.StateFile != "" {
		data, err := json.Marshal(pinState{InForce: next, Attested: nextAttested})
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
	s.attested = nextAttested
	if !changed {
		return false, nil
	}
	s.cur, s.decree = pol, sd
	s.gen++
	return true, nil
}

// Policy pins CDS to images under the launch anchors of the bootstrap set:
// which keys may launch a CDS comes from the launch document, which images
// it may run comes from the decree.
func Policy(bootstrap refvalues.ReferenceValues, images []cdsha.DecreeImage) (refvalues.ReferenceValues, error) {
	if bootstrap.Family != teetypes.FamilyTDX && bootstrap.Family != teetypes.FamilySNP {
		return refvalues.ReferenceValues{}, fmt.Errorf("cdspins: pin decrees name TDX or SNP images; the bootstrap set is for %q", bootstrap.Family)
	}
	if len(images) == 0 {
		return refvalues.ReferenceValues{}, errors.New("cdspins: a pin decree without images")
	}
	type anchor struct {
		name string
		key  []byte
	}
	// INVARIANT: every pin carries a launch-key anchor. A nil anchor would
	// admit a decreed image under any launch key.
	var anchors []anchor
	for _, img := range bootstrap.Images {
		if len(img.Anchor) == 0 {
			return refvalues.ReferenceValues{}, fmt.Errorf("cdspins: bootstrap image %q has no launch-key anchor", img.Name)
		}
		if !slices.ContainsFunc(anchors, func(a anchor) bool { return bytes.Equal(a.key, img.Anchor) }) {
			// A policy this function wrote names its pins <anchor>@<image>:
			// keep the anchor's name, so the names do not grow per rollout.
			name, _, _ := strings.Cut(img.Name, "@")
			anchors = append(anchors, anchor{name: name, key: img.Anchor})
		}
	}
	if len(anchors) == 0 {
		return refvalues.ReferenceValues{}, errors.New("cdspins: the bootstrap set pins no CDS image")
	}
	out := refvalues.ReferenceValues{Family: bootstrap.Family}
	for _, a := range anchors {
		for _, im := range images {
			if _, err := im.Pin(); err != nil {
				return refvalues.ReferenceValues{}, err
			}
			if im.SNP() != (bootstrap.Family == teetypes.FamilySNP) {
				return refvalues.ReferenceValues{}, fmt.Errorf("cdspins: a pin decree image of another TEE family than the bootstrap set's %q", bootstrap.Family)
			}
			// Images of one firmware share their MRTD and differ in their
			// RTMRs (kernel, command line): name each pin by all three, so
			// two images of one firmware get distinct names.
			id := sha256.Sum256([]byte(im.MRTD + im.RTMR1 + im.RTMR2 + im.Measurement))
			pin := remote.ImagePin{Name: a.name + "@" + hex.EncodeToString(id[:6]), Anchor: slices.Clone(a.key)}
			if im.SNP() {
				// As a launch document pins an SNP image: the launch digest.
				pin.Digest, _ = hex.DecodeString(im.Measurement)
			} else {
				pin.Digest, _ = hex.DecodeString(im.MRTD)
				r1, _ := hex.DecodeString(im.RTMR1)
				r2, _ := hex.DecodeString(im.RTMR2)
				pin.Registers = map[int][]byte{1: r1, 2: r2}
			}
			out.Images = append(out.Images, pin)
		}
	}
	// The shared parser is the schema check, as for launch documents.
	data, err := refvalues.Format(out)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	return refvalues.Parse(data)
}

// sameDecree reports whether two decrees say the same thing (their
// signatures may differ).
func sameDecree(a, b cdsha.Decree) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// HTTPFetch fetches GET <cdsURL>/ha/pins. The TLS peer is not verified: a
// client calls this precisely because it no longer recognises the CDS, and
// the decree carries the operator's signature.
func HTTPFetch(cdsURL string) Fetcher {
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // content is signature-verified
	}}
	return func(ctx context.Context) (*cdsha.SignedDecree, error) {
		return GetPins(ctx, hc, cdsURL)
	}
}

// AttestedHTTPFetch fetches GET <cdsURL>/ha/pins over armTLS from a CDS
// that passes the given pins, verified by the attestation-api at
// attestationAPIURL.
func AttestedHTTPFetch(cdsURL, attestationAPIURL string) AttestedFetcher {
	return func(ctx context.Context, pins refvalues.ReferenceValues) (*cdsha.SignedDecree, error) {
		hc, err := armtls.NewVerifyingHTTPClient(armtls.Pins(pins.Policy()), attestationAPIURL)
		if err != nil {
			return nil, err
		}
		defer hc.CloseIdleConnections()
		hc.Timeout = 10 * time.Second
		return GetPins(ctx, hc, cdsURL)
	}
}

// GetPins reads GET <cdsURL>/ha/pins with hc: the signed decree behind the
// replicas' pin set, or nil when they serve none (404). It does not verify
// the decree.
func GetPins(ctx context.Context, hc *http.Client, cdsURL string) (*cdsha.SignedDecree, error) {
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
