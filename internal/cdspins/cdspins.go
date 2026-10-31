// Package cdspins keeps a node's CDS pin set current across a CDS image roll.
//
// A node starts from the CDS pins its launch document carries. The operator
// moves a cluster to a new CDS image with a signed decree the replicas apply
// and serve at GET /ha/pins, carrying the cluster's pin document with every
// launch file elided. A client fills in the launch file it already pins,
// which must be the one the decree names, and verifies the decree under the
// operator keys and cluster id that same file carries: trust stays on the
// measured launch file, and a decree only says which images may boot it.
//
// A replica the client already pins answers over armTLS, and its answer is
// the decree the cluster applied. Where none answers, the client fetches over
// an unverified channel, where everything rests on the operator's signature:
// that decree is provisional and is taken only at a strictly higher version.
// The next attested answer replaces it at any version not below the last
// attested one.
//
// The state file carries both decrees across a restart of the client. There
// is no expiry: a host that withholds decrees can only delay a client, and a
// fail-closed timer would turn that delay into an outage.
package cdspins

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

var ErrSingleCDS = errors.New("cdspins: the launch file names a single CDS, which issues no pin decrees")

var errBelowFloor = errors.New("cdspins: the pin decree is below this node's floor")

// lookBudget bounds one look, every ask it makes together.
const lookBudget = 10 * time.Second

// Fetcher reads the decree the replicas serve, and nil where they serve none.
type Fetcher func(ctx context.Context) (*cdsdecree.Signed, error)

// AttestedFetcher is a Fetcher answered by a CDS that passed pins.
type AttestedFetcher func(ctx context.Context, pins refvalues.ReferenceValues) (*cdsdecree.Signed, error)

type Config struct {
	// Bootstrap names the launch file every decree is read against.
	Bootstrap refvalues.ReferenceValues
	// Attested is asked first, Fetch only where no pinned replica answers.
	Attested AttestedFetcher
	Fetch    Fetcher
	// StateFile carries the decrees across a restart of the client.
	StateFile string
	// Floor is the lowest version this node takes a decree at.
	Floor uint64
	// MinInterval spaces looks, so a burst of pin misses fetches once.
	MinInterval time.Duration
	Now         func() time.Time
}

func (c Config) check() error {
	switch {
	case c.Attested == nil || c.Fetch == nil:
		return errors.New("cdspins: a source reads decrees from a pinned replica and from an unverified fetch, and needs both")
	case c.StateFile == "":
		return errors.New("cdspins: a source keeps the decree it follows in a state file, and needs its path")
	}
	return nil
}

// Source is a client's CDS pin set as the cluster's decrees move it.
type Source struct {
	cfg        Config
	launchFile []byte
	clusterID  string
	keys       []*ecdsa.PublicKey

	mu         sync.Mutex
	generation uint64
	inForce    checked
	attested   checked
	// provisional marks a decree in force that no attested fetch delivered.
	provisional bool
	lastLook    time.Time
}

// checked is a decree past every check a client makes on its own.
type checked struct {
	signed  *cdsdecree.Signed
	version uint64
	pins    refvalues.ReferenceValues
}

type state struct {
	InForce  *cdsdecree.Signed `json:"in_force"`
	Attested *cdsdecree.Signed `json:"attested"`
}

// New resumes from the state file, and answers [ErrSingleCDS] where the
// bootstrap set pins a launch file naming one CDS rather than a cluster.
func New(cfg Config) (*Source, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	launchFile, err := cmdsutil.CDSLaunchFile(cfg.Bootstrap)
	if err != nil {
		return nil, fmt.Errorf("cdspins: the bootstrap pin set %w", err)
	}
	cluster, err := cdsconfig.ReadCluster(launchFile)
	if err != nil {
		return nil, fmt.Errorf("cdspins: the launch file the bootstrap set pins: %w", err)
	}
	if !cluster.Replicated {
		return nil, ErrSingleCDS
	}
	if cfg.MinInterval == 0 {
		cfg.MinInterval = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	source := &Source{
		cfg:        cfg,
		launchFile: launchFile,
		clusterID:  cluster.ClusterID,
		keys:       cluster.OperatorKeys,
	}
	if err := source.resume(); err != nil {
		return nil, err
	}
	return source, nil
}

// Current is the set to hold CDS to now.
func (s *Source) Current() refvalues.ReferenceValues {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pinsOf(s.inForce)
}

// Generation changes whenever Current does.
func (s *Source) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// Version is the version the decree in force applies at, and whether one is
// in force: a client holds its launch document's pins until the first decree.
func (s *Source) Version() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inForce.version, s.held()
}

// Refresh looks for a newer decree. Call it where CDS fails the pin check,
// and on a timer, so a node talking to no CDS still moves.
func (s *Source) Refresh() error {
	ask, due := s.dueForLook()
	if !due {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookBudget)
	defer cancel()
	served, answered := s.askPinnedReplica(ctx, ask)
	if answered {
		if served == nil {
			return nil
		}
		return s.takeAttested(served)
	}
	served, err := s.cfg.Fetch(ctx)
	if err != nil || served == nil {
		return err
	}
	return s.takeUnverified(served)
}

// askPinnedReplica reports the first answer, which may be that the cluster
// applied no decree, and false where no replica of any set answered.
func (s *Source) askPinnedReplica(ctx context.Context, ask []refvalues.ReferenceValues) (*cdsdecree.Signed, bool) {
	for _, pins := range ask {
		served, err := s.cfg.Attested(ctx, pins)
		if err == nil {
			return served, true
		}
	}
	return nil, false
}

// dueForLook reports the pin sets to ask a replica under, and nothing while
// the last look is newer than MinInterval. A provisional decree may pin
// images no replica runs, so the last attested set is asked under too.
func (s *Source) dueForLook() ([]refvalues.ReferenceValues, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if now.Sub(s.lastLook) < s.cfg.MinInterval {
		return nil, false
	}
	s.lastLook = now
	ask := []refvalues.ReferenceValues{s.pinsOf(s.inForce)}
	if s.provisional {
		ask = append(ask, s.pinsOf(s.attested))
	}
	return ask, true
}

// takeAttested takes the cluster's own answer, which replaces a provisional
// decree at any version.
func (s *Source) takeAttested(served *cdsdecree.Signed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken, err := s.check(served)
	if err != nil {
		return err
	}
	if s.olderThanLastAttested(taken) || s.olderThanTheClustersOwnAnswer(taken) {
		return nil
	}
	s.provisional = false
	return s.install(taken, taken)
}

// takeUnverified takes a decree off a channel that proved nothing, at a
// strictly higher version only: the host chooses what it serves there.
func (s *Source) takeUnverified(served *cdsdecree.Signed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken, err := s.check(served)
	if err != nil {
		return err
	}
	if !s.newerThanHeld(taken) {
		return nil
	}
	s.provisional = true
	return s.install(taken, s.attested)
}

// Callers hold s.mu.
func (s *Source) olderThanLastAttested(taken checked) bool {
	return taken.version < s.attested.version
}

// Callers hold s.mu.
func (s *Source) olderThanTheClustersOwnAnswer(taken checked) bool {
	return s.held() && !s.provisional && taken.version < s.inForce.version
}

// Callers hold s.mu.
func (s *Source) newerThanHeld(taken checked) bool {
	return !s.held() || taken.version > s.inForce.version
}

// check is everything a client decides about a decree on its own. Callers
// hold s.mu, so what is checked is what is installed.
func (s *Source) check(served *cdsdecree.Signed) (checked, error) {
	if err := cdsdecree.Verify(*served, s.keys, s.clusterID); err != nil {
		return checked{}, fmt.Errorf("cdspins: %w", err)
	}
	decree := served.Decree
	if decree.CDSPins == nil {
		return checked{}, fmt.Errorf("cdspins: the %s decree pins no CDS image", decree.Kind)
	}
	version := decree.AppliesAt()
	if belowFloor(version, s.cfg.Floor) {
		return checked{}, fmt.Errorf("%w: it applies at version %d, and the floor is %d", errBelowFloor, version, s.cfg.Floor)
	}
	pins, err := decree.CDSPins.WithLaunchFile(s.launchFile)
	if err != nil {
		return checked{}, fmt.Errorf("cdspins: %w", err)
	}
	return checked{
		signed:  served,
		version: version,
		pins:    pins,
	}, nil
}

// belowFloor refuses the replay of a decree the client was launched past.
func belowFloor(version, floor uint64) bool {
	return version < floor
}

// install writes the state file before either decree moves, so a restart
// comes back holding no more than the file says. Callers hold s.mu.
func (s *Source) install(inForce, attested checked) error {
	if err := s.save(inForce, attested); err != nil {
		return err
	}
	s.attested = attested
	s.hold(inForce)
	return nil
}

// hold moves the generation only for another decree, so a client rebuilds
// nothing for a re-served one. Callers hold s.mu.
func (s *Source) hold(decree checked) {
	if sameDecree(decree, s.inForce) {
		return
	}
	s.inForce = decree
	s.generation++
}

func (s *Source) save(inForce, attested checked) error {
	data, err := json.Marshal(state{
		InForce:  inForce.signed,
		Attested: attested.signed,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.StateFile), 0o700); err != nil {
		return fmt.Errorf("cdspins: state: %w", err)
	}
	if err := fileutil.WriteAtomic(s.cfg.StateFile, data, 0o600); err != nil {
		return fmt.Errorf("cdspins: state: %w", err)
	}
	return nil
}

// resume takes the last attested decree first, then the one in force.
func (s *Source) resume() error {
	held, err := s.storedState()
	if err != nil {
		return err
	}
	if err := s.resumeOne(held.Attested, s.takeAttested); err != nil {
		return err
	}
	return s.resumeOne(held.InForce, s.takeUnverified)
}

// resumeOne takes a stored decree by the rule that delivered it. One below a
// new floor leaves the client on its launch document's pins.
func (s *Source) resumeOne(stored *cdsdecree.Signed, take func(*cdsdecree.Signed) error) error {
	if stored == nil {
		return nil
	}
	if err := take(stored); err != nil && !errors.Is(err, errBelowFloor) {
		return err
	}
	return nil
}

// storedState is the zero state before the client has written the file.
func (s *Source) storedState() (state, error) {
	data, err := os.ReadFile(s.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return state{}, fmt.Errorf("cdspins: state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var held state
	if err := decoder.Decode(&held); err != nil {
		return state{}, fmt.Errorf("cdspins: state %s: %w", s.cfg.StateFile, err)
	}
	if held.InForce == nil {
		return state{}, fmt.Errorf("cdspins: state %s names no decree in force", s.cfg.StateFile)
	}
	return held, nil
}

// Callers hold s.mu.
func (s *Source) held() bool {
	return s.inForce.signed != nil
}

// pinsOf is the launch document's set before the first decree. Callers hold
// s.mu.
func (s *Source) pinsOf(decree checked) refvalues.ReferenceValues {
	if decree.signed == nil {
		return s.cfg.Bootstrap
	}
	return decree.pins
}

// sameDecree: the operator names every decree once, under its intent id.
func sameDecree(a, b checked) bool {
	return a.signed != nil && b.signed != nil && a.signed.Decree.IntentID == b.signed.Decree.IntentID
}
