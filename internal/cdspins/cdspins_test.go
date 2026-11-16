package cdspins

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

const clusterID = "lane"

// cluster is the launch file one cluster's replicas boot.
func cluster(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return []byte("schemaVersion: c8s-cds/v1\nclusterID: " + clusterID + "\noperatorPublicKeys: |\n  " +
		strings.ReplaceAll(strings.TrimRight(string(block), "\n"), "\n", "\n  ") + "\nha:\n  voters: 3\n")
}

// singleCDS is the launch file of a CDS that runs alone.
const singleCDS = "schemaVersion: c8s-cds/v1\nclusterID: " + clusterID + "\n"

func operatorKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// pinSet pins CDS images to launchFile, as `c8s cds config new` writes it.
func pinSet(t *testing.T, launchFile []byte, digests ...byte) refvalues.ReferenceValues {
	t.Helper()
	set := refvalues.ReferenceValues{Family: teetypes.FamilySNP}
	for _, digest := range digests {
		set.Images = append(set.Images, remote.ImagePin{
			Name:       "cds-" + strconv.Itoa(int(digest)),
			Digest:     bytes.Repeat([]byte{digest}, refvalues.DigestSize),
			LaunchFile: launchFile,
		})
	}
	document, err := refvalues.Format(set)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := refvalues.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// pinDecree signs the decree moving a cluster to the images digests names.
func pinDecree(t *testing.T, key *ecdsa.PrivateKey, launchFile []byte, version uint64, digests ...byte) *cdsdecree.Signed {
	t.Helper()
	document, err := refvalues.Format(pinSet(t, launchFile, digests...))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := cdsdecree.NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(cdsdecree.Decree{
		ClusterID:   clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.UpdateMeasurements,
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseVersion: version,
		CDSPins:     pins,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &signed
}

// served is a fetcher answering with one decree, and counts the looks.
type served struct {
	decree *cdsdecree.Signed
	err    error
	looks  int
}

func (s *served) attested(context.Context, refvalues.ReferenceValues) (*cdsdecree.Signed, error) {
	s.looks++
	return s.decree, s.err
}

func (s *served) unverified(context.Context) (*cdsdecree.Signed, error) {
	s.looks++
	return s.decree, s.err
}

// refused is an attested fetcher no replica answers.
func refused(context.Context, refvalues.ReferenceValues) (*cdsdecree.Signed, error) {
	return nil, errors.New("no replica of the pinned set answered")
}

// follower is a Source over launchFile, with the clock the test holds.
func follower(t *testing.T, launchFile []byte, cfg Config) *Source {
	t.Helper()
	cfg.Bootstrap = pinSet(t, launchFile, 0x11)
	if cfg.Attested == nil {
		cfg.Attested = refused
	}
	if cfg.Fetch == nil {
		cfg.Fetch = func(context.Context) (*cdsdecree.Signed, error) { return nil, nil }
	}
	if cfg.StateFile == "" {
		cfg.StateFile = filepath.Join(t.TempDir(), "cds-decree.json")
	}
	source, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return source
}

// version is the version the decree in force applies at.
func version(t *testing.T, source *Source) uint64 {
	t.Helper()
	held, inForce := source.Version()
	if !inForce {
		t.Fatal("the source holds no decree")
	}
	return held
}

// digestsOf names the images a pin set holds CDS to, by their first byte.
func digestsOf(set refvalues.ReferenceValues) []byte {
	var digests []byte
	for _, image := range set.Images {
		digests = append(digests, image.Digest[0])
	}
	return digests
}

// A client holds CDS to the images the operator decreed, bound to the launch
// file it already pins: the decree carries none, so the images it names
// become an identity only once the client's own file is in them.
func TestADecreeMovesTheClientToTheImagesItNames(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	answers := &served{decree: pinDecree(t, key, launchFile, 7, 0x11, 0x22)}
	source := follower(t, launchFile, Config{Attested: answers.attested})

	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	set := source.Current()
	if got := digestsOf(set); len(got) != 2 || got[0] != 0x11 || got[1] != 0x22 {
		t.Fatalf("pins = %x, want both decreed images", got)
	}
	for _, image := range set.Images {
		if !bytes.Equal(image.LaunchFile, launchFile) {
			t.Fatalf("image %q binds %q, want the launch file the client pins", image.Name, image.LaunchFile)
		}
	}
	if version(t, source) != 7 || source.Generation() == 0 {
		t.Fatalf("version = %d, generation = %d, want the decree's version and a moved set", version(t, source), source.Generation())
	}
}

// Nothing but the keys and the cluster id in the launch file the client pins
// decides whether a decree is the operator's.
func TestADecreeOfAnotherClusterOrKeyIsRefused(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	other := pinDecree(t, operatorKey(t), launchFile, 7, 0x22)
	elsewhere := pinDecree(t, key, launchFile, 7, 0x22)
	elsewhere.Decree.ClusterID = "another"

	for name, decree := range map[string]*cdsdecree.Signed{
		"another operator key": other,
		"another cluster":      elsewhere,
	} {
		t.Run(name, func(t *testing.T) {
			answers := &served{decree: decree}
			source := follower(t, launchFile, Config{Attested: answers.attested})
			if err := source.Refresh(); err == nil {
				t.Fatal("a decree this node's launch file does not authorise was taken")
			}
			if got := digestsOf(source.Current()); len(got) != 1 || got[0] != 0x11 {
				t.Fatalf("pins = %x, want the launch document's set", got)
			}
		})
	}
}

// The decree carries the digest of the launch file its images bind, and a
// client holding another file is pinning another cluster's CDS.
func TestADecreeForAnotherLaunchFileIsRefused(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	answers := &served{decree: pinDecree(t, key, append(launchFile, '\n'), 7, 0x22)}
	source := follower(t, launchFile, Config{Attested: answers.attested})

	err := source.Refresh()
	if err == nil || !strings.Contains(err.Error(), "launch file") {
		t.Fatalf("error = %v, want the launch-file digest refusal", err)
	}
}

// A node launched after a decree never follows one the operator signed
// before it, which the host could otherwise replay to bring a retired image
// back.
func TestADecreeBelowTheFloorIsRefused(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	answers := &served{decree: pinDecree(t, key, launchFile, 7, 0x22)}
	source := follower(t, launchFile, Config{
		Attested: answers.attested,
		Floor:    9,
	})

	err := source.Refresh()
	if !errors.Is(err, errBelowFloor) {
		t.Fatalf("error = %v, want errors.Is errBelowFloor", err)
	}
	if got := digestsOf(source.Current()); len(got) != 1 || got[0] != 0x11 {
		t.Fatalf("pins = %x, want the launch document's set", got)
	}
}

// An unverified fetch proves only the operator's signature, so the host can
// serve any decree it ever saw. One at a version the client already holds
// moves nothing.
func TestAnUnverifiedDecreeIsTakenOnlyAtAHigherVersion(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	answers := &served{decree: pinDecree(t, key, launchFile, 7, 0x22)}
	source := follower(t, launchFile, Config{
		Fetch:       answers.unverified,
		MinInterval: time.Nanosecond,
	})

	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := digestsOf(source.Current()); len(got) != 1 || got[0] != 0x22 {
		t.Fatalf("pins = %x, want the decreed image", got)
	}
	answers.decree = pinDecree(t, key, launchFile, 7, 0x33)
	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := digestsOf(source.Current()); len(got) != 1 || got[0] != 0x22 {
		t.Fatalf("pins = %x, want the host's replay at the same version refused", got)
	}
}

// A replica the client pins answers for the cluster, so its decree replaces
// a provisional one even at a lower version: the host served that one.
func TestAnAttestedDecreeReplacesAProvisionalOne(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	host := &served{decree: pinDecree(t, key, launchFile, 9, 0x33)}
	// The client reaches a replica the provisional decree does not pin only
	// because it also asks under the set it last had attested.
	replica := &onlyUnderLaunchPins{applied: pinDecree(t, key, launchFile, 7, 0x22)}
	source := follower(t, launchFile, Config{
		Attested:    replica.serve,
		Fetch:       host.unverified,
		MinInterval: time.Nanosecond,
	})

	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := digestsOf(source.Current()); len(got) != 1 || got[0] != 0x33 {
		t.Fatalf("pins = %x, want the unverified decree", got)
	}

	replica.serving = true
	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := digestsOf(source.Current()); len(got) != 1 || got[0] != 0x22 {
		t.Fatalf("pins = %x, want the decree the cluster applied", got)
	}
	if replica.asked != 3 {
		t.Fatalf("the client asked under %d sets, want the provisional one and the last attested one", replica.asked)
	}
}

// onlyUnderLaunchPins answers an ask under the launch document's pins only.
type onlyUnderLaunchPins struct {
	applied *cdsdecree.Signed
	serving bool
	asked   int
}

func (o *onlyUnderLaunchPins) serve(_ context.Context, pins refvalues.ReferenceValues) (*cdsdecree.Signed, error) {
	o.asked++
	if !o.serving || digestsOf(pins)[0] != 0x11 {
		return nil, errors.New("no replica of that set answered")
	}
	return o.applied, nil
}

// Once the cluster's own answer is in force, a lower-versioned one from a
// pinned replica is a replay and moves nothing.
func TestAnAttestedReplayIsRefused(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	answers := &served{decree: pinDecree(t, key, launchFile, 9, 0x33)}
	source := follower(t, launchFile, Config{
		Attested:    answers.attested,
		MinInterval: time.Nanosecond,
	})

	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	moved := source.Generation()
	answers.decree = pinDecree(t, key, launchFile, 7, 0x22)
	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if source.Generation() != moved || digestsOf(source.Current())[0] != 0x33 {
		t.Fatalf("pins = %x at generation %d, want the newer decree kept", digestsOf(source.Current()), source.Generation())
	}
}

// A client restarts without a reboot and holds the images it last followed:
// otherwise every restart would walk back to the launch document's set and
// fail against a CDS on the image the operator moved to.
func TestTheDecreeInForceSurvivesARestart(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	stateFile := filepath.Join(t.TempDir(), "run", "cds-decree.json")
	answers := &served{decree: pinDecree(t, key, launchFile, 7, 0x22)}
	if err := follower(t, launchFile, Config{Attested: answers.attested, StateFile: stateFile}).Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	resumed := follower(t, launchFile, Config{StateFile: stateFile})
	if got := digestsOf(resumed.Current()); len(got) != 1 || got[0] != 0x22 {
		t.Fatalf("pins = %x, want the decree the state file holds", got)
	}
	if version(t, resumed) != 7 {
		t.Fatalf("version = %d, want the stored decree's", version(t, resumed))
	}
}

// A node relaunched with a higher floor is past the decree its state file
// holds, so it starts from the pins its new launch document carries.
func TestAStoredDecreeBelowANewFloorIsDropped(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	stateFile := filepath.Join(t.TempDir(), "cds-decree.json")
	answers := &served{decree: pinDecree(t, key, launchFile, 7, 0x22)}
	if err := follower(t, launchFile, Config{Attested: answers.attested, StateFile: stateFile}).Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	resumed := follower(t, launchFile, Config{
		StateFile: stateFile,
		Floor:     9,
	})
	if got := digestsOf(resumed.Current()); len(got) != 1 || got[0] != 0x11 {
		t.Fatalf("pins = %x, want the launch document's set", got)
	}
}

// A state file the client cannot read as its own is a fault, not an empty
// one: carrying on would silently drop the decree it holds.
func TestAnUnreadableStateFileFails(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	for name, content := range map[string]string{
		"not a pin state file": `{"in_force":{},"surprise":1}`,
		"no decree in force":   `{"in_force":null,"attested":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			stateFile := filepath.Join(t.TempDir(), "cds-decree.json")
			if err := os.WriteFile(stateFile, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := New(Config{
				Bootstrap: pinSet(t, launchFile, 0x11),
				Attested:  refused,
				Fetch:     func(context.Context) (*cdsdecree.Signed, error) { return nil, nil },
				StateFile: stateFile,
			})
			if err == nil || !strings.Contains(err.Error(), "state") {
				t.Fatalf("error = %v, want the state file named", err)
			}
		})
	}
}

// A burst of pin misses must not fetch once per handshake: every client of
// the node calls Refresh the moment CDS fails its check.
func TestLooksAreSpaced(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	answers := &served{decree: pinDecree(t, key, launchFile, 7, 0x22)}
	now := time.Now()
	source := follower(t, launchFile, Config{
		Attested:    answers.attested,
		MinInterval: time.Minute,
		Now:         func() time.Time { return now },
	})

	for range 5 {
		if err := source.Refresh(); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	}
	if answers.looks != 1 {
		t.Fatalf("looks = %d, want a burst of misses to fetch once", answers.looks)
	}
	now = now.Add(time.Minute)
	if err := source.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if answers.looks != 2 {
		t.Fatalf("looks = %d, want the next look once the interval passed", answers.looks)
	}
}

// One CDS answers for its own image and issues no decree, so a node pinning
// one follows nothing and polls nobody.
func TestACDSThatRunsAloneIsFollowedByNoOne(t *testing.T) {
	_, err := New(Config{
		Bootstrap: pinSet(t, []byte(singleCDS), 0x11),
		Attested:  refused,
		Fetch:     func(context.Context) (*cdsdecree.Signed, error) { return nil, nil },
		StateFile: filepath.Join(t.TempDir(), "cds-decree.json"),
	})
	if !errors.Is(err, ErrSingleCDS) {
		t.Fatalf("error = %v, want errors.Is ErrSingleCDS", err)
	}
}

// A source that cannot read a decree, or cannot keep the one it read, is a
// fault at construction rather than at the first image roll.
func TestASourceNeedsItsFetchersAndItsStateFile(t *testing.T) {
	key := operatorKey(t)
	launchFile := cluster(t, key)
	complete := Config{
		Bootstrap: pinSet(t, launchFile, 0x11),
		Attested:  refused,
		Fetch:     func(context.Context) (*cdsdecree.Signed, error) { return nil, nil },
		StateFile: filepath.Join(t.TempDir(), "cds-decree.json"),
	}
	short := map[string]Config{
		"no attested fetcher": {
			Bootstrap: complete.Bootstrap,
			Fetch:     complete.Fetch,
			StateFile: complete.StateFile,
		},
		"no unverified fetcher": {
			Bootstrap: complete.Bootstrap,
			Attested:  complete.Attested,
			StateFile: complete.StateFile,
		},
		"no state file": {
			Bootstrap: complete.Bootstrap,
			Attested:  complete.Attested,
			Fetch:     complete.Fetch,
		},
	}
	for name, cfg := range short {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("a source was built without what it reads or keeps decrees with")
			}
		})
	}
	if _, err := New(complete); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// A pin set that is not one CDS VM's identity names no launch file, and the
// client would have nothing to read a decree against.
func TestABootstrapSetThatNamesNoCDSIsRefused(t *testing.T) {
	_, err := New(Config{
		Bootstrap: refvalues.ReferenceValues{},
		Attested:  refused,
		Fetch:     func(context.Context) (*cdsdecree.Signed, error) { return nil, nil },
		StateFile: filepath.Join(t.TempDir(), "cds-decree.json"),
	})
	if err == nil {
		t.Fatal("a bootstrap set pinning no CDS was accepted")
	}
}
