package cdsconfig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
)

// ObjectState fixes the storage authority and recovery signer in the measured
// launch. Credentials and the state encryption key never belong in this file.
type ObjectState struct {
	Bucket              string
	Key                 string
	Region              string
	Endpoint            string
	ExpectedBucketOwner string
	RecoveryAuthority   ed25519.PublicKey
	MaxBytes            int64
	Workers             int
	QueueCapacity       int
	SNPMinTCB           teetypes.SnpTcb
}

type objectStateWire struct {
	Bucket              string      `yaml:"bucket"`
	Key                 string      `yaml:"key"`
	Region              string      `yaml:"region"`
	Endpoint            string      `yaml:"endpoint,omitempty"`
	ExpectedBucketOwner string      `yaml:"expectedBucketOwner"`
	RecoveryAuthority   string      `yaml:"recoveryAuthority"`
	MaxBytes            int64       `yaml:"maxBytes,omitempty"`
	Workers             int         `yaml:"workers,omitempty"`
	QueueCapacity       int         `yaml:"queueCapacity,omitempty"`
	SNPMinTCB           *snpTCBWire `yaml:"snpMinTCB"`
}

type snpTCBWire struct {
	FMC        *uint8 `yaml:"fmc,omitempty"`
	Bootloader *uint8 `yaml:"bootloader"`
	Tee        *uint8 `yaml:"tee"`
	Snp        *uint8 `yaml:"snp"`
	Microcode  *uint8 `yaml:"microcode"`
}

var (
	objectBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	objectRegionPattern = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+-[1-9][0-9]*$`)
	objectOwnerPattern  = regexp.MustCompile(`^[0-9]{12}$`)
)

// ParseObjectState reads the standalone public settings passed to
// c8s cds config new --object-state-file; the surrounding objectState key is omitted.
func ParseObjectState(data []byte) (*ObjectState, error) {
	var document objectStateWire
	if err := yamlutil.Decode(
		data,
		&document,
	); err != nil {
		return nil, err
	}
	return document.parse()
}

func (w *objectStateWire) parse() (*ObjectState, error) {
	if w == nil {
		return nil, nil
	}
	if w.SNPMinTCB == nil || w.SNPMinTCB.FMC != nil || w.SNPMinTCB.Bootloader == nil || w.SNPMinTCB.Tee == nil || w.SNPMinTCB.Snp == nil || w.SNPMinTCB.Microcode == nil {
		return nil, errors.New("objectState.snpMinTCB requires all four approved SNP firmware components")
	}
	floor := teetypes.SnpTcb{Bootloader: *w.SNPMinTCB.Bootloader, Tee: *w.SNPMinTCB.Tee, Snp: *w.SNPMinTCB.Snp, Microcode: *w.SNPMinTCB.Microcode}
	if floor == (teetypes.SnpTcb{}) {
		return nil, errors.New("objectState.snpMinTCB must be an explicitly approved nonzero floor")
	}
	if !validObjectBucket(w.Bucket) {
		return nil, errors.New("objectState.bucket must name a general-purpose DNS bucket")
	}
	if !validObjectKey(w.Key) {
		return nil, errors.New("objectState.key must be a nonempty object path without control characters, empty segments or dot segments")
	}
	if !objectRegionPattern.MatchString(w.Region) {
		return nil, errors.New("objectState.region must name the storage Region explicitly")
	}
	if !validObjectEndpoint(w.Endpoint) {
		return nil, errors.New("objectState.endpoint must be an HTTPS origin without a path, credentials, query or fragment")
	}
	if !objectOwnerPattern.MatchString(w.ExpectedBucketOwner) {
		return nil, errors.New("objectState.expectedBucketOwner must be the 12-digit storage project identifier")
	}
	authority, err := base64.StdEncoding.Strict().DecodeString(w.RecoveryAuthority)
	if err != nil || len(authority) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(authority) != w.RecoveryAuthority {
		return nil, errors.New("objectState.recoveryAuthority must be a canonical base64 Ed25519 public key")
	}
	state := &ObjectState{
		Bucket:              w.Bucket,
		Key:                 w.Key,
		Region:              w.Region,
		Endpoint:            w.Endpoint,
		ExpectedBucketOwner: w.ExpectedBucketOwner,
		RecoveryAuthority:   authority,
		MaxBytes:            w.MaxBytes,
		Workers:             w.Workers,
		QueueCapacity:       w.QueueCapacity,
		SNPMinTCB:           floor,
	}
	state.setDefaults()
	if state.MaxBytes < 1<<20 || state.MaxBytes > 64<<20 {
		return nil, errors.New("objectState.maxBytes must be between 1 MiB and 64 MiB")
	}
	if state.Workers < 1 || state.Workers > 16 {
		return nil, errors.New("objectState.workers must be between 1 and 16")
	}
	if state.QueueCapacity < 1 || state.QueueCapacity > 256 {
		return nil, errors.New("objectState.queueCapacity must be between 1 and 256")
	}
	return state, nil
}

func validObjectBucket(bucket string) bool {
	if !objectBucketPattern.MatchString(bucket) || net.ParseIP(bucket) != nil {
		return false
	}
	for _, invalid := range []string{
		"..",
		".-",
		"-.",
	} {
		if strings.Contains(
			bucket,
			invalid,
		) {
			return false
		}
	}
	for _, prefix := range []string{
		"xn--",
		"sthree-",
	} {
		if strings.HasPrefix(
			bucket,
			prefix,
		) {
			return false
		}
	}
	for _, suffix := range []string{
		"-s3alias",
		"--ol-s3",
		".mrap",
		"--x-s3",
		"--table-s3",
	} {
		if strings.HasSuffix(
			bucket,
			suffix,
		) {
			return false
		}
	}
	return true
}

func validObjectKey(key string) bool {
	if len(key) == 0 || len(key) > 1024 || !utf8.ValidString(key) || strings.ContainsRune(
		key,
		'\\',
	) {
		return false
	}
	for _, character := range key {
		if unicode.IsControl(character) {
			return false
		}
	}
	for _, segment := range strings.Split(
		key,
		"/",
	) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validObjectEndpoint(endpoint string) bool {
	if endpoint == "" {
		return true
	}
	parsed, err := url.Parse(endpoint)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil &&
		parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery &&
		parsed.Fragment == "" && !strings.Contains(
		endpoint,
		"#",
	)
}

func (s *ObjectState) setDefaults() {
	if s.MaxBytes == 0 {
		s.MaxBytes = 16 << 20
	}
	if s.Workers == 0 {
		s.Workers = 4
	}
	if s.QueueCapacity == 0 {
		s.QueueCapacity = 64
	}
}

func (s *ObjectState) wire() *objectStateWire {
	if s == nil {
		return nil
	}
	return &objectStateWire{
		Bucket:              s.Bucket,
		Key:                 s.Key,
		Region:              s.Region,
		Endpoint:            s.Endpoint,
		ExpectedBucketOwner: s.ExpectedBucketOwner,
		RecoveryAuthority:   base64.StdEncoding.EncodeToString(s.RecoveryAuthority),
		MaxBytes:            s.MaxBytes,
		Workers:             s.Workers,
		QueueCapacity:       s.QueueCapacity,
		SNPMinTCB: &snpTCBWire{
			FMC:        s.SNPMinTCB.FMC,
			Bootloader: teetypes.Ptr(s.SNPMinTCB.Bootloader), Tee: teetypes.Ptr(s.SNPMinTCB.Tee), Snp: teetypes.Ptr(s.SNPMinTCB.Snp), Microcode: teetypes.Ptr(s.SNPMinTCB.Microcode),
		},
	}
}

// StorageDigest binds encrypted state and recovery grants to one storage
// authority, independently of launch policy and admission settings.
func (s *ObjectState) StorageDigest() [sha256.Size]byte {
	identity := struct {
		Bucket              string `json:"bucket"`
		Key                 string `json:"key"`
		Region              string `json:"region"`
		Endpoint            string `json:"endpoint"`
		ExpectedBucketOwner string `json:"expected_bucket_owner"`
	}{
		Bucket:              s.Bucket,
		Key:                 s.Key,
		Region:              s.Region,
		Endpoint:            s.Endpoint,
		ExpectedBucketOwner: s.ExpectedBucketOwner,
	}
	raw, _ := json.Marshal(identity)
	return sha256.Sum256(append(
		[]byte("c8s/cds/object-state/storage/v1\x00"),
		raw...,
	))
}
