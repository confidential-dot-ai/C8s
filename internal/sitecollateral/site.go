// Package sitecollateral reads the collateral currently selected by a trusted site.
package sitecollateral

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/strictjson"
)

var ErrUnavailable = errors.New("site collateral unavailable")

type Profile struct {
	Origin         string `json:"origin"`
	TLSCertificate string `json:"tlsCertificate"`
	MediaPublicKey string `json:"mediaPublicKey"`
	Target         string `json:"target"`
}

type Selection struct {
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
}

type Object struct {
	SHA256 string      `json:"sha256"`
	Header http.Header `json:"header,omitempty"`
}

type Manifest struct {
	Generation uint64            `json:"generation"`
	Target     string            `json:"target"`
	ExpiresAt  time.Time         `json:"expiresAt"`
	Objects    map[string]Object `json:"objects"`
}

// Snapshot holds the selection and time authenticated for one evidence verification.
type Snapshot struct {
	Selection Selection
	Time      time.Time
	Manifest  Manifest
	responses map[string][]byte
}

type authority struct {
	origin string
	cert   *x509.Certificate
	media  ed25519.PublicKey
	client *http.Client
}

func Open(ctx context.Context, path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted site profile: %w", err)
	}
	var p Profile
	if err := strictjson.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode site profile: %w", err)
	}
	a, err := p.authority()
	if err != nil {
		return nil, err
	}
	selection, start, err := a.selection(ctx)
	if err != nil {
		return nil, err
	}
	base := "/snapshots/" + selection.SHA256
	raw, _, err := a.get(ctx, base+".json", "", 4<<20)
	if err != nil {
		return nil, err
	}
	if !matchesDigest(raw, selection.SHA256) {
		return nil, errors.New("active snapshot digest mismatch")
	}
	sig, _, err := a.get(ctx, base+".sig", "", ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	manifest, err := Authenticate(raw, sig, a.media, p.Target, start)
	if err != nil {
		return nil, err
	}
	if manifest.Generation != selection.Generation {
		return nil, errors.New("active generation differs from signed snapshot")
	}
	responses := make(map[string][]byte)
	for name, obj := range manifest.Objects {
		if !strings.HasPrefix(name, "https://") {
			continue
		}
		if len(responses) == 4 {
			return nil, errors.New("target snapshot contains more than four Intel responses")
		}
		body, _, err := a.get(ctx, "/objects/"+obj.SHA256, "", 8<<20)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if !matchesDigest(body, obj.SHA256) {
			return nil, fmt.Errorf("digest mismatch for %s", name)
		}
		responses[name] = body
	}
	current, at, err := a.selection(ctx)
	if err != nil {
		return nil, err
	}
	if current != selection || at.Before(start) || !at.Before(manifest.ExpiresAt) {
		return nil, errors.New("site selection or validity changed while reading collateral")
	}
	return &Snapshot{Selection: current, Time: at, Manifest: *manifest, responses: responses}, nil
}

func (a *authority) selection(ctx context.Context) (Selection, time.Time, error) {
	var nonce [32]byte
	rand.Read(nonce[:])
	challenge := hex.EncodeToString(nonce[:])
	active, headers, err := a.get(ctx, "/active", challenge, 1024)
	if err != nil {
		return Selection{}, time.Time{}, err
	}
	date, err := time.Parse(time.RFC3339Nano, headers.Get("X-C8s-Time"))
	if err != nil || len(headers.Values("X-C8s-Time")) != 1 || len(headers.Values("X-C8s-Challenge")) != 1 || headers.Get("X-C8s-Challenge") != challenge {
		return Selection{}, time.Time{}, fmt.Errorf("%w: missing fresh site selection or authenticated time", ErrUnavailable)
	}
	if date.Before(a.cert.NotBefore) || !date.Before(a.cert.NotAfter) {
		return Selection{}, time.Time{}, errors.New("site TLS certificate outside its validity at site time")
	}
	var selection Selection
	if err := strictjson.Unmarshal(active, &selection); err != nil || selection.Generation == 0 || !isDigest(selection.SHA256) {
		return Selection{}, time.Time{}, errors.New("invalid active site selection")
	}
	return selection, date, nil
}

func (p Profile) authority() (*authority, error) {
	origin, err := url.Parse(p.Origin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.ForceQuery || p.Target == "" {
		return nil, errors.New("site profile requires an HTTPS origin without a path and a target inventory ID")
	}
	block, rest := pem.Decode([]byte(p.TLSCertificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("site profile requires one PEM TLS leaf certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse site TLS certificate: %w", err)
	}
	media, err := MediaKey([]byte(p.MediaPublicKey))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		// The provisioned leaf authenticates site time before its validity can be checked.
		Time: func() time.Time { return cert.NotBefore },
		VerifyConnection: func(conn tls.ConnectionState) error {
			if !cert.Equal(conn.PeerCertificates[0]) {
				return errors.New("site TLS leaf differs from the provisioned certificate")
			}
			return nil
		},
	}
	return &authority{
		origin: origin.String(), cert: cert, media: media,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				DialContext:     (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
				TLSClientConfig: config, DisableKeepAlives: true, DisableCompression: true,
				MaxResponseHeaderBytes: 32 << 10,
			},
		},
	}, nil
}

func MediaKey(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM media public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse media public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("media public key must be Ed25519")
	}
	return pub, nil
}

func Authenticate(raw, sig []byte, pub ed25519.PublicKey, target string, now time.Time) (*Manifest, error) {
	if !ed25519.Verify(pub, raw, sig) {
		return nil, errors.New("invalid media signature on snapshot")
	}
	var m Manifest
	if err := strictjson.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode signed snapshot: %w", err)
	}
	if m.Generation == 0 || target == "" || m.Target != target || len(m.Objects) == 0 {
		return nil, errors.New("snapshot requires a positive generation, matching inventory ID and named objects")
	}
	if now.IsZero() || !now.Before(m.ExpiresAt) {
		return nil, fmt.Errorf("snapshot expired at %s", m.ExpiresAt.UTC())
	}
	for name, obj := range m.Objects {
		if name == "" || !isDigest(obj.SHA256) {
			return nil, fmt.Errorf("invalid object name or digest for %q", name)
		}
	}
	return &m, nil
}

func (a *authority) get(ctx context.Context, path, challenge string, limit int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.origin+path, nil)
	if err != nil {
		return nil, nil, err
	}
	if challenge != "" {
		req.Header.Set("X-C8s-Challenge", challenge)
		req.Header.Set("Cache-Control", "no-store")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: GET %s: %w", ErrUnavailable, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: GET %s: %s", ErrUnavailable, path, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read %s: %w", ErrUnavailable, path, err)
	}
	if int64(len(body)) > limit {
		return nil, nil, fmt.Errorf("site response %s exceeds %d bytes", path, limit)
	}
	return body, resp.Header, nil
}

func (s *Snapshot) Get(name string) (map[string][]string, []byte, error) {
	body, ok := s.responses[name]
	if !ok {
		return nil, nil, fmt.Errorf("snapshot %d lacks %s", s.Manifest.Generation, name)
	}
	return s.Manifest.Objects[name].Header.Clone(), body, nil
}

func isDigest(s string) bool {
	if len(s) != 2*sha256.Size || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func matchesDigest(data []byte, digest string) bool {
	return fmt.Sprintf("%x", sha256.Sum256(data)) == digest
}
